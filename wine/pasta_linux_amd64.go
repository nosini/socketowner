package wine

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type pastaTarget struct {
	NetNS  uint64
	Active uint32
	Pad    uint32
}

// forwardKey names a pasta's DNS forward address as the sandbox sends to it.
type forwardKey struct {
	NetNS   uint64
	Address [16]byte
}

// dnsForward is the host resolver pasta connects instead of that address.
type dnsForward struct {
	Resolver [16]byte
}

// pastaProc is a pasta found by a scan, with the pidfd opened for it.
type pastaProc struct {
	pid, pidfd int
}

// registeredPasta is a registered pasta and the DNS forwards installed for it,
// so that they can be removed when it goes.
type registeredPasta struct {
	pid, fd  int
	forwards []forwardKey
}

// relays finds the pasta of each sandbox whose wineserver appeared. Nothing is
// read from pasta's memory, so no build matters: registration only says that
// sockets it connects stand in for flows from that network namespace, and its
// command line says where it sends DNS.
type relays struct {
	waiting map[int]*waitingServer
	// find, register, registered, dns, open, alive, closeFd and the forward
	// hooks are the process lookups, the pasta_targets and dns_forwards
	// updates and their pidfd handling, but for tests.
	find          func(server int) ([]pastaProc, error)
	register      func(pid, pidfd int, netns uint64) error
	registered    func(pidfd int, netns uint64) bool
	dns           func(pid int) (map[[16]byte][16]byte, error)
	updateForward func(key forwardKey, value dnsForward) error
	deleteForward func(key forwardKey) error
	open          func(pid int) (int, error)
	alive         func(pidfd int) bool
	closeFd       func(pidfd int)
	logf          func(format string, args ...any)
	reported      map[string]bool
}

// waitingServer is retried less often the longer no pasta appears: a sandbox may
// have no network or use another relay, and each scan walks all of /proc. Once
// a pasta is registered it stays on the list, so a replacement is found after
// the old one exits. serverFd identifies the wineserver and each pasta's fd
// identifies the registered pasta across PID reuse: a PID number can be reused
// while its pidfd is still held, so only liveness of that fd tells them apart.
type waitingServer struct {
	serverFd int
	netns    uint64
	next     time.Time
	delay    time.Duration
	pastas   map[int]*registeredPasta
}

const (
	maxScanDelay       = 30 * time.Second
	registeredMaxDelay = 5 * time.Second
)

// errPastaGone is a pasta which exited while being registered. Its sandbox is
// usually stopping; otherwise another pasta is looked for later.
var errPastaGone = errors.New("pasta exited")

func newRelays(targets, forwards *ebpf.Map) *relays {
	r := &relays{
		waiting:  map[int]*waitingServer{},
		find:     findPastas,
		open:     func(pid int) (int, error) { return unix.PidfdOpen(pid, 0) },
		alive:    alive,
		closeFd:  func(pidfd int) { unix.Close(pidfd) },
		logf:     log.Printf,
		reported: map[string]bool{},
		dns:      pastaDNS,
		register: func(pid, pidfd int, netns uint64) error {
			err := targets.Update(int32(pidfd), pastaTarget{NetNS: netns, Active: 1}, ebpf.UpdateAny)
			if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
				return errPastaGone
			}
			if err != nil {
				return fmt.Errorf("register pasta: %w", err)
			}
			return nil
		},
		// exec clears Active without closing the pidfd, so a live pasta fd
		// doesn't show that its registration still holds.
		registered: func(pidfd int, netns uint64) bool {
			var t pastaTarget
			return targets.Lookup(int32(pidfd), &t) == nil && t.Active != 0 && t.NetNS == netns
		},
	}
	if forwards != nil {
		r.updateForward = func(key forwardKey, value dnsForward) error {
			return forwards.Update(key, value, ebpf.UpdateAny)
		}
		r.deleteForward = func(key forwardKey) error {
			err := forwards.Delete(key)
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return nil
			}
			return err
		}
	}
	return r
}

// add records a wineserver seen now. The pidfd pins the process it names, so a
// later PID reuse does not mistake a successor for it.
func (r *relays) add(server int, netns uint64, now time.Time) {
	fd, err := r.open(server)
	if err != nil {
		if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) {
			return
		}
		r.report(fmt.Errorf("wineserver %d: %w", server, err))
		return
	}
	if w := r.waiting[server]; w != nil {
		if r.alive(w.serverFd) {
			w.netns = netns
			r.closeFd(fd)
			return
		}
		r.drop(w)
	}
	r.waiting[server] = &waitingServer{serverFd: fd, netns: netns, next: now, delay: scanInterval}
}

// drop releases the pidfds an entry holds and deletes the DNS forwards only it
// kept. pastas is cleared before pruning, so the removed entry's own list
// doesn't keep its old keys alive.
func (r *relays) drop(w *waitingServer) {
	r.closeFd(w.serverFd)
	var removed []forwardKey
	for _, rp := range w.pastas {
		removed = append(removed, rp.forwards...)
		r.closeFd(rp.fd)
	}
	w.pastas = nil
	r.pruneForwards(removed)
}

// close releases every held pidfd.
func (r *relays) close() {
	for server, w := range r.waiting {
		r.drop(w)
		delete(r.waiting, server)
	}
}

func (r *relays) report(err error) {
	if r.reported == nil {
		r.reported = make(map[string]bool)
	}
	message := err.Error()
	if r.reported[message] {
		return
	}
	r.reported[message] = true
	if r.logf != nil {
		r.logf("wine observer: %v", err)
	}
}

// findPastas wants every process outside the namespace, holding a descriptor
// for it, and running pasta. sandbox-game runs copies named NAME-pasta. The
// pidfd is opened before the checks and found alive after them, so they
// describe the process it refers to rather than a successor with a recycled
// PID. A process the observer may not inspect is reported without stopping the
// scan of the others.
func findPastas(server int) ([]pastaProc, error) {
	return findPastasAt("/proc", server)
}

func findPastasAt(proc string, server int) ([]pastaProc, error) {
	netns, err := os.Readlink(filepath.Join(proc, strconv.Itoa(server), "ns", "net"))
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(proc)
	if err != nil {
		return nil, err
	}
	var found []pastaProc
	var errs []error
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		pasta, perr := isPastaAt(proc, pid)
		if perr != nil {
			errs = append(errs, perr)
			continue
		}
		if !pasta {
			continue
		}
		pidfd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			continue
		}
		pasta, perr = isPastaAt(proc, pid)
		if perr != nil {
			unix.Close(pidfd)
			errs = append(errs, perr)
			continue
		}
		if !pasta {
			unix.Close(pidfd)
			continue
		}
		matches, rerr := relaysForAt(proc, pid, netns)
		if rerr != nil {
			unix.Close(pidfd)
			errs = append(errs, rerr)
			continue
		}
		if matches && alive(pidfd) {
			found = append(found, pastaProc{pid: pid, pidfd: pidfd})
		} else {
			unix.Close(pidfd)
		}
	}
	return found, errors.Join(errs...)
}

func isPasta(pid int) (bool, error) {
	return isPastaAt("/proc", pid)
}

// isPastaAt reports whether the process is pasta by the name of its
// executable. A process the observer may not inspect denies reading that
// link; its comm stays world-readable, so a pasta named there is reported
// instead of silently ignored, as relaysFor reports processes it may not
// inspect.
func isPastaAt(proc string, pid int) (bool, error) {
	exe, err := os.Readlink(filepath.Join(proc, strconv.Itoa(pid), "exe"))
	if err == nil {
		return strings.Contains(filepath.Base(exe), "pasta"), nil
	}
	// EACCES and EPERM both count, as for a hardened policy's denials.
	if !errors.Is(err, os.ErrPermission) {
		return false, nil
	}
	comm, cerr := os.ReadFile(filepath.Join(proc, strconv.Itoa(pid), "comm"))
	if cerr != nil || !strings.Contains(string(comm), "pasta") {
		return false, nil
	}
	return false, fmt.Errorf("pasta %d: %w", pid, err)
}

func relaysFor(pid int, netns string) (bool, error) {
	return relaysForAt("/proc", pid, netns)
}

func relaysForAt(proc string, pid int, netns string) (bool, error) {
	own, err := os.Readlink(filepath.Join(proc, strconv.Itoa(pid), "ns", "net"))
	if errors.Is(err, os.ErrPermission) {
		return false, fmt.Errorf("pasta %d: %w", pid, err)
	}
	if err != nil || own == netns {
		return false, nil
	}
	fds, err := os.ReadDir(filepath.Join(proc, strconv.Itoa(pid), "fd"))
	if errors.Is(err, os.ErrPermission) {
		return false, fmt.Errorf("pasta %d: %w", pid, err)
	}
	if err != nil {
		return false, nil
	}
	var permErr error
	for _, fd := range fds {
		link, err := os.Readlink(filepath.Join(proc, strconv.Itoa(pid), "fd", fd.Name()))
		if err == nil && link == netns {
			return true, nil
		}
		if errors.Is(err, os.ErrPermission) && permErr == nil {
			permErr = fmt.Errorf("pasta %d: %w", pid, err)
		}
	}
	return false, permErr
}

// alive needs no permission over the process: a pidfd polls readable once it
// exits. Even a zero-timeout poll can be interrupted, which says nothing.
func alive(pidfd int) bool {
	for range 3 {
		fds := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, 0)
		if err != unix.EINTR {
			return err == nil && n == 0
		}
	}
	return false
}

// scan registers the pastas found now. An entry whose wineserver fd is no longer
// alive is forgotten first. A sandbox with no pasta is retried, with growing
// delays, for as long as its wineserver lives. A registered pasta is checked
// again, so that a replacement joining the same namespace is registered too.
// Registration keeps nothing but the task storage entry, keyed by pidfd and
// revoked on exec. A pasta found again under the same pidfd is registered again
// unless that entry is still active, since it may have exec'd in between.
func (r *relays) scan(now time.Time, consume func(Event) error) error {
	for server, w := range r.waiting {
		if !r.alive(w.serverFd) {
			delete(r.waiting, server)
			r.drop(w)
			continue
		}
		if now.Before(w.next) {
			continue
		}
		found, err := r.find(server)
		if len(found) == 0 && errors.Is(err, os.ErrNotExist) {
			delete(r.waiting, server)
			r.drop(w)
			continue
		}
		if err != nil {
			r.report(err)
		}
		// No pasta was found. A held pasta fd which is still alive keeps the
		// registration: it could only have been missed, not replaced.
		if len(found) == 0 {
			for pid, rp := range w.pastas {
				if r.alive(rp.fd) {
					continue
				}
				delete(w.pastas, pid)
				r.closeFd(rp.fd)
				r.pruneForwards(rp.forwards)
			}
			w.next = now.Add(w.delay)
			w.delay = min(2*w.delay, maxScanDelay)
			continue
		}
		seen := make(map[int]bool, len(found))
		changed := false
		for idx, proc := range found {
			if seen[proc.pid] {
				r.closeFd(proc.pidfd)
				continue
			}
			seen[proc.pid] = true
			if rp := w.pastas[proc.pid]; rp != nil && r.alive(rp.fd) && r.registered(rp.fd, w.netns) {
				r.closeFd(proc.pidfd)
				continue
			}
			regErr := r.register(proc.pid, proc.pidfd, w.netns)
			if regErr == nil {
				changed = true
				old := w.pastas[proc.pid]
				if old != nil {
					r.closeFd(old.fd)
				}
				if w.pastas == nil {
					w.pastas = make(map[int]*registeredPasta)
				}
				rp := &registeredPasta{pid: proc.pid, fd: proc.pidfd}
				w.pastas[proc.pid] = rp
				r.registerDNS(rp, w.netns)
				if old != nil {
					r.pruneForwards(old.forwards)
				}
				if err := consume(Event{Type: "pasta", ServerTGID: uint32(server), PastaTGID: uint32(proc.pid), NetNS: w.netns}); err != nil {
					for _, rest := range found[idx+1:] {
						r.closeFd(rest.pidfd)
					}
					return err
				}
				continue
			}
			r.closeFd(proc.pidfd)
			if !errors.Is(regErr, errPastaGone) {
				for _, rest := range found[idx+1:] {
					r.closeFd(rest.pidfd)
				}
				return regErr
			}
			changed = true
			if old := w.pastas[proc.pid]; old != nil {
				delete(w.pastas, proc.pid)
				r.closeFd(old.fd)
				r.pruneForwards(old.forwards)
			}
		}
		for pid, old := range w.pastas {
			if seen[pid] {
				continue
			}
			// A scan that failed may only have missed a live pasta, as one
			// that found none does; keep it then too.
			if err != nil && r.alive(old.fd) {
				continue
			}
			delete(w.pastas, pid)
			r.closeFd(old.fd)
			r.pruneForwards(old.forwards)
			changed = true
		}
		if changed {
			w.delay = scanInterval
			w.next = now.Add(w.delay)
		} else {
			w.next = now.Add(w.delay)
			w.delay = min(2*w.delay, registeredMaxDelay)
		}
	}
	return nil
}

// registerDNS publishes the DNS forwarding a registered pasta applies. It only
// reports failures: the relay join still works without them, and DNS flows just
// stay unknown. Forwards the pasta no longer needs are deleted afterwards,
// unless another live registration still uses them.
func (r *relays) registerDNS(rp *registeredPasta, netns uint64) {
	old := rp.forwards
	rp.forwards = nil
	if r.updateForward == nil || r.dns == nil {
		r.pruneForwards(old)
		return
	}
	forward, err := r.dns(rp.pid)
	if err != nil {
		r.report(fmt.Errorf("pasta %d: %w", rp.pid, err))
	}
	for from, to := range forward {
		key := forwardKey{NetNS: netns, Address: from}
		if err := r.updateForward(key, dnsForward{Resolver: to}); err != nil {
			r.report(fmt.Errorf("pasta %d: register DNS forward: %w", rp.pid, err))
			break
		}
		rp.forwards = append(rp.forwards, key)
	}
	r.pruneForwards(old)
}

// pruneForwards deletes the given forwards which no registered pasta still
// uses, so that a replaced or exited pasta leaves no stale mapping.
func (r *relays) pruneForwards(keys []forwardKey) {
	if r.deleteForward == nil {
		return
	}
	for _, key := range keys {
		if r.forwardInUse(key) {
			continue
		}
		if err := r.deleteForward(key); err != nil {
			r.report(err)
		}
	}
}

func (r *relays) forwardInUse(key forwardKey) bool {
	for _, w := range r.waiting {
		for _, rp := range w.pastas {
			if slices.Contains(rp.forwards, key) {
				return true
			}
		}
	}
	return false
}

// pastaDNS reads the DNS address translation a pasta applies; see
// dnsTranslation for what it learns. Only the command line is read: pasta
// takes its default --dns-host from the resolv.conf of the environment it
// was started in, but pivots to an empty root before the observer can
// register it, so that file can no longer be reached.
func pastaDNS(pid int) (map[[16]byte][16]byte, error) {
	arguments, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil, err
	}
	fields := strings.Split(strings.TrimRight(string(arguments), "\x00"), "\x00")
	return dnsTranslation(fields)
}

// dnsOptions holds the DNS-related address options of a pasta's command
// line, indexed by family: 0 for IPv4 and IPv4-in-IPv6, 1 for IPv6.
type dnsOptions struct {
	forward [2]netip.Addr
	host    [2]netip.Addr
}

// parseDNSOptions reads the DNS-related address options of a pasta's command
// line, as pasta takes them: --dns-forward and --dns-host, each in joined or
// separate form and at most once per family.
func parseDNSOptions(fields []string) (dnsOptions, error) {
	var options dnsOptions
	for i := 0; i < len(fields); i++ {
		if fields[i] == "--" {
			// The command pasta runs follows; its arguments aren't pasta's.
			break
		}
		name, value, joined := strings.Cut(fields[i], "=")
		var target *[2]netip.Addr
		switch name {
		case "--dns-forward":
			target = &options.forward
		case "--dns-host":
			target = &options.host
		default:
			continue
		}
		if !joined {
			if i+1 >= len(fields) {
				return options, fmt.Errorf("%s without an address", name)
			}
			i++
			value = fields[i]
		}
		if value == "none" {
			// pasta's own spelling for an address option it unsets.
			*target = [2]netip.Addr{}
			continue
		}
		address, err := netip.ParseAddr(value)
		if err != nil {
			return options, fmt.Errorf("%s %s: %w", name, value, err)
		}
		if address.Is6() && !address.Is4In6() {
			(*target)[1] = address
		} else {
			(*target)[0] = address.Unmap()
		}
	}
	return options, nil
}

// dnsTranslation maps each address a pasta forwards DNS from onto the host
// resolver it connects instead, from its command line alone. pasta maps UDP
// and TCP to port 53 sent to each --dns-forward address onto the nameserver
// given by --dns-host, or by default the first nameserver of the resolv.conf
// it was started with. That default is not on the command line, and pasta
// pivots to an empty root before the observer can register it, so the
// resolv.conf can no longer be read: a family maps only when the command
// line names both addresses, and without --dns-host for a --dns-forward
// address the mapping is reported missing once for that pasta, and queries
// to that address stay unknown. Without --dns-forward, pasta maps its
// --map-host-loopback or default gateway address, whose host nameserver no
// command line names, and such queries stay unknown too.
func dnsTranslation(fields []string) (map[[16]byte][16]byte, error) {
	options, err := parseDNSOptions(fields)
	if err != nil {
		return nil, err
	}
	return options.translation()
}

// translation maps each --dns-forward address with a --dns-host address onto
// that host address, per family. A --dns-forward address without --dns-host
// is an error: the observer would otherwise silently leave that family's
// DNS unknown, and reporting it once names the pasta that needs a
// --dns-host on its command line.
func (o dnsOptions) translation() (map[[16]byte][16]byte, error) {
	translation := make(map[[16]byte][16]byte)
	var errs []error
	for family := range 2 {
		forward, host := o.forward[family], o.host[family]
		if !forward.IsValid() {
			continue
		}
		if !host.IsValid() {
			errs = append(errs, fmt.Errorf("--dns-forward %s without --dns-host: pasta takes its default host nameserver from a resolv.conf the observer cannot read", forward))
			continue
		}
		translation[forward.As16()] = host.As16()
	}
	return translation, errors.Join(errs...)
}
