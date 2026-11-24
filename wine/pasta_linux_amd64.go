package wine

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
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

// relays finds the pasta of each sandbox whose wineserver appeared. Nothing is
// read from pasta's memory, so no build matters: registration only says that
// sockets it connects stand in for flows from that network namespace, and its
// command line says where it sends DNS.
type relays struct {
	waiting map[int]*waitingServer
	// forwards holds the dns_forwards map. find, register, registered,
	// dns, open, alive and closeFd are the process lookups, the
	// pasta_targets and dns_forwards updates and their pidfd handling,
	// but for tests.
	forwards   *ebpf.Map
	find       func(server int) (pid, pidfd int, err error)
	register   func(pid, pidfd int, netns uint64) error
	registered func(pidfd int, netns uint64) bool
	dns        func(pid int) (map[[16]byte][16]byte, error)
	open       func(pid int) (int, error)
	alive      func(pidfd int) bool
	closeFd    func(pidfd int)
	logf       func(format string, args ...any)
	reported   map[string]bool
}

// waitingServer is retried less often the longer no pasta appears: a sandbox may
// have no network or use another relay, and each scan walks all of /proc. Once
// a pasta is registered it stays on the list, so a replacement is found after
// the old one exits. serverFd identifies the wineserver and pastaFd the
// registered pasta across PID reuse: a PID number can be reused while its pidfd
// is still held, so only liveness of that fd tells them apart.
type waitingServer struct {
	serverFd int
	netns    uint64
	next     time.Time
	delay    time.Duration
	pastaPid int
	pastaFd  int
}

const (
	maxScanDelay       = 30 * time.Second
	registeredMaxDelay = 5 * time.Second
)

// errPastaGone is a pasta which exited while being registered. Its sandbox is
// usually stopping; otherwise another pasta is looked for later.
var errPastaGone = errors.New("pasta exited")

func newRelays(targets, forwards *ebpf.Map) *relays {
	return &relays{
		waiting:  map[int]*waitingServer{},
		forwards: forwards,
		find:     findPasta,
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

// drop releases the pidfds an entry holds. pastaPid is set exactly when a pasta
// fd is held, so a zero entry never closes fd 0.
func (r *relays) drop(w *waitingServer) {
	r.closeFd(w.serverFd)
	if w.pastaPid != 0 {
		r.closeFd(w.pastaFd)
		w.pastaPid, w.pastaFd = 0, 0
	}
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

// findPasta wants a process outside the namespace, holding a descriptor for it,
// and running pasta. sandbox-game runs copies named NAME-pasta. The pidfd is
// opened before the checks and found alive after them, so they describe the
// process it refers to rather than a successor with a recycled PID.
func findPasta(server int) (int, int, error) {
	netns, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", server))
	if err != nil {
		return 0, -1, err
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, -1, err
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || !isPasta(pid) {
			continue
		}
		pidfd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			continue
		}
		if isPasta(pid) && relaysFor(pid, netns) && alive(pidfd) {
			return pid, pidfd, nil
		}
		unix.Close(pidfd)
	}
	return 0, -1, nil
}

func isPasta(pid int) bool {
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	return err == nil && strings.Contains(filepath.Base(exe), "pasta")
}

func relaysFor(pid int, netns string) bool {
	own, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil || own == netns {
		return false
	}
	fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return false
	}
	for _, fd := range fds {
		if link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name())); err == nil && link == netns {
			return true
		}
	}
	return false
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
			r.drop(w)
			delete(r.waiting, server)
			continue
		}
		if now.Before(w.next) {
			continue
		}
		pid, pidfd, err := r.find(server)
		if errors.Is(err, os.ErrNotExist) {
			r.drop(w)
			delete(r.waiting, server)
			continue
		}
		if err != nil {
			r.report(err)
			w.next = now.Add(w.delay)
			w.delay = min(2*w.delay, maxScanDelay)
			continue
		}
		// No pasta was found. A held pasta fd which is still alive keeps the
		// registration: it could only have been missed, not replaced.
		if pid == 0 {
			w.next = now.Add(w.delay)
			w.delay = min(2*w.delay, maxScanDelay)
			continue
		}
		if pid == w.pastaPid && r.alive(w.pastaFd) && r.registered(w.pastaFd, w.netns) {
			r.closeFd(pidfd)
			w.next = now.Add(w.delay)
			w.delay = min(2*w.delay, registeredMaxDelay)
			continue
		}
		err = r.register(pid, pidfd, w.netns)
		if err == nil {
			oldFd, oldPid := w.pastaFd, w.pastaPid
			w.pastaPid, w.pastaFd = pid, pidfd
			if oldPid != 0 {
				r.closeFd(oldFd)
			}
			w.delay = scanInterval
			w.next = now.Add(w.delay)
			r.registerDNS(pid, w.netns)
			if err := consume(Event{Type: "pasta", ServerTGID: uint32(server), PastaTGID: uint32(pid), NetNS: w.netns}); err != nil {
				return err
			}
			continue
		}
		r.closeFd(pidfd)
		if !errors.Is(err, errPastaGone) {
			return err
		}
		if w.pastaPid != 0 {
			r.closeFd(w.pastaFd)
			w.pastaPid, w.pastaFd = 0, 0
		}
		w.delay = scanInterval
		w.next = now.Add(w.delay)
	}
	return nil
}

// registerDNS publishes the DNS forwarding a registered pasta applies. It only
// reports failures: the relay join still works without them, and DNS flows just
// stay unknown.
func (r *relays) registerDNS(pid int, netns uint64) {
	if r.forwards == nil || r.dns == nil {
		return
	}
	forward, err := r.dns(pid)
	if err != nil {
		r.report(fmt.Errorf("pasta %d: %w", pid, err))
		return
	}
	for from, to := range forward {
		key := forwardKey{NetNS: netns, Address: from}
		if err := r.forwards.Update(key, dnsForward{Resolver: to}, ebpf.UpdateAny); err != nil {
			r.report(fmt.Errorf("pasta %d: register DNS forward: %w", pid, err))
			return
		}
	}
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
	for family := range 2 {
		forward, host := o.forward[family], o.host[family]
		if !forward.IsValid() {
			continue
		}
		if !host.IsValid() {
			return nil, fmt.Errorf("--dns-forward %s without --dns-host: pasta takes its default host nameserver from a resolv.conf the observer cannot read", forward)
		}
		translation[forward.As16()] = host.As16()
	}
	return translation, nil
}
