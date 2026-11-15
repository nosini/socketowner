package wine

import (
	"errors"
	"fmt"
	"log"
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

// relays finds the pasta of each sandbox whose wineserver appeared. Nothing is
// read from pasta's memory, so no build matters: registration only says that
// sockets it connects stand in for flows from that network namespace.
type relays struct {
	waiting map[int]*waitingServer
	// find, register, open, alive and closeFd are the process lookups, the
	// pasta_targets update and their pidfd handling, but for tests.
	find     func(server int) (pid, pidfd int, err error)
	register func(pidfd int, netns uint64) error
	open     func(pid int) (int, error)
	alive    func(pidfd int) bool
	closeFd  func(pidfd int)
	logf     func(format string, args ...any)
	reported map[string]bool
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

func newRelays(targets *ebpf.Map) *relays {
	return &relays{
		waiting:  map[int]*waitingServer{},
		find:     findPasta,
		open:     func(pid int) (int, error) { return unix.PidfdOpen(pid, 0) },
		alive:    alive,
		closeFd:  func(pidfd int) { unix.Close(pidfd) },
		logf:     log.Printf,
		reported: map[string]bool{},
		register: func(pidfd int, netns uint64) error {
			err := targets.Update(int32(pidfd), pastaTarget{NetNS: netns, Active: 1}, ebpf.UpdateAny)
			if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
				return errPastaGone
			}
			if err != nil {
				return fmt.Errorf("register pasta: %w", err)
			}
			return nil
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
// revoked on exec.
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
		if pid == w.pastaPid && r.alive(w.pastaFd) {
			r.closeFd(pidfd)
			w.next = now.Add(w.delay)
			w.delay = min(2*w.delay, registeredMaxDelay)
			continue
		}
		err = r.register(pidfd, w.netns)
		if err == nil {
			oldFd, oldPid := w.pastaFd, w.pastaPid
			w.pastaPid, w.pastaFd = pid, pidfd
			if oldPid != 0 {
				r.closeFd(oldFd)
			}
			w.delay = scanInterval
			w.next = now.Add(w.delay)
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
