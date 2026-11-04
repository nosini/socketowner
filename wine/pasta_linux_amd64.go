package wine

import (
	"errors"
	"fmt"
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
	waiting map[int]*waitingServer // by wineserver host PID
	// find and register are findPasta and a pasta_targets update, but for tests.
	find     func(server int) (pid, pidfd int, err error)
	register func(pidfd int, netns uint64) error
}

// waitingServer is retried less often the longer no pasta appears: a sandbox may
// have no network or use another relay, and each scan walks all of /proc.
type waitingServer struct {
	netns uint64
	next  time.Time
	delay time.Duration
}

const maxScanDelay = 30 * time.Second

// errPastaGone is a pasta which exited while being registered. Its sandbox is
// usually stopping; otherwise another pasta is looked for later.
var errPastaGone = errors.New("pasta exited")

func newRelays(targets *ebpf.Map) *relays {
	return &relays{
		waiting: map[int]*waitingServer{},
		find:    findPasta,
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

func (r *relays) add(server int, netns uint64, now time.Time) {
	r.waiting[server] = &waitingServer{netns: netns, next: now, delay: scanInterval}
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

// scan registers the pastas found now. A sandbox with no pasta is retried, with
// growing delays, for as long as its wineserver lives. Registration keeps
// nothing but the task storage entry, keyed by pidfd and revoked on exec.
func (r *relays) scan(now time.Time, consume func(Event) error) error {
	for server, w := range r.waiting {
		if now.Before(w.next) {
			continue
		}
		pid, pidfd, err := r.find(server)
		if errors.Is(err, os.ErrNotExist) {
			delete(r.waiting, server)
			continue
		}
		if err == nil && pid != 0 {
			err = r.register(pidfd, w.netns)
			unix.Close(pidfd)
			if err == nil {
				delete(r.waiting, server)
				if err := consume(Event{Type: "pasta", ServerTGID: uint32(server), PastaTGID: uint32(pid), NetNS: w.netns}); err != nil {
					return err
				}
				continue
			}
			if !errors.Is(err, errPastaGone) {
				return err
			}
		}
		w.next = now.Add(w.delay)
		w.delay = min(2*w.delay, maxScanDelay)
	}
	return nil
}
