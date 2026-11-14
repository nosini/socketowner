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

// process identifies a process across PID reuse.
type process struct {
	pid   int
	start uint64
}

// relays finds the pasta of each sandbox whose wineserver appeared. Nothing is
// read from pasta's memory, so no build matters: registration only says that
// sockets it connects stand in for flows from that network namespace.
type relays struct {
	waiting map[int]*waitingServer
	// find, register and start are the process lookups and the pasta_targets
	// update, but for tests.
	find     func(server int) (pid, pidfd int, err error)
	register func(pidfd int, netns uint64) error
	start    func(pid int) (uint64, error)
	logf     func(format string, args ...any)
	reported map[string]bool
}

// waitingServer is retried less often the longer no pasta appears: a sandbox may
// have no network or use another relay, and each scan walks all of /proc. Once
// a pasta is registered it stays on the list, so a replacement is found after
// the old one exits. start identifies the wineserver across PID reuse.
type waitingServer struct {
	start uint64
	netns uint64
	next  time.Time
	delay time.Duration
	pasta process
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
		start:    processStart,
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

func (r *relays) add(server int, netns uint64, now time.Time) {
	start, err := r.startProcess(server)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			r.report(fmt.Errorf("wineserver %d: %w", server, err))
		}
		return
	}
	if w := r.waiting[server]; w != nil && w.start == start {
		w.netns = netns
		return
	}
	r.waiting[server] = &waitingServer{start: start, netns: netns, next: now, delay: scanInterval}
}

func (r *relays) startProcess(pid int) (uint64, error) {
	if r.start == nil {
		return 0, nil
	}
	return r.start(pid)
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

// processStart reads the start time from /proc/<pid>/stat, whose field 22 can
// be compared with a later PID's. The command name may contain spaces and
// parentheses, so fields are counted after its last ')'.
func processStart(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	text := string(data)
	end := strings.LastIndexByte(text, ')')
	if end < 0 {
		return 0, errors.New("invalid process stat")
	}
	fields := strings.Fields(text[end+1:])
	const startField = 22 - 3 // fields after the command name start at field 3
	if len(fields) <= startField {
		return 0, errors.New("invalid process stat")
	}
	return strconv.ParseUint(fields[startField], 10, 64)
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
// growing delays, for as long as its wineserver lives. A registered pasta is
// checked again so that a replacement joining the same namespace is registered
// too. Registration keeps nothing but the task storage entry, keyed by pidfd
// and revoked on exec.
func (r *relays) scan(now time.Time, consume func(Event) error) error {
	for server, w := range r.waiting {
		if now.Before(w.next) {
			continue
		}
		start, err := r.startProcess(server)
		if errors.Is(err, os.ErrNotExist) {
			delete(r.waiting, server)
			continue
		}
		if err != nil {
			r.report(fmt.Errorf("wineserver %d: %w", server, err))
			w.next = now.Add(w.delay)
			w.delay = min(2*w.delay, maxScanDelay)
			continue
		}
		if start != w.start {
			delete(r.waiting, server)
			continue
		}
		pid, pidfd, err := r.find(server)
		if errors.Is(err, os.ErrNotExist) {
			delete(r.waiting, server)
			continue
		}
		if err != nil {
			r.report(err)
			w.next = now.Add(w.delay)
			w.delay = min(2*w.delay, maxScanDelay)
			continue
		}
		if pid == 0 {
			w.pasta = process{}
			w.next = now.Add(w.delay)
			w.delay = min(2*w.delay, maxScanDelay)
			continue
		}
		// The pidfd keeps the PID from being reused while its start time is read.
		start, err = r.startProcess(pid)
		if err != nil {
			unix.Close(pidfd)
			w.pasta = process{}
			w.next = now.Add(w.delay)
			w.delay = min(2*w.delay, maxScanDelay)
			continue
		}
		proc := process{pid: pid, start: start}
		if proc == w.pasta {
			unix.Close(pidfd)
			w.next = now.Add(w.delay)
			w.delay = min(2*w.delay, registeredMaxDelay)
			continue
		}
		err = r.register(pidfd, w.netns)
		unix.Close(pidfd)
		if err == nil {
			w.pasta = proc
			w.delay = scanInterval
			w.next = now.Add(w.delay)
			if err := consume(Event{Type: "pasta", ServerTGID: uint32(server), PastaTGID: uint32(proc.pid), NetNS: w.netns}); err != nil {
				return err
			}
			continue
		}
		if !errors.Is(err, errPastaGone) {
			return err
		}
		w.pasta = process{}
		w.delay = scanInterval
		w.next = now.Add(w.delay)
	}
	return nil
}
