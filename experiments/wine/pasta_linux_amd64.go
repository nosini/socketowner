package wine

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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
	targets *ebpf.Map
	waiting map[int]uint64 // wineserver host PID to network namespace cookie
}

// findPasta wants a process outside the namespace, holding a descriptor for it,
// and running pasta. sandbox-game runs copies named NAME-pasta.
func findPasta(server int) (int, error) {
	netns, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", server))
	if err != nil {
		return 0, err
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if err != nil || !strings.Contains(filepath.Base(exe), "pasta") {
			continue
		}
		own, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
		if err != nil || own == netns {
			continue
		}
		fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name())); err == nil && link == netns {
				return pid, nil
			}
		}
	}
	return 0, nil
}

// register retains nothing but the task storage entry, keyed from a pidfd so
// that a recycled PID can't be registered by mistake. Exec revokes it.
func (r *relays) register(pid int, netns uint64) error {
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return fmt.Errorf("open pasta pidfd: %w", err)
	}
	defer unix.Close(pidfd)
	if err := r.targets.Update(int32(pidfd), pastaTarget{NetNS: netns, Active: 1}, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("register pasta: %w", err)
	}
	return nil
}

// scan returns the pastas registered now. A sandbox with no pasta is retried
// for as long as its wineserver lives.
func (r *relays) scan(consume func(Event) error) error {
	for server, netns := range r.waiting {
		pid, err := findPasta(server)
		if errors.Is(err, os.ErrNotExist) {
			delete(r.waiting, server)
			continue
		}
		if err != nil || pid == 0 {
			continue
		}
		if err := r.register(pid, netns); err != nil {
			return err
		}
		delete(r.waiting, server)
		if err := consume(Event{Type: "pasta", ServerTGID: uint32(server), PastaTGID: uint32(pid), NetNS: netns}); err != nil {
			return err
		}
	}
	return nil
}
