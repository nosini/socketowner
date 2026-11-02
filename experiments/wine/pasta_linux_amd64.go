package wine

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Pasta retains the original pidfd. Nothing is read from pasta's memory, so no
// build profile applies: registration only says that sockets this process
// connects stand in for flows from its sandbox's network namespace.
type Pasta struct {
	PID   int
	pidfd int
}

type pastaTarget struct {
	NetNS  uint64
	Active uint32
	Pad    uint32
}

func (p *Pasta) Close() {
	if p.pidfd >= 0 {
		unix.Close(p.pidfd)
		p.pidfd = -1
	}
}

func (p *Pasta) alive() (bool, error) {
	fds := []unix.PollFd{{Fd: int32(p.pidfd), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, 0)
	if err == unix.EINTR {
		return true, nil
	}
	return n == 0, err
}

// PreparePasta refuses a process which holds no descriptor for the target's
// network namespace, so a mistyped PID can't attribute unrelated connections.
// pasta keeps that descriptor open for as long as it runs.
func PreparePasta(pid int, t *Target) (_ *Pasta, err error) {
	if pid <= 0 || t == nil {
		return nil, errors.New("a positive pasta process ID and a prepared target are required")
	}
	p := &Pasta{PID: pid, pidfd: -1}
	defer func() {
		if err != nil {
			p.Close()
		}
	}()
	if p.pidfd, err = unix.PidfdOpen(pid, 0); err != nil {
		return nil, fmt.Errorf("open pasta pidfd: %w", err)
	}
	netns, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", t.PID))
	if err != nil {
		return nil, err
	}
	own, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		return nil, err
	}
	if own == netns {
		return nil, errors.New("pasta shares the target's network namespace; it would not be its relay")
	}
	fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return nil, err
	}
	for _, fd := range fds {
		link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name()))
		if err == nil && strings.HasPrefix(link, "net:[") && link == netns {
			return p, nil
		}
	}
	return nil, errors.New("selected process holds no descriptor for the target's network namespace")
}

// register runs after the kernel supplied the target's namespace cookie.
func (p *Pasta) register(coll *ebpf.Collection, netns uint64) error {
	if err := coll.Maps["pasta_targets"].Update(int32(p.pidfd), pastaTarget{NetNS: netns, Active: 1}, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("register pasta task storage: %w", err)
	}
	if err := coll.Maps["pasta_targets"].Freeze(); err != nil {
		return fmt.Errorf("freeze pasta registration: %w", err)
	}
	if err := coll.Maps["relay_netns"].Update(uint32(0), netns, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("publish relay namespace: %w", err)
	}
	return nil
}
