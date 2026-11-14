package wine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	wineABI      uint32 = 2
	flowsPin            = "wine_flows"
	abiPin              = "wine_abi"
	heartbeatPin        = "wine_heartbeat"
	beatInterval        = time.Second
	// Readers treat a heartbeat older than this as a dead publisher, so an
	// older pin can only be a crashed observer's.
	heartbeatLimit = 5 * time.Second
)

// publication owns the pins. They replace nothing of socketowner's: ABI v1
// allows extra maps which leave its records unchanged, and sharing its maps
// directory reaches readers through their existing bind mount.
type publication struct {
	dir       string
	gid       int
	version   *ebpf.Map
	heartbeat *ebpf.Map
	flows     *ebpf.Map
	pins      map[string]pinID
	mu        sync.Mutex
}

// pinID identifies the inode a pin had when this process published it. A pin
// which still has that inode is ours to remove.
type pinID struct {
	dev, ino uint64
}

func bootTime() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, err
	}
	return uint64(ts.Nano()), nil
}

func pinIDOf(path string) (pinID, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return pinID{}, err
	}
	return pinID{dev: uint64(st.Dev), ino: st.Ino}, nil
}

// claim refuses a live publisher and clears what a crashed one left. The
// directory lock only serialises claim, so a stalled publisher can't remove a
// successor's fresh heartbeat after reading an older one. The heartbeat pin
// itself is then claimed atomically by publish.
func claim(dir string) error {
	lock, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return errors.New("another Wine publisher is active in " + dir)
		}
		return err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)

	m, err := ebpf.LoadPinnedMap(filepath.Join(dir, heartbeatPin), &ebpf.LoadPinOptions{ReadOnly: true})
	if err == nil {
		defer m.Close()
		var beat uint64
		now, nowErr := bootTime()
		if nowErr != nil {
			return nowErr
		}
		if m.Lookup(uint32(0), &beat) == nil && now-beat < uint64(heartbeatLimit) {
			return errors.New("another Wine publisher is active in " + dir)
		}
	}
	for _, name := range []string{flowsPin, heartbeatPin, abiPin} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// publish pins wine_flows last, which is the publication point, as conn_owners
// is for socketowner: a reader finding it also finds the other two.
func publish(coll *ebpf.Collection, dir string, gid int) (_ *publication, err error) {
	if err := claim(dir); err != nil {
		return nil, err
	}
	version, err := ebpf.NewMap(&ebpf.MapSpec{Name: abiPin, Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		return nil, err
	}
	heartbeat, err := ebpf.NewMap(&ebpf.MapSpec{Name: heartbeatPin, Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		version.Close()
		return nil, err
	}
	p := &publication{
		dir:       dir,
		gid:       gid,
		version:   version,
		heartbeat: heartbeat,
		flows:     coll.Maps[flowsPin],
		pins:      make(map[string]pinID),
	}
	defer func() {
		if err != nil {
			p.close()
		}
	}()
	if err := version.Update(uint32(0), wineABI, ebpf.UpdateAny); err != nil {
		return nil, err
	}
	if err := version.Freeze(); err != nil {
		return nil, err
	}
	if err := p.stamp(); err != nil {
		return nil, err
	}
	// Publish the heartbeat first: its rename claims the directory from any
	// publisher which looked just before us.
	if err := p.pin(heartbeatPin, heartbeat, true); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, errors.New("another Wine publisher is active in " + dir)
		}
		return nil, err
	}
	if err := p.ensurePins(); err != nil {
		return nil, err
	}
	// A publisher which was stalled while we claimed may have replaced the
	// heartbeat before the rest was visible. Then it owns the pins, not us.
	if ours, err := p.heartbeatOurs(); err != nil {
		return nil, err
	} else if !ours {
		return nil, errors.New("another Wine publisher took over in " + dir)
	}
	return p, nil
}

// pin publishes m under its final name only after it has its final owner and
// mode, so a reader never opens an unreadable inode. noReplace makes the
// heartbeat publication an atomic claim.
func (p *publication) pin(name string, m *ebpf.Map, noReplace bool) (err error) {
	final := filepath.Join(p.dir, name)
	tmp := filepath.Join(p.dir, fmt.Sprintf("%s-pin-%d-%d", name, os.Getpid(), pinSeq.Add(1)))
	os.Remove(tmp)
	if err := m.Pin(tmp); err != nil {
		return fmt.Errorf("pin %s: %w", name, err)
	}
	defer func() {
		if err != nil {
			os.Remove(tmp)
		}
	}()
	if p.gid >= 0 {
		if err := os.Chown(tmp, os.Getuid(), p.gid); err != nil {
			return err
		}
	}
	if err := os.Chmod(tmp, 0o440); err != nil {
		return err
	}
	id, err := pinIDOf(tmp)
	if err != nil {
		return err
	}
	if noReplace {
		if err := unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, final, unix.RENAME_NOREPLACE); err != nil {
			return fmt.Errorf("claim %s: %w", name, err)
		}
	} else {
		if err := os.Rename(tmp, final); err != nil {
			return fmt.Errorf("publish %s: %w", name, err)
		}
	}
	p.pins[name] = id
	return nil
}

var pinSeq atomic.Uint64

// stamp writes the current boot time to our heartbeat map.
func (p *publication) stamp() error {
	now, err := bootTime()
	if err != nil {
		return err
	}
	if err := p.heartbeat.Update(uint32(0), now, ebpf.UpdateAny); err != nil {
		return err
	}
	return nil
}

func (p *publication) heartbeatOurs() (bool, error) {
	id, err := pinIDOf(filepath.Join(p.dir, heartbeatPin))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return id == p.pins[heartbeatPin], nil
}

func (p *publication) ensurePins() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ensurePinsLocked()
}

// ensurePinsLocked re-pins anything a loader cleanup, a crash or a losing
// publisher removed. Our heartbeat is the right to do so: once another process
// owns it, this observer stops rather than fight it.
func (p *publication) ensurePinsLocked() error {
	heartbeatPath := filepath.Join(p.dir, heartbeatPin)
	id, err := pinIDOf(heartbeatPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := p.pin(heartbeatPin, p.heartbeat, true); err != nil {
			if errors.Is(err, os.ErrExist) {
				return errors.New("another Wine publisher owns " + heartbeatPath)
			}
			return err
		}
	case err != nil:
		return err
	case id != p.pins[heartbeatPin]:
		return errors.New("another Wine publisher owns " + heartbeatPath)
	}
	if err := p.stamp(); err != nil {
		return err
	}
	for _, name := range []string{abiPin, flowsPin} {
		path := filepath.Join(p.dir, name)
		id, err := pinIDOf(path)
		if err == nil && id == p.pins[name] {
			continue
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		m := p.version
		if name == flowsPin {
			m = p.flows
		}
		if m == nil {
			return fmt.Errorf("map %s is not loaded", name)
		}
		if err := p.pin(name, m, false); err != nil {
			return err
		}
	}
	return nil
}

// runHeartbeat beats independently of event output, so a blocked stdout does
// not stop the heartbeat and turn live flows into wine-unknown.
func runHeartbeat(ctx context.Context, interval time.Duration, beat func() error) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := beat(); err != nil {
				return err
			}
		}
	}
}

// removeOwn removes path only while it still is the inode we pinned there.
func removeOwn(path string, id pinID) {
	got, err := pinIDOf(path)
	if err != nil || got != id {
		return
	}
	os.Remove(path)
}

// close first makes the heartbeat stale, so that a crash while removing pins
// leaves nothing which claim takes for a live publisher. It removes only pins
// which are still ours: a successor or a stopped predecessor may own the
// names now.
func (p *publication) close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	heartbeatPath := filepath.Join(p.dir, heartbeatPin)
	if id, err := pinIDOf(heartbeatPath); err == nil && id == p.pins[heartbeatPin] {
		p.heartbeat.Update(uint32(0), uint64(0), ebpf.UpdateAny)
	}
	// The publication point goes first, as readers look for it.
	for _, name := range []string{flowsPin, heartbeatPin, abiPin} {
		if id, ok := p.pins[name]; ok {
			removeOwn(filepath.Join(p.dir, name), id)
		}
	}
	p.version.Close()
	p.heartbeat.Close()
}
