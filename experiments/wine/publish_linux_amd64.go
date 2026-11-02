package wine

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	wineABI      uint32 = 1
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
	heartbeat *ebpf.Map
	last      time.Time
}

func bootTime() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, err
	}
	return uint64(ts.Nano()), nil
}

// claim refuses a live publisher and clears what a crashed one left.
func claim(dir string) error {
	flows := filepath.Join(dir, flowsPin)
	if _, err := os.Stat(flows); errors.Is(err, os.ErrNotExist) {
		return nil
	}
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
	defer version.Close()
	if err := version.Update(uint32(0), wineABI, ebpf.UpdateAny); err != nil {
		return nil, err
	}
	if err := version.Freeze(); err != nil {
		return nil, err
	}
	heartbeat, err := ebpf.NewMap(&ebpf.MapSpec{Name: heartbeatPin, Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		return nil, err
	}
	p := &publication{dir: dir, heartbeat: heartbeat}
	defer func() {
		if err != nil {
			p.close()
		}
	}()
	if err := p.beat(); err != nil {
		return nil, err
	}
	for _, m := range []struct {
		name string
		m    *ebpf.Map
	}{{abiPin, version}, {heartbeatPin, heartbeat}, {flowsPin, coll.Maps[flowsPin]}} {
		path := filepath.Join(dir, m.name)
		if err := m.m.Pin(path); err != nil {
			return nil, fmt.Errorf("pin %s: %w", m.name, err)
		}
		if gid >= 0 {
			if err := os.Chown(path, os.Getuid(), gid); err != nil {
				return nil, err
			}
		}
		if err := os.Chmod(path, 0o440); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// beat is safe on a nil publication, which is how an unpublished run looks.
func (p *publication) beat() error {
	if p == nil || time.Since(p.last) < beatInterval {
		return nil
	}
	now, err := bootTime()
	if err != nil {
		return err
	}
	p.last = time.Now()
	return p.heartbeat.Update(uint32(0), now, ebpf.UpdateAny)
}

func (p *publication) close() {
	for _, name := range []string{flowsPin, heartbeatPin, abiPin} {
		os.Remove(filepath.Join(p.dir, name))
	}
	p.heartbeat.Close()
}
