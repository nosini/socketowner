package wine

//go:generate clang -O2 -g -Wall -Werror -mcpu=v3 -D__TARGET_ARCH_x86 -target bpfel -fdebug-compilation-dir=. -c bpf/wine.c -o wine_bpfel.o
//go:generate llvm-strip -g wine_bpfel.o

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

const scanInterval = 500 * time.Millisecond

type observerConfig struct {
	HostNetNS uint64
	Sends     uint32
	Pad       uint32
}

//go:embed wine_bpfel.o
var object []byte

type Options struct {
	Cgroup string
	Sends  bool
	// NoRelay leaves pasta unregistered, for a test's negative control.
	NoRelay bool
	// Pin publishes the routing maps in this directory; see publish_linux_amd64.go.
	Pin string
	// Group is given read access to the pins, or -1 for the observer's own.
	Group int
}

func hostNetNS() (uint64, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	var cookie uint64
	size := uint32(unsafe.Sizeof(cookie))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_SOCKET, unix.SO_NETNS_COOKIE,
		uintptr(unsafe.Pointer(&cookie)), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return 0, errno
	}
	return cookie, nil
}

// Observe runs until cancelled, attributing every wineserver which appears.
// It owns every FD/link: stop or exit closes the BPF attachments. Only an
// explicit Pin leaves anything behind after a crash, and its heartbeat tells
// readers that those records have gone stale.
func Observe(ctx context.Context, options Options, consume func(Event) error) error {
	if options.Cgroup == "" || consume == nil {
		return errors.New("explicit cgroup and event consumer required")
	}
	var instance [16]byte
	if _, err := rand.Read(instance[:]); err != nil {
		return err
	}
	observerID := hex.EncodeToString(instance[:])
	output := consume
	consume = func(e Event) error {
		e.Observer = observerID
		return output(e)
	}
	host, err := hostNetNS()
	if err != nil {
		return err
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load Wine observer: %w", err)
	}
	defer coll.Close()
	config := observerConfig{HostNetNS: host}
	if options.Sends {
		config.Sends = 1
	}
	if err := coll.Maps["wine_config"].Update(uint32(0), config, ebpf.UpdateAny); err != nil {
		return err
	}
	if err := coll.Maps["wine_config"].Freeze(); err != nil {
		return err
	}
	var links []link.Link
	defer func() {
		for i := len(links) - 1; i >= 0; i-- {
			links[i].Close()
		}
	}()
	for _, name := range []string{"wine_exec", "wine_file", "wine_create", "wine_connect", "wine_send"} {
		l, err := link.AttachLSM(link.LSMOptions{Program: coll.Programs[name]})
		if err != nil {
			return fmt.Errorf("attach %s: %w", name, err)
		}
		links = append(links, l)
	}
	l, err := link.AttachCgroup(link.CgroupOptions{Path: options.Cgroup, Attach: ebpf.AttachCGroupInetEgress, Program: coll.Programs["wine_egress"]})
	if err != nil {
		return fmt.Errorf("attach Wine egress: %w", err)
	}
	links = append(links, l)
	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		return err
	}
	defer rd.Close()
	var published *publication
	if options.Pin != "" {
		if published, err = publish(coll, options.Pin, options.Group); err != nil {
			return err
		}
		defer published.close()
	}
	if err := consume(Event{Type: "ready"}); err != nil {
		return err
	}
	pasta := newRelays(coll.Maps["pasta_targets"])
	var reportedLosses uint64
	var scanned time.Time
	for {
		if ctx.Err() != nil {
			return consume(Event{Type: "stopped", Reason: "cancelled"})
		}
		if err := published.beat(); err != nil {
			return err
		}
		if len(pasta.waiting) != 0 && time.Since(scanned) >= scanInterval {
			scanned = time.Now()
			if err := pasta.scan(scanned, consume); err != nil {
				return err
			}
		}
		var losses uint64
		if err := coll.Maps["counters"].Lookup(uint32(1), &losses); err != nil {
			return err
		}
		if losses != reportedLosses {
			if err := consume(Event{Type: "loss", LostEvents: losses - reportedLosses}); err != nil {
				return err
			}
			reportedLosses = losses
		}
		rd.SetDeadline(time.Now().Add(200 * time.Millisecond))
		record, err := rd.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		if err != nil {
			return err
		}
		e, err := decodeEvent(record.RawSample)
		if err != nil {
			return fmt.Errorf("decode Wine observation: %w", err)
		}
		if err := consume(e); err != nil {
			return err
		}
		if e.Type == "server" && !options.NoRelay {
			scanned = time.Now()
			pasta.add(int(e.ServerTGID), e.NetNS, scanned)
			if err := pasta.scan(scanned, consume); err != nil {
				return err
			}
		}
	}
}
