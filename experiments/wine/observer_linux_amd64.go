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
	"io"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:embed wine_bpfel.o
var object []byte

type Options struct {
	Cgroup string
	Sends  bool
	// Pasta joins that process's replacement sockets to this target's flows.
	Pasta *Pasta
	// Pin publishes the routing maps in this directory; see publish_linux_amd64.go.
	Pin string
	// Group is given read access to the pins, or -1 for the observer's own.
	Group int
}

// Observe owns every FD/link. The callback's ready event is emitted only after
// registration, hook attachment and target revalidation. Stop/exit closes the
// BPF attachments. Only an explicit Pin leaves anything behind after a crash,
// and its heartbeat tells readers that those records have gone stale.
func Observe(ctx context.Context, t *Target, options Options, consume func(Event) error) error {
	if t == nil || t.pidfd < 0 || t.exe == nil || options.Cgroup == "" || consume == nil {
		return errors.New("prepared Wine target, explicit cgroup and event consumer required")
	}
	var instance [16]byte
	if _, err := rand.Read(instance[:]); err != nil {
		return err
	}
	observerID := hex.EncodeToString(instance[:])
	output := consume
	consume = func(e Event) error {
		e.Observer, e.Profile = observerID, t.Profile.ID
		return output(e)
	}
	if err := t.recheck(); err != nil {
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
	config := t.config
	if options.Sends {
		config.Sends = 1
	}
	if err := coll.Maps["wine_targets"].Update(int32(t.pidfd), config, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("register Wine task storage: %w", err)
	}
	var links []link.Link
	defer func() {
		for i := len(links) - 1; i >= 0; i-- {
			links[i].Close()
		}
	}()
	for _, name := range []string{"wine_exec", "wine_create", "wine_connect", "wine_send"} {
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
	it, err := link.AttachIter(link.IterOptions{Program: coll.Programs["wine_seed"]})
	if err != nil {
		return fmt.Errorf("attach Wine target seed: %w", err)
	}
	r, err := it.Open()
	if err == nil {
		_, err = io.Copy(io.Discard, r)
		r.Close()
	}
	it.Close()
	if err != nil {
		return fmt.Errorf("seed Wine executable identity: %w", err)
	}
	if err := coll.Maps["wine_targets"].Lookup(int32(t.pidfd), &config); err != nil || config.Active != 1 || config.KernelExe == 0 || config.NetNS == 0 {
		return errors.New("could not seed the selected Wine executable")
	}
	if err := coll.Maps["wine_targets"].Freeze(); err != nil {
		return fmt.Errorf("freeze Wine registration: %w", err)
	}
	if options.Pasta != nil {
		if err := options.Pasta.register(coll, config.NetNS); err != nil {
			return err
		}
	}
	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		return err
	}
	defer rd.Close()
	if err := t.recheck(); err != nil {
		return err
	}
	var published *publication
	if options.Pin != "" {
		if published, err = publish(coll, options.Pin, options.Group); err != nil {
			return err
		}
		defer published.close()
	}
	if err := consume(Event{Type: "ready", Profile: t.Profile.ID, ServerTGID: uint32(t.PID)}); err != nil {
		return err
	}
	var reportedLosses uint64
	for {
		if ctx.Err() != nil {
			return consume(Event{Type: "stopped", Reason: "cancelled"})
		}
		alive, err := t.alive()
		if err != nil {
			return err
		}
		if !alive {
			return consume(Event{Type: "stopped", Reason: "target-exit"})
		}
		if options.Pasta != nil {
			if alive, err = options.Pasta.alive(); err != nil {
				return err
			}
			if !alive {
				return consume(Event{Type: "stopped", Reason: "pasta-exit"})
			}
		}
		if err := published.beat(); err != nil {
			return err
		}
		if err := coll.Maps["wine_targets"].Lookup(int32(t.pidfd), &config); err != nil || config.Active != 1 {
			return errors.New("Wine registration revoked (target exec or observer exhaustion)")
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
		e.Profile = t.Profile.ID
		if err := consume(e); err != nil {
			return err
		}
	}
}
