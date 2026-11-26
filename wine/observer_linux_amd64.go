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
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

const (
	scanInterval     = 500 * time.Millisecond
	eventQueueSize   = 1024
	stopFlushTimeout = 250 * time.Millisecond
)

// eventSink decouples diagnostic event output from the observer's control loop,
// pasta discovery, and shutdown unpinning. When consume blocks, new events are
// dropped and counted rather than stalling the observer.
type eventSink struct {
	observerID string
	queue      chan Event
	done       chan struct{}
	dropped    atomic.Uint64
	mu         sync.Mutex
	errVal     error
}

func newEventSink(observerID string, capacity int, consume func(Event) error) *eventSink {
	if capacity < 1 {
		capacity = 1
	}
	s := &eventSink{
		observerID: observerID,
		queue:      make(chan Event, capacity),
		done:       make(chan struct{}),
	}
	go func() {
		defer close(s.done)
		for e := range s.queue {
			if err := consume(e); err != nil {
				s.mu.Lock()
				if s.errVal == nil {
					s.errVal = err
				}
				s.mu.Unlock()
				return
			}
		}
	}()
	return s
}

// emit enqueues e without blocking, returning any consumer error already seen.
// When the queue is full, e is dropped and counted for a later loss event.
func (s *eventSink) emit(e Event) error {
	if err := s.err(); err != nil {
		return err
	}
	e.Observer = s.observerID
	select {
	case s.queue <- e:
	default:
		s.dropped.Add(1)
	}
	return nil
}

// emitLoss reports lost events. A loss event that cannot be queued adds lost
// back to the dropped count instead of 1, so a full queue cannot collapse many
// lost events into one. The loss event itself is not counted again: the next
// report carries exactly the losses still undelivered.
func (s *eventSink) emitLoss(lost uint64) error {
	if err := s.err(); err != nil {
		return err
	}
	select {
	case s.queue <- Event{Type: "loss", Observer: s.observerID, LostEvents: lost}:
	default:
		s.dropped.Add(lost)
	}
	return nil
}

func (s *eventSink) takeDropped() uint64 {
	return s.dropped.Swap(0)
}

func (s *eventSink) err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.errVal
}

// close finishes diagnostic delivery with a bounded wait so a blocked consumer
// cannot hang shutdown and prevent pin removal.
func (s *eventSink) close(timeout time.Duration) error {
	close(s.queue)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-s.done:
		return s.err()
	case <-timer.C:
		return s.err()
	}
}

// lsmPath lists the active Linux security modules.
const lsmPath = "/sys/kernel/security/lsm"

// checkBPFLSM refuses a host where the BPF LSM is built but not active. The
// observer's capture depends on LSM hooks, so attaching them would report
// ready while no Wine identity was ever recorded.
func checkBPFLSM() error {
	return checkBPFLSMAt(lsmPath)
}

func checkBPFLSMAt(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("check BPF LSM: %w", err)
	}
	for _, name := range strings.Split(string(data), ",") {
		if strings.TrimSpace(name) == "bpf" {
			return nil
		}
	}
	return fmt.Errorf("BPF LSM is not active (\"bpf\" missing from %s); the Wine observer cannot record identities", path)
}

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
	if err := checkBPFLSM(); err != nil {
		return err
	}
	var instance [16]byte
	if _, err := rand.Read(instance[:]); err != nil {
		return err
	}
	observerID := hex.EncodeToString(instance[:])
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
	for _, name := range []string{"wine_exec", "wine_file", "wine_pipe_release", "wine_create", "wine_connect", "wine_send"} {
		var l link.Link
		var err error
		if coll.Programs[name].Type() == ebpf.Tracing {
			l, err = link.AttachTracing(link.TracingOptions{Program: coll.Programs[name]})
		} else {
			l, err = link.AttachLSM(link.LSMOptions{Program: coll.Programs[name]})
		}
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
	var beatDone <-chan error
	if options.Pin != "" {
		if published, err = publish(coll, options.Pin, options.Group); err != nil {
			return err
		}
		// The heartbeat is independent of event output: a blocked stdout
		// must not make every flow look stale.
		beatCtx, stopBeat := context.WithCancel(ctx)
		beats := make(chan error, 1)
		beatDone = beats
		go func() {
			defer close(beats)
			beats <- runHeartbeat(beatCtx, beatInterval, published.ensurePins)
		}()
		defer published.close()
		defer func() {
			stopBeat()
			<-beats
		}()
	}
	sink := newEventSink(observerID, eventQueueSize, consume)
	sinkClosed := false
	defer func() {
		if !sinkClosed {
			_ = sink.close(stopFlushTimeout)
		}
	}()
	if err := sink.emit(Event{Type: "ready"}); err != nil {
		return err
	}
	pasta := newRelays(coll.Maps["pasta_targets"], coll.Maps["dns_forwards"])
	defer pasta.close()
	var reportedLosses uint64
	var scanned time.Time
	for {
		if err := pollHeartbeat(beatDone); err != nil {
			return err
		}
		if err := sink.err(); err != nil {
			return err
		}
		if ctx.Err() != nil {
			_ = sink.emit(Event{Type: "stopped", Reason: "cancelled"})
			sinkClosed = true
			return sink.close(stopFlushTimeout)
		}
		if len(pasta.waiting) != 0 && time.Since(scanned) >= scanInterval {
			scanned = time.Now()
			if err := pasta.scan(scanned, sink.emit); err != nil {
				return err
			}
		}
		var losses uint64
		if err := coll.Maps["counters"].Lookup(uint32(1), &losses); err != nil {
			return err
		}
		lost := (losses - reportedLosses) + sink.takeDropped()
		if lost != 0 {
			reportedLosses = losses
			if err := sink.emitLoss(lost); err != nil {
				return err
			}
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
		// Register sandboxes before diagnostic output so pasta discovery is
		// never delayed behind event formatting.
		if e.Type == "server" && !options.NoRelay {
			scanned = time.Now()
			pasta.add(int(e.ServerTGID), e.NetNS, scanned)
			if err := pasta.scan(scanned, sink.emit); err != nil {
				return err
			}
		}
		if err := sink.emit(e); err != nil {
			return err
		}
	}
}

func pollHeartbeat(done <-chan error) error {
	if done == nil {
		return nil
	}
	select {
	case err := <-done:
		return err
	default:
		return nil
	}
}
