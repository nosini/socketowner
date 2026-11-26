package wine

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

type connKey struct {
	NetNS    uint64
	Address  [16]byte
	Port     uint16
	Protocol uint8
	Pad      [5]uint8
}

// A port which a relay used can pass to a native socket. Its first packet must
// remove the Wine record, so that readers don't name the Windows program for a
// native process's flow.
func TestEgressDropsRecordOnPortReuse(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load the observer")
	}
	dir := pinDir(t)
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- Observe(ctx, Options{Cgroup: "/sys/fs/cgroup", Pin: dir, Group: -1}, func(e Event) error {
			if e.Type == "ready" {
				close(ready)
			}
			return nil
		})
	}()
	select {
	case <-ready:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(10 * time.Second):
		t.Fatal("observer not ready")
	}
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	flows, err := ebpf.LoadPinnedMap(filepath.Join(dir, flowsPin), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer flows.Close()
	peerFlows, err := ebpf.LoadPinnedMap(filepath.Join(dir, peerFlowsPin), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer peerFlows.Close()

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	bound, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	port := bound.(*unix.SockaddrInet4).Port
	host, err := hostNetNS()
	if err != nil {
		t.Fatal(err)
	}
	key := func(port int) connKey {
		return connKey{NetNS: host, Address: netip.MustParseAddr("127.0.0.1").As16(), Port: uint16(port), Protocol: unix.IPPROTO_UDP}
	}
	record := rawOwner{SocketID: 1, ServerStartNS: 1, ServerTGID: 1, Status: 1, Protocol: unix.IPPROTO_UDP}
	reused, control := key(port), key(port+1)
	if port == 65535 {
		control = key(port - 1)
	}
	for _, k := range []connKey{reused, control} {
		if err := flows.Update(k, record, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	loopback := netip.MustParseAddr("127.0.0.1").As16()
	peerKey := func(destinationPort uint16) flowKey {
		return flowKey{NetNS: host, Source: loopback, Destination: loopback, SourcePort: uint16(port),
			DestinationPort: destinationPort, Protocol: unix.IPPROTO_UDP}
	}
	// The flow the native socket sends is dropped; the same port's flow to
	// another peer is another socket's and stays.
	peerReused, peerOther := peerKey(9), peerKey(10)
	for _, k := range []flowKey{peerReused, peerOther} {
		if err := peerFlows.Update(k, record, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Sendto(fd, []byte("x"), 0, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}, Port: 9}); err != nil {
		t.Fatal(err)
	}
	var value rawOwner
	if err := flows.Lookup(reused, &value); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("record kept after a native socket sent from its port: %v", err)
	}
	if err := flows.Lookup(control, &value); err != nil {
		t.Fatalf("unrelated record removed: %v", err)
	}
	if err := peerFlows.Lookup(peerReused, &value); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("peer record kept after a native socket sent the flow: %v", err)
	}
	if err := peerFlows.Lookup(peerOther, &value); err != nil {
		t.Fatalf("peer record of another destination removed: %v", err)
	}
}

// testNetNS is a synthetic cookie, distinct from the host namespace.
const testNetNS uint64 = 0xfeedbeef

type relayKey struct {
	NetNS                       uint64
	Destination                 [16]byte
	DestinationPort, SourcePort uint16
	Protocol                    uint8
	Pad                         [3]byte
	Generation                  uint64
}

type relayStorage struct {
	Owner                              rawOwner
	Ready, FirstEgress, Sends, Creator uint32
	SeenNS                             uint64
	Count, Ambiguous                   uint32
}

// readRelayEvent waits for the next relay event on the collection's ringbuf.
func readRelayEvent(t *testing.T, reader *ringbuf.Reader) Event {
	t.Helper()
	reader.SetDeadline(time.Now().Add(5 * time.Second))
	for {
		record, err := reader.Read()
		if err != nil {
			t.Fatal(err)
		}
		e, err := decodeEvent(record.RawSample)
		if err != nil {
			t.Fatalf("decode relay event: %v", err)
		}
		if e.Type == "relay" {
			return e
		}
	}
}

// A UDP relay record is consumed and deleted on pasta's connect, and an expired
// one names no flow.
func TestRelayConnectUDPExpiryAndDelete(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load the observer")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()
	if got, want := binary.Size(relayStorage{}), coll.Maps["relay_flows"].ValueSize(); uint32(got) != want {
		t.Fatalf("relay value size = %d, map value size = %d", got, want)
	}
	pidfd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pidfd)
	if err := coll.Maps["pasta_targets"].Update(int32(pidfd),
		pastaTarget{NetNS: testNetNS, Active: 1}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	connect, err := link.AttachLSM(link.LSMOptions{Program: coll.Programs["wine_connect"]})
	if err != nil {
		t.Fatal(err)
	}
	defer connect.Close()
	reader, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	destination := netip.MustParseAddr("::ffff:127.0.0.1").As16()
	bindUDP := func() (int, uint16) {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { unix.Close(fd) })
		if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
			t.Fatal(err)
		}
		bound, err := unix.Getsockname(fd)
		if err != nil {
			t.Fatal(err)
		}
		return fd, uint16(bound.(*unix.SockaddrInet4).Port)
	}
	connectUDP := func(fd int) {
		if err := unix.Connect(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}, Port: 9}); err != nil {
			t.Fatal(err)
		}
	}

	now, err := bootTime()
	if err != nil {
		t.Fatal(err)
	}
	expired := now - uint64(5*time.Second)
	if now <= uint64(5*time.Second) {
		expired = 1
	}
	fd, port := bindUDP()
	expiredKey := relayKey{NetNS: testNetNS, Destination: destination,
		DestinationPort: 9, SourcePort: port, Protocol: unix.IPPROTO_UDP}
	expiredValue := relayStorage{
		Owner:  rawOwner{SocketID: 11, ServerTGID: 1, ServerStartNS: 1, Status: 1, Protocol: unix.IPPROTO_UDP},
		Ready:  1,
		SeenNS: expired,
	}
	if err := coll.Maps["relay_flows"].Update(expiredKey, expiredValue, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	connectUDP(fd)
	var got relayStorage
	if err := coll.Maps["relay_flows"].Lookup(expiredKey, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("expired UDP relay record kept after connect: %v", err)
	}
	if e := readRelayEvent(t, reader); e.Status != "no-inner-flow" {
		t.Fatalf("expired UDP relay status = %q, want no-inner-flow: %+v", e.Status, e)
	}

	fd, port = bindUDP()
	freshKey := relayKey{NetNS: testNetNS, Destination: destination,
		DestinationPort: 9, SourcePort: port, Protocol: unix.IPPROTO_UDP}
	freshNow, err := bootTime()
	if err != nil {
		t.Fatal(err)
	}
	image := utf16.Encode([]rune(`C:\games\alpha.exe`))
	freshValue := relayStorage{
		Owner: rawOwner{SocketID: 12, ServerTGID: 1, ServerStartNS: 1, Status: 1,
			Protocol: unix.IPPROTO_UDP, ImageBytes: uint32(len(image) * 2)},
		Ready:  1,
		SeenNS: freshNow,
	}
	copy(freshValue.Owner.Image[:], image)
	if err := coll.Maps["relay_flows"].Update(freshKey, freshValue, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	connectUDP(fd)
	if err := coll.Maps["relay_flows"].Lookup(freshKey, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("fresh UDP relay record kept after connect: %v", err)
	}
	e := readRelayEvent(t, reader)
	if e.Status != "known" || e.WindowsName != "alpha.exe" {
		t.Fatalf("fresh UDP relay = %+v, want known alpha.exe", e)
	}

	// Non-UDP SOCK_DGRAM sockets (such as pasta's ICMP ping sockets) must not
	// be classified as UDP or emit spurious relay events.
	if icmpFD, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMP); err == nil {
		defer unix.Close(icmpFD)
		if err := unix.Connect(icmpFD, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err == nil {
			reader.SetDeadline(time.Now().Add(150 * time.Millisecond))
			if rec, err := reader.Read(); err == nil {
				ev, _ := decodeEvent(rec.RawSample)
				t.Fatalf("SOCK_DGRAM IPPROTO_ICMP emitted unexpected relay event: %+v", ev)
			} else if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("read ringbuf after ICMP connect: %v", err)
			}
		}
	}
}

type flowKey struct {
	NetNS                       uint64
	Source, Destination         [16]byte
	SourcePort, DestinationPort uint16
	Protocol                    uint8
	Pad                         [3]byte
}
