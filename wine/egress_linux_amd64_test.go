package wine

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
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
}
