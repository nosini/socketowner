//go:build linux && sockowner_vm

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// isolatedTestEnv creates a cgroup and pin directory for one test and moves
// the test process into the cgroup. Run the privileged tests in a dedicated
// network namespace, as TestRedirectSourcePort does.
func isolatedTestEnv(t *testing.T) (cgroup, pin string) {
	t.Helper()
	selfNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	initNS, err := os.Readlink("/proc/1/ns/net")
	if err != nil || selfNS == initNS {
		t.Fatal("run in a dedicated network namespace with unshare --net")
	}
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	_, oldGroup, ok := strings.Cut(strings.TrimSpace(string(data)), "0::")
	if !ok {
		t.Fatal("cgroup v2 required")
	}
	name := strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	cgroup = filepath.Join("/sys/fs/cgroup", fmt.Sprintf("sockowner-%s-%d", name, os.Getpid()))
	if err := os.Mkdir(cgroup, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.WriteFile(filepath.Join("/sys/fs/cgroup", oldGroup, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0); err != nil {
			t.Error(err)
		}
		if err := os.Remove(cgroup); err != nil {
			t.Error(err)
		}
	})
	if err := os.WriteFile(filepath.Join(cgroup, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0); err != nil {
		t.Fatal(err)
	}
	pin = fmt.Sprintf("/sys/fs/bpf/sockowner-%s-%d", name, os.Getpid())
	t.Cleanup(func() {
		if err := detach(pin); err != nil {
			t.Error(err)
		}
		for _, path := range []string{"links", "maps", ""} {
			if err := os.Remove(filepath.Join(pin, path)); err != nil {
				t.Error(err)
			}
		}
	})
	return cgroup, pin
}

type ownerKey struct {
	NetNS uint64
	Addr  [16]byte
	Port  uint16
	Proto uint8
	Pad   [5]byte
}

type ownerValue struct {
	TGID, UID uint32
	BootNS    uint64
}

func testNetNSCookie(t *testing.T) uint64 {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	if err != nil {
		t.Fatal(err)
	}
	return cookie
}

func testChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + sum>>16
	}
	return ^uint16(sum)
}

func testTCPPacket(sourcePort, destinationPort uint16) []byte {
	src := [4]byte{127, 0, 0, 1}
	dst := [4]byte{127, 0, 0, 1}
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 40)
	ip[8] = 64
	ip[9] = unix.IPPROTO_TCP
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	binary.BigEndian.PutUint16(ip[10:12], testChecksum(ip))
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], destinationPort)
	binary.BigEndian.PutUint32(tcp[4:8], 1)
	tcp[12] = 5 << 4
	tcp[13] = 0x02
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], src[:])
	copy(pseudo[4:8], dst[:])
	pseudo[9] = unix.IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	binary.BigEndian.PutUint16(tcp[16:18], testChecksum(append(pseudo, tcp...)))
	return append(ip, tcp...)
}

// A kernel-generated RST or ACK leaves from a per-CPU SOCK_RAW TCP control
// socket. A user raw socket has the same type, so it exercises the same skip
// without needing to attach to the root cgroup.
func TestRawEgressKeepsOwner(t *testing.T) {
	cgroup, pin := isolatedTestEnv(t)
	if err := attach(cgroup, pin, false, -1); err != nil {
		t.Fatal(err)
	}
	owners, err := ebpf.LoadPinnedMap(filepath.Join(pin, "maps", mapName), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer owners.Close()

	key := ownerKey{
		NetNS: testNetNSCookie(t),
		Addr:  netip.MustParseAddr("127.0.0.1").As16(),
		Port:  40000,
		Proto: unix.IPPROTO_TCP,
	}
	owner := ownerValue{TGID: 424242, BootNS: 1}
	if err := owners.Update(key, owner, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Sendto(fd, testTCPPacket(40000, 9), 0,
		&unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}, Port: 9}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)

	var got ownerValue
	if err := owners.Lookup(key, &got); err != nil {
		t.Fatalf("record removed by raw egress: %v", err)
	}
	if got.TGID != 424242 {
		t.Fatalf("record replaced by raw egress: %+v", got)
	}
}

// An accepted socket never passed through sock_create, so it has no owner. Its
// first packet must replace a stale entry with an empty owner.
func TestAcceptedEgressPublishesNoOwner(t *testing.T) {
	cgroup, pin := isolatedTestEnv(t)
	if err := attach(cgroup, pin, false, -1); err != nil {
		t.Fatal(err)
	}
	owners, err := ebpf.LoadPinnedMap(filepath.Join(pin, "maps", mapName), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer owners.Close()

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var server *net.TCPConn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("accept timed out")
	}
	defer server.Close()
	server.SetNoDelay(true)

	local := server.LocalAddr().(*net.TCPAddr)
	key := ownerKey{
		NetNS: testNetNSCookie(t),
		Addr:  local.AddrPort().Addr().As16(),
		Port:  uint16(local.Port),
		Proto: unix.IPPROTO_TCP,
	}
	if err := owners.Update(key, ownerValue{TGID: 424242, BootNS: 1}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)

	var got ownerValue
	if err := owners.Lookup(key, &got); err != nil {
		t.Fatalf("stale record kept after accepted socket sent: %v", err)
	}
	if got.TGID != 0 {
		t.Fatalf("accepted socket published owner %+v, want TGID 0", got)
	}
}

type flowKey struct {
	Netns        uint64
	Saddr, Daddr [16]byte
	Sport, Dport uint16
	Proto        uint8
	Pad          [3]byte
}

type flowValue struct {
	TGID, UID uint32
	BootNS    uint64
	CgroupID  uint64
}

// Sockets with different peers may share a source address and port. conn_owners
// holds only the last one to send; conn_flows keeps each under its destination.
func TestFlowsSharedSourcePort(t *testing.T) {
	cgroup, pin := isolatedTestEnv(t)
	if err := attach(cgroup, pin, true, -1); err != nil {
		t.Fatal(err)
	}
	flows := loadPinned(t, pin, flowMapName)
	owners := loadPinned(t, pin, mapName)
	var port int
	var files []*os.File
	for _, destination := range []string{"127.0.0.2", "127.0.0.3"} {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		file := os.NewFile(uintptr(fd), "udp")
		defer file.Close()
		files = append(files, file)
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			t.Fatal(err)
		}
		if err := unix.Bind(fd, &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
			t.Fatal(err)
		}
		if port == 0 {
			local, err := unix.Getsockname(fd)
			if err != nil {
				t.Fatal(err)
			}
			port = local.(*unix.SockaddrInet4).Port
		}
		if err := unix.Connect(fd, &unix.SockaddrInet4{Port: 9, Addr: netip.MustParseAddr(destination).As4()}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := unix.Write(int(files[0].Fd()), []byte("x")); err != nil {
		t.Fatal(err)
	}
	// Another process sends on the second socket; with -exec-paths, its
	// connected send records it as that socket's owner.
	child := exec.Command("/bin/sh", "-c", "printf x >&3")
	child.ExtraFiles = []*os.File{files[1]}
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("%s: %v", output, err)
	}
	cookie := testNetNSCookie(t)
	source := netip.MustParseAddr("127.0.0.1").As16()
	for destination, want := range map[string]uint32{
		"127.0.0.2": uint32(os.Getpid()),
		"127.0.0.3": uint32(child.Process.Pid),
	} {
		key := flowKey{Netns: cookie, Saddr: source, Daddr: netip.MustParseAddr(destination).As16(),
			Sport: uint16(port), Dport: 9, Proto: unix.IPPROTO_UDP}
		var flow flowValue
		if err := flows.Lookup(&key, &flow); err != nil || flow.TGID != want || flow.CgroupID == 0 {
			t.Errorf("%s: flow = %+v, %v; want TGID %d with a cgroup", destination, flow, err, want)
		}
	}
	var owner ownerValue
	key := ownerKey{NetNS: cookie, Addr: source, Port: uint16(port), Proto: unix.IPPROTO_UDP}
	if err := owners.Lookup(&key, &owner); err != nil || owner.TGID != uint32(child.Process.Pid) {
		t.Errorf("conn_owners = %+v, %v; want the last sender %d", owner, err, child.Process.Pid)
	}
}
