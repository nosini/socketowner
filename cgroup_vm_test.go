//go:build linux && sockowner_vm

package main

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type cgroupValue struct {
	TGID     uint32
	Pad      uint32
	BootNS   uint64
	CgroupID uint64
}

// cgroupInode returns the cgroup v2 ID of a cgroupfs directory, which is its
// inode number on 64-bit kernels.
func cgroupInode(t *testing.T, dir string) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(dir, &st); err != nil {
		t.Fatal(err)
	}
	return st.Ino
}

// moveSelf moves the test process into dir.
func moveSelf(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0); err != nil {
		t.Fatal(err)
	}
}

// childCgroup creates a cgroup below parent and removes it after the test,
// moving the test process back to parent first.
func childCgroup(t *testing.T, parent, name string) string {
	t.Helper()
	dir := filepath.Join(parent, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		moveSelf(t, parent)
		if err := os.Remove(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}

func loadPinned(t *testing.T, pin, name string) *ebpf.Map {
	t.Helper()
	m, err := ebpf.LoadPinnedMap(filepath.Join(pin, "maps", name), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

func lookupFlow(t *testing.T, owners, cgroups *ebpf.Map, key ownerKey) (ownerValue, cgroupValue) {
	t.Helper()
	var owner ownerValue
	var cg cgroupValue
	deadline := time.Now().Add(2 * time.Second)
	for {
		errOwner := owners.Lookup(key, &owner)
		errCgroup := cgroups.Lookup(key, &cg)
		if errOwner == nil && errCgroup == nil {
			return owner, cg
		}
		if time.Now().After(deadline) {
			t.Fatalf("flow %+v not published: owner %v, cgroup %v", key, errOwner, errCgroup)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func udpKey(t *testing.T, conn *net.UDPConn) ownerKey {
	t.Helper()
	local := conn.LocalAddr().(*net.UDPAddr)
	return ownerKey{
		NetNS: testNetNSCookie(t),
		Addr:  local.AddrPort().Addr().As16(),
		Port:  uint16(local.Port),
		Proto: unix.IPPROTO_UDP,
	}
}

// The loader advertises conn_cgroups and conn_flows at key 1 of the frozen
// version map.
func TestABIFeatures(t *testing.T) {
	cgroup, pin := isolatedTestEnv(t)
	if err := attach(cgroup, pin, false, -1); err != nil {
		t.Fatal(err)
	}
	version := loadPinned(t, pin, abiVersionMap)
	var v, features uint32
	if err := version.Lookup(uint32(0), &v); err != nil || v != abiVersion {
		t.Fatalf("version %d, %v", v, err)
	}
	if err := version.Lookup(uint32(1), &features); err != nil || features != abiFeatureConnCgroups|abiFeatureConnFlows {
		t.Fatalf("features %#x, %v; want conn_cgroups and conn_flows without -exec-paths", features, err)
	}
	if err := version.Update(uint32(1), uint32(0), ebpf.UpdateAny); err == nil {
		t.Fatal("version map is writable")
	}
}

// An unconnected send runs the cgroup sendmsg hook in the sending process,
// whose cgroup is published with the owner it belongs to. After moving to
// another cgroup, the next send publishes the new one.
func TestCgroupPublished(t *testing.T) {
	cgroup, pin := isolatedTestEnv(t)
	if err := attach(cgroup, pin, false, -1); err != nil {
		t.Fatal(err)
	}
	owners := loadPinned(t, pin, mapName)
	cgroups := loadPinned(t, pin, cgroupMapName)
	inner := childCgroup(t, cgroup, "app-flatpak-test.App-123.scope")
	moveSelf(t, inner)

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	dst := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9}
	if _, err := conn.WriteToUDP([]byte("x"), dst); err != nil {
		t.Fatal(err)
	}
	key := udpKey(t, conn)
	owner, cg := lookupFlow(t, owners, cgroups, key)
	if owner.TGID != uint32(os.Getpid()) {
		t.Fatalf("owner %+v, want TGID %d", owner, os.Getpid())
	}
	want := cgroupValue{TGID: owner.TGID, BootNS: owner.BootNS, CgroupID: cgroupInode(t, inner)}
	if cg != want {
		t.Fatalf("cgroup record %+v, want %+v", cg, want)
	}

	moveSelf(t, cgroup)
	if _, err := conn.WriteToUDP([]byte("x"), dst); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	_, cg = lookupFlow(t, owners, cgroups, key)
	if want.CgroupID = cgroupInode(t, cgroup); cg != want {
		t.Fatalf("after moving: cgroup record %+v, want %+v", cg, want)
	}
}

// A send on a connected socket skips the cgroup hooks; with -exec-paths the
// LSM hook records the sender's cgroup.
func TestCgroupConnectedSendWithExecPaths(t *testing.T) {
	cgroup, pin := isolatedTestEnv(t)
	if err := attach(cgroup, pin, true, -1); err != nil {
		t.Fatal(err)
	}
	owners := loadPinned(t, pin, mapName)
	cgroups := loadPinned(t, pin, cgroupMapName)

	// A listener keeps ICMP errors from failing later writes.
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	conn, err := net.DialUDP("udp4", nil, sink.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	inner := childCgroup(t, cgroup, "app-flatpak-test.App-123.scope")
	moveSelf(t, inner)
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	owner, cg := lookupFlow(t, owners, cgroups, udpKey(t, conn))
	want := cgroupValue{TGID: uint32(os.Getpid()), BootNS: owner.BootNS, CgroupID: cgroupInode(t, inner)}
	if owner.TGID != want.TGID || cg != want {
		t.Fatalf("owner %+v, cgroup record %+v, want %+v", owner, cg, want)
	}

	// The cgroup is named by its path below the cgroupfs root, and stays
	// named after it's removed.
	var features uint32
	if err := loadPinned(t, pin, abiVersionMap).Lookup(uint32(1), &features); err != nil ||
		features != abiFeatureConnCgroups|abiFeatureConnFlows|abiFeatureCgroupPaths {
		t.Fatalf("features %#x, %v", features, err)
	}
	paths := loadPinned(t, pin, cgroupPathsMap)
	rel, err := filepath.Rel("/sys/fs/cgroup", inner)
	if err != nil {
		t.Fatal(err)
	}
	checkPath := func(id uint64, want string) {
		t.Helper()
		var v cgroupPathValue
		if err := paths.Lookup(id, &v); err != nil {
			t.Fatalf("cgroup %d not named: %v", id, err)
		}
		if v.Len != int32(len(want)+1) || string(v.Path[:len(want)]) != want || v.Path[len(want)] != 0 {
			t.Fatalf("cgroup %d: len %d, path %q, want %q", id, v.Len, v.Path[:max(0, min(int(v.Len), len(v.Path)))], want)
		}
	}
	checkPath(cg.CgroupID, "/"+rel)

	// Evicting the cgroup from cgroup_paths must be repaired on the next send
	// on the same connected socket, without reconnecting or changing cgroup.
	if err := paths.Delete(cg.CgroupID); err != nil {
		t.Fatalf("delete cgroup_paths[%d]: %v", cg.CgroupID, err)
	}
	var gone cgroupPathValue
	if err := paths.Lookup(cg.CgroupID, &gone); err == nil {
		t.Fatal("cgroup_paths entry still present after delete")
	}
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	checkPath(cg.CgroupID, "/"+rel)

	// A cgroup deeper than the limit is recorded as too long.
	deep := inner
	for i := 0; i < 33; i++ {
		deep = childCgroup(t, deep, "d")
	}
	moveSelf(t, deep)
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	var v cgroupPathValue
	if err := paths.Lookup(cgroupInode(t, deep), &v); err != nil || v.Len != -int32(unix.ENAMETOOLONG) {
		t.Fatalf("deep cgroup: len %d, %v", v.Len, err)
	}
	moveSelf(t, cgroup)
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	checkPath(cgroupInode(t, cgroup), "/"+filepath.Base(cgroup))
}

type cgroupPathValue struct {
	Len  int32
	Pad  uint32
	Path [1024]byte
}

// An accepted socket has no owner and must replace a stale cgroup record with
// an empty one, just as it does in conn_owners.
func TestAcceptedEgressPublishesNoCgroup(t *testing.T) {
	cgroup, pin := isolatedTestEnv(t)
	if err := attach(cgroup, pin, false, -1); err != nil {
		t.Fatal(err)
	}
	cgroups := loadPinned(t, pin, cgroupMapName)

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err == nil {
			accepted <- conn
		}
		close(accepted)
	}()
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var server *net.TCPConn
	select {
	case server = <-accepted:
	case <-time.After(5 * time.Second):
	}
	if server == nil {
		t.Fatal("accept failed")
	}
	defer server.Close()

	local := server.LocalAddr().(*net.TCPAddr)
	key := ownerKey{
		NetNS: testNetNSCookie(t),
		Addr:  netip.MustParseAddr(local.IP.String()).As16(),
		Port:  uint16(local.Port),
		Proto: unix.IPPROTO_TCP,
	}
	if err := cgroups.Update(key, cgroupValue{TGID: 424242, BootNS: 1, CgroupID: 1}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	var got cgroupValue
	if err := cgroups.Lookup(key, &got); err != nil {
		t.Fatal(err)
	}
	if got != (cgroupValue{}) {
		t.Fatalf("accepted socket published %+v, want an empty record", got)
	}
}
