//go:build linux && sockowner_vm

package main

import (
	"bufio"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// A parent that was running before the iterator seeded it can fork a child the
// iterator never visits. With the parent's task storage removed, the fork hook
// must still build the child's record from the parent's executable.
func TestForkFromUnseededParentGetsRecord(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 needed to fork without exec:", err)
	}
	cgroup, pin := isolatedTestEnv(t)
	const helper = `import os,sys,time
sys.stdout.write("ready\n"); sys.stdout.flush()
while True:
    c = sys.stdin.read(1)
    if not c: break
    pid = os.fork()
    if pid == 0:
        time.sleep(120)
        os._exit(0)
    sys.stdout.write("child %d\n" % pid); sys.stdout.flush()
`
	cmd := exec.Command(python, "-c", helper)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	helperPid := cmd.Process.Pid
	t.Cleanup(func() {
		stdin.Close()
		cmd.Process.Kill()
		cmd.Wait()
	})
	reader := bufio.NewReader(stdout)
	if line, err := reader.ReadString('\n'); err != nil || strings.TrimSpace(line) != "ready" {
		t.Fatalf("helper: %q, %v", line, err)
	}

	if err := attach(cgroup, pin, true, -1); err != nil {
		t.Fatal(err)
	}
	tasks, err := ebpf.LoadPinnedMap(filepath.Join(pin, "maps", "exec_tasks"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tasks.Close()
	pidfd, err := unix.PidfdOpen(helperPid, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pidfd)
	var record struct {
		StartNS uint64
		ExitNS  uint64
		Len     int32
		Pad     uint32
		Path    [1024]byte
	}
	if err := tasks.Lookup(int32(pidfd), &record); err != nil {
		t.Fatalf("helper was not seeded: %v", err)
	}
	if err := tasks.Delete(int32(pidfd)); err != nil {
		t.Fatalf("delete helper record: %v", err)
	}
	if err := tasks.Lookup(int32(pidfd), &record); err == nil {
		t.Fatal("helper record still present")
	}

	if _, err := stdin.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var childPid int
	if _, err := fmt.Sscanf(strings.TrimSpace(line), "child %d", &childPid); err != nil {
		t.Fatalf("helper said %q: %v", line, err)
	}
	t.Cleanup(func() { syscall.Kill(childPid, syscall.SIGKILL) })
	childPidfd, err := unix.PidfdOpen(childPid, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(childPidfd)
	want, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", helperPid))
	if err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		err = tasks.Lookup(int32(childPidfd), &record)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("child has no record: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if record.Len < 1 || record.Len > 1024 {
		t.Fatalf("child record length %d", record.Len)
	}
	got := string(record.Path[:record.Len-1])
	if got != want {
		t.Fatalf("child path %q, want %q", got, want)
	}
}

type execRecord struct {
	StartNS uint64
	ExitNS  uint64
	Len     int32
	Pad     uint32
	Path    [1024]byte
}

func decodeExecRecord(t *testing.T, r execRecord) string {
	t.Helper()
	if r.Len < 2 || int(r.Len) > len(r.Path) {
		t.Fatalf("invalid exec record length %d", r.Len)
	}
	return string(r.Path[:r.Len-1])
}

// Deleting a process's exec_recent entry must be repaired on the next send on
// the same connected socket, without reconnecting or switching owners.
func TestExecRecentRefreshedAfterEviction(t *testing.T) {
	cgroup, pin := isolatedTestEnv(t)
	if err := attach(cgroup, pin, true, -1); err != nil {
		t.Fatal(err)
	}
	recent := loadPinned(t, pin, "exec_recent")
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

	if _, err := conn.Write([]byte("1")); err != nil {
		t.Fatal(err)
	}
	tgid := uint32(os.Getpid())
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var rec execRecord
	if err := recent.Lookup(tgid, &rec); err != nil {
		t.Fatalf("exec_recent[%d] missing after first send: %v", tgid, err)
	}
	if got := decodeExecRecord(t, rec); got != self {
		t.Fatalf("exec_recent[%d] = %q, want %q", tgid, got, self)
	}

	if err := recent.Delete(tgid); err != nil {
		t.Fatalf("delete exec_recent[%d]: %v", tgid, err)
	}
	if err := recent.Lookup(tgid, &rec); err == nil {
		t.Fatal("exec_recent entry still present after delete")
	}

	if _, err := conn.Write([]byte("2")); err != nil {
		t.Fatal(err)
	}
	if err := recent.Lookup(tgid, &rec); err != nil {
		t.Fatalf("exec_recent[%d] not repopulated after second send: %v", tgid, err)
	}
	if got := decodeExecRecord(t, rec); got != self || rec.ExitNS != 0 {
		t.Fatalf("exec_recent[%d] = %q (exit_ns=%d), want %q (exit_ns=0)", tgid, got, rec.ExitNS, self)
	}
}

// When a task is freed after a newer process with the same PID has already
// written exec_recent, record_free must neither overwrite the newer entry nor
// stamp exit_ns onto it.
func TestRecordFreeDoesNotOverwriteNewerPID(t *testing.T) {
	cgroup, pin := isolatedTestEnv(t)
	if err := attach(cgroup, pin, true, -1); err != nil {
		t.Fatal(err)
	}
	recent := loadPinned(t, pin, "exec_recent")
	cmd := exec.Command("/bin/sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := uint32(cmd.Process.Pid)
	// Wait until exec_tasks/exec_recent has the child recorded.
	deadline := time.Now().Add(2 * time.Second)
	var rec execRecord
	for {
		if err := recent.Lookup(pid, &rec); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatalf("child %d not in exec_recent", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Simulate a newly reused live PID with a later start_ns in exec_recent.
	newer := execRecord{
		StartNS: math.MaxUint64,
		ExitNS:  0,
		Len:     int32(len("/newer") + 1),
	}
	copy(newer.Path[:], "/newer\x00")
	if err := recent.Update(pid, newer, ebpf.UpdateAny); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatal(err)
	}

	cmd.Process.Kill()
	cmd.Wait()
	// Give RCU task_free a moment to run.
	time.Sleep(150 * time.Millisecond)

	var got execRecord
	if err := recent.Lookup(pid, &got); err != nil {
		t.Fatalf("exec_recent[%d] missing after child free: %v", pid, err)
	}
	if got.StartNS != newer.StartNS || got.ExitNS != 0 || decodeExecRecord(t, got) != "/newer" {
		t.Fatalf("record_free clobbered newer PID entry: start=%d exit=%d path=%q",
			got.StartNS, got.ExitNS, decodeExecRecord(t, got))
	}
}

// Two processes in distinct cgroups sending concurrently on a shared connected
// socket must never cross-poison exec_recent or publish a torn (owner, cgroup)
// pair in conn_flows.
func TestSharedSocketConcurrentSendConsistency(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 required:", err)
	}
	pythonReal, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	cgroup, pin := isolatedTestEnv(t)
	if err := attach(cgroup, pin, true, -1); err != nil {
		t.Fatal(err)
	}
	flows := loadPinned(t, pin, flowMapName)
	recent := loadPinned(t, pin, "exec_recent")

	cgParent := childCgroup(t, cgroup, "shared-parent")
	cgChild := childCgroup(t, cgroup, "shared-child")
	parentCgID := cgroupInode(t, cgParent)
	childCgID := cgroupInode(t, cgChild)
	moveSelf(t, cgParent)

	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	sinkAddr := sink.LocalAddr().(*net.UDPAddr)

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	sockFile := os.NewFile(uintptr(fd), "shared-udp")
	defer sockFile.Close()
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Connect(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}, Port: sinkAddr.Port}); err != nil {
		t.Fatal(err)
	}
	local, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	sport := uint16(local.(*unix.SockaddrInet4).Port)

	const childScript = `import os, sys, time
with open(sys.argv[1] + "/cgroup.procs", "w") as f:
    f.write(str(os.getpid()))
sys.stdout.write("ready\n")
sys.stdout.flush()
end = time.monotonic() + 0.5
while time.monotonic() < end:
    os.write(3, b"c")
`
	cmd := exec.Command(python, "-c", childScript, cgChild)
	cmd.ExtraFiles = []*os.File{sockFile}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	childPid := uint32(cmd.Process.Pid)
	parentPid := uint32(os.Getpid())
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || strings.TrimSpace(line) != "ready" {
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatalf("child ready: %q, %v", line, err)
	}

	var stop atomic.Bool
	go func() {
		buf := make([]byte, 64)
		for !stop.Load() {
			sink.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			sink.Read(buf)
		}
	}()

	key := flowKey{
		Netns: testNetNSCookie(t),
		Saddr: netip.MustParseAddr("127.0.0.1").As16(),
		Daddr: netip.MustParseAddr("127.0.0.1").As16(),
		Sport: sport,
		Dport: uint16(sinkAddr.Port),
		Proto: unix.IPPROTO_UDP,
	}

	var checkErr atomic.Pointer[string]
	setErr := func(msg string) {
		checkErr.CompareAndSwap(nil, &msg)
	}
	var seenParent, seenChild atomic.Uint64
	doneCheck := make(chan struct{})
	go func() {
		defer close(doneCheck)
		for !stop.Load() {
			var fv flowValue
			if err := flows.Lookup(&key, &fv); err == nil {
				switch fv.TGID {
				case parentPid:
					seenParent.Add(1)
					if fv.CgroupID != parentCgID {
						setErr(fmt.Sprintf("torn flow: parent TGID %d paired with cgroup %d (want %d)", fv.TGID, fv.CgroupID, parentCgID))
						return
					}
				case childPid:
					seenChild.Add(1)
					if fv.CgroupID != childCgID {
						setErr(fmt.Sprintf("torn flow: child TGID %d paired with cgroup %d (want %d)", fv.TGID, fv.CgroupID, childCgID))
						return
					}
				}
			}
			var r execRecord
			if err := recent.Lookup(parentPid, &r); err == nil {
				if p := string(r.Path[:max(0, min(int(r.Len)-1, len(r.Path)))]); p != self {
					setErr(fmt.Sprintf("exec_recent[parent %d] poisoned with %q (want %q)", parentPid, p, self))
					return
				}
			}
			if err := recent.Lookup(childPid, &r); err == nil {
				if p := string(r.Path[:max(0, min(int(r.Len)-1, len(r.Path)))]); p != pythonReal {
					setErr(fmt.Sprintf("exec_recent[child %d] poisoned with %q (want %q)", childPid, p, pythonReal))
					return
				}
			}
		}
	}()

	end := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(end) && checkErr.Load() == nil {
		if _, err := unix.Write(fd, []byte("p")); err != nil {
			break
		}
	}
	errWait := cmd.Wait()
	stop.Store(true)
	<-doneCheck
	if errWait != nil {
		t.Fatalf("child exited with error: %v", errWait)
	}
	if msg := checkErr.Load(); msg != nil {
		t.Fatal(*msg)
	}
	// Verify final exec_recent entries for both processes.
	var r execRecord
	if err := recent.Lookup(parentPid, &r); err != nil || decodeExecRecord(t, r) != self {
		t.Fatalf("final exec_recent[parent %d] = %q (%v), want %q", parentPid, decodeExecRecord(t, r), err, self)
	}
	if err := recent.Lookup(childPid, &r); err != nil || decodeExecRecord(t, r) != pythonReal {
		t.Fatalf("final exec_recent[child %d] = %q (%v), want %q", childPid, decodeExecRecord(t, r), err, pythonReal)
	}
	t.Logf("observed flows: parent=%d child=%d", seenParent.Load(), seenChild.Load())
}
