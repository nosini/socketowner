//go:build linux && sockowner_vm

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
