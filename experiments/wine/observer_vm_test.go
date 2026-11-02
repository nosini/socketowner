//go:build linux && amd64 && wine_vm

package wine

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type vmFixture struct {
	cmd           *exec.Cmd
	in            io.WriteCloser
	out           *bufio.Scanner
	pid, innerPID int
}

func vmFixtureStart(t *testing.T, ports []string, nested bool) *vmFixture {
	t.Helper()
	path := os.Getenv("WINE_FIXTURE")
	if !filepath.IsAbs(path) {
		t.Fatal("WINE_FIXTURE must name the compiled testdata/wineserver-fixture.c")
	}
	command, args := path, ports
	if nested {
		command = "/usr/bin/bwrap"
		args = append([]string{"--unshare-user", "--unshare-pid", "--disable-userns", "--ro-bind", "/", "/", "--proc", "/proc", "--die-with-parent", path}, ports...)
	}
	cmd := exec.Command(command, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000}}
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	f := &vmFixture{cmd: cmd, in: in, out: bufio.NewScanner(out), pid: cmd.Process.Pid}
	t.Cleanup(func() { in.Close(); cmd.Process.Kill(); cmd.Wait() })
	if !f.out.Scan() || !strings.HasPrefix(f.out.Text(), "ready pid=") {
		t.Fatalf("fixture did not become ready: %q", f.out.Text())
	}
	f.innerPID, err = strconv.Atoi(strings.TrimPrefix(f.out.Text(), "ready pid="))
	if err != nil {
		t.Fatal(err)
	}
	if nested {
		// Test-only descendant discovery. Admission itself is by pidfd and exact
		// executable identity, not the fixture's argv or reported numeric PID.
		want, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		var find func(int) int
		find = func(pid int) int {
			if st, err := os.Stat(fmt.Sprintf("/proc/%d/exe", pid)); err == nil && os.SameFile(want, st) {
				return pid
			}
			data, _ := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", pid, pid))
			for _, s := range strings.Fields(string(data)) {
				child, _ := strconv.Atoi(s)
				if found := find(child); found != 0 {
					return found
				}
			}
			return 0
		}
		f.pid = find(cmd.Process.Pid)
		if f.pid == 0 {
			t.Fatal("fixture descendant not found")
		}
		if f.pid == f.innerPID {
			t.Fatal("PID namespace test did not change PID")
		}
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", f.pid))
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
			if !strings.Contains(string(status), name+":\t0000000000000000\n") {
				t.Fatalf("sandbox fixture retained %s", name)
			}
		}
	}
	return f
}

func (f *vmFixture) command(t *testing.T, c byte) {
	t.Helper()
	if _, err := fmt.Fprintf(f.in, "%c\n", c); err != nil {
		t.Fatal(err)
	}
	if !f.out.Scan() || f.out.Text() != fmt.Sprintf("done %c 1", c) {
		t.Fatalf("fixture command %c: %q", c, f.out.Text())
	}
}

type vmObserver struct {
	events chan Event
	done   chan error
	cancel context.CancelFunc
	id     string
}

func vmObserve(t *testing.T, f *vmFixture, profile Profile, cgroup string) *vmObserver {
	t.Helper()
	target, err := Prepare(f.pid, profile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(target.Close)
	ctx, cancel := context.WithCancel(context.Background())
	o := &vmObserver{events: make(chan Event, 1024), done: make(chan error, 1), cancel: cancel}
	go func() {
		o.done <- Observe(ctx, target, Options{Cgroup: cgroup, Sends: true}, func(e Event) error {
			select {
			case o.events <- e:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-o.done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("observer did not stop")
		}
	})
	ready := o.next(t, func(e Event) bool { return e.Type == "ready" })
	if len(ready.Observer) != 32 {
		t.Fatal("missing observer lifetime ID")
	}
	o.id = ready.Observer
	return o
}

func (o *vmObserver) next(t *testing.T, match func(Event) bool) Event {
	t.Helper()
	deadline := time.NewTimer(8 * time.Second)
	defer deadline.Stop()
	var seen []Event
	for {
		select {
		case e := <-o.events:
			seen = append(seen, e)
			if match(e) {
				return e
			}
		case err := <-o.done:
			o.done <- err
			t.Fatalf("observer stopped before expected event: %v", err)
		case <-deadline.C:
			t.Fatalf("timed out waiting for Wine event; received %+v", seen)
		}
	}
}

// These are kernel integration tests. Run in a dedicated VM network namespace:
// sudo env WINE_FIXTURE=/absolute/fixture unshare --net sh -c
// 'ip link set lo up; ./wine.test -test.v -test.timeout 120s'
func TestWineObserverVM(t *testing.T) {
	self, _ := os.Readlink("/proc/self/ns/net")
	init, _ := os.Readlink("/proc/1/ns/net")
	if self == "" || self == init || os.Geteuid() != 0 {
		t.Fatal("run as root in a dedicated network namespace")
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	netnsCookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	unix.Close(fd)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(os.Getenv("WINE_FIXTURE"))
	if err != nil {
		t.Fatal(err)
	}
	profile, err := GenerateProfile(file)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	var ports []string
	for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
		address := "127.0.0.1:0"
		if strings.HasSuffix(network, "6") {
			address = "[::1]:0"
		}
		if strings.HasPrefix(network, "tcp") {
			ln, err := net.Listen(network, address)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { ln.Close() })
			ports = append(ports, strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go func() { defer c.Close(); io.Copy(io.Discard, c) }()
				}
			}()
		} else {
			c, err := net.ListenPacket(network, address)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { c.Close() })
			ports = append(ports, strconv.Itoa(c.LocalAddr().(*net.UDPAddr).Port))
			go func() {
				b := make([]byte, 64)
				for {
					if _, _, err := c.ReadFrom(b); err != nil {
						return
					}
				}
			}()
		}
	}
	for _, nested := range []bool{false, true} {
		t.Run(fmt.Sprintf("pidns=%t", nested), func(t *testing.T) {
			f := vmFixtureStart(t, ports, nested)
			cg := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("wine-observer-test-%d", f.pid))
			if err := os.Mkdir(cg, 0700); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.Remove(cg); err != nil {
					t.Error(err)
				}
			})
			// Reap the fixture before removing its cgroup (cleanup is LIFO).
			t.Cleanup(func() { f.in.Close(); f.cmd.Process.Kill(); f.cmd.Wait() })
			if err := os.WriteFile(filepath.Join(cg, "cgroup.procs"), []byte(strconv.Itoa(f.pid)), 0600); err != nil {
				t.Fatal(err)
			}
			bad := profile
			bad.SHA256 = strings.Repeat("0", 64)
			if target, err := Prepare(f.pid, bad); err == nil {
				target.Close()
				t.Fatal("accepted wrong binary hash")
			}
			o := vmObserve(t, f, profile, cg)
			check := func(e Event, name string, pid uint32) {
				t.Helper()
				if e.Status != "known" || e.WindowsName != name || e.WindowsPID != pid || e.ClientUnixPID != uint32(f.innerPID) || e.ServerTGID != uint32(f.pid) {
					t.Fatalf("incorrect Windows owner: %+v", e)
				}
			}
			f.command(t, '4')
			first := o.next(t, func(e Event) bool { return e.Type == "first-egress" })
			check(first, "alpha.exe", 101)
			if first.TCPFlags&2 == 0 || first.Source == "" || first.NetNS != netnsCookie {
				t.Fatalf("first packet was not attributed at SYN: %+v", first)
			}
			if dst, err := netip.ParseAddrPort(first.Destination); err != nil || strconv.Itoa(int(dst.Port())) != ports[0] {
				t.Fatalf("wrong SYN destination: %+v", first)
			}
			f.command(t, 'b')
			f.command(t, 'c')
			f.command(t, 's')
			check(o.next(t, func(e Event) bool { return e.Type == "connect" && e.SocketID == first.SocketID }), "alpha.exe", 101)
			check(o.next(t, func(e Event) bool { return e.Type == "send" && e.SocketID == first.SocketID }), "alpha.exe", 101)
			f.command(t, 'f')
			child := o.next(t, func(e Event) bool {
				return e.Type == "send" && e.SocketID == first.SocketID && e.ActorTGID != uint32(f.pid)
			})
			check(child, "alpha.exe", 101)
			f.command(t, 'g')
			select {
			case unexpected := <-o.events:
				t.Fatalf("registration leaked to an unregistered fork: %+v", unexpected)
			case <-time.After(100 * time.Millisecond):
			}
			f.command(t, 'd')
			udp := o.next(t, func(e Event) bool { return e.Type == "first-egress" && e.Network == "udp" })
			check(udp, "beta.exe", 202)
			f.command(t, '6')
			v6 := o.next(t, func(e Event) bool { return e.Type == "first-egress" && e.Network == "tcp" })
			check(v6, "beta.exe", 202)
			if !strings.HasPrefix(v6.Source, "[") {
				t.Fatalf("missing IPv6 source: %+v", v6)
			}
			f.command(t, 'e')
			check(o.next(t, func(e Event) bool { return e.Type == "first-egress" && e.Network == "udp" }), "beta.exe", 202)
			for _, tc := range []struct {
				command byte
				status  string
			}{{'u', "invalid-image"}, {'l', "invalid-image"}, {'n', "unreadable-request"}} {
				f.command(t, tc.command)
				f.command(t, 'd')
				e := o.next(t, func(e Event) bool { return e.Type == "first-egress" && e.Network == "udp" })
				if e.Status != tc.status || e.WindowsName != "" || e.WindowsImage != "" || e.WindowsPID != 0 {
					t.Fatalf("invalid request retained a name: %+v", e)
				}
			}
			f.command(t, 'r')
			seen := map[uint64]bool{first.SocketID: true}
			for i := 0; i < 8; i++ {
				f.command(t, '4')
				e := o.next(t, func(e Event) bool { return e.Type == "first-egress" && e.Network == "tcp" })
				check(e, "alpha.exe", 101)
				if seen[e.SocketID] {
					t.Fatal("socket identity reused")
				}
				seen[e.SocketID] = true
			}
			if _, err := fmt.Fprintln(f.in, "q"); err != nil {
				t.Fatal(err)
			}
			o.next(t, func(e Event) bool { return e.Type == "stopped" && e.Reason == "target-exit" })
		})
	}
	t.Run("restart-does-not-adopt-existing-socket", func(t *testing.T) {
		f := vmFixtureStart(t, ports, false)
		first := vmObserve(t, f, profile, "/sys/fs/cgroup")
		f.command(t, '4')
		old := first.next(t, func(e Event) bool { return e.Type == "first-egress" })
		first.cancel()
		select {
		case err := <-first.done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			first.done <- nil
		case <-time.After(5 * time.Second):
			t.Fatal("old observer did not stop")
		}
		second := vmObserve(t, f, profile, "/sys/fs/cgroup")
		if first.id == second.id {
			t.Fatal("observer lifetime identity reused")
		}
		f.command(t, 's')
		select {
		case e := <-second.events:
			t.Fatalf("adopted old socket: %+v", e)
		case <-time.After(100 * time.Millisecond):
		}
		f.command(t, '4')
		fresh := second.next(t, func(e Event) bool { return e.Type == "first-egress" })
		if fresh.Status != "known" || fresh.WindowsName != "alpha.exe" || fresh.Observer == old.Observer {
			t.Fatalf("bad fresh observation: %+v", fresh)
		}
	})
	t.Run("exec-revokes", func(t *testing.T) {
		f := vmFixtureStart(t, ports, false)
		o := vmObserve(t, f, profile, "/sys/fs/cgroup")
		fmt.Fprintln(f.in, "x")
		select {
		case err := <-o.done:
			if err == nil || !strings.Contains(err.Error(), "revoked") {
				t.Fatalf("exec did not revoke registration: %v", err)
			}
			// The expected error has been checked; cleanup only needs completion.
			o.done <- nil
		case <-time.After(5 * time.Second):
			t.Fatal("observer survived target exec")
		}
	})
}
