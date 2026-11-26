package wine

// Root tests for sockets the Windows program's own Linux process creates.
// Wine itself is not needed: the fixtures imitate its request protocol. A
// helper process named wineserver reads a FIFO once, and a client helper
// writes it with a fake TEB, PEB and parameter block mapped at its GS base,
// the public Windows x86-64 layouts the capture reads. Each helper re-executes
// this test binary under a role from WINE_HELPER_ROLE.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	helperEnv      = "WINE_HELPER_ROLE"
	helperFIFO     = "WINE_HELPER_FIFO"
	helperListener = "WINE_HELPER_LISTENER"
	helperUDP      = "WINE_HELPER_UDP"
	helperFork     = "WINE_HELPER_FORK"
	helperWindows  = 4242
	helperImage    = `C:\games\alpha.exe`
	// arch_prctl's GS-base setter (0x1001), the call a Wine client's loader
	// makes; 0x1002 would instead clobber the runtime's FS-based TLS.
	archSetGS = 0x1001
)

func TestMain(m *testing.M) {
	if role := os.Getenv(helperEnv); role != "" {
		runHelper(role)
	}
	os.Exit(m.Run())
}

// runHelper never returns: it exits with the status its role reports. The
// calling thread is pinned, because both the wineserver name and the GS base
// are per thread.
func runHelper(role string) {
	runtime.LockOSThread()
	var err error
	switch role {
	case "server":
		err = serverHelper()
	case "client":
		err = clientHelper(os.Getenv(helperFork) == "1")
	case "plain":
		err = plainHelper()
	case "pipe-server":
		err = pipeServerHelper()
	case "pipe-writer":
		err = pipeWriterHelper()
	case "client-race":
		err = clientRaceHelper()
	case "client-pageout":
		err = clientPageoutHelper()
	case "server-two-req":
		err = serverTwoReqHelper()
	default:
		err = fmt.Errorf("unknown role %q", role)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "helper %s: %v\n", role, err)
		os.Exit(1)
	}
	os.Exit(0)
}

// helperMessage is one line a helper prints for the test driving it.
type helperMessage struct {
	Event string `json:"event"`
	Port  int    `json:"port,omitempty"`
	PID   int    `json:"pid,omitempty"`
}

func announce(event string, port int) error {
	message, err := json.Marshal(helperMessage{Event: event, Port: port})
	if err != nil {
		return err
	}
	fmt.Println(string(message))
	return nil
}

// announcePID reports a process id, which the port field would truncate.
func announcePID(event string, pid int) error {
	message, err := json.Marshal(helperMessage{Event: event, PID: pid})
	if err != nil {
		return err
	}
	fmt.Println(string(message))
	return nil
}

// blockUntilKilled keeps a helper alive for the observer's lookups.
func blockUntilKilled() {
	_, _ = io.Copy(io.Discard, os.Stdin)
}

// serverHelper imitates wineserver far enough to attribute a socket: it is
// named wineserver, reads the request FIFO, and after the client's request
// creates a socket, as wineserver does for a client's connections.
func serverHelper() error {
	name := append([]byte("wineserver"), 0)
	if err := unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(&name[0])), 0, 0, 0); err != nil {
		return err
	}
	fifo, err := unix.Open(os.Getenv(helperFIFO), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fifo)
	// The first read marks the pipe and its wineserver, naming no client.
	if _, err := unix.Read(fifo, make([]byte, 1)); err != nil && !errors.Is(err, unix.EAGAIN) {
		return err
	}
	if err := announce("read", 0); err != nil {
		return err
	}
	// The next read serves the client's request, so a socket created
	// afterwards belongs to it.
	goahead := make([]byte, 1)
	if _, err := os.Stdin.Read(goahead); err != nil {
		return err
	}
	if _, err := unix.Read(fifo, make([]byte, 64)); err != nil && !errors.Is(err, unix.EAGAIN) {
		return err
	}
	connection, err := net.Dial("tcp", os.Getenv(helperListener))
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := announce("socket", connection.LocalAddr().(*net.TCPAddr).Port); err != nil {
		return err
	}
	blockUntilKilled()
	return nil
}

// clientHelper imitates a 64-bit Wine client: it writes a request to the FIFO
// with a fake Windows identity at its GS base, then opens sockets in its own
// process, as the resolver behind getaddrinfo does.
func clientHelper(fork bool) error {
	if err := fakeWindowsIdentity(helperWindows, helperImage); err != nil {
		return err
	}
	request, err := os.OpenFile(os.Getenv(helperFIFO), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer request.Close()
	if _, err := request.Write([]byte("request")); err != nil {
		return err
	}
	if err := announce("wrote", 0); err != nil {
		return err
	}
	if fork {
		child, err := forkedSocket(os.Getenv(helperListener))
		if err != nil {
			return err
		}
		if err := announcePID("child", child); err != nil {
			return err
		}
	}
	connection, err := net.Dial("tcp", os.Getenv(helperListener))
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := announce("tcp", connection.LocalAddr().(*net.TCPAddr).Port); err != nil {
		return err
	}
	packet, err := net.Dial("udp", os.Getenv(helperUDP))
	if err != nil {
		return err
	}
	defer packet.Close()
	if _, err := packet.Write([]byte("probe")); err != nil {
		return err
	}
	if err := announce("udp", packet.LocalAddr().(*net.UDPAddr).Port); err != nil {
		return err
	}
	blockUntilKilled()
	return nil
}

// plainHelper runs a process which never talked to wineserver and opens
// sockets of its own.
func plainHelper() error {
	connection, err := net.Dial("tcp", os.Getenv(helperListener))
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := announce("tcp", connection.LocalAddr().(*net.TCPAddr).Port); err != nil {
		return err
	}
	packet, err := net.Dial("udp", os.Getenv(helperUDP))
	if err != nil {
		return err
	}
	defer packet.Close()
	if _, err := packet.Write([]byte("probe")); err != nil {
		return err
	}
	if err := announce("udp", packet.LocalAddr().(*net.UDPAddr).Port); err != nil {
		return err
	}
	blockUntilKilled()
	return nil
}

// fakeWindowsIdentity maps a TEB, PEB and parameter block at the GS base of
// the calling thread: the public Windows x86-64 layouts the capture reads, so
// the observer finds this helper's image and Windows PID.
func fakeWindowsIdentity(windowsPID uint32, image string) error {
	_, err := fakeWindowsIdentityMapped(windowsPID, image)
	return err
}

func fakeWindowsIdentityMapped(windowsPID uint32, image string) ([]byte, error) {
	base, err := unix.Mmap(-1, 0, 5*4096, unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return nil, err
	}
	address := uintptr(unsafe.Pointer(unsafe.SliceData(base)))
	teb, peb, parameters, buffer := address, address+0x1000, address+0x2000, address+0x3000
	store64 := func(at, value uintptr) {
		binary.LittleEndian.PutUint64(base[at-address:], uint64(value))
	}
	store32 := func(at uintptr, value uint32) {
		binary.LittleEndian.PutUint32(base[at-address:], value)
	}
	store16 := func(at uintptr, value uint16) {
		binary.LittleEndian.PutUint16(base[at-address:], value)
	}
	store64(teb+0x30, teb)                 // TEB.Self
	store64(teb+0x40, uintptr(windowsPID)) // TEB.ClientId.UniqueProcess
	store64(teb+0x60, peb)                 // TEB.ProcessEnvironmentBlock
	store64(peb+0x20, parameters)          // PEB.ProcessParameters
	store32(parameters+8, 1)               // parameters validated
	store64(parameters+0x68, buffer)       // ImagePathName.Buffer
	encoded := utf16.Encode([]rune(image))
	for i, unit := range encoded {
		store16(buffer+uintptr(i)*2, unit)
	}
	store16(parameters+0x60, uint16(len(encoded)*2)) // ImagePathName.Length
	_, _, errno := unix.Syscall6(unix.SYS_ARCH_PRCTL, archSetGS, teb, 0, 0, 0, 0)
	if errno != 0 {
		return nil, errno
	}
	return base, nil
}

// forkAddress is the sockaddr_in a forked child connects: a global, so its
// address stays valid in a process where the Go runtime is not running.
var forkAddress [16]byte

// forkedSocket forks the client and lets the child create and connect a
// socket with the parent's memory, fake TEB included: a forked child is not a
// Wine client, and its socket must stay unlabelled. The Go runtime's
// guarantees end at the fork, so the child runs raw syscalls only.
func forkedSocket(listener string) (int, error) {
	address, err := net.ResolveTCPAddr("tcp", listener)
	if err != nil {
		return 0, err
	}
	forkAddress = [16]byte{2, 0, byte(address.Port >> 8), byte(address.Port), 127, 0, 0, 1}
	pid, _, errno := unix.RawSyscall6(unix.SYS_CLONE, uintptr(unix.SIGCHLD), 0, 0, 0, 0, 0)
	if errno != 0 {
		return 0, errno
	}
	if pid == 0 {
		// Child: raw syscalls only, and no return into the runtime.
		fd, _, errno := unix.RawSyscall6(unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0, 0, 0, 0)
		if errno != 0 {
			unix.RawSyscall(unix.SYS_EXIT_GROUP, 99, 0, 0)
		}
		_, _, _ = unix.RawSyscall6(unix.SYS_CONNECT, fd, uintptr(unsafe.Pointer(&forkAddress[0])), uintptr(len(forkAddress)), 0, 0, 0)
		unix.RawSyscall(unix.SYS_CLOSE, fd, 0, 0)
		unix.RawSyscall(unix.SYS_EXIT_GROUP, 0, 0, 0)
	}
	var status unix.WaitStatus
	if _, err := unix.Wait4(int(pid), &status, 0, nil); err != nil {
		return 0, err
	}
	if !status.Exited() || status.ExitStatus() != 0 {
		return 0, fmt.Errorf("forked child failed: %v", status)
	}
	return int(pid), nil
}

// helper drives one role of this test binary and collects what it announces.
type helper struct {
	process *exec.Cmd
	stdin   io.Writer
	mu      sync.Mutex
	seen    []helperMessage
}

func startHelper(t *testing.T, role string, env map[string]string) *helper {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), helperEnv+"="+role)
	for name, value := range env {
		cmd.Env = append(cmd.Env, name+"="+value)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	h := &helper{process: cmd, stdin: stdin}
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			var message helperMessage
			if json.Unmarshal(scanner.Bytes(), &message) == nil {
				h.mu.Lock()
				h.seen = append(h.seen, message)
				h.mu.Unlock()
			}
		}
	}()
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	return h
}

func (h *helper) messages() []helperMessage {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]helperMessage(nil), h.seen...)
}

// await waits until the helper announced an event.
func (h *helper) await(t *testing.T, event string) helperMessage {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		for _, message := range h.messages() {
			if message.Event == event {
				return message
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("helper did not announce %q: %+v", event, h.messages())
	return helperMessage{}
}

// eventLog collects the observer's events until the test stops it.
type eventLog struct {
	mu     sync.Mutex
	events []Event
}

func (l *eventLog) record(e Event) {
	l.mu.Lock()
	l.events = append(l.events, e)
	l.mu.Unlock()
}

func (l *eventLog) snapshot() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Event(nil), l.events...)
}

// waitForEvents waits until want accepts the events collected so far.
func waitForEvents(t *testing.T, log *eventLog, want func([]Event) error) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		err := want(log.snapshot())
		if err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected events never arrived: %v\n%+v", want(log.snapshot()), log.snapshot())
}

// startObserver runs the observer for a test, publishing in a fresh pin
// directory, and stops it when the test ends.
func startObserver(t *testing.T) (*eventLog, *ebpf.Map) {
	t.Helper()
	dir := pinDir(t)
	ctx, cancel := context.WithCancel(context.Background())
	log := &eventLog{}
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- Observe(ctx, Options{Cgroup: "/sys/fs/cgroup", Pin: dir, Group: -1}, func(e Event) error {
			if e.Type == "ready" {
				close(ready)
			}
			log.record(e)
			return nil
		})
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	select {
	case <-ready:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(10 * time.Second):
		t.Fatal("observer not ready")
	}
	flows, err := ebpf.LoadPinnedMap(filepath.Join(dir, flowsPin), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { flows.Close() })
	return log, flows
}

// listenLocal listens on loopback for the helpers' sockets.
func listenLocal(t *testing.T) (tcp, udp string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	// Connections complete without an accept, but drain them anyway.
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			connection.Close()
		}
	}()
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { packet.Close() })
	return listener.Addr().String(), packet.LocalAddr().String()
}

// flowRecord reads the published identity of one outgoing loopback flow.
func flowRecord(t *testing.T, flows *ebpf.Map, netns uint64, port int, protocol uint8) rawOwner {
	t.Helper()
	key := connKey{NetNS: netns, Address: netip.MustParseAddr("127.0.0.1").As16(), Port: uint16(port), Protocol: protocol}
	var record rawOwner
	if err := flows.Lookup(key, &record); err != nil {
		t.Fatalf("no flow record for port %d: %v", port, err)
	}
	return record
}

// A Windows program's own sockets are labelled with its identity and
// published under their packet source, and wineserver's sockets for the same
// client keep their identity.
func TestClientCreatedSockets(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load the observer")
	}
	tcp, udp := listenLocal(t)
	fifo := filepath.Join(t.TempDir(), "request")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	log, flows := startObserver(t)
	env := map[string]string{helperFIFO: fifo, helperListener: tcp, helperUDP: udp}
	server := startHelper(t, "server", env)
	server.await(t, "read")
	client := startHelper(t, "client", env)
	client.await(t, "wrote")
	if _, err := server.stdin.Write([]byte("go")); err != nil {
		t.Fatal(err)
	}
	serverPID := uint32(server.process.Process.Pid)
	clientPID := uint32(client.process.Process.Pid)
	serverSocket := server.await(t, "socket")
	clientTCP := client.await(t, "tcp")
	clientUDP := client.await(t, "udp")

	known := func(e Event) bool {
		return e.Type == "create" && e.Status == "known" && e.WindowsName == "alpha.exe" &&
			e.WindowsPID == helperWindows && e.ClientTGID == clientPID && e.ServerTGID == serverPID
	}
	waitForEvents(t, log, func(events []Event) error {
		creators := map[string]int{}
		for _, e := range events {
			if known(e) {
				creators[e.Creator]++
			}
		}
		if creators["wineserver"] < 1 {
			return errors.New("no wineserver-created socket")
		}
		if creators["client"] < 2 {
			return fmt.Errorf("client created %d of 2 sockets", creators["client"])
		}
		return nil
	})
	for _, e := range log.snapshot() {
		if !known(e) {
			continue
		}
		// The actor names who created each socket.
		expected := serverPID
		if e.Creator == "client" {
			expected = clientPID
		}
		if e.ActorTGID != expected {
			t.Fatalf("creator %s named actor %d, want %d", e.Creator, e.ActorTGID, expected)
		}
	}
	host, err := hostNetNS()
	if err != nil {
		t.Fatal(err)
	}
	for _, probe := range []struct {
		port     int
		protocol uint8
	}{
		{serverSocket.Port, unix.IPPROTO_TCP},
		{clientTCP.Port, unix.IPPROTO_TCP},
		{clientUDP.Port, unix.IPPROTO_UDP},
	} {
		record := flowRecord(t, flows, host, probe.port, probe.protocol)
		if record.Status != 1 || record.WindowsPID != helperWindows ||
			record.ServerTGID != serverPID || record.ClientTGID != clientPID {
			t.Fatalf("flow record for port %d: %+v", probe.port, record)
		}
		image, name, err := windowsImage(record.Image[:], record.ImageBytes)
		if err != nil || image != helperImage || name != "alpha.exe" {
			t.Fatalf("image %q %q %v", image, name, err)
		}
	}
}

// A process which never wrote a request keeps no Wine identity, even though
// its sockets pass the same hooks.
func TestPlainSocketNotLabelled(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load the observer")
	}
	tcp, udp := listenLocal(t)
	log, flows := startObserver(t)
	plain := startHelper(t, "plain", map[string]string{helperListener: tcp, helperUDP: udp})
	clientTCP := plain.await(t, "tcp")
	clientUDP := plain.await(t, "udp")
	// The hooks have run by now; give asynchronous events a moment.
	time.Sleep(300 * time.Millisecond)
	pid := uint32(plain.process.Process.Pid)
	for _, e := range log.snapshot() {
		if e.ActorTGID == pid {
			t.Fatalf("a plain process produced a %s event: %+v", e.Type, e)
		}
	}
	host, err := hostNetNS()
	if err != nil {
		t.Fatal(err)
	}
	for _, probe := range []struct {
		port     int
		protocol uint8
	}{
		{clientTCP.Port, unix.IPPROTO_TCP},
		{clientUDP.Port, unix.IPPROTO_UDP},
	} {
		key := connKey{NetNS: host, Address: netip.MustParseAddr("127.0.0.1").As16(), Port: uint16(probe.port), Protocol: probe.protocol}
		var record rawOwner
		if err := flows.Lookup(key, &record); !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("plain flow at port %d published: %v %v", probe.port, err, record)
		}
	}
}

// A forked child inherits a client's memory, fake TEB included, but it is not
// a Wine client: its socket stays unlabelled while the parent's is labelled.
func TestForkedChildNotLabelled(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load the observer")
	}
	tcp, udp := listenLocal(t)
	fifo := filepath.Join(t.TempDir(), "request")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	log, _ := startObserver(t)
	env := map[string]string{helperFIFO: fifo, helperListener: tcp, helperUDP: udp, helperFork: "1"}
	server := startHelper(t, "server", env)
	server.await(t, "read")
	client := startHelper(t, "client", env)
	client.await(t, "wrote")
	child := client.await(t, "child")
	client.await(t, "tcp")
	client.await(t, "udp")
	// The parent's labelled socket proves the capture is live; the child,
	// which has already exited, must have produced nothing.
	clientPID, childPID := uint32(client.process.Process.Pid), uint32(child.PID)
	waitForEvents(t, log, func(events []Event) error {
		for _, e := range events {
			if e.Type == "create" && e.Creator == "client" && e.ClientTGID == clientPID && e.Status == "known" {
				return nil
			}
		}
		return errors.New("no labelled client socket")
	})
	time.Sleep(300 * time.Millisecond)
	for _, e := range log.snapshot() {
		if e.ActorTGID == childPID {
			t.Fatalf("the forked child produced a %s event: %+v", e.Type, e)
		}
	}
}

// recycledPipes is how many pipes each side of the recycled-pipe test opens:
// enough that some of the writer's land on inodes the server's left behind.
const recycledPipes = 3000

// pinToFirstCPU keeps the helpers' pipe inodes in one CPU's slab cache, where
// a freed inode is reused soonest.
func pinToFirstCPU() error {
	var set unix.CPUSet
	set.Set(0)
	return unix.SchedSetaffinity(0, &set)
}

// pipeServerHelper is named wineserver and reads from many pipes, which it
// then closes, so that their freed inodes are reused for later pipes.
func pipeServerHelper() error {
	if err := pinToFirstCPU(); err != nil {
		return err
	}
	name := append([]byte("wineserver"), 0)
	if err := unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(&name[0])), 0, 0, 0); err != nil {
		return err
	}
	var buf [1]byte
	for range recycledPipes {
		var fds [2]int
		if err := unix.Pipe2(fds[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
			return err
		}
		unix.Read(fds[0], buf[:])
		unix.Close(fds[0])
		unix.Close(fds[1])
	}
	return nil
}

// pipeWriterHelper is no Wine client: it writes to pipes of its own, which
// may reuse the inodes of pipes a wineserver read, and then sends from a
// socket.
func pipeWriterHelper() error {
	if err := pinToFirstCPU(); err != nil {
		return err
	}
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		return err
	}
	limit.Cur = limit.Max
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		return err
	}
	for range recycledPipes {
		var fds [2]int
		if err := unix.Pipe2(fds[:], unix.O_CLOEXEC); err != nil {
			return err
		}
		if _, err := unix.Write(fds[1], []byte("x")); err != nil {
			return err
		}
	}
	packet, err := net.Dial("udp", os.Getenv(helperUDP))
	if err != nil {
		return err
	}
	defer packet.Close()
	if _, err := packet.Write([]byte("probe")); err != nil {
		return err
	}
	if err := announce("udp", packet.LocalAddr().(*net.UDPAddr).Port); err != nil {
		return err
	}
	blockUntilKilled()
	return nil
}

// The kernel reuses a freed pipe inode's memory for new pipes. A process that
// writes to such a pipe must not become a client of the wineserver that read
// the old one: every socket it created would then be labelled.
func TestRecycledPipeNotLabelled(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load the observer")
	}
	_, udp := listenLocal(t)
	log, _ := startObserver(t)
	for round := range 5 {
		server := startHelper(t, "pipe-server", nil)
		if err := server.process.Wait(); err != nil {
			t.Fatalf("pipe server: %v", err)
		}
		// Inodes are freed after an RCU grace period.
		time.Sleep(time.Second)
		writer := startHelper(t, "pipe-writer", map[string]string{helperUDP: udp})
		writer.await(t, "udp")
		time.Sleep(300 * time.Millisecond)
		pid := uint32(writer.process.Process.Pid)
		for _, e := range log.snapshot() {
			if e.ActorTGID == pid || e.ClientTGID == pid {
				t.Fatalf("round %d: a process writing to recycled pipes was labelled: %+v", round, e)
			}
		}
		writer.process.Process.Kill()
		writer.process.Wait()
	}
}

// clientRaceHelper hammers request FIFO writes and client socket creation
// concurrently from multiple OS threads: half with a valid TEB/PEB and half
// without GS set, exercising concurrent clients[tgid] initialization and
// read_client failures racing against KNOWN publication.
func clientRaceHelper() error {
	request, err := os.OpenFile(os.Getenv(helperFIFO), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer request.Close()
	listener := os.Getenv(helperListener)
	const workers = 8
	const rounds = 25
	ready := make(chan struct{}, workers)
	start := make(chan struct{})
	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			if id%2 == 0 {
				if err := fakeWindowsIdentity(helperWindows, helperImage); err != nil {
					errCh <- err
					return
				}
			}
			ready <- struct{}{}
			<-start
			for range rounds {
				if _, err := request.Write([]byte("r")); err != nil {
					errCh <- err
					return
				}
				conn, err := net.Dial("tcp", listener)
				if err != nil {
					errCh <- err
					return
				}
				conn.Close()
			}
		}(i)
	}
	for range workers {
		select {
		case <-ready:
		case err := <-errCh:
			return err
		}
	}
	close(start)
	wg.Wait()
	select {
	case err := <-errCh:
		return err
	default:
	}
	if err := announce("done", 0); err != nil {
		return err
	}
	blockUntilKilled()
	return nil
}

// Multi-threaded clients concurrently writing request pipes and creating
// sockets must never crash the observer with ServerStartNS==0 or corrupt a
// KNOWN image back to no-image.
func TestConcurrentClientInitAndSockets(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load the observer")
	}
	tcp, udp := listenLocal(t)
	fifo := filepath.Join(t.TempDir(), "request")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	log, _ := startObserver(t)
	env := map[string]string{helperFIFO: fifo, helperListener: tcp, helperUDP: udp}
	server := startHelper(t, "server", env)
	server.await(t, "read")
	client := startHelper(t, "client-race", env)
	client.await(t, "done")
	if _, err := server.stdin.Write([]byte("go")); err != nil {
		t.Fatal(err)
	}
	server.await(t, "socket")
	serverPID := uint32(server.process.Process.Pid)
	clientPID := uint32(client.process.Process.Pid)

	waitForEvents(t, log, func(events []Event) error {
		knownClient := 0
		knownServer := 0
		for _, e := range events {
			if e.Type == "create" && e.ClientTGID == clientPID && e.Status == "known" && e.WindowsName == "alpha.exe" {
				if e.Creator == "client" {
					knownClient++
				} else if e.Creator == "wineserver" {
					knownServer++
				}
			}
		}
		if knownClient < 10 || knownServer < 1 {
			return fmt.Errorf("known creates: client=%d server=%d", knownClient, knownServer)
		}
		return nil
	})
	sawKnown := false
	for _, e := range log.snapshot() {
		if e.Type != "create" || e.ClientTGID != clientPID {
			continue
		}
		if e.ServerTGID != serverPID || e.ServerStartNS == 0 {
			t.Fatalf("invalid server identity on concurrent create: %+v", e)
		}
		if e.Status == "known" {
			sawKnown = true
			if e.WindowsName != "alpha.exe" || e.WindowsImage != helperImage {
				t.Fatalf("corrupted known image: %+v", e)
			}
		} else if sawKnown && e.Creator == "wineserver" {
			t.Fatalf("client regressed from known to %s: %+v", e.Status, e)
		}
	}
}

// clientPageoutHelper maps a fake Windows identity, swaps out the ImagePathName
// page with MADV_PAGEOUT before writing the FIFO (so non-sleepable
// file_permission gets -EFAULT), and then creates a socket in its own process
// so sleepable lsm.s/socket_post_create faults the page in via bpf_copy_from_user.
func clientPageoutHelper() error {
	base, err := fakeWindowsIdentityMapped(helperWindows, helperImage)
	if err != nil {
		return err
	}
	// Page out the ImagePathName buffer page before writing the request FIFO.
	if err := unix.Madvise(base[0x3000:0x4000], unix.MADV_PAGEOUT); err != nil {
		return fmt.Errorf("madvise MADV_PAGEOUT: %w", err)
	}
	request, err := os.OpenFile(os.Getenv(helperFIFO), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer request.Close()
	if _, err := request.Write([]byte("request1")); err != nil {
		return err
	}
	if err := announce("wrote", 0); err != nil {
		return err
	}
	goahead := make([]byte, 1)
	if _, err := os.Stdin.Read(goahead); err != nil {
		return err
	}
	conn, err := net.Dial("tcp", os.Getenv(helperListener))
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := announce("tcp", conn.LocalAddr().(*net.TCPAddr).Port); err != nil {
		return err
	}
	blockUntilKilled()
	return nil
}

// serverTwoReqHelper reads a FIFO, creates a socket after signal 1, then reads
// again and creates a second socket after signal 2.
func serverTwoReqHelper() error {
	name := append([]byte("wineserver"), 0)
	if err := unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(&name[0])), 0, 0, 0); err != nil {
		return err
	}
	fifo, err := unix.Open(os.Getenv(helperFIFO), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fifo)
	if os.Getenv("WINE_SKIP_INITIAL_READ") != "1" {
		if _, err := unix.Read(fifo, make([]byte, 1)); err != nil && !errors.Is(err, unix.EAGAIN) {
			return err
		}
	}
	if err := announce("ready", 0); err != nil {
		return err
	}
	buf := make([]byte, 1)
	for i := range 2 {
		if _, err := os.Stdin.Read(buf); err != nil {
			return err
		}
		if _, err := unix.Read(fifo, make([]byte, 64)); err != nil && !errors.Is(err, unix.EAGAIN) {
			return err
		}
		conn, err := net.Dial("tcp", os.Getenv(helperListener))
		if err != nil {
			return err
		}
		defer conn.Close()
		if err := announce(fmt.Sprintf("socket%d", i+1), conn.LocalAddr().(*net.TCPAddr).Port); err != nil {
			return err
		}
	}
	blockUntilKilled()
	return nil
}

func hasActiveSwap() bool {
	data, err := os.ReadFile("/proc/swaps")
	if err != nil {
		return false
	}
	return len(strings.Split(strings.TrimSpace(string(data)), "\n")) > 1
}

// When ImagePathName is swapped out before file_permission runs, sleepable
// lsm.s/socket_post_create must fault it back in with bpf_copy_from_user and
// publish the KNOWN identity for both the client socket and subsequent
// wineserver sockets.
func TestSwappedOutImagePageResolvedOnSocketCreate(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load the observer")
	}
	tcp, udp := listenLocal(t)
	fifo := filepath.Join(t.TempDir(), "request")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	log, flows := startObserver(t)
	env := map[string]string{helperFIFO: fifo, helperListener: tcp, helperUDP: udp}
	server := startHelper(t, "server-two-req", env)
	server.await(t, "ready")
	client := startHelper(t, "client-pageout", env)
	client.await(t, "wrote")
	// Trigger first wineserver socket before client creates any socket: with
	// active swap, MADV_PAGEOUT causes non-sleepable file_permission to miss
	// the swapped-out ImagePathName page and leave the client no-image.
	if _, err := server.stdin.Write([]byte("1")); err != nil {
		t.Fatal(err)
	}
	firstSock := server.await(t, "socket1")
	clientPID := uint32(client.process.Process.Pid)
	serverPID := uint32(server.process.Process.Pid)
	host, err := hostNetNS()
	if err != nil {
		t.Fatal(err)
	}
	firstRec := flowRecord(t, flows, host, firstSock.Port, unix.IPPROTO_TCP)
	if hasActiveSwap() && firstRec.Status != 3 {
		t.Logf("note: first socket status=%d (page may have stayed resident)", firstRec.Status)
	}

	// Now let client create a socket: lsm.s/socket_post_create faults the page in.
	if _, err := client.stdin.Write([]byte("1")); err != nil {
		t.Fatal(err)
	}
	clientSock := client.await(t, "tcp")
	// And trigger a second wineserver socket, which now sees KNOWN in clients.
	if _, err := server.stdin.Write([]byte("2")); err != nil {
		t.Fatal(err)
	}
	secondSock := server.await(t, "socket2")

	for _, port := range []int{clientSock.Port, secondSock.Port} {
		rec := flowRecord(t, flows, host, port, unix.IPPROTO_TCP)
		if rec.Status != 1 || rec.ClientTGID != clientPID || rec.ServerTGID != serverPID || rec.WindowsPID != helperWindows {
			t.Fatalf("port %d not resolved after sleepable read: %+v", port, rec)
		}
		image, name, err := windowsImage(rec.Image[:], rec.ImageBytes)
		if err != nil || image != helperImage || name != "alpha.exe" {
			t.Fatalf("port %d image %q %q (%v)", port, image, name, err)
		}
	}
	waitForEvents(t, log, func(events []Event) error {
		for _, e := range events {
			if e.Type == "create" && e.Creator == "client" && e.ClientTGID == clientPID &&
				e.Status == "known" && e.WindowsName == "alpha.exe" {
				return nil
			}
		}
		return errors.New("no known client create event")
	})
}

// Closing all ends of a pipe must prune its entry from request_pipes via
// lsm/file_free_security, while closing only one end must keep the entry so
// buffered requests can still be read and attributed.
func TestRequestPipePrunedOnClose(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load BPF programs")
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
	host, err := hostNetNS()
	if err != nil {
		t.Fatal(err)
	}
	if err := coll.Maps["wine_config"].Update(uint32(0), observerConfig{HostNetNS: host}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	lFile, err := link.AttachLSM(link.LSMOptions{Program: coll.Programs["wine_file"]})
	if err != nil {
		t.Fatal(err)
	}
	defer lFile.Close()
	lFree, err := link.AttachLSM(link.LSMOptions{Program: coll.Programs["wine_file_free"]})
	if err != nil {
		t.Fatal(err)
	}
	defer lFree.Close()

	// Create a pipe and read from it under comm "wineserver" on a dedicated OS thread.
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fds[0], &st); err != nil {
		unix.Close(fds[0])
		unix.Close(fds[1])
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() {
		// Keep the OS thread locked until exit so the Go runtime terminates it
		// rather than returning a thread named "wineserver" to the pool.
		runtime.LockOSThread()
		name := append([]byte("wineserver"), 0)
		if err := unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(&name[0])), 0, 0, 0); err != nil {
			readDone <- err
			return
		}
		var b [1]byte
		_, err := unix.Read(fds[0], b[:])
		if err != nil && !errors.Is(err, unix.EAGAIN) {
			readDone <- err
			return
		}
		readDone <- nil
	}()
	if err := <-readDone; err != nil {
		unix.Close(fds[0])
		unix.Close(fds[1])
		t.Fatal(err)
	}

	type pipeKey struct {
		Inode uint64
		Ino   uint64
	}
	type processID struct {
		StartNS       uint64
		ServerStartNS uint64
		TGID          uint32
		ServerTGID    uint32
	}
	hasPipe := func() bool {
		iter := coll.Maps["request_pipes"].Iterate()
		var k pipeKey
		var v processID
		for iter.Next(&k, &v) {
			if k.Ino == st.Ino {
				return true
			}
		}
		return false
	}
	if !hasPipe() {
		unix.Close(fds[0])
		unix.Close(fds[1])
		t.Fatalf("pipe ino %d not recorded in request_pipes", st.Ino)
	}
	// Closing only the write end while the read end stays open must keep the entry.
	unix.Close(fds[1])
	if !hasPipe() {
		unix.Close(fds[0])
		t.Fatalf("pipe ino %d pruned while read end was still open", st.Ino)
	}
	// Closing the last end must prune the entry immediately.
	unix.Close(fds[0])
	if hasPipe() {
		t.Fatalf("pipe ino %d remained in request_pipes after both ends closed", st.Ino)
	}
}

// When the observer starts while a Wine client pipe already exists and the
// client writes before any observed wineserver read, the first wineserver
// socket is labelled no-client (never misattributed), and the client's next
// write on that pipe names both wineserver and client sockets.
func TestPreExistingClientPipeAfterObserverStart(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load the observer")
	}
	tcp, udp := listenLocal(t)
	fifo := filepath.Join(t.TempDir(), "request")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	// Start server BEFORE observer, skipping initial read so the pipe exists
	// unopened/unseen by the observer when the client makes its first write.
	env := map[string]string{
		helperFIFO:             fifo,
		helperListener:         tcp,
		helperUDP:              udp,
		"WINE_SKIP_INITIAL_READ": "1",
	}
	server := startHelper(t, "server-two-req", env)
	server.await(t, "ready")

	_, flows := startObserver(t)

	// Open the FIFO in a client process and write request 1 before server reads.
	client := startHelper(t, "client", env)
	client.await(t, "wrote")
	// Server reads request 1 -> registers the pipe with tgid=0 -> socket1 is no-client.
	if _, err := server.stdin.Write([]byte("1")); err != nil {
		t.Fatal(err)
	}
	sock1 := server.await(t, "socket1")
	host, err := hostNetNS()
	if err != nil {
		t.Fatal(err)
	}
	rec1 := flowRecord(t, flows, host, sock1.Port, unix.IPPROTO_TCP)
	if rec1.Status != 2 { // NO_CLIENT
		t.Fatalf("first socket on unseen pipe had status %d, want 2 (no-client)", rec1.Status)
	}
	// Now a second client write on the same pipe (after server learned it) names the client.
	client2 := startHelper(t, "client", env)
	client2.await(t, "wrote")
	client2TCP := client2.await(t, "tcp")
	if _, err := server.stdin.Write([]byte("2")); err != nil {
		t.Fatal(err)
	}
	sock2 := server.await(t, "socket2")
	for _, port := range []int{sock2.Port, client2TCP.Port} {
		rec := flowRecord(t, flows, host, port, unix.IPPROTO_TCP)
		if rec.Status != 1 {
			t.Fatalf("port %d status = %d, want 1 (known)", port, rec.Status)
		}
	}
}

// A blocked diagnostic consumer must not prevent Observe from shutting down
// promptly on context cancellation and removing its pinned maps.
func TestObserveBlockedStdoutUnpinsOnCancel(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load the observer")
	}
	dir := pinDir(t)
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	blocked := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	done := make(chan error, 1)
	go func() {
		done <- Observe(ctx, Options{Cgroup: "/sys/fs/cgroup", Pin: dir, Group: -1}, func(e Event) error {
			if e.Type == "ready" {
				close(ready)
				close(blocked)
				<-release
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
	<-blocked
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Observe returned error on cancel with blocked stdout: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Observe hung on cancel while stdout consumer was blocked")
	}
	for _, name := range []string{flowsPin, peerFlowsPin, abiPin, heartbeatPin} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("pin %s left behind after cancel with blocked stdout: %v", name, err)
		}
	}
}
