package wine

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// pinDir needs root: pins live on bpffs, normally /sys/fs/bpf.
func pinDir(t *testing.T) string {
	dir, err := os.MkdirTemp("/sys/fs/bpf", "wine-claim-")
	if err != nil {
		t.Skip("needs a writable bpffs:", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func pinArray(t *testing.T, path string, valueSize uint32, value any) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: valueSize, MaxEntries: 1})
	if err != nil {
		t.Skip("needs BPF map creation:", err)
	}
	defer m.Close()
	if err := m.Update(uint32(0), value, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := m.Pin(path); err != nil {
		t.Fatal(err)
	}
}

// A publisher killed between pins, while publishing or closing, leaves no
// wine_flows; the next one must still be able to pin.
func TestClaimClearsPartialPins(t *testing.T) {
	dir := pinDir(t)
	pinArray(t, filepath.Join(dir, abiPin), 4, wineABI)
	pinArray(t, filepath.Join(dir, heartbeatPin), 8, uint64(0))
	if err := claim(dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{abiPin, heartbeatPin} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s left behind: %v", name, err)
		}
	}
}

func TestClaimRefusesPublisherStillPinning(t *testing.T) {
	dir := pinDir(t)
	now, err := bootTime()
	if err != nil {
		t.Fatal(err)
	}
	pinArray(t, filepath.Join(dir, abiPin), 4, wineABI)
	pinArray(t, filepath.Join(dir, heartbeatPin), 8, now)
	if err := claim(dir); err == nil {
		t.Fatal("claimed the pins of a live publisher")
	}
}

// close must not remove a pin which a successor has replaced.
func TestRemoveOwnKeepsReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, flowsPin)
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	old, err := pinIDOf(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "replacement")
	if err := os.WriteFile(replacement, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	current, err := pinIDOf(path)
	if err != nil {
		t.Fatal(err)
	}
	removeOwn(path, old)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("removed a successor's pin: %v", err)
	}
	removeOwn(path, current)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("did not remove our own pin: %v", err)
	}
}

// A writer blocked on stdout must not stop the heartbeat.
func TestHeartbeatNotBlockedByWriter(t *testing.T) {
	blocked := make(chan struct{})
	release := make(chan struct{})
	go func() {
		blocked <- struct{}{}
		<-release
	}()
	<-blocked
	ctx, cancel := context.WithCancel(context.Background())
	beats := make(chan struct{}, 4)
	done := make(chan error, 1)
	go func() {
		done <- runHeartbeat(ctx, time.Millisecond, func() error {
			beats <- struct{}{}
			return nil
		})
	}()
	for range 3 {
		select {
		case <-beats:
		case <-time.After(time.Second):
			close(release)
			t.Fatal("heartbeat stopped while output was blocked")
		}
	}
	cancel()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLockDirSerializesCallers(t *testing.T) {
	dir := t.TempDir()
	first, err := lockDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	acquired := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		second, err := lockDir(dir)
		if err != nil {
			done <- err
			return
		}
		close(acquired)
		unlockDir(second)
		done <- nil
	}()
	select {
	case <-acquired:
		unlockDir(first)
		t.Fatal("second caller acquired directory lock while first held it")
	case <-time.After(50 * time.Millisecond):
	}
	unlockDir(first)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("second caller did not acquire lock after release")
	}
}

func newTestCollection(t *testing.T) *ebpf.Collection {
	t.Helper()
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Skip("needs BPF privileges:", err)
	}
	t.Cleanup(func() { coll.Close() })
	return coll
}

// A stalled publisher whose heartbeat expired must neither overwrite nor delete
// a live successor's pins when it resumes ensurePins() and close().
func TestStalledPublisherDoesNotClobberSuccessor(t *testing.T) {
	dir := pinDir(t)
	collA := newTestCollection(t)
	collB := newTestCollection(t)

	pubA, err := publish(collA, dir, -1)
	if err != nil {
		t.Fatal(err)
	}
	// Make A's heartbeat stale, as if A stalled past heartbeatLimit.
	now, err := bootTime()
	if err != nil {
		t.Fatal(err)
	}
	stale := uint64(1)
	if now > uint64(2*heartbeatLimit) {
		stale = now - uint64(2*heartbeatLimit)
	}
	if err := pubA.heartbeat.Update(uint32(0), stale, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}

	// Successor B claims and publishes while A is stalled.
	pubB, err := publish(collB, dir, -1)
	if err != nil {
		t.Fatalf("successor publish failed: %v", err)
	}
	defer pubB.close()

	pinNames := []string{abiPin, heartbeatPin, peerFlowsPin, flowsPin}
	wantIDs := make(map[string]pinID, len(pinNames))
	for _, name := range pinNames {
		id, err := pinIDOf(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("successor pin %s missing: %v", name, err)
		}
		wantIDs[name] = id
	}

	// A resumes: ensurePins must fail and leave every one of B's pins untouched.
	if err := pubA.ensurePins(); err == nil {
		t.Fatal("stalled publisher's ensurePins succeeded after successor takeover")
	}
	for _, name := range pinNames {
		got, err := pinIDOf(filepath.Join(dir, name))
		if err != nil || got != wantIDs[name] {
			t.Fatalf("pin %s changed after stalled ensurePins: got %+v (%v), want %+v", name, got, err, wantIDs[name])
		}
	}

	// A closes: must not delete any of B's pins or zero B's heartbeat.
	pubA.close()
	for _, name := range pinNames {
		got, err := pinIDOf(filepath.Join(dir, name))
		if err != nil || got != wantIDs[name] {
			t.Fatalf("pin %s changed after stalled close: got %+v (%v), want %+v", name, got, err, wantIDs[name])
		}
	}
	var beat uint64
	if err := pubB.heartbeat.Lookup(uint32(0), &beat); err != nil || beat == 0 {
		t.Fatalf("successor heartbeat corrupted: %d (%v)", beat, err)
	}
}
