package wine

import (
	"os"
	"path/filepath"
	"testing"

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
