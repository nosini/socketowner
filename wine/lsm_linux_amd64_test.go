package wine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckBPFLSM(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "active")
	if err := os.WriteFile(active, []byte("lockdown,yama,integrity,bpf\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkBPFLSMAt(active); err != nil {
		t.Fatal(err)
	}
	inactive := filepath.Join(dir, "inactive")
	if err := os.WriteFile(inactive, []byte("lockdown,yama,integrity\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkBPFLSMAt(inactive); err == nil {
		t.Fatal("accepted a host without the BPF LSM")
	}
}
