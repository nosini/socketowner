package wine

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

func TestEmbeddedObjectLayout(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]struct {
		typ  ebpf.MapType
		size int
	}{
		"wine_config":   {ebpf.Array, binary.Size(observerConfig{})},
		"wine_sockets":  {ebpf.SkStorage, binary.Size(rawOwner{}) + 32},
		"relay_flows":   {ebpf.LRUHash, binary.Size(rawOwner{}) + 32},
		"wine_flows":    {ebpf.LRUHash, binary.Size(rawOwner{})},
		"pasta_targets": {ebpf.TaskStorage, binary.Size(pastaTarget{})},
	} {
		m := spec.Maps[name]
		if m == nil || m.Type != want.typ || int(m.ValueSize) != want.size {
			t.Fatalf("map %s: %+v, expected size %d", name, m, want.size)
		}
	}
	if binary.Size(rawEvent{}) != 1144 || binary.Size(rawOwner{}) != 1088 {
		t.Fatal("unexpected userspace structure layout")
	}
	if len(spec.Programs) != 6 {
		t.Fatalf("unexpected programs: %v", spec.Programs)
	}
	for _, name := range []string{"wine_file", "wine_create", "wine_connect", "wine_send", "wine_exec"} {
		if spec.Programs[name].Type != ebpf.LSM {
			t.Fatal(name)
		}
	}
	var owner *btf.Struct
	if err := spec.Types.TypeByName("owner", &owner); err != nil {
		t.Fatal(err)
	}
	if int(owner.Size) != binary.Size(rawOwner{}) || owner.Members[4].Offset != 256 || owner.Members[12].Offset != 512 {
		t.Fatalf("BPF owner layout changed: %+v", owner)
	}
}
