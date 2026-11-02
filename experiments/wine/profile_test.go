//go:build linux && amd64

package wine

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

func testProfile() Profile {
	return Profile{Version: 1, ID: "test", SHA256: strings.Repeat("1", 64), Architecture: "amd64", ELFType: "DYN", CurrentSymbol: 0x4000,
		Offsets: Offsets{ThreadProcess: 8, ProcessID: 8, ProcessUnixPID: 12, ProcessStartTime: 16, ProcessImageLen: 24, ProcessImage: 32}}
}

func TestProfileRefusals(t *testing.T) {
	valid := testProfile()
	data, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProfile(bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Profile){
		"version": func(p *Profile) { p.Version++ }, "architecture": func(p *Profile) { p.Architecture = "arm64" },
		"hash": func(p *Profile) { p.SHA256 = "1" }, "uppercase-hash": func(p *Profile) { p.SHA256 = strings.Repeat("A", 64) },
		"zero-symbol": func(p *Profile) { p.CurrentSymbol = 0 }, "kernel-address": func(p *Profile) { p.CurrentSymbol = 1 << 63 },
		"unaligned-pointer": func(p *Profile) { p.Offsets.ThreadProcess = 9 },
		"overlap":           func(p *Profile) { p.Offsets.ProcessImage = p.Offsets.ProcessStartTime },
		"huge-offset":       func(p *Profile) { p.Offsets.ProcessID = 1 << 31 },
	} {
		t.Run(name, func(t *testing.T) {
			p := valid
			change(&p)
			if p.Validate() == nil {
				t.Fatal("accepted invalid profile")
			}
		})
	}
	for name, bad := range map[string]string{
		"unknown-field":     strings.Replace(string(data), `"version":1`, `"version":1,"surprise":1`, 1),
		"trailing-document": string(data) + " {}", "oversized": string(data) + strings.Repeat(" ", 64<<10) + "x",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadProfile(strings.NewReader(bad)); err == nil {
				t.Fatal("accepted malformed profile")
			}
		})
	}
}

func TestGenerateExactProfile(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("GCC needed for the DWARF profile fixture")
	}
	for _, pie := range []bool{false, true} {
		t.Run(map[bool]string{false: "exec", true: "pie"}[pie], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "wineserver-fixture")
			mode := "-no-pie"
			if pie {
				mode = "-pie"
			}
			cmd := exec.Command("gcc", "-g", "-O0", mode, "testdata/wineserver-fixture.c", "-o", path)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s: %v", out, err)
			}
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			p, err := GenerateProfile(f)
			if err != nil {
				t.Fatal(err)
			}
			digest, err := fileDigest(f)
			if err != nil || p.SHA256 != digest {
				t.Fatal("profile not bound to exact ELF bytes")
			}
			if p.Offsets != testProfile().Offsets {
				t.Fatalf("unexpected fixture offsets: %+v", p.Offsets)
			}
			e, err := elf.NewFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var mapping strings.Builder
			bias := uint64(0)
			if pie {
				bias = 0x550000000000
			}
			page := uint64(os.Getpagesize())
			for _, seg := range e.Progs {
				if seg.Type != elf.PT_LOAD {
					continue
				}
				perms := "r--p"
				if seg.Flags&elf.PF_X != 0 {
					perms = "r-xp"
				}
				if seg.Flags&elf.PF_W != 0 {
					perms = "rw-p"
				}
				start := bias + (seg.Vaddr &^ (page - 1))
				end := (bias + seg.Vaddr + seg.Memsz + page - 1) &^ (page - 1)
				fmtMapping(&mapping, start, end, perms, seg.Off&^(page-1), "00:29", 123)
			}
			address, err := currentAddress(e, p.CurrentSymbol, mapping.String(), 0, 41, 123)
			if err != nil || address != bias+p.CurrentSymbol {
				t.Fatalf("ASLR relocation: %#x %v", address, err)
			}
			for _, bad := range []string{strings.ReplaceAll(mapping.String(), "00:29", "00:2a"), strings.ReplaceAll(mapping.String(), " 123 ", " 456 "), strings.ReplaceAll(mapping.String(), "r-xp", "r--p")} {
				if _, err := currentAddress(e, p.CurrentSymbol, bad, 0, 41, 123); err == nil {
					t.Fatal("accepted wrong mapped file or nonexecuting mapping")
				}
			}
			stripped := exec.Command("strip", "--strip-all", path)
			if out, err := stripped.CombinedOutput(); err != nil {
				t.Fatalf("strip: %s %v", out, err)
			}
			if _, err := GenerateProfile(f); err == nil {
				t.Fatal("generated layout for stripped ELF")
			}
		})
	}
}

func fmtMapping(b *strings.Builder, start, end uint64, perms string, offset uint64, dev string, inode uint64) {
	// Keep a path with spaces: admission must use dev/inode, not the path text.
	fmt.Fprintf(b, "%x-%x %s %08x %s %d /a path/wineserver\n", start, end, perms, offset, dev, inode)
}

func TestObserverObjectLayout(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]struct {
		typ  ebpf.MapType
		size int
	}{
		"wine_targets": {ebpf.TaskStorage, binary.Size(targetConfig{})},
		"wine_sockets": {ebpf.SkStorage, binary.Size(rawOwner{}) + 16},
	} {
		m := spec.Maps[name]
		if m == nil || m.Type != want.typ || int(m.ValueSize) != want.size {
			t.Fatalf("map %s: %+v, expected size %d", name, m, want.size)
		}
	}
	if binary.Size(rawEvent{}) != 1144 || binary.Size(rawOwner{}) != 1088 || binary.Size(targetConfig{}) != 56 {
		t.Fatal("unexpected userspace structure layout")
	}
	if len(spec.Programs) != 6 {
		t.Fatalf("unexpected programs: %v", spec.Programs)
	}
	for _, name := range []string{"wine_create", "wine_connect", "wine_send", "wine_exec"} {
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
