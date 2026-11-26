package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// Both embedded objects must parse and agree on the programs and the layout
// readers use (docs/map-interface.md).
func TestObjects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		object []byte
		order  binary.ByteOrder
	}{
		{"bpfel", objectLE, binary.LittleEndian},
		{"bpfeb", objectBE, binary.BigEndian},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(tc.object))
			if err != nil {
				t.Fatal(err)
			}
			if spec.ByteOrder != tc.order {
				t.Fatalf("byte order %v", spec.ByteOrder)
			}
			if err := validateMapABI(spec, false); err != nil {
				t.Fatal(err)
			}
			checkStructABI(t, spec.Maps[mapName].Key, 32, []abiMember{
				{"netns", 0, 8}, {"addr", 8, 16}, {"port", 24, 2}, {"proto", 26, 1}, {"pad", 27, 5},
			})
			checkStructABI(t, spec.Maps[mapName].Value, 16, []abiMember{
				{"tgid", 0, 4}, {"uid", 4, 4}, {"boot_ns", 8, 8},
			})
			checkStructABI(t, spec.Maps[cgroupMapName].Key, 32, []abiMember{
				{"netns", 0, 8}, {"addr", 8, 16}, {"port", 24, 2}, {"proto", 26, 1}, {"pad", 27, 5},
			})
			checkStructABI(t, spec.Maps[cgroupMapName].Value, 24, []abiMember{
				{"tgid", 0, 4}, {"pad", 4, 4}, {"boot_ns", 8, 8}, {"cgroup_id", 16, 8},
			})
			checkStructABI(t, spec.Maps[flowMapName].Key, 48, []abiMember{
				{"netns", 0, 8}, {"saddr", 8, 16}, {"daddr", 24, 16}, {"sport", 40, 2},
				{"dport", 42, 2}, {"proto", 44, 1}, {"pad", 45, 3},
			})
			checkStructABI(t, spec.Maps[flowMapName].Value, 24, []abiMember{
				{"owner", 0, 16}, {"cgroup_id", 16, 8},
			})
			want := map[string]ebpf.AttachType{
				"sock_create": ebpf.AttachCGroupInetSockCreate,
				"connect4":    ebpf.AttachCGroupInet4Connect,
				"connect6":    ebpf.AttachCGroupInet6Connect,
				"sendmsg4":    ebpf.AttachCGroupUDP4Sendmsg,
				"sendmsg6":    ebpf.AttachCGroupUDP6Sendmsg,
				"egress":      ebpf.AttachCGroupInetEgress,
			}
			if len(spec.Programs) != len(want) {
				t.Fatalf("%d programs", len(spec.Programs))
			}
			if len(cgroupPrograms) != len(want) || cgroupPrograms[len(cgroupPrograms)-1] != "egress" {
				t.Fatalf("cgroupPrograms = %v, want %d programs ending with egress", cgroupPrograms, len(want))
			}
			seen := make(map[string]bool, len(cgroupPrograms))
			for _, name := range cgroupPrograms {
				if seen[name] {
					t.Errorf("duplicate program %s in cgroupPrograms", name)
				}
				seen[name] = true
				if _, ok := want[name]; !ok {
					t.Errorf("unexpected program %s in cgroupPrograms", name)
				}
			}
			for name, attach := range want {
				if p := spec.Programs[name]; p == nil || p.AttachType != attach {
					t.Errorf("program %s: %+v", name, p)
				}
				if !seen[name] {
					t.Errorf("program %s missing from cgroupPrograms", name)
				}
			}
			m := spec.Maps[mapName]
			if m == nil || m.Type != ebpf.LRUHash || m.KeySize != 32 || m.ValueSize != 16 {
				t.Fatalf("map %s: %+v", mapName, m)
			}
		})
	}
}

// The exec-path objects must carry the LSM hooks, the iterator and the maps
// readers use (docs/map-interface.md), and
// share the socket storage of the socket-owner objects.
func TestExecObjects(t *testing.T) {
	for _, tc := range []struct {
		name       string
		object     []byte
		sockObject []byte
		order      binary.ByteOrder
	}{
		{"bpfel", execObjectLE, objectLE, binary.LittleEndian},
		{"bpfeb", execObjectBE, objectBE, binary.BigEndian},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(tc.object))
			if err != nil {
				t.Fatal(err)
			}
			if spec.ByteOrder != tc.order {
				t.Fatalf("byte order %v", spec.ByteOrder)
			}
			if err := validateMapABI(spec, true); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"exec_tasks", "exec_recent"} {
				checkStructABI(t, spec.Maps[name].Value, 1048, []abiMember{
					{"start_ns", 0, 8}, {"exit_ns", 8, 8}, {"len", 16, 4}, {"pad", 20, 4}, {"path", 24, 1024},
				})
			}
			checkStructABI(t, spec.Maps[cgroupPathsMap].Value, 1032, []abiMember{
				{"len", 0, 4}, {"pad", 4, 4}, {"path", 8, 1024},
			})
			if n, err := btf.Sizeof(spec.Maps[cgroupPathsMap].Key); err != nil || n != 8 {
				t.Errorf("%s key: %d bytes, %v", cgroupPathsMap, n, err)
			}
			want := map[string]struct {
				typ    ebpf.ProgramType
				attach ebpf.AttachType
			}{
				"seed_tasks": {ebpf.Tracing, ebpf.AttachTraceIter},
			}
			for _, name := range execPrograms {
				want[name] = struct {
					typ    ebpf.ProgramType
					attach ebpf.AttachType
				}{ebpf.LSM, ebpf.AttachLSMMac}
			}
			if len(spec.Programs) != len(want) {
				t.Fatalf("%d programs", len(spec.Programs))
			}
			for name, w := range want {
				if p := spec.Programs[name]; p == nil || p.Type != w.typ || p.AttachType != w.attach {
					t.Errorf("program %s: %+v", name, p)
				}
			}
			const valueSize = 24 + 1024
			for name, typ := range map[string]ebpf.MapType{"exec_tasks": ebpf.TaskStorage, "exec_recent": ebpf.LRUHash} {
				m := spec.Maps[name]
				if m == nil || m.Type != typ || m.KeySize != 4 || m.ValueSize != valueSize {
					t.Errorf("map %s: %+v", name, m)
				}
			}
			for _, name := range execMapNames {
				if spec.Maps[name] == nil {
					t.Errorf("pinned map %s missing", name)
				}
			}
			// attach gives the exec-path object the socket-owner object's map.
			sockSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(tc.sockObject))
			if err != nil {
				t.Fatal(err)
			}
			m, s := spec.Maps[sockMapName], sockSpec.Maps[sockMapName]
			if m == nil || s == nil || m.Type != s.Type || m.KeySize != s.KeySize || m.ValueSize != s.ValueSize || m.Flags != s.Flags {
				t.Errorf("map %s: %+v, socket-owner object: %+v", sockMapName, m, s)
			}
		})
	}
}

type abiMember struct {
	name         string
	offset, size int
}

// Check field offsets as well as total sizes: reordering equal-sized fields
// changes the ABI without changing the kernel's reported map dimensions.
func checkStructABI(t *testing.T, typ btf.Type, size uint32, want []abiMember) {
	t.Helper()
	s, ok := typ.(*btf.Struct)
	if !ok || s.Size != size || len(s.Members) != len(want) {
		t.Fatalf("unexpected ABI struct: %+v", typ)
	}
	for i, w := range want {
		m := s.Members[i]
		n, err := btf.Sizeof(m.Type)
		if err != nil || m.Name != w.name || int(m.Offset) != w.offset*8 || n != w.size {
			t.Errorf("%s member %d: %+v (size %d, error %v), want %+v", s.Name, i, m, n, err, w)
		}
	}
}

func TestRejectIncompatibleMapABI(t *testing.T) {
	for _, execPaths := range []bool{false, true} {
		object := objectLE
		if execPaths {
			object = execObjectLE
		}
		spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
		if err != nil {
			t.Fatal(err)
		}
		names := []string{mapName, cgroupMapName, flowMapName}
		if execPaths {
			names = execMapNames
		}
		for _, name := range names {
			for _, field := range []string{"missing", "type", "key", "value"} {
				t.Run(name+"/"+field, func(t *testing.T) {
					changed := spec.Copy()
					switch field {
					case "missing":
						delete(changed.Maps, name)
					case "type":
						changed.Maps[name].Type = ebpf.Hash
					case "key":
						changed.Maps[name].KeySize++
					case "value":
						changed.Maps[name].ValueSize++
					}
					if err := validateMapABI(changed, execPaths); err == nil {
						t.Fatal("accepted incompatible map")
					}
				})
			}
		}
	}
}

// A reader must be able to pass through the pin directory to the maps, also
// when an earlier version created it for root alone. The links stay the
// loader's, and so does the maps directory, which an earlier version gave to
// a reader user; the reader group only gets read access.
func TestMakePinDirs(t *testing.T) {
	pin := filepath.Join(t.TempDir(), "mihomo")
	maps := filepath.Join(pin, "maps")
	if err := os.MkdirAll(maps, 0o700); err != nil {
		t.Fatal(err)
	}
	gid := os.Getgid()
	if os.Getuid() == 0 { // can test taking the directory back
		gid = 4242
		if err := os.Chown(maps, 4243, 4243); err != nil {
			t.Fatal(err)
		}
	}
	links, maps, err := makePinDirs(pin, gid)
	if err != nil {
		t.Fatal(err)
	}
	for dir, want := range map[string]os.FileMode{pin: 0o711, links: 0o700, maps: 0o750} {
		fi, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s: mode %v, want %v", dir, fi.Mode().Perm(), want)
		}
	}
	fi, err := os.Stat(maps)
	if err != nil {
		t.Fatal(err)
	}
	if st := fi.Sys().(*syscall.Stat_t); int(st.Uid) != os.Getuid() || int(st.Gid) != gid {
		t.Errorf("%s: owner %d:%d, want %d:%d", maps, st.Uid, st.Gid, os.Getuid(), gid)
	}
}

// The flag accepts a GID with no group entry, which is how a service can name
// a group it doesn't need to look up.
func TestLookupGroupNumeric(t *testing.T) {
	if gid, err := lookupGroup(""); err != nil || gid != -1 {
		t.Fatalf("empty group: %d, %v", gid, err)
	}
	const want = 424242
	if gid, err := lookupGroup(strconv.Itoa(want)); err != nil || gid != want {
		t.Fatalf("numeric group: %d, %v", gid, err)
	}
	if _, err := lookupGroup("socketowner-no-such-group"); err == nil {
		t.Fatal("accepted a missing group name")
	}
}

func TestSeedWithRetries(t *testing.T) {
	t.Run("no busy", func(t *testing.T) {
		calls := 0
		var sleeps []time.Duration
		err := seedWithRetries(seedMaxAttempts, func() (uint64, error) {
			calls++
			return 0, nil
		}, func(d time.Duration) { sleeps = append(sleeps, d) })
		if err != nil || calls != 1 || len(sleeps) != 0 {
			t.Fatalf("calls %d, sleeps %v, err %v", calls, sleeps, err)
		}
	})
	t.Run("transient busy", func(t *testing.T) {
		busy := []uint64{3, 1, 0}
		calls := 0
		var sleeps []time.Duration
		err := seedWithRetries(seedMaxAttempts, func() (uint64, error) {
			calls++
			return busy[calls-1], nil
		}, func(d time.Duration) { sleeps = append(sleeps, d) })
		want := []time.Duration{seedRetryDelay, 2 * seedRetryDelay}
		if err != nil || calls != 3 || !slices.Equal(sleeps, want) {
			t.Fatalf("calls %d, sleeps %v, err %v; want 3 calls and %v", calls, sleeps, err, want)
		}
	})
	t.Run("persistent busy", func(t *testing.T) {
		calls := 0
		var sleeps []time.Duration
		err := seedWithRetries(seedMaxAttempts, func() (uint64, error) {
			calls++
			return 2, nil
		}, func(d time.Duration) { sleeps = append(sleeps, d) })
		if err != nil || calls != seedMaxAttempts || len(sleeps) != seedMaxAttempts-1 {
			t.Fatalf("calls %d, sleeps %v, err %v", calls, sleeps, err)
		}
	})
	t.Run("error", func(t *testing.T) {
		failure := errors.New("read failed")
		calls := 0
		var sleeps []time.Duration
		err := seedWithRetries(seedMaxAttempts, func() (uint64, error) {
			calls++
			return 0, failure
		}, func(d time.Duration) { sleeps = append(sleeps, d) })
		if !errors.Is(err, failure) || calls != 1 || len(sleeps) != 0 {
			t.Fatalf("calls %d, sleeps %v, err %v", calls, sleeps, err)
		}
	})
}

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
	if err := checkBPFLSMAt(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("accepted a missing LSM list")
	}
}

// Attach and detach share the maps directory with the Wine observer. Only the
// loader's own maps, including a temporary pin, may be removed.
func TestDetachKeepsWinePins(t *testing.T) {
	pin := t.TempDir()
	for _, dir := range []string{"links", "maps"} {
		if err := os.Mkdir(filepath.Join(pin, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	loader := []string{"links/sock_create", "maps/conn_owners", "maps/conn_cgroups", "maps/conn_flows", "maps/abi_version", "maps/exec_tasks", "maps/conn_owners-pin-12-1"}
	wine := []string{"maps/wine_flows", "maps/wine_heartbeat", "maps/wine_abi"}
	for _, path := range append(loader, wine...) {
		if err := os.WriteFile(filepath.Join(pin, path), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := detach(pin); err != nil {
		t.Fatal(err)
	}
	for _, path := range loader {
		if _, err := os.Stat(filepath.Join(pin, path)); !os.IsNotExist(err) {
			t.Errorf("%s left behind: %v", path, err)
		}
	}
	for _, path := range wine {
		if _, err := os.Stat(filepath.Join(pin, path)); err != nil {
			t.Errorf("removed another publisher's %s: %v", path, err)
		}
	}
}
