package main

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
)

// See docs/map-interface.md. Breaking changes require a new ABI version and
// a separate pin directory so readers cannot mix maps from different ABIs.
const (
	abiVersion    uint32 = 1
	abiVersionMap        = "abi_version"
)

// Optional features of ABI v1, advertised at key 1 of the version map. A
// loader that predates the key has none of them, and a reader finds the key
// missing.
const (
	// conn_cgroups holds the owner's cgroup for each conn_owners key.
	abiFeatureConnCgroups uint32 = 1 << 0
	// cgroup_paths names those cgroups; recorded with -exec-paths.
	abiFeatureCgroupPaths uint32 = 1 << 1
	// conn_flows holds owners and cgroups keyed by source and destination.
	abiFeatureConnFlows uint32 = 1 << 2
)

// abiFeatures returns the features a loader with or without -exec-paths
// publishes.
func abiFeatures(execPaths bool) uint32 {
	features := abiFeatureConnCgroups | abiFeatureConnFlows
	if execPaths {
		features |= abiFeatureCgroupPaths
	}
	return features
}

// validateMapABI checks the public maps before loading an embedded object.
// The loader must only advertise the ABI its objects actually implement.
func validateMapABI(spec *ebpf.CollectionSpec, execPaths bool) error {
	type mapLayout struct {
		typ        ebpf.MapType
		key, value uint32
	}
	want := map[string]mapLayout{
		mapName:       {ebpf.LRUHash, 32, 16},
		cgroupMapName: {ebpf.LRUHash, 32, 24},
		flowMapName:   {ebpf.LRUHash, 48, 24},
	}
	if execPaths {
		want = map[string]mapLayout{
			"exec_tasks":   {ebpf.TaskStorage, 4, 1048},
			"exec_recent":  {ebpf.LRUHash, 4, 1048},
			cgroupPathsMap: {ebpf.LRUHash, 8, 1032},
		}
	}
	for name, w := range want {
		m := spec.Maps[name]
		if m == nil || m.Type != w.typ || m.KeySize != w.key || m.ValueSize != w.value {
			return fmt.Errorf("socketowner ABI v%d: incompatible map %s: %+v", abiVersion, name, m)
		}
	}
	return nil
}

// pinABIVersion publishes a frozen marker before conn_owners becomes visible:
// the version at key 0 and the optional features at key 1. Freeze prevents
// userspace from changing the advertised ABI after attach.
func pinABIVersion(path string, features uint32, gid int) error {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       abiVersionMap,
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 2,
		Contents: []ebpf.MapKV{
			{Key: uint32(0), Value: abiVersion},
			{Key: uint32(1), Value: features},
		},
	})
	if err != nil {
		return err
	}
	defer m.Close()
	if err := m.Freeze(); err != nil {
		return err
	}
	return pinMap(m, filepath.Dir(path), filepath.Base(path), 0o440, gid)
}
