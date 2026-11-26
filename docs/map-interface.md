# Pinned map interface, version 1

This is the contract between independently released socketowner loaders and
readers. It covers pinned names, map types, field offsets, byte order and record
meaning. Loader and reader release numbers are independent of this ABI version.

## Discovery and lifetime

Under the loader's `-pin` directory (default `/sys/fs/bpf/mihomo`), public maps
live in `maps/` and private BPF links in `links/`. A reader is given only `maps/`,
usually through a read-only directory bind mount. Pins remain owned by the loader
(root in the service setup); the reader group gets directory mode 0750 and map
mode 0440. Owning a pin would let a reader grant itself write access.

| Pin in `maps/` | Linux map type | Key bytes | Value bytes | Availability |
| --- | --- | ---: | ---: | --- |
| `abi_version` | `BPF_MAP_TYPE_ARRAY` (2) | 4 | 4 | Required; one or two entries |
| `conn_owners` | `BPF_MAP_TYPE_LRU_HASH` (9) | 32 | 16 | Required |
| `conn_cgroups` | `BPF_MAP_TYPE_LRU_HASH` (9) | 32 | 24 | With feature bit 0 |
| `conn_flows` | `BPF_MAP_TYPE_LRU_HASH` (9) | 48 | 24 | With feature bit 2 |
| `exec_tasks` | `BPF_MAP_TYPE_TASK_STORAGE` (29) | 4 | 1048 | With `-exec-paths` |
| `exec_recent` | `BPF_MAP_TYPE_LRU_HASH` (9) | 4 | 1048 | With `-exec-paths` |
| `cgroup_paths` | `BPF_MAP_TYPE_LRU_HASH` (9) | 8 | 1032 | With feature bit 1 (`-exec-paths`) |

The `abi_version` entry at native-endian uint32 key 0 is native-endian uint32
value 1. Key 1, when present, holds a native-endian uint32 bitmask of optional
features: bit 0 means `conn_cgroups` is published, bit 1 that `cgroup_paths` is
(only with `-exec-paths`), and bit 2 that `conn_flows` is. Loaders that predate the
feature mask have only key 0, and a lookup of key 1 fails; treat that as no
features. Readers must ignore feature bits they don't know. The loader freezes
this map before pinning it. Readers must reject a
missing marker or an unsupported version before interpreting connection records.
They must also check the type, key size and value size of every map before
performing any lookup; a larger kernel value would overflow a smaller userspace
buffer. Open maps with `BPF_F_RDONLY` and close-on-exec descriptors.

Attach replaces previous links and pins in the same directories. Optional maps,
`conn_cgroups`, `conn_flows` and the version marker are pinned before `conn_owners`, which is
the publication point. Each pin appears under its documented name only with its final owner and
mode, so a reader that opens one of these paths never finds it unreadable.
Readers should reopen all maps when that pin's inode changes and retry
unavailable optional maps. Detach removes the loader's pins but keeps the
directories, and leaves the optional Wine observer's pins in place. If attaching
fails after it has attached programs, the loader detaches, so a failed run
leaves no partial attachment. Previously opened map descriptors remain valid, so
readers must notice pin removal and replacement rather than retaining old maps
indefinitely. Replacement is not atomic and may briefly leave lookup
unavailable.

Private socket storage, scratch maps and program/link names are implementation
details. Map capacities are not part of the ABI. This interface describes the
initial PID and user namespaces and the network namespaces where the programs
are attached. Readers in a separate PID namespace cannot resolve a recorded host
TGID through `/proc` or a pidfd: those name their own namespace's processes. In
particular, such a reader must not use `exec_tasks`, whose key is a pidfd it
would open for the recorded number. That pidfd either names an unrelated local
process, whose record passes the ownership interval below if it started before
the owner was recorded, or cannot be opened because no local process has that
number. `exec_recent` is keyed by the recorded host TGID and needs no local
process: it can name a process that executed, first used a tracked socket, or
was freed after the loader attached. A process that has done none of these since
the loader attached, such as one already running at attach, is only in
`exec_tasks`.

All timestamps in these maps are host `CLOCK_BOOTTIME`; a reader in a time
namespace must apply that namespace's offset before comparing them with its own
clock. UIDs are initial-user-namespace values, not values in the reader's user
namespace.

## Connection records

All integers are native endian; address bytes use network order. A connection key
is exactly 32 bytes:

| Byte offset | Type | Meaning |
| ---: | --- | --- |
| 0 | uint64 | Network namespace cookie (`SO_NETNS_COOKIE`) |
| 8 | byte[16] | Source IP; IPv4 uses IPv4-mapped IPv6 (`::ffff:a.b.c.d`) |
| 24 | uint16 | Source port, host byte order |
| 26 | uint8 | IP protocol: 6 for TCP, 17 for UDP |
| 27 | byte[5] | Zero padding |

A connection value is exactly 16 bytes:

| Byte offset | Type | Meaning |
| ---: | --- | --- |
| 0 | uint32 | Owner TGID (process ID); 0 means unknown |
| 4 | uint32 | Owner UID, in the initial user namespace |
| 8 | uint64 | Host `CLOCK_BOOTTIME` nanoseconds when that owner was recorded |

The owner is the process that creates, connects or sends on the socket. With
`-exec-paths`, LSM hooks also see sends on connected sockets; without it, passing
an already connected socket may leave the earlier owner recorded. The egress hook
publishes the current owner against the outgoing packet's source address/port.
The key does not distinguish remote destinations: `connect()` lets sockets with
different peers share a local address and port, and the entry then holds
whichever of them sent last. [Flow records](#flow-records) tell them apart. Entries outlive closed sockets
and are evicted by LRU; active flows republish after eviction. A TCP or UDP
socket without a recorded owner, such as one from before attachment or an
accepted socket, publishes an unknown owner (TGID 0) without `-exec-paths` and
before its first send, so a stale entry for the same address and port is never
taken for its own. With `-exec-paths`, `lsm/socket_sendmsg` records the sending
process as the owner on the first send. Repeated observations of the same TGID
retain its first timestamp and UID, even if the process changes UID later.

A kernel-generated packet, such as a reset or acknowledgement sent from the
kernel's control socket rather than by a userspace socket, changes nothing: it
neither publishes nor replaces an owner, and it does not remove a Wine record
(see [Wine pins](#wine-pins)). MPTCP subflows are kernel-created TCP sockets
with no recorded owner, so MPTCP connections are reported as unknown.

Without the exec maps, a reader resolves the owner through `/proc`. The owner was
running when `boot_ns` was recorded, so a `/proc/<pid>/stat` start time later than
`boot_ns` (field 22, in `USER_HZ` ticks since boot, allowing for tick resolution)
names a different process; such a reader must not use that process's executable.

## Flow records

When feature bit 2 is set, `conn_flows` publishes the owner and its cgroup keyed
by both ends of the outgoing packet. Its key is 48 bytes:

| Byte offset | Type | Meaning |
| ---: | --- | --- |
| 0 | uint64 | Network namespace cookie (`SO_NETNS_COOKIE`) |
| 8 | byte[16] | Source IP; IPv4 uses IPv4-mapped IPv6 |
| 24 | byte[16] | Destination IP; IPv4 uses IPv4-mapped IPv6 |
| 40 | uint16 | Source port, host byte order |
| 42 | uint16 | Destination port, host byte order |
| 44 | uint8 | IP protocol: 6 for TCP, 17 for UDP |
| 45 | byte[3] | Zero padding |

Its value is 24 bytes:

| Byte offset | Type | Meaning |
| ---: | --- | --- |
| 0 | uint32 | Owner TGID; 0 means unknown |
| 4 | uint32 | Owner UID, in the initial user namespace |
| 8 | uint64 | `boot_ns`, as in `conn_owners` |
| 16 | uint64 | cgroup v2 ID of the owner, or 0; as in `conn_cgroups`, 0 when the TGID is 0 |

The egress hook writes it with `conn_owners` and `conn_cgroups`, under the same
rules, so the owner fields equal what `conn_owners` holds for a socket that was
the last to send from its address and port. Owner and cgroup are one record, so
unlike `conn_cgroups` no match against `conn_owners` is needed.

Addresses and ports are the packet's as it leaves the egress hook, after
netfilter's output and postrouting translation. A flow redirected to a local
listener (`redirect`, as TUN `auto-redirect` does) is keyed by that listener's
address and port, not by its original destination; a reader should look up the
listener's address and port rather than the original destination. An unconnected
UDP socket gets a record for every destination it sends to.

Readers should prefer `conn_flows` when they know the flow's destination, and
fall back to `conn_owners` when it has no record, as for flows sent before the
loader attached or evicted since. A miss there doesn't mean the owner is
unknown.

## Owner cgroups

When feature bit 0 is set, `conn_cgroups` uses the connection key above and a
24-byte value:

| Byte offset | Type | Meaning |
| ---: | --- | --- |
| 0 | uint32 | Owner TGID this record belongs to; 0 means unknown |
| 4 | uint32 | Zero padding |
| 8 | uint64 | That owner's `boot_ns`, as in `conn_owners` |
| 16 | uint64 | cgroup v2 ID of the owner when it was last recorded, or 0 |

The egress hook publishes it together with `conn_owners`, under the same rules:
kernel-generated packets change nothing, and a socket without a recorded owner
publishes an all-zero record. The cgroup is the default-hierarchy cgroup of the
process at the moment it last created, connected or sent on the socket (sends on
connected sockets only with `-exec-paths`), so a process that moves to another
cgroup is seen in the new one from its next such call on.

The two maps are evicted independently and are updated one after the other, so
a reader must look up `conn_owners` first and use the cgroup record only if its
TGID and `boot_ns` equal those of the owner record. Any other combination,
including a missing cgroup record or a TGID of 0, means the cgroup is unknown;
it is never the cgroup of a different owner.

A cgroup v2 ID is the inode number of the cgroup's directory in cgroupfs on
64-bit kernels; IDs are not reused while the system runs. With feature bit 1,
`cgroup_paths` names them. Otherwise a reader has to resolve IDs through
cgroupfs itself: a cgroup removed before the lookup can't be resolved then,
and a reader in a separate cgroup namespace, or one that doesn't see the host's
cgroupfs, can't resolve IDs outside its view.

`cgroup_paths` is keyed by the native-endian uint64 cgroup ID. Its value:

| Byte offset | Type | Meaning |
| ---: | --- | --- |
| 0 | int32 | Path byte length including NUL (2 to 1024), or negative errno |
| 4 | uint32 | Zero padding |
| 8 | byte[1024] | Path bytes; meaningful only up to the length |

The path is relative to the cgroup v2 root and starts with `/`, such as
`/user.slice/user-1000.slice/session-2.scope`; the root cgroup is `/`. Names
appear as in cgroupfs, including systemd's `\x2d`-style escapes. A path longer
than 1024 bytes or more than 32 levels deep is recorded with length
`-ENAMETOOLONG` (-36); ignore the path bytes then. As with executable paths, use
the length and never scan for the NUL.

The LSM socket hooks check `cgroup_paths` on every connect and send, saving the
path of the socket user's cgroup whenever its ID is missing from the map. An
entry is never rewritten, so it describes the cgroup when it was first seen; a
cgroup renamed later keeps its old path. Entries outlive the cgroup and are
evicted by LRU; looking up the map on every send keeps active cgroups recently
used and repopulates an evicted entry on the next send or connect. Treat a
missing entry as unknown.

cgroups are attribution, not authentication. A process can create cgroups in
any subtree delegated to it, such as its systemd user manager's, give them any
name and move itself into them. Treat a cgroup name like a process name: good
enough to route a cooperative application, not a security boundary.

## Executable records

Both executable maps use the same 1048-byte value:

| Byte offset | Type | Meaning |
| ---: | --- | --- |
| 0 | uint64 | Process start time, `CLOCK_BOOTTIME` nanoseconds |
| 8 | uint64 | Time the task was freed in the same clock, or 0 while not freed |
| 16 | int32 | Path byte length including NUL (2 to 1024), or negative errno |
| 20 | uint32 | Zero padding |
| 24 | byte[1024] | Path bytes; meaningful only up to `Len` |

`exec_tasks` is keyed by an int32 pidfd opened by the reader for the recorded
TGID. `exec_recent` is keyed by uint32 TGID and retains the most recent record,
including processes that have exited. Its entries are published at exec, first
socket use by an owner, and task-free; the latter can occur after reaping. Forked
processes inherit the parent's executable. An iterator seeds existing processes
when the loader attaches, into `exec_tasks` only.

Use `Len` and never scan for the NUL. On success `bpf_d_path` returns the length
including the NUL, which is 2 through 1024 here; the loader never writes 0 or 1,
and a reader must treat those as invalid. The bytes after the NUL are not
necessarily zero and can hold leftovers from an earlier write, so a NUL scan can
run past the path. When `Len` is negative, `Path` is undefined: a seeded record
holds the previous seeded process's path, because the iterator reuses one scratch
record. Ignore `Path` then and report the record as having no executable.

A record belongs to an owner only if `start_ns <= owner.boot_ns` and either
`exit_ns == 0` or `exit_ns >= owner.boot_ns`. Check task storage first and then
history. This narrows, but does not remove, PID reuse. `exit_ns` is when the task
was freed, after it was reaped, so a process that reuses the ID in between can
match the old record; the task-free hook stamps `exit_ns` before updating
`exec_recent` and skips the update when an entry with a later `start_ns` is
already present, though a concurrent update by a newly reused PID can still race
with it. A socket's owner record also keeps the timestamp and UID it first
recorded for a TGID: a socket that outlives its owner and is then used by a new
process with that ID keeps the old `boot_ns`, so the old record still matches.
The UID is the owner's at `boot_ns`, not after a later setuid. Calling `execve`
after sending on a socket keeps the same TGID and `start_ns` while overwriting
`exec_tasks` and `exec_recent` with the new program, so a pre-exec flow still
being resolved is attributed to the post-exec binary, matching `/proc/<pid>/exe`.
A fork that fails after its ID is allocated may still run the task-free hook,
leaving an entry for a process that never ran.

Scripts name the interpreter, like `/proc/<pid>/exe`. A path can end in
` (deleted)` when the executable has been unlinked; seeded records of such
processes carry it. Records made by the exec hook resolve against the executing
process's root and mount context, so a chrooted process records its in-chroot
path. Seeded records are written by the iterator in the loader's context and are
relative to the loader's root and mount namespace instead. Neither needs to name
an accessible file in the reader's namespace.

## Wine pins

An optional Wine observer publishes four more pins in the same `maps/`
directory: `wine_abi`, `wine_heartbeat`, `wine_peer_flows` and `wine_flows`.
They have their own version, currently 2, and come and go with the observer
rather than with this loader; their presence does not change ABI v1 records.
`wine_abi` key 1 advertises `wine_peer_flows` with feature bit 0; that map is
keyed by the flow key above. `wine_flows` is keyed by the connection key above
and is pinned last as the publication point. It is written by BPF from raw
client memory without validation, so every reader must validate an image before
using it as a name. See [the Wine observer](../wine/README.md) for their
layouts, statuses, heartbeat rule and validation.

## Evolution

Changes to names, layouts, byte order or record meaning require a new ABI version.
An optional map that keeps every v1 guarantee is added with a new feature bit at
key 1 of `abi_version` instead, as `conn_cgroups` and `conn_flows` were.
A breaking version must also use a separate pin directory so a reader cannot mix
old and new maps during replacement. Keep old ABI support explicitly if needed;
never silently reinterpret v1 records. Extra private maps or optional features
that preserve all v1 guarantees do not require a version change.

Loaders before v1 used the same record layouts but had no version marker.
Updated readers require this loader's marker; update the loader first. Readers
that predate version checks can continue to consume this loader's unchanged v1
record maps.

The Wine pins evolve under their own version; see
[the Wine observer](../wine/README.md).
