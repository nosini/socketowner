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
| `abi_version` | `BPF_MAP_TYPE_ARRAY` (2) | 4 | 4 | Required; one entry |
| `conn_owners` | `BPF_MAP_TYPE_LRU_HASH` (9) | 32 | 16 | Required |
| `exec_tasks` | `BPF_MAP_TYPE_TASK_STORAGE` (29) | 4 | 1048 | With `-exec-paths` |
| `exec_recent` | `BPF_MAP_TYPE_LRU_HASH` (9) | 4 | 1048 | With `-exec-paths` |

The `abi_version` entry at native-endian uint32 key 0 is native-endian uint32
value 1. The loader freezes this map before pinning it. Readers must reject a
missing marker or an unsupported version before interpreting connection records.
They must also check the type, key size and value size of every map before
performing any lookup; a larger kernel value would overflow a smaller userspace
buffer. Open maps with `BPF_F_RDONLY` and close-on-exec descriptors.

Attach replaces previous links and pins in the same directories. Optional maps
and the version marker are pinned before `conn_owners`, which is the publication
point. Each pin appears under its documented name only with its final owner and
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
The key does not distinguish remote destinations. Entries outlive closed sockets
and are evicted by LRU; active flows republish after eviction. A TCP or UDP
socket without a recorded owner, such as one from before attachment or an
accepted socket, publishes an unknown owner (TGID 0), so a stale entry for the
same address and port is never taken for its own. Repeated observations of the
same TGID retain its first timestamp and UID, even if the process changes UID
later.

A kernel-generated packet, such as a reset or acknowledgement sent from the
kernel's control socket rather than by a userspace socket, changes nothing: it
neither publishes nor replaces an owner, and it does not remove a Wine record
(see [Wine pins](#wine-pins)). MPTCP subflows are kernel-created TCP sockets
with no recorded owner, so MPTCP connections are reported as unknown.

Without the exec maps, a reader resolves the owner through `/proc`. The owner was
running when `boot_ns` was recorded, so a `/proc/<pid>/stat` start time later than
`boot_ns` (field 22, in `USER_HZ` ticks since boot, allowing for tick resolution)
names a different process; such a reader must not use that process's executable.

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
match the old record; when the old task is finally freed, that hook can
overwrite the new process's `exec_recent` entry with the old record and a later
`exit_ns`. A socket's owner record also keeps the timestamp and UID it first
recorded for a TGID: a socket that outlives its owner and is then used by a new
process with that ID keeps the old `boot_ns`, so the old record still matches.
The UID is the owner's at `boot_ns`, not after a later setuid. A fork that fails
after its ID is allocated may still run the task-free hook, leaving an entry for
a process that never ran.

Scripts name the interpreter, like `/proc/<pid>/exe`. A path can end in
` (deleted)` when the executable has been unlinked; seeded records of such
processes carry it. Records made by the exec hook resolve against the executing
process's root and mount context, so a chrooted process records its in-chroot
path. Seeded records are written by the iterator in the loader's context and are
relative to the loader's root and mount namespace instead. Neither needs to name
an accessible file in the reader's namespace.

## Wine pins

An optional Wine observer publishes three more pins in the same `maps/`
directory: `wine_abi`, `wine_heartbeat` and `wine_flows`. They have their own
version, currently 2, and come and go with the observer rather than with this
loader; their presence does not change ABI v1 records. `wine_flows` is keyed by
the connection key above and is the publication point for the trio. It is
written by BPF from raw client memory without validation, so every reader must
validate an image before using it as a name. See
[the Wine observer](../wine/README.md) for their layouts, statuses, heartbeat
rule and validation.

## Evolution

Changes to names, layouts, byte order or record meaning require a new ABI version.
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
