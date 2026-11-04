# Observe Windows socket creators from the host

This optional command names the Windows program behind each outgoing TCP/UDP
socket of every wineserver on the machine, for as long as it runs. It prints JSON
diagnostics, and with `-pin` publishes the identities for mihomo's `WINE-PROCESS-NAME`
and `WINE-PROCESS-PATH` rules, through each sandbox's pasta.

It needs no Wine or pasta patch, injected DLL, uprobe, TLS adapter or sandbox
capability, and no per-build profile. It is told nothing about Wine: wineservers
and their pastas are found as they appear, so it only has to be running before a
game starts.

The observer is an optional feature available on `main`. It has been validated
with real Wine clients, pasta and mihomo, including its confined systemd service;
see [validation](#validation) and [known limitations](#known-limitations). It leaves
native socketowner maps unchanged. Do not use the diagnostic event stream as a
routing authority: readers use the pinned [routing maps](#routing-maps).

## Build and run

The ordinary socketowner command and its installation are unchanged. Build this
command explicitly, on Linux amd64:

```sh
CGO_ENABLED=0 go build -o socketowner-wine-observer ./wine/cmd/socketowner-wine-observer
sudo ./socketowner-wine-observer -pin /sys/fs/bpf/mihomo/maps -reader-group mihomo
```

Without `-pin` it only prints diagnostics. `-sends` also reports send attempts,
including the Linux process performing each send. `-cgroup` selects the cgroup v2
ancestor used for egress observation; its default is `/sys/fs/cgroup`. Select an
ancestor covering Wine and pasta. Stop it with Ctrl-C. Nothing stays attached
after it exits or crashes. Pins are removed on exit; a crash leaves them until the
next publisher.

The observer needs host BPF/LSM and cgroup attachment privileges, and permission
to inspect other processes' file descriptors to find pasta, so `CAP_SYS_PTRACE`
in addition to `CAP_BPF`, `CAP_PERFMON` and `CAP_NET_ADMIN`. Root in the test VM
supplies these rights. The optional service and SELinux policy live in
[hardened-proxy-service](https://github.com/nosini/hardened-proxy-service), not in
this repository. The command sends systemd readiness after publishing its maps
when `NOTIFY_SOCKET` is set. Wine and games remain unprivileged.

A wineserver which predates the observer is picked up at its next request, but
sockets it already created stay unlabelled.

## What the events mean

`ready` and `stopped` bracket a run. `server` reports a wineserver in another
network namespace, and `pasta` the relay registered for it.

Each observation carries an unpredictable `observer` lifetime ID and a `socket_id`
unique within that lifetime. This ID is **not** Linux `SO_COOKIE`. Events include
the wineserver's host TGID and start time, and the client's host TGID and start
time, with the Windows PID and image where known.

`first-egress` adds the network namespace cookie and the packet's source and
destination addresses/ports, including any translation already applied when the
cgroup egress hook runs. TCP flags permit checking that the first observed packet
was the SYN. This event is emitted once per socket; later UDP peers are not a
complete flow table. Packet/header parsing is limited to TCP/UDP, IPv4 with options
and up to eight supported IPv6 extension headers; noninitial fragments and
unsupported protocols are omitted.

`relay` reports a pasta socket joined to its inner flow, or its unknown status.

The identity describes the **Windows socket creator**. It is immutable after
creation. A subsequent connect attempt, failed connect, or send through a
duplicated/inherited FD does not replace it with the requesting process. The
actual sending Linux TGID is a separate field. This is deliberately distinct from
native socketowner's latest-Linux-user semantics. Connect/send diagnostics describe
attempted operations, not successful completion.

A client whose name could not be read has status `no-image`, and a socket with no
known client `no-client`. Neither carries a partial name. Paths are limited to 1024
UTF-16 bytes; no truncated path becomes a matchable name.

The event buffer is bounded. Buffer exhaustion increments a reported `loss`
count, and a lost `server` event leaves that sandbox's pasta unregistered. Routing
records do not pass through this buffer.

## How capture works

wineserver creates and connects Windows programs' sockets, so kernel hooks see
only wineserver. Which program asked is recoverable from Wine's request protocol:

1. Each client thread has a request pipe. wineserver's read from a FIFO marks it,
   and the next write by another process names that pipe's client
   (`lsm/file_permission`).
2. Each later read records the client being served. wineserver is single-threaded
   and handles a request within the read which fetched it, so the sockets which
   follow are that client's (`lsm/socket_post_create`).
3. The client names itself, read during its own write, while its memory is
   current. For 64-bit clients, GS holds the TEB, confirmed by `TEB.Self`, and
   `Peb`, `ProcessParameters` and `ImagePathName` lead to the full path. These are
   public Windows x86-64 layouts, not Wine's.
4. 32-bit programs run as true 32-bit Linux processes on the tested runners, so
   GS is glibc's TLS and that check fails. They fall back to the first mapped file
   named `*.exe`, which gives the name but not the path, and no Windows PID.

Client records carry the process's start time and are dropped on exec, so a reused
PID can't inherit a name. A failed read is retried on the client's next request.

The record is published before socket creation returns to userspace, and remains
immutable in socket storage. Connect/send/egress hooks use that record instead of
traversing an FD table or reconstructing an earlier request.

wineserver is recognised by its process name. This supports cooperative Wine
applications, not a security claim. A malicious process can rename itself, rewrite
its own PEB, map a misleading file, or ask another program to do its networking.
The cost: FIFO reads and writes system-wide pay about 130 ns per round trip, which
was 37% in a benchmark doing nothing else.

## Routing maps

`-pin DIR`, normally socketowner's `maps` directory, adds three optional pins
beside its ABI v1 maps. V1 records are unchanged, so no v1 version change applies.
These have their own version, currently 2, and their pins come and go with the
observer:

| Pin | Linux map type | Key bytes | Value bytes | Meaning |
| --- | --- | ---: | ---: | --- |
| `wine_abi` | `ARRAY` (2) | 4 | 4 | Frozen; key 0 holds the version |
| `wine_heartbeat` | `ARRAY` (2) | 4 | 8 | Key 0 holds `CLOCK_BOOTTIME` nanoseconds, updated every second |
| `wine_flows` | `LRU_HASH` (9) | 32 | 1088 | Identity by outgoing packet source |

`wine_flows` is pinned last and is the publication point. Its key is the v1
connection key. All integers are native endian. The value is:

| Byte offset | Type | Meaning |
| ---: | --- | --- |
| 0 | uint64 | Socket ID, unique within one observer lifetime; not `SO_COOKIE` |
| 8 | uint64 | wineserver start, `CLOCK_BOOTTIME` nanoseconds |
| 16 | uint64 | Client start, `CLOCK_BOOTTIME` nanoseconds |
| 24 | uint64 | `CLOCK_BOOTTIME` nanoseconds at capture |
| 32 | uint32 | wineserver host TGID |
| 36 | uint32 | UID of the capturing process |
| 40 | uint32 | Windows PID, or 0 if unavailable |
| 44 | uint32 | Client host TGID |
| 48 | uint32 | Status; only 1 names a program |
| 52 | uint32 | Image length in bytes |
| 56 | uint32 | IP protocol |
| 60 | uint32 | Image encoding |
| 64 | uint16[512] | Image, not NUL terminated |

Encoding 0 is a full Windows path in UTF-16. Encoding 1 is a filename in bytes,
with no directory. Readers must reject other values.

Status 1 is known. 2 means no client was known, 3 that its name could not be read,
6 that owners differed while waiting for pasta, 7 that pasta's socket matched no
inner flow, and 8 that the inner flow came from a socket with no Windows identity.

The kernel writes a record before the packet it describes leaves `wine_egress`,
so it precedes mihomo's first lookup; it does not depend on the event buffer.
An unlabelled socket which sends from a recorded address and port removes the
record. Active flows republish after LRU eviction. A reader must:

1. Check the version, map types and sizes before any lookup, as for v1.
2. Consult `wine_flows` first. No record means ordinary lookup proceeds.
3. Treat a record with another status, a heartbeat older than five seconds, or an
   image failing validation as **unknown**, not as absent. Falling through would
   name the relay, or whichever process now holds a reused port.

mihomo keeps the socket's own process, the sandbox's pasta, and reports the
Windows program separately, as `wine-unknown` when unknown, so that a deny can be
written for it:

```yaml
rules:
  - WINE-PROCESS-NAME,tbs_browser.exe,REJECT
  - WINE-PROCESS-NAME,wine-unknown,REJECT
```

A crash leaves the pins, which a new publisher replaces once the heartbeat has
expired. While no observer runs, new flows have no record and show only as pasta.
A rule for the sandbox's pasta name can decide what those may do; it also matches
the sandbox's identified flows, so place it after rules for its programs.
`WINE-PROCESS-PATH` rules can't match a 32-bit client's full path, because it
isn't known.

## How the relay works

pasta opens a host socket for each flow it reads from its TAP, so mihomo sees
pasta, with a TCP source port unrelated to the inner one. pasta can't be asked
which flow a socket serves, but the kernel sees both sides in order:

1. `wine_egress` sees each new inner flow in the sandbox's namespace before it
   can reach the TAP, and records its owner in `relay_flows`. That includes
   flows from unlabelled sockets.
2. pasta connects its replacement socket from its one socket-handling thread.
   `lsm/socket_connect` finds the record and copies the identity to that socket.
3. `wine_egress` then publishes it under the host packet's actual source.

UDP's key includes the source port, which pasta preserves, so it is exact and
covers each peer of an unconnected socket. A TCP replacement socket can't see the
inner port, so concurrent flows to one destination share a record. If they share
an owner the result is the same whichever connect comes first. If not, all of
them are ambiguous and stay unknown: waiting flows are never paired by arrival
order. Records older than two seconds are ignored.

A wineserver's first request tells BPF its network namespace, and from then on
flows there are recorded, before any of its programs can have sent one. The
observer then looks for the sandbox's pasta: a process outside that namespace,
holding a descriptor for it, whose executable name contains `pasta`. Registration
is keyed by pidfd and revoked on exec. No pasta memory is read, so its updates
don't matter. A flow pasta connects before that registration has no record, and
shows as pasta; this did not occur in testing, but nothing prevents it.

The relay inherits the capture's trust limit, and a sandboxed program can provoke
unknown results by racing another program to one destination.

## Validation

[Always-on validation](validation/always-on/README.md) covers this design, with
real pasta, mihomo, nftables and `sandbox-game`. [NIKKE's launcher](validation/nikke/README.md) was observed on the desktop, without
routing. Earlier reports are history: the
[first observer](validation/README.md), [routing](validation/routing/README.md),
[sandbox](validation/sandbox/README.md) and
[prototype](research/generic-capture/README.md) records describe superseded
capture or attachment. The [research](research/README.md) explains the design.

Regenerate the embedded object after a BPF change using clang/llvm and libbpf
headers, then rebuild:

```sh
go generate ./wine
go test ./...
```

Privileged tests belong in the dedicated test VM, and run as the ordinary user;
only the observer, mihomo and test firewall rules use sudo:

```sh
python3 wine/testdata/real-wine.py --runner /path/to/runner/bin --observer /absolute/path/socketowner-wine-observer --work /absolute/task/real-wine
python3 wine/testdata/pasta-route.py --runner /path/to/runner/bin --observer /absolute/path/socketowner-wine-observer --mihomo /absolute/path/mihomo --work /absolute/task/route
python3 wine/testdata/sandbox-route.py --sandbox /path/to/run-in-sandbox --runner /path/to/runner/bin --observer /absolute/path/socketowner-wine-observer --mihomo /absolute/path/mihomo --work /absolute/task/sandbox
```

`pasta-route.py --control` repeats its run without the relay, where no rule may see
a Windows name. `sandbox-route.py --bits 32` uses 32-bit probes. Add `--observer-service` to
exercise the installed systemd observer (restarts it and leaves it running),
including its SELinux domain and shared routing maps. Probes need Wine's
`winegcc` or mingw.

## Known limitations

- **Removed tests.** The fixture VM tests modelled wineserver's memory, which is no
  longer read. Exec revocation, nested PID namespaces with no capabilities, FD reuse
  and failed connects on the new capture have only incidental coverage.
- **Untested:** new-style WOW64, IPv6 through the relay, and load. Native per-packet cost is measured in the
  [service validation](validation/service/README.md); Wine relay load remains untested.
- **A multi-threaded wineserver** would break step 2 of capture. None exists among
  the tested runners; the design has no detection for one yet.
- **DNS.** Flows sent to pasta's `--dns-forward` address are translated, so they
  find no inner record and are unknown, [as seen in NIKKE](validation/nikke/README.md).
  A rule refusing `wine-unknown` must exempt any it reaches.
- **UDP reuse.** A new inner socket reusing a live UDP 4-tuple inherits pasta's
  existing flow, and with it the previous owner until that flow expires.
