# Observe Windows socket creators from the host

This optional command names the Windows program behind each outgoing TCP/UDP
socket created by wineserver or by a Wine client's own Linux process, for as
long as it runs. It prints JSON
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
ancestor covering Wine and pasta. `-reader-group` takes a group name or a numeric
GID; a GID needs no group entry. SIGINT (Ctrl-C), SIGTERM, SIGHUP and SIGPIPE
stop it and remove its pins. Nothing stays attached after it exits or crashes.
Pins are removed on exit; a crash leaves them until the next publisher.

The observer needs host BPF/LSM and cgroup attachment privileges, and permission
to inspect other processes' file descriptors to find pasta, so `CAP_SYS_PTRACE`
in addition to `CAP_BPF`, `CAP_PERFMON` and `CAP_NET_ADMIN`. Root in the test VM
supplies these rights. The optional service and SELinux policy live in
[hardened-proxy-service](https://github.com/nosini/hardened-proxy-service), not in
this repository. The command sends systemd readiness after publishing its maps
when `NOTIFY_SOCKET` is set. It refuses to start unless `bpf` appears in
`/sys/kernel/security/lsm`, because its LSM hooks would otherwise attach without
recording anything. Wine and games remain unprivileged.

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

A socket's events carry a `creator`: `wineserver` for a socket wineserver made
for the program, `client` for one the program's own Linux process made. A relay
event describes a pasta socket, which has no creator.

A client whose name could not be read has status `no-image`, and a socket with no
known client `no-client`. Neither carries a partial name. Images are limited to
1024 bytes; no truncated image becomes a matchable name.

The event buffer is bounded. Buffer exhaustion increments a reported `loss`
count, and a lost `server` event is retried rather than leaving that sandbox's
pasta unregistered. Routing records do not pass through this buffer.

## How capture works

wineserver creates and connects Windows programs' sockets, so kernel hooks see
wineserver for those. Which program asked is recoverable from Wine's request
protocol:

1. Each client thread has a request pipe. wineserver's read from a FIFO marks it,
   and the next write by another process names that pipe's client
   (`lsm/file_permission`). A pipe read for the first time names nobody until
   its client writes, so a socket created before then is `no-client`, not the
   client of an earlier request. The pipe's record also names the wineserver
   that read it.
2. Each later read records the client being served. wineserver is single-threaded
   and handles a request within the read which fetched it, so the sockets which
   follow are that client's (`lsm/socket_post_create`).
3. The client names itself, read during its own write, while its memory is
   current. For 64-bit clients, GS holds the TEB, confirmed by `TEB.Self`, and
   `Peb`, `ProcessParameters` and `ImagePathName` lead to the full path. These are
   public Windows x86-64 layouts, not Wine's. If the path can't be read yet, the
   client stays `no-image` and is retried on its next request; it does not fall
   back to a mapped name.
4. Under old-style WOW64, the default of a Wine with 32-bit Unix libraries,
   32-bit programs run as true 32-bit Linux processes, so GS is glibc's TLS and that check fails.
   Encoding 1 is used only for such a client: the first mapping by address
   whose Linux file name ends in `.exe`. That gives a file name but not the
   path, and no Windows PID. The first such mapping need not be the program's
   image, so the name can be wrong. Under new-style WOW64 (a `WINEARCH=wow64`
   prefix, or a Wine built with `--enable-archs=i386,x86_64`) a 32-bit program runs
   in a 64-bit Linux process whose GS holds the 64-bit TEB, so step 3 applies
   and it is named by full path, with its Windows PID.

A Windows program also opens sockets in its own Linux process: the glibc
resolver behind `getaddrinfo`, GStreamer, libldap. The same
`lsm/socket_post_create` finds their creator by process ID in the client
records, with the process's start time ruling out a reused ID, and labels them
with that client's identity: status, image, encoding, Windows PID, client TGID
and start time, and, in the fields which name a wineserver, the one that reads
the client's requests. A client whose wineserver is not known, possible only
when its pipe's record was evicted before its write, keeps its sockets
unlabelled rather than name itself as its own server. Every socket creation by
a process which is neither a wineserver nor a Wine client costs one map lookup
by process ID, and nothing else.

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
observer. Each pin appears under its final name with its final owner and mode.
The heartbeat runs independently of the diagnostic output, so a blocked or closed
stdout does not make live records stale. If its pins disappear, for example after
a `socketowner detach` from a loader that removed them, the observer publishes
them again. On exit it removes only pins that are still its own.

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

Encoding 0 is an absolute Windows path in UTF-16. Encoding 1 is one file name in
bytes, with no directory. Readers must reject other values.

The wineserver fields always name the client's wineserver, including for a
socket the client's own process created. The UID is the capturing process's,
so for such a socket it is the client's own.

An image is valid only under these rules. For encoding 0, `ImageBytes` is even
and 2 to 1024; the UTF-16 text has no U+0000 and no unpaired surrogate; after `/`
becomes `\` and a `\??\` or `\\?\` prefix is removed (with a following `UNC\`
becoming `\\`), it begins with a drive letter and `:\`, or with
`\\server\share\`; and its last component is neither empty nor `.` or `..`. For
encoding 1, `ImageBytes` is 1 to 1024, the bytes are valid UTF-8 with no NUL, `/`
or `\`, and the name is a single component, not `.` or `..`. A name from
encoding 1 is reported with no path, because no directory is known. `wine_flows`
is written by BPF from the client's raw memory and checks only the length it
copies, so every reader must apply these rules; an image that fails them is
unknown.

Status 1 is known. 2 means no client was known, 3 that its name could not be read,
6 that owners differed while waiting for pasta, 7 that pasta's socket matched no
inner flow, and 8 that the inner flow came from a socket with no Windows identity.
Any other status is invalid.

The kernel writes a record before the packet it describes leaves `wine_egress`,
so it precedes mihomo's first lookup; it does not depend on the event buffer.
An unlabelled userspace socket which sends from a recorded address and port
removes the record; a packet from the kernel's TCP control socket, such as a
generated reset or acknowledgement, changes nothing. Active flows republish
after LRU eviction. A reader must:

1. Check the version, map types and sizes before any lookup, as for v1.
2. Consult `wine_flows` first. No record means ordinary lookup proceeds.
3. Treat a record with another status, a heartbeat older than five seconds, or an
   image failing the validation above as **unknown**, not as absent. Falling
   through would name the relay, or whichever process now holds a reused port.

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
`WINE-PROCESS-PATH` rules can't match the full path of a 32-bit client under
old-style WOW64, because it isn't known.

### Evolution

Any change to the key or value layout, or to the meaning of a field, status value
or image encoding, requires a new `wine_abi` version; a reader must reject a
version it does not know before interpreting `wine_flows`. Version 1 had the same
sizes and offsets, but field 16 held the Windows process start time that
wineserver recorded, field 44 the client's Unix PID in wineserver's namespace,
field 60 was padding, and the image was always a UTF-16 Windows path. Its statuses
2 to 5 were capture failures. Version 2 replaced it before the mihomo reader was
released, and that reader has required 2 since it appeared.

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

pasta's `--dns-forward` translation rewrites one destination: a query sent to
the forward address leaves through a socket connected to the host's resolver
instead, so the inner record is keyed by that destination, which keeps the join
exact, with the source port pasta preserves and the shared-key rules above
unchanged. The observer learns the translation when it registers the pasta,
from its command line, and a family maps only when that line names both its
`--dns-forward` address and its `--dns-host` address: pasta's default
`--dns-host` comes from the resolv.conf of the environment it was started in,
but pasta isolates itself into an empty root before the observer can register
it, so that file can no longer be read. A pasta with `--dns-forward` but no
`--dns-host` gets no mapping; the observer reports the missing address once
for that pasta, and DNS to its forward address stays `wine-unknown`, so a
sandbox that wants its DNS joined starts pasta with `--dns-host`. Only
UDP and TCP to port 53 are translated, matching what pasta maps on the tested
versions; pasta also maps port 853 on some versions, and those flows stay
`wine-unknown`. Without `--dns-forward`, pasta maps its `--map-host-loopback`
or default gateway address, whose host nameserver no command line names, and
DNS in such sandboxes stays unknown. DNS sent to
an address pasta does not map keeps its own record and joins as any other
flow.

A wineserver's first request tells BPF its network namespace, and from then on
flows there are recorded, before any of its programs can have sent one. The
observer then looks for the sandbox's pasta: a process outside that namespace,
holding a descriptor for it, whose executable name contains `pasta`. A failed
lookup is logged and retried; it does not stop the observer. Registration is
keyed by pidfd and revoked on exec. A registered sandbox is checked again, so a
pasta that replaces the previous one, or that exec'd and lost its registration, is
registered again. No pasta memory is read,
so its updates don't matter. A flow pasta connects before that registration has
no record, and shows as pasta; this did not occur in testing, but nothing
prevents it.

The relay inherits the capture's trust limit, and a sandboxed program can provoke
unknown results by racing another program to one destination.

## Validation

[Always-on validation](validation/always-on/README.md) covers this design, with
real pasta, mihomo, nftables and `sandbox-game`. [Relay validation](validation/relay/README.md)
adds IPv6 through the relay, new-style WOW64 and relay load. [NIKKE's launcher](validation/nikke/README.md) was observed on the desktop, without
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
python3 wine/testdata/pasta-dns.py --observer /absolute/path/socketowner-wine-observer --work /absolute/task/dns
python3 wine/testdata/pasta-relay.py --runner /path/to/runner/bin --observer /absolute/path/socketowner-wine-observer --mihomo /absolute/path/mihomo --work /absolute/task/relay --family 6 --load
```

`pasta-route.py --control` repeats its run without the relay, where no rule may see
a Windows name. `sandbox-route.py --bits 32` uses 32-bit probes. Add `--observer-service` to
exercise the installed systemd observer (restarts it and leaves it running),
including its SELinux domain and shared routing maps. Probes need Wine's
`winegcc` or mingw. `real-wine.py` and `pasta-route.py` expect Winelib images
named `.exe`; Wine builds which report `.exe.so` fail their name checks.

`pasta-relay.py` uses mingw probes. `--family 6` relays IPv6 through a dummy
interface, `--bits 32 --wow64` runs 32-bit probes under new-style WOW64, and
`--load` adds two load phases: programs with separate destinations, where every
flow must be named after its program, and one shared destination, where a flow
may be unknown but never named after another program. Each program's rule leads
to its own SOCKS outbound, which checks the tag the connection carries.
`--baseline` repeats the first load phase without the observer, for timing.

The wine package's own privileged tests need no Wine at all: a helper process
named `wineserver` reads a FIFO, a client helper writes it with a fake Windows
identity at its GS base, and their sockets, a plain process's and a forked
child's, are asserted against the events and `wine_flows`.

## Known limitations

- **Removed tests.** The fixture VM tests modelled wineserver's memory, which is no
  longer read. Exec revocation, nested PID namespaces with no capabilities, FD reuse
  and failed connects on the new capture have only incidental coverage.
- **Per-packet cost.** Native per-packet cost is measured in the
  [service validation](validation/service/README.md). Relay load showed no
  throughput difference with the observer, but the test's own servers limit it;
  `wine_egress` alone is not measured.
- **A multi-threaded wineserver** would break step 2 of capture. None exists among
  the tested runners; the design has no detection for one yet.
- **Sockets the client opens itself.** These are labelled with the client's
  identity, like wineserver's sockets for it, and reach mihomo the same two
  ways. Still not covered: a client that hands lookups to another process, for
  example over `systemd-resolved`'s or nscd's Unix socket, names that process,
  which is not a Wine client; a forked child of a client which never wrote a
  request of its own has its own process ID and stays unlabelled; a socket
  created before the client's first request names nobody, because no client
  record exists yet; and a client whose pipe record was evicted, a bounded-map
  corner, keeps its own sockets unlabelled while wineserver's for it still work.
- **DNS.** A query through pasta's `--dns-forward` address joins its client
  only when pasta is started with `--dns-host`: the observer learns the
  translation from the command line alone, and pasta's default host
  nameserver comes from a resolv.conf that pasta's own isolation hides. DNS
  stays `wine-unknown` where pasta's forward address is its default gateway,
  which no command line names, where a pasta also maps port 853, because only
  port 53 is translated, and where `--dns-forward` has no `--dns-host`. A rule
  refusing `wine-unknown` must still exempt any it reaches.
- **32-bit names.** Under old-style WOW64, a 32-bit client is named after the first mapped file whose
  Linux name ends in `.exe`, in address order. That need not be the program's
  image, and a Linux file name is not a Windows image name, so the name can be
  wrong. No path is available.
- **UDP reuse.** A new inner socket reusing a live UDP 4-tuple inherits pasta's
  existing flow, and with it the previous owner until that flow expires.
- **TCP join race, which can misname a flow.** pasta's connect can delete a
  destination's TCP record while another CPU is recording the next SYN on it.
  That SYN's update is lost: its flow finds no record and is `wine-unknown`, or,
  if a SYN from the record's earlier program creates a new record first, it is
  named after that program. Under load with several programs sharing one
  destination, 5 of 44,800 TCP flows were named after the wrong program; with
  separate destinations, 4 of 48,000 were unknown and none was misnamed.
  Do not rely on a deny rule for a program whose sandbox runs other programs
  connecting to the same destinations at the same time.
- **Shared source ports.** Linux lets sockets with different peers share a local
  address and port. When an unlabelled socket sends from the address and port of
  a live pasta socket, it removes that socket's record by design, and the flow
  shows only as pasta, or as whichever process mihomo finds for that port.
