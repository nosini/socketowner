# Observe Windows socket creators from the host

This optional command identifies the Windows program which creates an outgoing
TCP/UDP socket in an unchanged, explicitly selected wineserver. It prints JSON
diagnostics for socket creation, connect attempts and the first outgoing packet.
With `-pin` it publishes those identities for mihomo's `PROCESS-NAME` and
`PROCESS-PATH` rules, and with `-pasta-pid` they survive a sandbox's pasta.
No Wine or pasta patch, injected DLL, uprobe, TLS adapter or sandbox capability
is needed.

This remains an experiment, started by hand for one sandbox; see
[what is missing](#what-is-missing). It leaves native socketowner maps unchanged.
Do not use the diagnostic event stream as a routing authority: readers use the
pinned [routing maps](#routing-maps). Unsupported binaries are refused;
unreadable or incomplete Windows metadata is reported without an executable name.

## Build and run

The ordinary socketowner command and its installation are unchanged. Build this
command explicitly, on Linux amd64:

```sh
CGO_ENABLED=0 go build -o socketowner-wine-observer ./experiments/wine/cmd/socketowner-wine-observer
```

Prepare a profile from a **trusted wineserver binary with its matching DWARF and
symbol table**, then review the generated file:

```sh
./socketowner-wine-observer -make-profile /path/to/wineserver > wine-profile.json
```

Profile generation needs no BPF attachment. A stripped binary needs a separately
reviewed profile for its exact SHA-256. The checked-in
[test-build profile](profiles/wineserver-3bb468ca4d60c890.json) admits only the
specific DW-based build used in VM validation, not every DW 11.0-15 release.

Select the wineserver's **host PID**, and start the observer before the Windows
program creates its sockets:

```sh
sudo ./socketowner-wine-observer -profile wine-profile.json -pid HOST_PID
```

`HOST_PID` is a placeholder for a numeric process ID. `-sends` also reports send
attempts, including the Linux process performing each send. `-cgroup` selects
the cgroup v2 ancestor used for first-packet observation; its default is
`/sys/fs/cgroup`. Select an ancestor covering both wineserver and the clients
which use its FDs. The LSM hooks are globally attached but accept metadata only
from the registered task and observe only its labelled sockets.

Add `-pasta-pid PID` for the sandbox's pasta, and `-pin DIR` with
`-reader-group GROUP` to publish [routing maps](#routing-maps).

Wait for the `ready` event before launching the program. Sockets which already
existed when observation started remain unlabelled. Stop with Ctrl-C. Target or
pasta exit stops the observer; exec revokes registration. Nothing stays attached
after the command exits or crashes. Pins are removed on exit; a crash leaves them
until the next publisher.

The observer needs host BPF/LSM/iterator and cgroup attachment privileges, and
permission to inspect the selected process's executable and mappings. Depending
on process credentials and policy, preparation may require `CAP_SYS_PTRACE` in
addition to `CAP_BPF`, `CAP_PERFMON` and `CAP_NET_ADMIN`. Root in the test VM
supplies these rights. No service or SELinux policy change is included; adding
this command to a host service is a separate step. Wine and games remain
unprivileged.

## What the events mean

Each observation carries an unpredictable `observer` lifetime ID and a
`socket_id` unique within that lifetime. This ID is **not** Linux `SO_COOKIE`.
Events include the wineserver's host TGID/start time, Windows PID/start time,
complete normalized Windows image, and basename. `client_unix_pid` is in
wineserver's PID namespace; it must not be treated as a host PID.

`first-egress` adds the network namespace cookie and the packet's source and
destination addresses/ports, including any translation already applied when the
cgroup egress hook runs. TCP flags permit checking that the first observed
packet was the SYN. This event is emitted once per socket; later UDP peers are
not a complete flow table. Packet/header parsing is limited to TCP/UDP,
IPv4 with options and up to eight supported IPv6 extension headers;
noninitial fragments and unsupported protocols are omitted.

`relay` reports a pasta socket joined to its inner flow, or its unknown status.

The identity describes the **Windows socket creator**. It is immutable after
creation. A subsequent connect attempt, failed connect, or send through a
duplicated/inherited FD does not replace it with the requesting process. The
actual sending Linux TGID is a separate field. This is deliberately distinct
from native socketowner's latest-Linux-user semantics. Connect/send diagnostics
describe attempted operations, not successful completion.

Read failures, an absent current request, oversized/odd-length image data,
incomplete UTF-16, relative paths or malformed process identity produce unknown
records with no Windows image/PID. There is no partial-path fallback. Paths
are limited to 1024 UTF-16 bytes; no truncated path becomes a matchable name.

The event buffer is bounded. Buffer exhaustion increments a reported `loss`
count; short-lived/late-attached sockets, shutdown and unsupported packet paths
can also leave incomplete diagnostics. Records retained by an external log
reader have no continuing authority after the observer exits. A future routing
reader needs its own lifecycle, publication and unknown-result contract.

## Routing maps

`-pin DIR`, normally socketowner's `maps` directory, adds three optional pins
beside its ABI v1 maps. V1 records are unchanged, so no v1 version change applies.
These have their own version, and their pins come and go with the observer:

| Pin | Linux map type | Key bytes | Value bytes | Meaning |
| --- | --- | ---: | ---: | --- |
| `wine_abi` | `ARRAY` (2) | 4 | 4 | Frozen; key 0 holds version 1 |
| `wine_heartbeat` | `ARRAY` (2) | 4 | 8 | Key 0 holds `CLOCK_BOOTTIME` nanoseconds, updated every second |
| `wine_flows` | `LRU_HASH` (9) | 32 | 1088 | Identity by outgoing packet source |

`wine_flows` is pinned last and is the publication point. Its key is the v1
connection key. All integers are native endian. The value is:

| Byte offset | Type | Meaning |
| ---: | --- | --- |
| 0 | uint64 | Socket ID, unique within one observer lifetime; not `SO_COOKIE` |
| 8 | uint64 | wineserver start, `CLOCK_BOOTTIME` nanoseconds |
| 16 | uint64 | Windows process start time, as wineserver records it |
| 24 | uint64 | `CLOCK_BOOTTIME` nanoseconds at capture |
| 32 | uint32 | wineserver host TGID |
| 36 | uint32 | UID of the capturing process |
| 40 | uint32 | Windows PID |
| 44 | uint32 | Client Unix PID, in wineserver's PID namespace |
| 48 | uint32 | Status; only 1 names a program |
| 52 | uint32 | Image length in bytes |
| 56 | uint32 | IP protocol |
| 60 | uint32 | Padding |
| 64 | uint16[512] | Windows image, UTF-16, not NUL terminated |

Status 1 is known. 2-5 are the capture failures listed above. 6 means owners
differed while waiting for pasta, 7 that pasta's socket matched no inner flow,
and 8 that the inner flow came from a socket with no Windows identity.

The kernel writes a record before the packet it describes leaves `wine_egress`,
so it precedes mihomo's first lookup; it does not depend on the event buffer.
An unlabelled socket which sends from a recorded address and port removes the
record. Active flows republish after LRU eviction. A reader must:

1. Check the version, map types and sizes before any lookup, as for v1.
2. Consult `wine_flows` first. No record means ordinary lookup proceeds.
3. Treat a record with another status, a heartbeat older than five seconds, or an
   image failing validation as **unknown**, not as absent. Falling through would
   name the relay, or whichever process now holds a reused port.

mihomo reports unknown as the process `wine-unknown`, so that a deny can be
written for it:

```yaml
rules:
  - PROCESS-NAME,tbs_browser.exe,REJECT
  - PROCESS-NAME,wine-unknown,REJECT
```

A crash leaves the pins, which a new publisher replaces once the heartbeat has
expired. While no observer runs, new flows have no record and show as pasta.
A rule for the sandbox's pasta name can decide what those may do.

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

`-pasta-pid` is refused unless that process holds a descriptor for the target's
network namespace. Registration is keyed by pidfd and revoked on exec. No pasta
memory is read, so pasta needs no profile and its updates don't affect one.
The relay inherits the Wine trust limit below, and a sandboxed program can
provoke unknown results by racing another program to one destination.

## How registration works

The operator supplies a trusted layout profile. Preparation opens a pidfd and
the running `/proc/PID/exe`, hashes that exact file, checks ELF architecture and
relocates `current` using executable dev/inode mappings. Fixed-address ELF and
PIE/ASLR builds are supported. The selected wineserver must initially be
single-threaded; only its leader can capture request metadata.

Registration is in BPF task storage keyed from the original pidfd, not a
reusable numeric PID. An iterator seeds the kernel-held `mm->exe_file`
reference, and preparation rechecks the executable and mappings before
publishing readiness. Every new capture verifies that same kernel file;
`bprm_committed_creds` revokes registration on exec. The private registration map
is frozen against later userspace writes. No kernel file pointer is emitted.

At `socket_post_create`, the host LSM hook reads wineserver's live
`current -> thread.process -> image/PID/start_time` and labels the actual held
kernel socket. It checks request pointers/identity again after reading. The
record is published before socket creation returns to userspace, and remains
immutable in socket storage. Connect/send/egress hooks use that record instead
of traversing an FD table or reconstructing an earlier request.

Win32's public API stability supplies a common application boundary; it does
not stabilize the internal structures read here. Profiles remain build
specific. The selected runner must remain unchanged during observation. This
supports cooperative Wine applications, not a security claim against a
malicious process capable of modifying wineserver memory/code or delegating
network activity to other programs.

## Validation

Recorded results and raw evidence are in [validation](validation/README.md).
The earlier [research and proof-of-concept evidence](research/README.md) explain
the design choices and the remaining Wine-to-pasta attribution problem.

Ordinary tests check profile/UTF-16 refusal, ELF/DWARF generation, PIE relocation,
mapped file identity, BPF structure layout and event decoding:

```sh
go test ./...
```

Regenerate the embedded object after a BPF change using clang/llvm and libbpf
headers, then rebuild:

```sh
go generate ./experiments/wine
```

Privileged tests belong in the dedicated test VM. They compile a controlled
request-object fixture; this fixture is not Wine. Run the tests in a private
network namespace, using an absolute path for `WINE_FIXTURE`:

```sh
gcc -g -O0 -fPIE -pie -Wall -Wextra -Werror experiments/wine/testdata/wineserver-fixture.c -o /absolute/task/wineserver-fixture
go test -c -tags wine_vm -o /absolute/task/wine.test ./experiments/wine
sudo env WINE_FIXTURE=/absolute/task/wineserver-fixture unshare --net sh -c 'ip link set lo up; exec /absolute/task/wine.test -test.v -test.run TestWineObserverVM -test.timeout 100s'
```

The kernel tests cover ordinary and nested PID/user namespaces, zero sandbox
capabilities, correct netns cookie, IPv4/IPv6 TCP SYN and unconnected UDP,
failed-connect creator preservation, a fork sending through an inherited socket,
an unregistered fork creating its own socket, malformed/oversized/absent request
data, repeated FD reuse, observer restart, target exit and exec revocation.

The [routing test](validation/routing/README.md) runs the same way, with real
pasta, mihomo and nftables around Wine:

```sh
python3 experiments/wine/testdata/pasta-route.py --runner /path/to/runner/bin --observer /absolute/path/socketowner-wine-observer --mihomo /absolute/path/mihomo --work /absolute/task/route
```

`--control` repeats it without the relay, where no rule may see a Windows name.

`testdata/sandbox-route.py` does the same inside real `sandbox-game --net`, with
`--pe` for native PE probes; see its [results](validation/sandbox/README.md).

A separate real-Wine smoke test runs as the ordinary VM user. Only its observer
uses sudo. It requires the existing Wine runner's compiler and writes only to
the supplied task directory:

```sh
python3 experiments/wine/testdata/real-wine.py --runner /path/to/runner/bin --observer /absolute/path/socketowner-wine-observer --work /absolute/task/real-wine
```

This compiles two 64-bit Winelib probes, uses a private prefix and loopback echo
listeners, and checks three distinct sockets/first packets per Windows image:
ordinary TCP, ConnectEx TCP, and UDP sendto before connect. The probes also
complete a pending overlapped receive and connected UDP. It verifies the
Windows PID against each probe's own output and target-exit cleanup.

The tested real runner was an unchanged existing DW 11.0-15-based build.

## What is missing

- **Launch integration.** The observer needs the wineserver and pasta PIDs, and
  must be ready before the program's first socket. Nothing automates that yet,
  and an earlier socket stays unlabelled. A root observer can't be asked from
  inside a sandbox, and a real launch has no pause for it to attach.
- **Packaged runners.** Those without DWARF, such as packaged DW releases, can't
  generate a profile yet; see the [sandbox validation](validation/sandbox/README.md).
- **Several sandboxes.** One observer serves one wineserver and one pasta, and
  one publisher may use a pin directory. A second sandbox is refused.
- **Deployment.** No service unit, SELinux policy or reader-group setup exists.
- **Untested:** NIKKE, 32-bit PE through WOW64, Proton's launch script, IPv6
  through the relay, UDP through a mihomo inbound (only its published record was
  checked), other DW builds, and load. The per-packet cost of `wine_egress`,
  which now parses every packet on the host, has not been measured.
- **DNS.** Flows sent to pasta's `--dns-forward` address are translated, so they
  find no inner record and will be unknown. A rule refusing `wine-unknown` should
  exempt them. Reasoned from pasta's source, not tested.
- **UDP reuse.** A new inner socket reusing a live UDP 4-tuple inherits pasta's
  existing flow, and with it the previous owner until that flow expires.
