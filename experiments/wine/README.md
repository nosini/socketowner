# Observe Windows socket creators from the host

This optional command identifies the Windows program which creates an outgoing
TCP/UDP socket in an unchanged, explicitly selected wineserver. It prints JSON
diagnostics for socket creation, connect attempts and the first outgoing packet.
No Wine patch, injected DLL, uprobe, TLS adapter or sandbox capability is needed.

This is the first implementation milestone. It does **not** publish a routing
interface, change native socketowner maps, map pasta's replacement sockets, or
enable mihomo rules. Do not use the diagnostic event stream as a routing
authority. Unsupported binaries are refused; unreadable or incomplete Windows
metadata is reported without an executable name.

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

Wait for the `ready` event before launching the program. Sockets which already
existed when observation started remain unlabelled. Stop with Ctrl-C. Target
exit stops the observer; target exec revokes registration. Nothing is pinned,
installed or left attached after the command exits or crashes.

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

The tested real runner was an unchanged existing DW 11.0-15-based build. This
does not establish NIKKE, all packaged DW builds, native PE/WOW64, complete
Windows firewall semantics, multiple server registration, packet-loss behavior
under load, or the pasta/mihomo stages. The next stage is a versioned routing
reader with lifecycle/publication guarantees, followed by the pasta relation.
