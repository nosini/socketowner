# VM validation, 2026-10-28

**Historical.** This report describes the profile-based observer, since replaced. See [always-on validation](always-on/README.md).

The `wine-process-attribution` implementation was tested without installing a
service or changing the desktop. These are diagnostic results. Source and reproduction commands are in the
[observer README](../README.md).
Later [routing validation](routing/README.md) covers mihomo and pasta.
The [earlier research evidence](../research/README.md) records separate
proof-of-concept runs; its observations are not results from this implementation.

Environment: dedicated x86-64 VM, kernel `7.2.8-1-default`, BPF LSM enabled,
Btrfs root, clang 23.1.2. Go binaries were built with Go 1.27.3 in the agent
container. The embedded BPF object was compiled from `../bpf/wine.c` in the VM
and stripped of DWARF, retaining BTF/CO-RE metadata. Its SHA-256 is
`16849d4b779e8218fd79161cd95bf62d8ea1e8746d7484f943043674d611cab6`.

Local checks passed: `go test ./...`, `go test -race ./wine/...`
and `go vet ./...`. The separate command and the `wine_vm` tagged test binary
also built successfully. No native map format or mihomo code changed.

## Controlled kernel tests

[vm-test.log](vm-test.log) is the final run, using the checked-in C request
fixture compiled as PIE with DWARF. Tests ran as root in a private network
namespace with only loopback enabled. The fixture ran as UID/GID 1000. Both the
ordinary fixture and the nested bwrap PID/user namespace case passed; the latter
checked all five capability sets were zero. Neither case gave the fixture BPF
privileges.

Assertions covered exact-hash refusal, correct Windows image/PID and host versus
namespace PID, the actual network namespace cookie, first TCP SYN before a
payload, unconnected UDP, IPv6 TCP/UDP, a failed connect after changing the
current request, inherited-FD sends by a fork, refusal to label new sockets made
by an unregistered fork, malformed UTF-16, oversized images, null requests,
eight FD reuse cycles, and exit cleanup. Separate cases confirmed exec revokes
registration and restarting the observer does not adopt an existing socket.
New sockets after restart received a different observer lifetime ID.

The fixture models request memory; it is **not Wine**, and its namespace tests
do not by themselves establish real Wine behavior inside run-in-sandbox.

## Unchanged real DW build

[real-dw.log](real-dw.log) records the final real-Wine smoke test.
[events.jsonl](events.jsonl) contains all 30 JSON records; probe stdout supplies
the independently expected Windows PIDs in [alpha](alpha-stdout.log) and
[beta](beta-stdout.log).

The runner was the existing DW 11.0-15-based VM build, using Wine socket source
`b75a4125963073b01d2b3bfce6060d697d02066b` with existing local display patches
through `a451b29d1ca0baf2da86d3cdf0b9bffdc9752226`. It was not rebuilt or patched
for attribution. The wineserver hash and layout were recorded in
`wineserver-3bb468ca4d60c890.json`, removed when profile-free capture replaced
that design.

Two sequential Winelib clients, `alpha.exe` (Windows PID 32) and `beta.exe`
(Windows PID 252), used the same wineserver. Each created three sockets:
ordinary TCP, ConnectEx TCP with initial data, and UDP sendto before connect.
All six creations and all six first outgoing packets carried the expected
complete Windows image/PID. Both TCP first packets were SYNs for each image.
The probes also completed synchronous sends, WSASend, a pending overlapped
WSARecv (`WSA_IO_PENDING`, 997), ConnectEx initial data, and connected UDP.
Connect/send observations retained the creator, including client-side sends.
The observer stopped on target exit and its stderr was empty. No loss event
occurred in this small run; overload behavior was not tested.

Wine ran as the ordinary VM user with a task-only prefix and loopback echo
listeners. Only the observer used sudo. These were 64-bit Winelib probes;
native PE/WOW64, NIKKE, multiple Wine servers, concurrent clients, malicious
memory changes, packet-parser edge cases, pasta and mihomo routing were not
tested. No assertion here establishes those cases.

## Issues found and corrected

An earlier BPF version failed verification because a second `socket->sk` load
lost the verifier's non-null refinement. Caching and checking the typed pointer
once fixed that failure. An initial executable fingerprint using a kernel
superblock device number alongside userspace `st_dev` produced no observations
on the Btrfs VM. The final version instead seeds the actual kernel-held
`mm->exe_file` reference through a task iterator, keeps userspace dev/inode
checks for `/proc/PID/maps`, and revokes on exec. The exact filesystem cause of
the earlier mismatch was not separately established.

The first real-Wine harness waited for EOF on stdout pipes inherited by Wine
services after the probe had completed. It now waits for the probe process and
uses regular log files. Final logs above come from the corrected harness and
the final embedded object. Earlier failures were not counted as passes.

All observer links/maps were private and unpinned. Task processes, prefix,
builds and VM scratch were removed after collecting this evidence; the VM
keep-awake hold was released. The pre-existing Wine build was retained.
