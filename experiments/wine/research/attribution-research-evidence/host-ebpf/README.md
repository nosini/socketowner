# Host-only Wine attribution prototype

Read-only inspection of the existing hostname-discovery branch led to a separate
VM experiment. The original shelved hostname feature was not resumed. No project
in mihomo-dev, production service, desktop configuration or Wine binary changed.

The final run used the existing DW Wine build and two 64-bit Winelib executables
compiled from `../winsock-probe.c`, plus the task-only echo server from
`../echo-server.py`. `alpha.exe` and `beta.exe` were ordinary copies compiled
with different output names; no injected annotation code was added.

The host loader attaches three non-sleepable LSM BPF programs. Creation/connect
read Wine's live request context and put image/PID metadata on the actual socket;
the send hook demonstrates that metadata survives the FD being shared with the
client, and ConnectEx sends from wineserver. Stage 3 means creation, stage 1
connect and stage 2 send. `dport=0` means no recorded connect destination yet;
it does not claim that the UDP datagram's actual destination port is zero.

`observations.txt` contains all 22 final observations. Both probe stdout files
independently report their Windows PID and successful I/O results. Assertions
check the two image/PID pairs, server/client identities, three creates, three
connects and five sends per client, plus the first unconnected UDP send occurring
before UDP connect. `observer-stderr.txt` was empty in the final run.

Exact profile, obtained from offline GDB types/symbols in the existing binary:

| Item | Value |
| --- | --- |
| wineserver ELF type | EXEC, 64-bit |
| wineserver SHA-256 | `3bb468ca4d60c89074c6d854af871931f963586ac5915cca964e488b21422186` |
| `current` address | `0x4abba0` |
| `thread.process` offset | 136 |
| `process.id` offset | 152 |
| `process.unix_pid` offset | 188 |
| `process.imagelen` offset | 252 |
| `process.image` offset | 256 |

Source context is DW Wine `b75a4125963073b01d2b3bfce6060d697d02066b`; the existing
build has the display-only local commits described in the parent evidence README.
Kernel remained `7.2.8-1-default`. No packages were installed.

This recorder is deliberately a diagnostic prototype, not a safe production
observer: fixed offsets/address, scalar target PID, bounded path buffer, in-place
socket-record mutation on send, and no complete publication/lifetime authority
protocol. Only sequential clients were tested. It must not be loaded as a general
policy service. A production version needs binary/mapping and process-generation
validation, concurrency/lifetime handling and explicit unknown behavior.

Preparation failures were excluded from the result: an initial BPF stack-limit
failure, verifier rejections for lost pointer type and a missing null check,
initial Wine prefix setup delays, and overlapping preparation launches which
were stopped and cleaned before the final independent run. The final source
compiled, loaded and produced the complete observations without BPF stderr.

The loader pins nothing and destroys its links/maps on exit. The task's VM source,
binaries, Wine prefix and processes were removed, and its durable hold released.
No persistent VM configuration changed.
