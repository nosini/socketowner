# Relay validation, 2026-11-25

This covers what the [always-on validation](../always-on/README.md) left untested:
IPv6 through the relay, new-style WOW64, and relay load. It ran in the dedicated
VM on kernel `7.3.1-1-default`, pasta `20261002.cba3570-1.1`, with the observer
from socketowner `9b84d10` and mihomo `9dd7dfd3`. No game was run.

[testdata/pasta-relay.py](../../testdata/pasta-relay.py) runs mingw PE probes
behind real pasta in their own user and network namespaces, with the observer
started before wineserver and mihomo routing the relayed TCP flows by
`WINE-PROCESS-NAME`. pasta's host sockets leave from their own address, so no
test server or mihomo socket shares their address and port (see
[shared source ports](../../README.md#known-limitations)).

## Attribution

Each case runs two programs: `alpha.exe` is routed DIRECT, and `beta.exe` is
refused. A pass means both programs were matched by name on both TCP flows, with
three known relay joins each, TCP and UDP, the UDP host packet named, no unknown
relay, and no `wine-unknown` in mihomo. The client's Linux architecture is read
from the `ntdll.so` it maps.

| Runner | Probes | Family | Linux process | Name | Result |
| --- | --- | --- | --- | --- | --- |
| Wine 11.20 (openSUSE) | 64-bit | IPv4 | x86_64 | Full path, Windows PID | Pass |
| Wine 11.20 (openSUSE) | 64-bit | IPv6 | x86_64 | Full path, Windows PID | Pass |
| Wine 11.20 (openSUSE) | 32-bit, `WINEARCH=wow64` | IPv4 | x86_64 | Full path, Windows PID | Pass |
| Wine 11.20 (openSUSE) | 32-bit, old-style WOW64 | IPv4 | i386 | File name only | Pass |
| DW 15 (Wine 11.0), local build | 32-bit, `WINEARCH=wow64` | IPv6 | x86_64 | Full path, Windows PID | Pass |
| DW 15 (Wine 11.0), local build | 32-bit, default prefix | IPv4 | x86_64 | Full path, Windows PID | Pass |

The local DW 15 build was configured with `--enable-archs=i386,x86_64`, so it
uses new-style WOW64 without `WINEARCH`. Under new-style WOW64 a 32-bit program
is named exactly like a 64-bit one, because its Linux process is 64-bit and GS
holds the 64-bit TEB.

IPv6 used a dummy interface as pasta's template, a ULA destination on the
loopback interface and nftables' `ip6` redirect. mihomo needs `allow-lan` with
`bind-address: '*'` for its redirect listener to accept on `::1`.

## Load

Programs run `load-probe.exe`, each thread opening short TCP connections and,
in the first phase, one UDP socket per round. Each program's mihomo rule leads to
its own SOCKS outbound, which echoes and records the four-byte tag the connection
carries, so a flow named after the wrong program is seen exactly. UDP is judged
from the observer's events for pasta's host packets.

- **Separate destinations:** each program has its own TCP and UDP destination.
  Every flow must be named after its program.
- **One shared destination:** all programs connect to one TCP destination at
  once. Unknown is expected; a wrong name is a failure. UDP is left out, because
  a reused UDP 4-tuple keeps pasta's earlier flow and its owner.

| Case | Phase | TCP flows | Named | `wine-unknown` | Wrong name |
| --- | --- | ---: | ---: | ---: | ---: |
| 4 programs x 8 threads x 100, 7 runs | Separate | 22,400 | 22,399 | 1 | 0 |
| 8 programs x 16 threads x 200 | Separate | 25,600 | 25,597 | 3 | 0 |
| 4 programs x 8 threads x 100, 6 runs | Shared | 19,200 | 12,882 | 6,317 | 1 |
| 8 programs x 16 threads x 200 | Shared | 25,600 | 6,523 | 19,073 | 4 |

The 4 x 8 x 100 runs cover IPv4 and IPv6, 64-bit and new-style WOW64 probes, and
both runners. Every UDP host packet seen was named after its program, about
98% of UDP sockets; the rest reused a source port already used for the same
destination, so pasta kept its existing flow and no new host packet appeared. No
event was lost. One IPv6 run lost a UDP reply after three tries and stopped
before its shared phase; the test no longer fails on lost UDP replies, since
attribution is judged from events. The large case exceeds `relay_flows` (8,192) and `wine_flows`
(16,384), and eviction caused no miss.

The unknown flows in separate destinations are `no-inner-flow`, and the wrong
names in the shared phase come from the same race: pasta's connect deletes a TCP
record while another CPU records a SYN on it. That SYN's update is lost, so its
flow finds no record, or finds a new one created by the earlier program's next
SYN and takes that program's name. This is listed under
[known limitations](../../README.md#known-limitations).

Throughput was limited by the test's Python servers. Three alternating runs of
the separate-destination phase gave 301-421 TCP connections per second, each
with a UDP socket, with the observer, and 308-615 without it. Run-to-run
variation is larger than any difference, so the observer's cost was not
measured.

## Earlier suites

`real-wine.py` and `pasta-route.py` passed with the DW 15 runner after the
probe gained IPv6 support. With openSUSE's Wine 11.20 both fail their name
checks, before and after this change: that Wine reports Winelib images as
`alpha.exe.so`.
