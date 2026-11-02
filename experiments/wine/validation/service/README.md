# Confined service validation

Tested in the dedicated VM on 2026-11-02, kernel `7.2.8-1-default`, with
SELinux enforcing throughout. The BPF object is unchanged from the
[always-on validation](../always-on/README.md). No desktop installation was made.

The optional `socketowner-wine-observer.service` and policy version 1.9 in
hardened-proxy-service run the observer in `socketowner_wine_t`. systemd waits for
its `READY=1` notification after BPF attachment and map publication. The observer
retains the host network namespace and can inspect other users' fd links; Wine
and pasta run unprivileged.

## Routing and reader access

The existing `testdata/sandbox-route.py` now accepts `--observer-service`. It
restarts the installed observer, consumes that invocation's journal events, and
uses its shared maps. It leaves the service running and preserves the native
socketowner maps. Its ordinary standalone mode is unchanged.

With the packaged DW 11.0-14 runner, two unpaused PE sandboxes passed with both
64-bit and 32-bit clients ([64-bit counts](route64-result.txt),
[32-bit results](route32-result.txt)):
`alpha.exe` had two TCP matches using DIRECT, `beta.exe` had two using REJECT,
and each had three known relay flows including UDP. Two pastas were registered,
with no unknown relay or `wine-unknown` result.

A separate static reader, labeled `mihomo_exec_t` and launched by systemd as the
unprivileged mihomo user and group, opened all three Wine maps through a read-only
bind mount and read ABI 2 and the heartbeat. Their layouts were ARRAY 4/4,
ARRAY 4/8 and LRU_HASH 32/1088. This checks the actual SELinux map-creator rule
separately from the routing fixture, whose mihomo runs from the test directory.

SIGKILL left the pins behind. The unit restarted after six seconds, replaced the
expired publisher, and reached readiness again. Restarting native
socketowner also stopped and restarted the observer through `PartOf=`, and all
three Wine pins were republished after readiness. No policy permissive mode was
used. Development denials for the notification socket were resolved with explicit
Unix datagram creation and systemd notification permissions.

The mihomo `sockowner_vm` test `TestWineFlowStalePublisher` also passed using real
pinned maps: a known record matches, an expired heartbeat yields `wine-unknown`,
a fresh heartbeat restores the known result, status 7 remains unknown, and an
absent record permits ordinary lookup.

## Native packet cost

Reproduce the alternating benchmark with `testdata/native-cost.c` and
`testdata/native-cost.py`. It pins a native UDP sender/receiver to one CPU and
measures 1,000,000 send/receive iterations for each IPv4/IPv6 and 64/1400-byte
payload case. Six pairs alternate observer-off and observer-on, reversing pair
order each time. Native socketowner stays attached in both cases. These runs have
kernel BPF timing disabled. They include all observer hooks reached by this
workload, plus socket send and receive overhead.

A separate pass temporarily enables kernel BPF run-time accounting through a
scoped `BPF_ENABLE_STATS` FD and reads only `wine_egress`'s time and call count.
These are instrumented timings, not isolated throughput measurements. The script
refuses multiple programs with that name rather than silently timing another
observer. It restores the original service active state.

Results are recorded in [native-cost.json](native-cost.json). Median differences
between the six observer-on and six observer-off samples:

| IP | Payload bytes | Added ns per send/receive | Added time | Instrumented egress ns/call |
| --- | ---: | ---: | ---: | ---: |
| IPv4 | 64 | 93 | 4.0% | 105.5 |
| IPv4 | 1400 | 111 | 4.7% | 107.3 |
| IPv6 | 64 | 70 | 2.8% | 101.3 |
| IPv6 | 1400 | 78 | 3.1% | 101.6 |

Each instrumented pass observed 1,000,000 to 1,000,024 egress calls; incidental
VM traffic was not subtracted. Variation between samples makes these approximate
costs for this VM, not a universal performance prediction.

This workload measures the native
no-Wine-record path. It does not establish Wine capture/relay publication cost,
TCP throughput, latency under load, or packet-rate capacity.
