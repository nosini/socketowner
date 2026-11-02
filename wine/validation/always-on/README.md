# Always-on validation, 2026-11-02

This covers the current design: no profile, and an observer started first and told
nothing about Wine. It ran in the dedicated VM, on kernel `7.2.8-1-default` with
pasta `20260612.a9c61ff-1.3`. The embedded BPF object's SHA-256 is
`724a79c8fa6197174e268e05463f87bc3af9ab8751d67bded526b1c701c038fe`.
No game was run, and nothing was installed on the desktop.

## Two sandboxes, no pause

[testdata/sandbox-route.py](../../testdata/sandbox-route.py) starts the observer,
then launches two real `sandbox-game --net --headless` instances at once, at
run-in-sandbox `8c22b9d`. Each has its own wineserver and pasta, and runs a mingw
PE probe straight after boot, with nothing waiting for the observer. Both race to
one destination. mihomo's rules send `alpha.exe` to DIRECT, and refuse `beta.exe`.

| Runner | Probes | Runs passed |
| --- | --- | ---: |
| DW 11.0-15, local debug build | 64-bit PE | 3 of 3 |
| DW 11.0-15, local debug build | 32-bit PE | 1 of 1 |
| DW 11.0-14, packaged, no DWARF | 64-bit PE | 3 of 3 |
| DW 11.0-14, packaged, no DWARF | 32-bit PE | 3 of 3 |

Each pass means both programs were matched by name on both TCP flows, with three
relayed flows each, two pastas registered, no unknown relay and no `wine-unknown`
in mihomo. 64-bit runs also matched the Windows PID from the probe's own output.
UDP's result is the relay record, not a mihomo inbound.

Logs for the packaged runner:
[64-bit rules](packaged-64bit-mihomo-rules.log), [events](packaged-64bit-events.jsonl);
[32-bit rules](packaged-32bit-mihomo-rules.log), [events](packaged-32bit-events.jsonl).

The runner was wrapped in a minimal Proton directory with `--with-proton`, so
Proton's own launch script was not involved. These are small runs: they show no
miss in ten launches, not that registration can't lose a race.

## Other suites

- [testdata/pasta-route.py](../../testdata/pasta-route.py), DW 11.0-15, 1 run:
  routing by name, a native program in the namespace (`not-wine`, refused by the
  `wine-unknown` rule), two owners racing with pasta stopped (both
  `ambiguous-relay`), SIGKILL of the observer followed by a replacement which
  picked up the running wineserver, and pins remaining until the observer stops.
- Its `--control` run, without the relay: mihomo saw `pasta.avx2`.
- [testdata/real-wine.py](../../testdata/real-wine.py): three sockets and first
  packets per program, Winelib, DW 11.0-15.
- `go test` and `go vet` for this experiment, and mihomo's `component/process` tests.

Stress results on loopback are in the [prototype record](../../research/generic-capture/README.md).
That object differs from this one, so its counts are not results of this code.

## Hook cost

Alternating runs of 3,000,000 pipe write/read round trips, on one pinned CPU, six
times each: 352-364 ns without the observer, 479-493 ns with it, about 130 ns or
37%. Nothing else was measured, including `wine_egress` per packet.
