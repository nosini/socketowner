# Real sandbox validation, 2026-11-02

This repeats the [routing validation](../routing/README.md) inside real
`sandbox-game --net`, at run-in-sandbox `8c22b9d`: bwrap with
`--disable-userns`, its seccomp filter and Landlock layer, its PID namespace and
route rules, and pasta from its own launch. Same VM, kernel, pasta, runner and BPF
object. It ran `--headless --with-proton`, using a minimal Proton directory around
the unchanged DW 11.0-15-based Wine install, so Proton's own launch script was
not involved. No sandbox-game change was made. No game was run.

[testdata/sandbox-route.py](../../testdata/sandbox-route.py) finds pasta by name
and wineserver by matching network namespace from outside the sandbox. The script
inside waits for a file before starting the probes, so the observer attaches
first. That wait is a test device: nothing yet provides it for a real launch.

| Run | Programs | mihomo TCP | Relays with the right Windows PID |
| --- | --- | --- | --- |
| Winelib | `alpha.exe`, `beta.exe` | 2 DIRECT, 2 REJECT | 3 each, TCP and UDP |
| Native PE32+, mingw `-static` | `alpha.exe`, `beta.exe` | 2 DIRECT, 2 REJECT | 3 each, TCP and UDP |

Logs: [PE rules](pe-mihomo-rules.log), [PE events](pe-events.jsonl), and
[Winelib events](winelib-events.jsonl). The PE images were reported as
`Z:\game\alpha.exe`. The Windows PIDs came from the probes' own output. The
destination was a task address with host scope, because the sandbox refuses this
machine's global addresses. As before, UDP's result is the observer's first host
packet, not a mihomo inbound.

This covers real Wine in bwrap and 64-bit native PE. It does not cover 32-bit PE
through WOW64, Proton's launch script, a graphical program, or a real launcher.

## Profiles are the next blocker

The packaged DW 11.0-14 runner in the VM has a symbol table but no DWARF, so
`-make-profile` refuses its wineserver. The tests above used a local build with
debug information. Packaged runners therefore need a reviewed profile made some
other way for their exact hash: the same source built with `-g` gives the offsets,
provided the result is checked against that binary. That has not been tried.
