# Routing validation, 2026-11-02

**Historical.** This report predates profile-free capture, and its observer was started per sandbox. See [always-on validation](../always-on/README.md).

This covers the [routing maps and relay](../../README.md#routing-maps) with real
programs in the dedicated x86-64 VM: kernel `7.2.8-1-default`, BPF LSM, pasta
`20260612.a9c61ff-1.3`, and the unchanged DW 11.0-15-based runner from the
[earlier validation](../README.md). The embedded BPF object was compiled in the
VM; its SHA-256 is
`b27b7d6e63056955daaa63955182d99a5e89f8ed8062374d1c0018ad5f2451ab`.
No service or desktop state changed. The result is this test's, not NIKKE's.

[testdata/pasta-route.py](../../testdata/pasta-route.py) runs wineserver and three
Winelib probes as the ordinary user in a separate user and network namespace,
with unmodified pasta as their way out. pasta's arguments follow `sandbox-game`,
except for `--userns` by path, and with no bwrap. An nftables rule redirects TCP
for the task address to mihomo's redirect port, with these rules:

```yaml
- PROCESS-NAME,beta.exe,REJECT
- PROCESS-NAME,alpha.exe,DIRECT
- PROCESS-NAME,wine-unknown,REJECT
- MATCH,DIRECT
```

## Results

[mihomo-rules.log](mihomo-rules.log) is mihomo's own account of the final run,
and [events.jsonl](events.jsonl) the observer's.

| Case | Result |
| --- | --- |
| `alpha.exe`, two TCP flows | Matched by name, DIRECT; probe completed through it, including ConnectEx |
| `beta.exe`, two TCP flows | Matched by name, REJECT |
| Windows PID | Relay records matched the PID from the probe's own output |
| UDP, both programs | First host packet carried the identity; **not** taken through a mihomo inbound |
| Native Linux program in the namespace | Status `not-wine`; matched `wine-unknown`, REJECT |
| Native and Windows SYNs waiting together | Pasta held with SIGSTOP: both `ambiguous-relay`; matched `wine-unknown` |
| Observer killed with SIGKILL | Pins stayed; a new observer replaced them after the heartbeat expired, and attribution resumed |
| wineserver exit | Observer stopped, all pins removed, stderr empty, no mihomo errors |

In the race case, `gamma.exe`'s next connection was named again. It has no rule of
its own, so it went to `MATCH`.

**Negative control:** [control-mihomo-rules.log](control-mihomo-rules.log) is the
same run of `alpha.exe` without `-pasta-pid`. mihomo saw `pasta.avx2`, and no rule
saw a Windows name. The name matches above therefore come from the relay.

The [fixture VM tests](../README.md) and `real-wine.py` also passed again with
this BPF object, as did `go test`, `go vet` and mihomo's `component/process` tests.

Not exercised: the reader's handling of a stale record, which needs a port reused
after a crash. Its status and heartbeat checks have no test of their own. See also [what is missing](../../README.md#what-is-missing).

## Issues found during the work

pasta refused to start from `nsenter -U`, because exec drops capabilities for a
non-root user, and could not create its pidfile. The harness passes `--userns` by
path and supplies an existing file, as `sandbox-game` does with `mktemp`.

All VM task state was removed after collecting this evidence.
