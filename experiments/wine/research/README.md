# Wine attribution research

[The research report](attribution-research.md) records the 2026-10-28
investigation of Windows process attribution across Wine, pasta and mihomo.
[Original scripts and selected output](attribution-research-evidence/README.md)
include syscall traces, a custom socket-option experiment, and the initial
host-only BPF proof of concept. These files were moved from run-in-sandbox.

The report records how the design evolved. Its early prototypes and proposed
routing interfaces are historical context. The [observer README](../README.md)
describes the current diagnostic command, and [validation](../validation/README.md)
records that implementation's later tests and remaining gaps.

The archived scripts retain their original VM paths and build assumptions;
they are evidence of the recorded runs. Use the observer README and its
`testdata/` harnesses for current reproduction commands. The archived
`winsock-probe.c` and `echo-server.py` match the copies reused in `../testdata/`.
