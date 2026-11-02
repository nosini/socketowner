# Attribution research evidence — 2026-10-28

Scripts and selected output from the isolated VM experiments. The [research report](../attribution-research.md) explains coverage and limits. `dw-trace-excerpts.txt` and `upstream-trace-excerpts.txt` retain original strace file names and line numbers. Startup/service traffic was omitted.

DW Wine source: b75a4125963073b01d2b3bfce6060d697d02066b. Runtime was an existing local build at a451b29d1ca0baf2da86d3cdf0b9bffdc9752226 with display patches. Its server/sock.c and dlls/ntdll/unix/socket.c exactly matched the release source (SHA-256 cca829e3624afe56d928fc3ad0ea909e617b9f27e1cd6f1316f199f6988ea8a3 and 311f0ca42d7e4ccac41c8f842b62f36aef50af76de87781410010ab1303beb73).

Upstream VM runtime: packaged wine-11.19. Pasta: 20260612.a9c61ff-1.3. Kernel: 7.2.8-1-default. The Winsock probe is a 64-bit Winelib executable compiled with the existing DW Wine compiler; it is not NIKKE or a 32-bit PE test.

The first DW prefix initialization timed out after 60 seconds. Running the probe with that task-only prefix then succeeded. Pasta detached standard output from the command in the first run; the final probe writes inner.jsonl explicitly. The final Wine harness tolerates wineserver already having exited. No evidence is inferred from the failed initialization or empty first output file.

The custom sockopt test uses an experimental private level only in a dedicated temporary cgroup. This demonstrates a scalar label and BPF socket-local storage, not a proposed production ABI or a complete attribution bridge. It detaches its BPF program and deletes its pins and cgroup on exit.

These are archived experiments preceding the maintained observer. The
[current observer](../../README.md) and its [validation](../../validation/README.md)
cover the later implementation. Original scripts and outputs retain the paths
used during the experiments.
