# Build-independent capture prototype, 2026-11-02

This prototype tested whether the observer could drop per-build profiles. The
observer now works this way, so this is a historical record. `main.go` embeds `g.o`, compiled from `g.c`, and carries `go:build ignore` to stay out of the
module's build.

Instead of reading wineserver's memory, it follows Wine's request protocol:

1. wineserver's read from a FIFO marks it a request pipe. A later write by another
   process names that pipe's client (`lsm/file_permission`).
2. Each read then records the client being served. wineserver handles a request
   within the read's call and is single-threaded, so the next socket is that
   client's (`lsm/socket_post_create`).
3. The client's name comes from its PEB, a public Windows layout: GS holds the TEB,
   checked through `TEB.Self`, then `Peb`, `ProcessParameters` and `ImagePathName`.
4. 32-bit clients are true 32-bit Linux processes here. GS is glibc's TLS, so step
   3 fails its check. They fall back to the first mapped file named `*.exe`.

## Results

Unchanged runners, in the VM, on loopback, with no profile or DWARF. Two programs
ran at once with four threads each, 2,400 sockets per run. Each probe counted its
own successful sockets. Clients send on their own sockets, which checks each label
against the actual sender.

| Runner | Client | Runs | Named | Unknown client | Sender mismatches |
| --- | --- | ---: | --- | ---: | ---: |
| DW 11.0-15, local debug build | 64-bit PE | 4 | All, full path | 0 | 0 |
| DW 11.0-14, packaged, no DWARF | 64-bit PE | 5 | All, full path | 0 | 0 |
| Wine 11.19, system package | 64-bit PE | 4 | All, full path | 0 | 0 |
| DW 11.0-14, packaged, no DWARF | 32-bit PE | 3 | All, basename only | 0 | 0 |
| Wine 11.19, system package | 32-bit PE | 3 | All, basename only | 0 | 0 |

The final object produced the 32-bit rows and one 64-bit packaged run. The other
64-bit rows predate the mapped-file fallback, which those clients do not reach.

Hook cost was later measured properly: see the always-on validation.

## Limits

- wineserver is recognised by `comm`, which any process can imitate.
- Client images are cached by TGID alone. Integration must add process birth time.
- Only one wineserver at a time, no real game, and no 32-bit full paths.
- A multi-threaded wineserver would break step 2.

## A false alarm

Runs intermittently reported few or no sockets. This was the prototype's loader:
`os.IsTimeout` missed the ring buffer's deadline error, so an idle second ended
the loader and detached its hooks. The observer already uses `errors.Is`.
Recursion misses were zero throughout, on this fully preemptible kernel.
