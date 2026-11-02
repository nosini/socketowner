# Per-Windows-program network attribution through Wine and pasta

Research date: 2026-10-28. No production code, desktop configuration, proxy rules, or installed runners were changed. Experiments ran only in the agent VM. Effort estimates below are engineering estimates, not measured implementation sizes.

## Finding and recommendation

**Feasible with coordinated changes; unavailable as a stock Wine/pasta/mihomo configuration.** There are three identities to carry: the Windows image, its inner socket/flow, and pasta's replacement host socket. Recovering only the Linux client PID, or preserving only a port, does not complete that chain.

**Follow-up finding:** after inspecting the existing `ebpf-hostname-discovery` branch, a host-only LSM prototype successfully recovered two Windows programs' image paths and PIDs from an unchanged DW wineserver and attached them to their actual kernel sockets. A Wine patch is optional. See [the host-only follow-up](#follow-up-host-only-attribution-without-a-wine-patch) and its retained evidence below. This revises the original preference for a Wine metadata patch.

For rules in the host's mihomo, the most promising design to investigate next is:

1. A host-side Wine adapter reads the requesting Windows process/image at LSM socket creation/connect hooks, using a verified wineserver build profile. A small Wine annotation patch remains an alternative for reducing internal-layout dependence.
2. A small pasta patch labels each replacement host socket with its originating namespace and inner flow before connecting or forwarding a datagram.
3. The privileged socketowner loader consumes these labels, joins the two sockets, and publishes a **separate versioned Windows identity/relay interface**. Mihomo consults it before its existing Linux process lookup.

A custom socket option consumed by a cgroup BPF hook is a useful transport for both labels. It requires no capabilities in Wine or pasta, introduces no host service accessible from the sandbox, and can preserve the current routing restrictions. The Linux kernel documents this mechanism, and a minimal VM experiment succeeded with all capability sets empty. The complete chain remains a proposed design, not a tested implementation. [Kernel socket-option hooks][sockopt-doc]

For the narrower immediate need—deny all networking by `tbs_browser.exe`—the host loader could potentially reject its socket operations after resolving the Windows image, avoiding the pasta hop entirely. That enforcement was not implemented or tested. A Wine AFD policy patch is another smaller option than implementing complete host proxy attribution. Neither would by itself make this a mihomo rule. Keeping the current hosts workaround while developing either option is reasonable.

Do not grant `CAP_NET_ADMIN`, enable nested user namespaces, expose the host network namespace, or expose a general host proxy to make this work.

## Revisions and evidence scope

Run-in-sandbox's README was read first, particularly its Proton, network, and isolation descriptions. The implementation was inspected at run-in-sandbox `18efb491689f211ec19a27da67340c7941e33141`, including its external pasta helper and capability-free bwrap launch. Socketowner was inspected at `2f7ff573da36c60f2ad921af6bacc7d7954cf67f`, mihomo's local fork at `08632a080a40e3330b3cb5829d61e9cc223a8bcb`. [Sandbox network implementation][sandbox-net], [map contract][map-contract]

| Source | Pinned revision inspected |
| --- | --- |
| Upstream Wine | `wine-11.19`, and master `0738d528db522f52d9d75f2aec712688dd31d1d2` (2026-10-27) |
| Historical upstream Wine | Release tags `wine-5.0`, `wine-6.0`, `wine-7.0`, `wine-8.0`, `wine-9.0`, `wine-10.0`, `wine-11.0`; socket implementation only for historical comparisons |
| Valve Proton 11 | Superproject `bc896217ffcd67f892f952b010f898fe7bd0f0a1`, Wine gitlink `e60892cc2398b0a83c332a2078c7b85e47bdb42b` |
| Valve Proton experimental_11.0 | Superproject `7a94df49e4695fc101fd47d614166e69c43d9669`, Wine gitlink `7fc704ef49c50e9702c9983a5250d5738697bb04` |
| DW-Proton 11.0-15 | Release superproject `b8c56daa4cd1f8ce0ce9c4135bf587e063e4b02f`, Wine gitlink `b75a4125963073b01d2b3bfce6060d697d02066b` |
| DW-Proton 11.0-14 / 11.0-13 | Wine gitlinks `b585905ec92032840e924e4e2a88382523e92ed3` / `0f9987ff4bcd61a88ff68a53ab808e19bb3f0f5c` |
| passt/pasta | Upstream `6aa4f88bd9846411edff3ed70460475b538addca` (2026-10-25); VM package based on `a9c61ffaf15347b8dfcc2347c5440e4b0e82333b` (2026-06-12) |
| Upstream mihomo | Meta branch `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8` (2026-10-21), for the SOCKS identity check |

DW's mirror default branch is older than its release tags; the release gitlink and the Wine source on `dawn.wine` were used, not an assumption that GitHub's default branch represents the current runner. [DW release tree][dw-release], [DW submodule declaration][dw-module]

**Evidence labels:** “source” means verified in those sources; “experiment” means observed in this task's VM; proposed designs and estimates are identified as such. No NIKKE launcher, `tbs_browser.exe`, production DW binary, or host mihomo was instrumented. Results should not be presented as an observed trace of NIKKE itself.

## Part 1: which process actually performs Winsock operations?

### Current Wine's AFD path

In the inspected current implementations, `ws2_32!socket` reaches `WSASocketW`, which opens `\\Device\\Afd` and sends `IOCTL_AFD_WINE_CREATE`. Wineserver's socket ioctl handler calls `init_socket()`, which calls Unix `socket()`. [Client socket creation, lines 4040–4138][w-create], [server creation, lines 1901–1940][w-init]

The FD is shared with the client using `SCM_RIGHTS`; the client caches/accesses it through `server_get_unix_fd()`. It is one underlying kernel socket, not two independent connections. [Server FD transfer, lines 440–465][w-fd-server], [client FD receipt, lines 988–1029][w-fd-client]

| Operation | Unix syscall executor in current Wine | Consequence |
| --- | --- | --- |
| TCP or UDP `socket()` / `WSASocket` | Wineserver | Kernel creator is wineserver. |
| Explicit `bind`, `listen`, `accept`/`AcceptEx` socket management | Wineserver | Binding, accepting, and initial accept data need attribution too. |
| TCP `connect`, including nonblocking connect | Wineserver | First SYN is emitted in server context. |
| UDP `connect` / disconnect | Wineserver | Connected UDP's setup owner can also be wineserver. |
| Unconnected UDP's first implicit bind | Wineserver's `send_socket` request handler | The actual datagram is subsequently sent by the client. |
| Ordinary TCP/UDP `send`, `sendto`, `WSASend[To/Msg]` | Client process, through ntdll's Unix `sendmsg()` | A send-aware observer can subsequently identify the Linux client. |
| Ordinary TCP/UDP `recv`, `recvfrom`, `WSARecv[From/Msg]` | Client process, through ntdll's receive helper / Unix `recvmsg()` | Receive readiness/completion management does not mean server performs the payload read. |
| Overlapped ordinary send/receive | Client performs the I/O; server queues/polls and alerts/completes asynchronous requests | Pending I/O is retried through client callbacks. |
| `ConnectEx` with initial data | Server connects and sends initial data | A client-only send probe misses this first payload. |
| `AcceptEx` with initial receive | Server can perform the initial receive | Another exception to “all payload I/O is in the client.” |
| `ReadFile` / `WriteFile` on socket handles | ntdll dispatches to client socket read/write paths | Still reaches the same socket. |
| `TransmitFile` and its async retry | Client ntdll transmit path | Do not restrict instrumentation to the exported Winsock `send` function. |

The detailed source anchors are [server connect][w-connect], [server UDP autobind][w-autobind], [client send and receive][w-io], [pending receive callback][w-recv-async], [pending send callback][w-send-async], [server ConnectEx payload][w-connect-data], [server AcceptEx payload][w-accept-data], [socket ReadFile][w-readfile], [socket WriteFile][w-writefile], and [client transmit][w-transmit]. The VM trace agrees for TCP, unconnected/connected UDP, a pending overlapped receive, and ConnectEx initial data; it did not exercise AcceptEx or TransmitFile.

**Correction to the initial hypothesis:** sockets are created and connected in wineserver, but ordinary sends/receives are normally in the Windows client process. Socketowner with `-exec-paths` already changes its recorded owner on connected sends through its LSM hooks. Thus a stream can first be attributed to wineserver and later to the Wine client. A host proxy normally makes its TCP routing decision before that later send, so waiting for payload ownership does not solve first-connection rules. [Socketowner send/connect hooks][so-lsm], [mihomo process lookup during rule matching][mh-process]

### WinHTTP, WinINet, schannel, browser processes

Wine's built-in WinHTTP creates an overlapped Winsock socket, calls Winsock `connect`, and sends/receives via Winsock. Its TLS layer calls SSPI `EncryptMessage`/`DecryptMessage` and transfers the resulting records on that same socket. [WinHTTP connection][w-http-connect], [WinHTTP send][w-http-send], [WinHTTP TLS][w-http-tls]

Built-in WinINet similarly uses its Winsock connection helper and send/recv wrappers. Schannel's GnuTLS transport adapters read/write caller-supplied buffers; they do not create a separate network connection owned by a TLS daemon. [WinINet connection helper][w-inet-connect], [WinINet transport][w-inet], [WinINet TLS send][w-inet-tls], [schannel buffer adapters][w-schannel]

These libraries therefore do not add another Unix ownership hop beyond AFD. Worker threads still belong to their containing Windows process. Native DLL overrides and Chromium/CEF/custom TLS implementations need not call Wine's WinHTTP or schannel, but their ordinary Windows Winsock sockets still reach AFD. Native Unix libraries loaded by Wine can instead create sockets directly in the client and must be handled by the existing Linux attribution path. DNS, certificate checks, proxy discovery, delegated helper processes, and connection pooling can generate additional connections: attribute the process actually opening/using each connection, rather than assuming every connection belongs to the visible launcher UI.

The same library boundaries were checked in the pinned Valve and DW source: WinHTTP opens/connects a Winsock socket, WinINet retains its send/recv wrappers, and schannel retains its buffer adapters. TLS/version-specific fixes do not change those ownership boundaries in these revisions. [Valve WinHTTP][v-http], [DW WinHTTP][dw-http], [Valve WinINet][v-inet], [DW WinINet][dw-inet], [Valve schannel][v-schannel], [DW schannel][dw-schannel]

Whether NIKKE's browser networking really occurs in `tbs_browser.exe`, in another instance of that image acting as a network service, or in a different helper remains unverified here. A Windows-image collector described below would establish that without guessing from hostnames.

### Differences between Wine, Proton, DW-Proton, and older versions

The ownership architecture is the same in the inspected modern sources. Valve's Wine calls `socket()` in server `sock.c:1950` and `connect()` at `:2750`; DW's calls are at `:1965` and `:2859`. Both retain client ntdll `sendmsg()`; DW's inspected differences include AF_UNIX support, not relocation of IPv4/IPv6 socket creation into clients. The same pattern was checked in Proton experimental and DW 11.0-13/-14. [Valve server socket][v-init], [Valve connect][v-connect], [Valve client send][v-send], [experimental connect][ve-connect], [DW socket][dw-init], [DW connect][dw-connect], [DW client send][dw-send], [DW 14 connect][dw14-connect], [DW 13 connect][dw13-connect]

There **is** a historical difference: Wine 5.0 and 6.0 execute ordinary `connect()` in client `ws2_32/socket.c`; socket creation is still server-side. By Wine 7.0, connect is in the server. Wine 8/9/10/11 retain server creation/connect. This brackets the change between the checked 6.0 and 7.0 release tags; the exact introducing development commit was not established. Do not assume every historical Proton version behaves like current Proton. [Wine 5 client connect][old5-connect], [Wine 5 server socket][old5-init], [Wine 6 client connect][old6-connect], [Wine 6 server socket][old6-init], [Wine 7 server connect][old7-connect], [Wine 8][old8-connect], [Wine 9][old9-connect], [Wine 10][old10-connect], [Wine 11.0][old11-connect]

No client-created IPv4/IPv6 AFD socket branch was found in the checked Wine/Valve/DW revisions. This is a bounded source finding, not a claim about every third-party Wine fork.

## Learning the Windows owner: candidate designs

“Small” below means roughly tens to a few hundred lines at narrow integration points; a robust protocol/collector is additional work. Rebase survivability concerns both source changes and rebuilding/distributing a patched DW runner.

| Candidate | How it works and what it needs | Risks / update survival | Effort and verdict |
| --- | --- | --- | --- |
| Existing Wine owner tables | A Windows helper queries `GetExtendedTcpTable` with owner PID information, `GetExtendedUdpTable`, and process image names. No Wine patch or root. | Polling misses short-lived sockets and cannot guarantee a result before the first SYN. UDP tables identify endpoints, not every remote peer; duplicated handles can yield multiple owners. Public Windows API is relatively stable. | Small collector, medium if connected to pasta. Good discovery/diagnostic path; insufficient alone for reliable first-connection blocking. |
| Wineserver metadata patch | At AFD creation, record requesting Windows PID, process generation/image, and socket identity; retain it through async callbacks. Emit metadata through a narrowly defined interface. | Define ownership for inherited/duplicated sockets, and distinguish creator, connect requester, and sender. Small localized source patch should rebase better than an internal-structure probe, but every runner update needs a rebuild. | Small producer, medium complete metadata protocol. Preferred basis. |
| SO_MARK from Wine | Set a per-image socket mark before connect. | Requires `CAP_NET_RAW` or `CAP_NET_ADMIN` in the socket netns's governing user namespace. The actual game has neither; VM result was EPERM. A mark is kernel metadata and does not appear on the TAP wire. No generic mihomo MARK rule. | Tiny setter but disallowed privilege requirement; reject as a Wine-only design. A host BPF service could set marks without granting the game capabilities, after learning identity another way. |
| Cgroup per Windows program | Place each Linux client in a host-created/delegated cgroup and use BPF cgroup identity. | Shared wineserver creates sockets in its own cgroup; moving clients later does not reassign the socket's creation cgroup. Letting Wine move the shared server around is not a safe attribution scheme. No mihomo cgroup rule. | Medium orchestration, still needs an ownership bridge. Not a standalone answer. |
| DSCP/TOS tag | Wineserver sets `IP_TOS` / `IPV6_TCLASS` from image identity before connect, with no capability needed for the tested values. | Only 64 DSCP values, QoS semantics, app can overwrite tags, preserve ECN bits. Pasta would need a propagation patch. Mihomo's documented DSCP match applies only to TPROXY UDP, so it cannot block the browser's TCP this way. | Small Wine setter plus medium propagation/inbound changes. Unsuitable for the general goal. |
| Per-program source-port range | Choose a range in wineserver before autobind. Linux ≥6.3 offers per-socket `IP_LOCAL_PORT_RANGE`; explicit bind allocation is another implementation. | Current pasta replaces TCP ports. Explicit application binds, port exhaustion/reuse, multiple sandboxes, IPv6 behavior, and collisions need handling. The socket option narrows the namespace's global ephemeral range; it is not a reservation or identity guarantee. | Small proof of concept, medium/higher robust allocator plus pasta changes. Possible controlled workaround with `SRC-PORT`; not recommended as the identity ABI. |
| Uprobes on unmodified wineserver | Read request context (`current->process`, image, client PID) around AFD creation/connect/send requests; correlate server FD with a kernel socket in loader hooks. | Stripped/LTO binaries, layout/offset drift, architecture/WOW64 differences, async callbacks outside request context, nested request state, and missed events. Host loader needs tracing privileges/policy. Existing socketowner deliberately avoids tracing hooks for ownership correctness because of possible skipped executions on its kernel; probe loss cannot silently mean “allowed.” | Medium prototype, high ongoing maintenance. Useful investigation, poor production default. |
| Live Wine state at kernel LSM hooks | At `socket_post_create`/`socket_connect`, read the target wineserver's `current->process` and image, while the kernel supplies the held socket. Store the identity in socket-local storage. No Wine patch, uprobe, injected DLL or earlier observation cache. | Wine internal fields and ELF symbol address need an exact build profile, mapping validation and safe unknown results; Win32 ABI stability does not stabilize those fields. Preserve owner semantics across shared sockets and later async operations. | Small prototype succeeded in the follow-up. Medium production adapter/validation work. Preferred next investigation for Wine attribution without runner rebuilds. |
| Explicit Wine USDT/noinline probe patch | Add a stable, versioned annotation point with socket FD and owner data; privileged loader attaches a uprobe. | Avoids decoding arbitrary Wine structs, but retains tracing/attachment/missed-event concerns. Need to handle server-side async sends and process identity translation. | Small producer, medium loader. Better than probing internals; custom socket option is simpler to make synchronous. |
| Client creates socket, passes FD to wineserver | Move Unix socket creation into ntdll, pass FD back through existing FD-transfer infrastructure, have server adopt it. | Server still calls connect and can overwrite BPF ownership; `/proc/PID/exe` still names a Wine loader. Must preserve AFD error behavior, accept-into, caching, duplication, protocol variants, WOW64, and synchronization. | Large invasive Wine change, poor rebase survival. Does not by itself solve either the Windows path or pasta hop. |
| Custom socket option consumed by socketowner | Wine calls `setsockopt` with a private versioned owner record. Host-installed cgroup/setsockopt BPF consumes it and stores metadata on that same socket. No game capabilities or mounted control service. | Requires a new loader feature, strict validation, attachment across sandbox cgroups, and explicit missing-label handling. Labels remain cooperative application metadata, not a new trusted Windows security boundary. | Small Wine integration; medium loader/ABI. Scalar mechanism tested successfully. Preferred transport to prototype. |
| Enforce the deny rule directly in Wine | Refuse AFD socket creation for a matching image, and/or check connect and send requests so passed/inherited sockets cannot bypass the chosen semantics. | Runner-specific policy, not host mihomo attribution. Must cover UDP send without connect and inherited sockets. Applications can delegate network work to another process; exact Windows firewall security equivalence is not established. | Small fixed-image proof of concept, medium configurable policy/tests. Shortest path for just the browser block. |

Wineserver already has the needed high-level identity: each request is dispatched with a `current` thread; its process contains a Windows PID, Unix PID, start time, and full main image path. Its network-table enumerator already reports Windows process owners by enumerating process handles. There is no need to infer the EXE from the Linux loader's filename. [Request dispatch][w-request], [process fields][w-process], [TCP table enumeration][w-tcp-table], [UDP table enumeration][w-udp-table], [NSI TCP request][w-nsi-tcp], [NSI UDP request][w-nsi-udp]

Important implementation details:

- Windows PIDs and `process->unix_pid` are not automatically host TGIDs. Wine runs in a PID namespace; preserve namespace identity and process birth identity, and translate through a trusted host-side registration/lookup if a host PID is needed. Do not reuse a bare PID after exit.
- A Linux task's recorded executable is the Wine ELF loader/preloader. Socketowner's current executable maps do not represent Wine's Windows image. Preserve both identities, with a distinct Windows-image field.
- `current` is cleared after a request. Save the socket's owner while handling creation/connect; do not inspect `current` in a later readiness callback and assume it still names the requester.
- An image identity should include a sandbox/prefix generation and a normalized full Windows path. Define case handling and basename matching. `tbs_browser.exe` alone can match multiple copies; full-path rules offer narrower scope.
- A stable per-connection owner is usually appropriate for mihomo routing. “Latest sender” and “creator/connect requester” must not be silently interchanged, especially with duplicated sockets.

The SO_MARK capability check is explicit in [Linux v6.18 `net/core/sock.c:1514`][kernel-mark]. The unprivileged per-socket range facility is documented in [IP_LOCAL_PORT_RANGE][port-range]. Neither tags packets with a Windows path.

## Part 2: carrying identity beyond pasta

### Verified port and flow behavior

Current upstream `fwd_nat_from_tap()` sets host source port to zero for TCP, allowing the kernel to choose it. For UDP it sets it to the original inner source port. The VM's June pasta source has the same policy. This applies to ordinary outbound TAP traffic, not just gateway-to-loopback mapping. [Current forwarding policy, lines 918–935][p-fwd], [June forwarding policy][p-old-fwd]

TCP obtains a replacement socket and calls connect; normal pasta mode does not populate the flow's actual host address/port using the `getsockname()` branch restricted to vhost-user mode. UDP creates per-flow sockets, binds/connects them, and updates endpoint information. A reliable exporter should query the actual host socket rather than export a configured source port of zero. [TCP creation/connect][p-tcp], [TCP actual-address branch][p-tcp-name], [UDP per-flow socket][p-udp], [UDP actual-address update][p-udp-name]

The source-port preservation idea is therefore **already partly true for UDP and false for TCP**, and neither behavior provides a general cross-namespace identity mapping. Even matching ports must be scoped to the particular pasta instance/inner netns. Host socketowner currently records pasta as the emitting process.

### Existing passt upstream work

The checked manual exposes packet capture/debugging and forwarding configuration, not a supported process-owner or live socket-attribution API. The internal flow table already holds both sides and flow IDs. Its debug formatter can display both sides, but logging is not an atomic, lossless publication protocol, and ordinary pasta TCP records may still contain host port zero. [Manual source][p-man], [flow debug formatter][p-log]

Related upstream work found:

- The 2024 flow-table work made TCP outbound addresses and per-flow UDP translation explicit. [TCP flow-table change][p-flow-commit], [UDP per-flow change][p-udp-commit]
- The February 2025 migration series exports state and socket information for **guest migration**, not Windows process attribution. [Migration discussion][mail-migration], [getsockname change][p-name-commit]
- March 2026's **Pesto protocol proposals** discuss a control protocol to modify/read the *forwarding-rule table*. That is not a readout of live flow → host FD/owner relations. [Pesto discussion][mail-pesto]
- An older UDP splicing discussion specifically addresses retaining UDP source ports. [UDP source-port discussion][mail-udp]

Searches covered the current git tree/log and public passt-dev archive queries for source ports, flow-table export/dump, process ownership/attribution, SO_MARK, and DSCP. No ready-to-use owner export, mark propagation feature, or TCP preservation switch was found. SO_MARK/DSCP archive searches returned HTTP 404; they are inconclusive negatives, not proof no discussion exists. These searches do not rule out unpublished work or every historical thread.

### Candidate transport designs

| Candidate | How it works / matchable result | Requirements, risks, effort |
| --- | --- | --- |
| Preserve TCP source ports | Bind pasta's replacement TCP socket to the inner source port; use `SRC-PORT`, or join to an inner map scoped by pasta/netns. | Small experiment, medium robust patch. Port conflicts with host sockets/other sandboxes, TIME_WAIT, explicit binds and low ports require failure handling. Silent fallback breaks attribution. Port equality does not resolve Wine's Windows image, and source-only keys can conflate flows. No current switch found. |
| Export pasta flow relations | Publish inner netns + full tuple ↔ actual host socket cookie/tuple, with creation/deletion/generation events. Host reader joins to inner owners. Can fill `PROCESS-NAME`/`PROCESS-PATH` after a mihomo reader extension. | Medium pasta patch plus medium/higher loader/reader work. Query actual host endpoints; handle FD reuse, flow-index reuse, UDP expiry, restarts and lost events. An asynchronous event after connect can lose the race to mihomo. Need pre-connect socket labeling or a synchronizing broker. Preferred conceptual bridge. |
| Copy SO_MARK | Pasta cannot read an inner socket's mark from an Ethernet/IP packet: it is not on the wire. A host service could look up an inner mark/identity and set a host mark. | Requires a separate lookup channel/BPF relation anyway; setting marks on host sockets requires host privileges or privileged BPF. Mark may drive routing but fills no stock mihomo process/user rule. Reject as a standalone transport. |
| Copy DSCP/TOS | Read DSCP in TAP IPv4/IPv6 packets and set the host socket's TOS/TCLASS before connect/send. Could fill `DSCP` where the inbound supports it. | Medium patch: retain original headers at TCP flow creation, update UDP per-flow/per-packet treatment, preserve ECN/QoS behavior. Current source has no such propagation. Stock mihomo documents only TPROXY UDP matching. Cannot deliver general TCP browser rules without more changes. |
| Pasta per process/group | Distinct host executable names give `PROCESS-NAME`; distinct inbound channels can give `IN-NAME`. | Works for independent applications/namespaces. Multiple pasta TAPs in one netns do not select themselves by Windows EXE. A shared wineserver still creates every AFD socket in its own netns; moving only clients is insufficient. Splitting prefixes/servers can break launcher/game IPC and shared state. High Wine integration effort for child programs. Not recommended here. |
| slirp4netns/libslirp | Replace pasta with another unprivileged user-mode network backend. | Still opens host sockets in the backend process. Does not recover Windows ownership or supply an attribution bridge automatically. Medium migration/testing and likely another backend patch, without solving Part 1. [slirp4netns project][slirp] |
| Application-configured SOCKS/HTTP proxy | Select per-image proxy credentials; authenticated TCP fills `IN-USER`, or dedicate an inbound for `IN-NAME`/`IN-PORT`. | Small only for cooperative programs with usable per-process proxy settings. WinHTTP, WinINet and Chromium settings differ; UDP/QUIC/custom networking may bypass them. Environment-wide proxy settings are not per-image isolation. Host destination restrictions must also be enforced by the broker. |
| Transparent/TUN proxy inside namespace | A helper learns inner owner, intercepts all traffic, and opens an authenticated proxy connection per identity. | High effort. Transparent interception needs namespace setup outside the capability-free game, and usually a TUN/userspace TCP/IP stack. Does not solve Wine owner identity by itself. Stock SOCKS UDP username propagation fails the checked code path; choose a proven user-aware UDP protocol or dedicated inbound instead. |
| Dedicated host broker to mihomo | A restricted channel transports requests/identity to a host service which can talk to one specific inbound. `IN-USER`/`IN-NAME` can represent the program. | Medium/high service/protocol work. No general host listener access for the game. Revalidate every requested destination after resolution and maintain the existing LAN/host deny rules: CONNECT payloads can otherwise bypass namespace routing prohibitions. No additional access is authorized by this report. |
| Extend socketowner relay maps | Keep native host ownership intact; publish separate relations from pasta sockets to inner owners and Windows image metadata. Mihomo resolves them before native process fallback. | Medium/high, but fits existing privileged loader architecture. Requires Wine identity plus pasta mapping, new schemas, lifecycle/error policy, and reader support. Recommended with synchronous annotation. |

Preserving ports is not necessary if pasta annotates its socket while it still has both the inner tuple and replacement FD. A socket cookie or socket-local record can identify the replacement before its source port is allocated. The existing egress hook can publish the eventual **packet** source tuple after host redirect/NAT. This avoids guessing a port translation.

## What mihomo can actually match

The official rule documentation lists the relevant fields below. They are inputs to rule matching, not arbitrary variables that pasta can set by changing its command line. [Mihomo rule reference][mh-rules]

| Rule field | Which designs can supply it | Limit |
| --- | --- | --- |
| `PROCESS-NAME`, `PROCESS-PATH`, regex/wildcard variants | Existing separate pasta binaries; proposed Windows metadata resolver | Stock Linux lookup returns the Linux executable. Windows full paths need separate parsing/normalization; Go's Linux `filepath.Base` does not split Windows backslashes. |
| `UID` | Actual host UID from socketowner | All sandbox programs normally share the user. Do not invent per-program UIDs inside v1 records. |
| `SRC-PORT`, source IP rules | Deliberate host port/address allocation | Namespace source ports do not automatically become host ports. Finite identifiers, collisions and reuse. |
| `IN-USER` | Inbound authentication in protocols which propagate user identity | Not Windows login identity, SO_MARK, or a cgroup. Checked SOCKS TCP supports it; the separate SOCKS UDP listener does not attach the authenticated TCP username. |
| `IN-NAME`, `IN-PORT`, `IN-TYPE` | Dedicated/configured proxy inbounds | Classifies the inbound connection/channel, not an arbitrary inner process without a broker. |
| `DSCP` | Packet DSCP reaching a supported inbound | Documentation restricts it to TPROXY UDP. |
| `NETWORK`, destination/domain rules | Already available with normal inbound metadata | Useful in combination, but they do not establish Windows executable identity. |

There is no documented generic socket-mark, cgroup-ID, Windows-PID, or socket-cookie rule. Marks used for routing/listener configuration are not a `MARK` routing-rule predicate. Extending metadata resolution to populate process fields is the natural way to keep rules such as `PROCESS-NAME,tbs_browser.exe,REJECT`.

In both the local fork and checked upstream mihomo, SOCKS5 TCP sets `WithInUser(user)` after authentication. UDP association keeps the TCP connection alive, while datagrams enter through a separate handler without that user addition. Therefore do **not** claim that “one SOCKS username per program” already works for TCP and UDP together. [SOCKS TCP implementation][mh-socks-tcp], [SOCKS UDP implementation][mh-socks-udp], [authenticated SOCKS configuration][mh-socks-doc]

## Proposed annotation implementation, with unchanged sandbox privileges

This is the original custom-sockopt alternative, not a patch delivered by this research. The later host-only follow-up replaces its Wine annotation step with live LSM inspection for a supported Wine build; the relay/schema/lifecycle requirements still apply.

### Ownership and relation records

Keep socketowner ABI v1 unchanged. Its `conn_owners` values mean actual Linux socket users and its executable maps mean Linux executable paths. Replacing pasta/wineserver with a claimed Windows PID or putting a Windows path into `exec_tasks` would change that contract. Optional maps may be added only if v1 guarantees remain true; otherwise use a distinct ABI version and pin directory. [ABI evolution rules][map-contract]

Add logically separate records for:

- **Windows socket identity:** socket cookie/storage identity, sandbox/prefix generation, Windows process ID/generation, normalized Windows image; actual Linux reporter identity alongside it.
- **Inner flow identity:** inner netns cookie, address family, protocol, full local and remote tuples, observation/expiry generation. Preserve ownership source and whether it is known or ambiguous.
- **Relay relation:** pasta instance generation, host socket identity, inner netns/flow, relation lifetime. Use full tuples where sockets share a local port. FD numbers and flow-table indices are not persistent IDs.

The v1 source-address/port/protocol key can be useful for initial prototypes but cannot distinguish different destinations, shared UDP endpoints, or all reuse cases. Do not silently interpret an old LRU entry as the owner of a new connection. Close/retirement, LRU eviction, relaunch, process exit and namespace teardown need explicit treatment. Existing UID and PID/start-time validation should remain independent of any Windows image claim.

### Synchronous labeling path

1. The host loader attaches its new sockopt and flow hooks to the relevant cgroup hierarchy. Existing cgroup placement/attachment must be checked for both game and external pasta. No BPF program is loaded by the sandbox.
2. In wineserver, after Unix socket creation and before making it usable, call a private, versioned annotation sockopt with the requesting image identity. Retain a per-socket policy identity for later async work. Decide how duplicated/inherited sockets and connect-by-another-process update that identity. The generic Linux LSM “latest sender” hook must not erase the separate Windows record.
3. The loader consumes that sockopt and stores the label on the kernel socket. At inner egress, publish the inner tuple/owner before the packet reaches the TAP reader. This ordering matters for the first SYN and first UDP datagram.
4. Pasta obtains/registers the target netns cookie during its namespace setup. Before connecting a TCP replacement socket, or sending the first UDP datagram, annotate that host socket with the inner flow reference. The sockopt BPF hook can resolve/copy the inner identity into host socket storage synchronously. Socket pooling means labeling must happen on the selected FD after any discard/replacement in the connection path.
5. Host egress publishes the resolved identity using the actual outgoing tuple, alongside native owner records. This preserves existing NAT/redirect handling and avoids a notification arriving after mihomo's first lookup.
6. Mihomo reads the new optional metadata first, populates an explicitly normalized Windows basename/path for process rules, and preserves native provenance for diagnostics. Its current process rule lookup must not subsequently overwrite an already resolved Windows identity. Ordinary Linux and unlabelled traffic continue through the existing resolver.

The special sockopt does **not** need to grant permission to set a kernel mark. The BPF handler recognizes a private level/option, validates the payload, records metadata, sets `optlen=-1`, and lets the syscall succeed without invoking the normal sockopt implementation. Without a handler it gets ENOPROTOOPT. A production protocol needs a proper capability/ABI handshake: do not silently treat “labeling unsupported” as “the requested block is enforced.” [Kernel mechanism][sockopt-doc]

For the specific rule, the intended outcome would be:

```yaml
rules:
  - PROCESS-NAME,tbs_browser.exe,REJECT
  # Existing per-sandbox/default rules follow.
```

This is an example for the proposed resolver. It does not work through the unmodified chain today. Namespace/prefix scoping may need a synthetic path or an additional metadata field if the same basename should be blocked in only one sandbox. Do not overload `IN-USER` with an unauthenticated label to avoid adding the appropriate interface.

### Trust, unknown cases, and maintenance

Use the actual reporter's cgroup, UID, host process generation and registered pasta instance to scope annotations. A pasta relation must reference only its registered inner namespace. It must not let an arbitrary sandbox claim another user's host socket or overwrite another sandbox's identity. Keep pinned maps writable only by the loader; do not mount map write access into the game.

Windows labels are cooperative Wine/runtime metadata. An actively malicious process sharing an untrusted Wine environment can lie, tamper with user-space state, duplicate sockets, or ask another program to communicate. This design supports executable-specific policy for normal applications; it does not turn Wine into a trusted Windows kernel firewall. Uncertain/missing attribution needs a deliberate rule outcome, especially if the goal is to guarantee a deny. Never silently fall back to an allow merely because a probe or annotation was missing.

The patches should avoid AFD protocol changes: add annotations at a few existing creation/connection/send ownership points and keep the public label schema independent of Wine structs. Source rebases should be modest; rebuilding DW remains a maintenance cost. Pasta's flow code has changed materially across releases, so test both TCP and UDP integration points on each update. Keep changes out of run-in-sandbox's game privilege setup.

Estimated work: a scalar producer/consumer demonstration is small (and was run here); a first end-to-end TCP prototype is several focused days; robust TCP/UDP lifecycle, native/WOW64 builds, ABI compatibility, unknown-owner behavior and regression coverage are more plausibly several weeks. These estimates assume familiarity with the existing loader and reader and do not include upstreaming. No upstream contact or PR is needed for a local prototype.

## Experiments and observed results

Scripts and selected outputs are retained in [attribution-research-evidence/](attribution-research-evidence/README.md). Tests used the VM's kernel `7.2.8-1-default`; no packages were installed for this task.

### 1. Outbound internet through unmodified pasta

Pasta `20260612.a9c61ff-1.3` created a fresh namespace with `--config-net -4`, all four automatic forwarding directions disabled, and host-loopback/guest-address mappings disabled. A Python client explicitly bound source ports and connected to public `1.1.1.1:443` / `1.1.1.1:53`. Host `ss` identified pasta's actual socket FDs/ports; strace correlated them to the client requests. This was the TAP-to-internet path, not a host-loopback test.

| Protocol / remote | Inner source port | VM host socket source port | Result |
| --- | ---: | ---: | --- |
| TCP / 1.1.1.1:443 | 41234 | 37386 | Established |
| TCP / 1.1.1.1:443 | 58830 | 37402 | Established |
| UDP / 1.1.1.1:53 | 41234 | 41234 | 61-byte DNS response |
| UDP / 1.1.1.1:53 | 58830 | 58830 | 61-byte DNS response |

These are **VM host socket ports**. The upstream router's WAN NAT port was not observed or needed. IPv6, source-port collisions, multiple concurrent pasta instances, and throughput were not tested. The namespace used pasta's standalone setup for this narrow test, not the full sandbox's route policy; only the listed public destinations were contacted.

### 2. Wine syscall ownership

A 64-bit Winelib Winsock probe was built using the already installed DW Wine compiler and run against a task-only TCP/UDP echo server on VM loopback. It exercised synchronous TCP, overlapped send, deliberately pending overlapped receive, ConnectEx with initial data, unconnected UDP sendto, then connected UDP send/recv.

- DW runtime: existing local DW 11.0-15 build at `a451b29d1ca0baf2da86d3cdf0b9bffdc9752226` with display patches. SHA-256 comparison showed its `server/sock.c` and `dlls/ntdll/unix/socket.c` **exactly match** the inspected release sources. No changes were made to that existing build.
- Upstream runtime: VM's packaged Wine 11.19, separate task prefix, same probe.
- Both traced runs showed wineserver creating TCP/UDP sockets and calling connect. Ordinary payload sendmsg/recvmsg ran in the client process. ConnectEx initial payload ran in wineserver. The receive reported WSA_IO_PENDING (997) and completed successfully; ConnectEx also reported pending and returned the 14-byte echo.

The helper is Winelib, not a NIKKE binary or a test of 32-bit PE/WOW64 syscall dispatch. It confirms the shared Winsock/AFD Unix paths; modern Proton comparisons beyond DW are source-only. WinHTTP/WinINet/schannel, AcceptEx and TransmitFile findings are source-only. No BPF attribution map was loaded for this Wine trace, so exact timing of a production mihomo routing decision was not measured.

### 3. Capability-free tagging options

Inside `bwrap --unshare-all --unshare-user --disable-userns` with all capability sets zero:

| Operation | Observed result |
| --- | --- |
| IPv4 and IPv6 SO_MARK=123 | EPERM |
| IPv4 IP_TOS=40 | Success, read back 40 |
| IPv6 IPV6_TCLASS=40 | Success, read back 40 |
| IPv4 per-socket IP_LOCAL_PORT_RANGE=45100–45199 | Success; an ephemeral bind selected 45157 |

The test checked setters, not preservation through pasta. The TOS value represents DSCP 10 with ECN zero. IPv6 per-socket port range behavior was not tested.

### 4. Custom BPF socket annotation

A minimal cgroup/setsockopt program was loaded under a **dedicated temporary cgroup**, with dedicated bpffs pins. It recognized an experimental private socket-option level, copied one 32-bit label into `BPF_MAP_TYPE_SK_STORAGE`, copied the stored value to an observation map, and bypassed ordinary kernel sockopt processing.

A bwrap child with every capability set zero successfully submitted `0x12345678`; the observation map contained decimal `305419896`. SO_MARK still failed with EPERM. The same client outside the attached cgroup got ENOPROTOOPT for the private option. This verifies a synchronous, unprivileged label submission and socket-storage mechanism on the VM. It does **not** verify the proposed complete Wine label schema, source/relay join, first-SYN publication, or mihomo integration.

### Cleanup and remaining validation

The task's echo servers, Wine servers/prefixes, pasta processes/namespaces, temporary cgroup, BPF program/pins, and VM run directory were removed after collecting evidence. No firewall, service configuration, installed runner, kernel setting, or package state was changed. The VM keep-awake hold was released. Existing unrelated VM work was preserved.

Before adopting the proposed design, the decisive next test is an end-to-end VM prototype proving that a TCP SYN and the first UDP datagram are attributed before mihomo matches rules. Include native Linux bypass, UDP/QUIC, IPv4/IPv6, two sandbox instances with overlapping ports, socket duplication, fast exit/PID reuse, FD/socket-pool reuse, loader and pasta restarts, map eviction, label failure, and NAT/redirection. Then trace the real launcher to verify that the selected Windows image owns all traffic intended to be blocked.

## Follow-up: host-only attribution without a Wine patch

The user pointed to the existing eBPF domain-routing work and asked whether Wine's common Win32 boundary avoids the browser-specific TLS problem. **Yes for process attribution, and a small host-only experiment now demonstrates the essential mechanism.** The archived feature was inspected read-only; it was not resumed or deployed.

The hostname branch at socketowner `b93b7808d0e5b5e26dfec88b94b8515736f72e8f` already reads live userspace state from `lsm/socket_sendmsg` while the kernel holds the actual socket. Its mature send path does not require the earlier handshake uprobe. Different OpenSSL/BIO/browser call chains made the TLS adapter complicated. [Existing live-send design][hostname-live], [existing LSM implementation][hostname-code]

Wine offers a shorter path. DW wineserver's request dispatcher assigns its global `current` pointer to the requesting thread before handling the request, then clears it afterwards. That thread points to a process containing the Windows image, Windows PID and client Unix PID. At synchronous Unix socket creation/connect, those values can be read from the server's own memory with `bpf_probe_read_user`, directly in the kernel LSM hook. The kernel socket pointer is supplied by that hook; no numeric-FD-table traversal is necessary. [DW request dispatch][dw-request], [DW process fields][dw-process]

The prototype used:

- `lsm/socket_post_create` to capture the requesting image before returning the new AFD socket, including unconnected UDP;
- `lsm/socket_connect` to capture the connect requester before the kernel sends a SYN;
- socket-local BPF storage to retain that Windows identity;
- `lsm/socket_sendmsg` to verify the same identity is present when the client sends, or when wineserver sends ConnectEx's initial payload.

An unchanged existing DW 11.0-15 build ran two differently named copies of the earlier Winelib Winsock probe through one wineserver. Each performed ordinary TCP, overlapped I/O, ConnectEx initial send, UDP sendto before connect, and connected UDP. **All 22 observations matched the correct image and Windows PID:** `alpha.exe` / Windows PID 116 / client Unix PID 61140, and `beta.exe` / Windows PID 124 / client Unix PID 61144. The actual create/connect caller was the same wineserver, TGID 61100. The first unconnected UDP send was labelled before any UDP connect. The later ConnectEx server send retained the corresponding client's Windows identity. Probe stdout independently supplied the expected Windows PIDs.

Evidence and source: [host-ebpf/README.md](attribution-research-evidence/host-ebpf/README.md), [observations](attribution-research-evidence/host-ebpf/observations.txt), [assertions](attribution-research-evidence/host-ebpf/assertions.txt). No Wine modification, uprobe, DLL injection, custom sockopt, app TLS hook, or process debugging attachment was used. GDB read debug types/symbols from the binary offline to establish the exact profile.

This is not a stable-Win32-ABI-only implementation. The Windows public ABI offers common socket functions, and a public-function uprobe can identify its calling process, but its `SOCKET` is a Windows handle rather than the held Linux socket. The demonstrated LSM method gets both the actual socket and request identity together by reading Wine internals. Those internals require per-build profiles. For the tested ELF EXEC binary, `current` was at `0x4abba0`; the thread/process field offsets were 136, 152, 188, 252 and 256. Its SHA-256 was `3bb468ca4d60c89074c6d854af871931f963586ac5915cca964e488b21422186`. PIE/ASLR builds need verified mapping relocation. Stripped binaries need matching symbols or a separately established build profile.

The experiment is narrower than production support: two sequential 64-bit Winelib clients, one existing unmodified DW build, VM loopback, no bwrap/PID namespace or pasta in this follow-up. It did not test concurrent mutation, inherited/duplicated sockets, multiple Wine servers, IPv6, native PE/WOW64, cold memory reads, denied connections, or lifecycle/map failures. Its small diagnostic recorder mutates a socket record on send and has none of the hostname branch's production-style publication/lifetime guards; it is evidence of feasibility, not a deployable policy module. Source-layout reads can fail and must yield unknown rather than an invented identity.

The corrected recommendation is to investigate this **host-only Wine adapter before requiring a runner patch**. Its compatibility scope is a Wine build, rather than every application's TLS stack. Pasta still needs a separate relation to its replacement host sockets; another build-specific host adapter may be possible there, but was not tested. The custom-sockopt Wine/pasta patches remain an alternative with a cleaner explicit metadata contract. All BPF links/objects, task processes/prefix and VM scratch were removed after the final run, and this follow-up's keep-awake hold was released.

## Implementation milestone: host-only Wine observer

The follow-up is now implemented on branch `wine-process-attribution`, under
`experiments/wine/`. The [observer README](../README.md) has build/use
instructions; [validation](../validation/README.md) and raw logs record the checks. This remains
a separate diagnostic command, with no deployment or native map ABI change.

The implementation verifies the exact running ELF and its mapping against a
reviewed SHA-256/layout profile, registers the original task through a pidfd,
binds its kernel executable reference, and revokes on exec. It captures an
immutable Windows **socket creator** at socket creation, rather than replacing
the name on every connect/send. The first outgoing packet carries the actual
namespace cookie and tuple. Unsupported/read-failed metadata stays unknown;
observer lifetime IDs distinguish restarts.

The final VM checks passed for nested PID/user namespaces with all capabilities
zero, IPv4/IPv6 TCP and UDP, first SYNs, inherited sends, unregistered forks,
failed-connect creator preservation, malformed/oversized/absent requests, FD
reuse, restart, exit and exec revocation. Those cases used an explicit request
fixture, not Wine. Separately, the unchanged DW build passed with two sequential
Winelib programs: all six socket creations and six first packets matched their
expected Windows images/PIDs. The probes also completed pending overlapped I/O
and ConnectEx initial data. Real Wine in bwrap, native PE/WOW64, concurrent
clients and NIKKE remain untested.

This establishes a more carefully bound diagnostic Wine hop. A production
reader still needs publication, expiry/closure and unknown-result semantics;
pasta's replacement-socket relation and mihomo integration remain open. The
observer is not a routing authority and does not yet make a `tbs_browser.exe`
rule work. All task-only VM state was cleaned after retaining the evidence.

## Implementation milestone: routing through pasta

A second milestone removed the need for the pasta patch recommended above. The
relay joins a pasta socket to the inner flow from kernel hooks alone, and mihomo
reads a separate versioned map. See the [observer README](../README.md#how-the-relay-works)
and the [routing validation](../validation/routing/README.md).

## Implementation milestone: no profiles

A third milestone replaced the build profile. The server's memory is no longer read:
the request pipe identifies the client, and the client's public PEB names it. See
the [observer README](../README.md#how-capture-works).

## Source links

[sandbox-net]: https://github.com/nosini/run-in-sandbox/blob/18efb491689f211ec19a27da67340c7941e33141/sandbox-game#L2080
[map-contract]: https://github.com/nosini/socketowner/blob/2f7ff573da36c60f2ad921af6bacc7d7954cf67f/docs/map-interface.md
[so-lsm]: https://github.com/nosini/socketowner/blob/2f7ff573da36c60f2ad921af6bacc7d7954cf67f/bpf/execpath.c#L224
[mh-process]: https://github.com/nosini/mihomo/blob/08632a080a40e3330b3cb5829d61e9cc223a8bcb/tunnel/tunnel.go#L351
[dw-release]: https://github.com/dawn-winery/dwproton-mirror/tree/b8c56daa4cd1f8ce0ce9c4135bf587e063e4b02f
[dw-module]: https://github.com/dawn-winery/dwproton-mirror/blob/b8c56daa4cd1f8ce0ce9c4135bf587e063e4b02f/.gitmodules#L1
[w-create]: https://github.com/wine-mirror/wine/blob/0738d528db522f52d9d75f2aec712688dd31d1d2/dlls/ws2_32/socket.c#L4040
[w-init]: https://github.com/wine-mirror/wine/blob/0738d528db522f52d9d75f2aec712688dd31d1d2/server/sock.c#L1901
[w-connect]: https://github.com/wine-mirror/wine/blob/0738d528db522f52d9d75f2aec712688dd31d1d2/server/sock.c#L2663
[w-autobind]: https://github.com/wine-mirror/wine/blob/0738d528db522f52d9d75f2aec712688dd31d1d2/server/sock.c#L4013
[w-io]: https://github.com/wine-mirror/wine/blob/0738d528db522f52d9d75f2aec712688dd31d1d2/dlls/ntdll/unix/socket.c#L790
[w-recv-async]: https://github.com/wine-mirror/wine/blob/0738d528db522f52d9d75f2aec712688dd31d1d2/dlls/ntdll/unix/socket.c#L878
[w-send-async]: https://github.com/wine-mirror/wine/blob/0738d528db522f52d9d75f2aec712688dd31d1d2/dlls/ntdll/unix/socket.c#L1134
[w-connect-data]: https://github.com/wine-mirror/wine/blob/0738d528db522f52d9d75f2aec712688dd31d1d2/server/sock.c#L1057
[w-accept-data]: https://github.com/wine-mirror/wine/blob/0738d528db522f52d9d75f2aec712688dd31d1d2/server/sock.c#L920
[w-fd-server]: https://github.com/wine-mirror/wine/blob/0738d528db522f52d9d75f2aec712688dd31d1d2/server/request.c#L440
[w-fd-client]: https://github.com/wine-mirror/wine/blob/0738d528db522f52d9d75f2aec712688dd31d1d2/dlls/ntdll/unix/server.c#L988
[w-readfile]: https://github.com/wine-mirror/wine/blob/0738d528db522f52d9d75f2aec712688dd31d1d2/dlls/ntdll/unix/file.c#L5837
[w-writefile]: https://github.com/wine-mirror/wine/blob/0738d528db522f52d9d75f2aec712688dd31d1d2/dlls/ntdll/unix/file.c#L6156
[w-transmit]: https://github.com/wine-mirror/wine/blob/0738d528db522f52d9d75f2aec712688dd31d1d2/dlls/ntdll/unix/socket.c#L1372
[w-http-connect]: https://github.com/wine-mirror/wine/blob/0738d528db522f52d9d75f2aec712688dd31d1d2/dlls/winhttp/net.c#L212
[w-http-send]: https://github.com/wine-mirror/wine/blob/0738d528db522f52d9d75f2aec712688dd31d1d2/dlls/winhttp/net.c#L35
[w-http-tls]: https://github.com/wine-mirror/wine/blob/0738d528db522f52d9d75f2aec712688dd31d1d2/dlls/winhttp/net.c#L449
[w-inet]: https://github.com/wine-mirror/wine/blob/0738d528db522f52d9d75f2aec712688dd31d1d2/dlls/wininet/netconnection.c#L289
[w-inet-connect]: https://github.com/wine-mirror/wine/blob/0738d528db522f52d9d75f2aec712688dd31d1d2/dlls/wininet/utility.c#L96
[w-inet-tls]: https://github.com/wine-mirror/wine/blob/0738d528db522f52d9d75f2aec712688dd31d1d2/dlls/wininet/netconnection.c#L600
[w-schannel]: https://github.com/wine-mirror/wine/blob/0738d528db522f52d9d75f2aec712688dd31d1d2/dlls/secur32/schannel_gnutls.c#L317
[w-request]: https://github.com/wine-mirror/wine/blob/0738d528db522f52d9d75f2aec712688dd31d1d2/server/request.c#L271
[w-process]: https://github.com/wine-mirror/wine/blob/0738d528db522f52d9d75f2aec712688dd31d1d2/server/process.h#L36
[w-tcp-table]: https://github.com/wine-mirror/wine/blob/0738d528db522f52d9d75f2aec712688dd31d1d2/server/sock.c#L4250
[w-udp-table]: https://github.com/wine-mirror/wine/blob/0738d528db522f52d9d75f2aec712688dd31d1d2/server/sock.c#L4334
[w-nsi-tcp]: https://github.com/wine-mirror/wine/blob/0738d528db522f52d9d75f2aec712688dd31d1d2/dlls/nsiproxy.sys/tcp.c#L316
[w-nsi-udp]: https://github.com/wine-mirror/wine/blob/0738d528db522f52d9d75f2aec712688dd31d1d2/dlls/nsiproxy.sys/udp.c#L226
[v-init]: https://github.com/ValveSoftware/wine/blob/e60892cc2398b0a83c332a2078c7b85e47bdb42b/server/sock.c#L1950
[v-connect]: https://github.com/ValveSoftware/wine/blob/e60892cc2398b0a83c332a2078c7b85e47bdb42b/server/sock.c#L2750
[v-send]: https://github.com/ValveSoftware/wine/blob/e60892cc2398b0a83c332a2078c7b85e47bdb42b/dlls/ntdll/unix/socket.c#L1094
[v-http]: https://github.com/ValveSoftware/wine/blob/e60892cc2398b0a83c332a2078c7b85e47bdb42b/dlls/winhttp/net.c#L221
[v-inet]: https://github.com/ValveSoftware/wine/blob/e60892cc2398b0a83c332a2078c7b85e47bdb42b/dlls/wininet/netconnection.c#L379
[v-schannel]: https://github.com/ValveSoftware/wine/blob/e60892cc2398b0a83c332a2078c7b85e47bdb42b/dlls/secur32/schannel_gnutls.c#L317
[ve-connect]: https://github.com/ValveSoftware/wine/blob/7fc704ef49c50e9702c9983a5250d5738697bb04/server/sock.c#L2750
[dw-init]: https://dawn.wine/dawn-winery/wine-dwproton/src/commit/b75a4125963073b01d2b3bfce6060d697d02066b/server/sock.c#L1965
[dw-connect]: https://dawn.wine/dawn-winery/wine-dwproton/src/commit/b75a4125963073b01d2b3bfce6060d697d02066b/server/sock.c#L2859
[dw-send]: https://dawn.wine/dawn-winery/wine-dwproton/src/commit/b75a4125963073b01d2b3bfce6060d697d02066b/dlls/ntdll/unix/socket.c#L1098
[dw-http]: https://dawn.wine/dawn-winery/wine-dwproton/src/commit/b75a4125963073b01d2b3bfce6060d697d02066b/dlls/winhttp/net.c#L223
[dw-inet]: https://dawn.wine/dawn-winery/wine-dwproton/src/commit/b75a4125963073b01d2b3bfce6060d697d02066b/dlls/wininet/netconnection.c#L379
[dw-schannel]: https://dawn.wine/dawn-winery/wine-dwproton/src/commit/b75a4125963073b01d2b3bfce6060d697d02066b/dlls/secur32/schannel_gnutls.c#L317
[dw14-connect]: https://dawn.wine/dawn-winery/wine-dwproton/src/commit/b585905ec92032840e924e4e2a88382523e92ed3/server/sock.c#L2859
[dw13-connect]: https://dawn.wine/dawn-winery/wine-dwproton/src/commit/0f9987ff4bcd61a88ff68a53ab808e19bb3f0f5c/server/sock.c#L2859
[old5-connect]: https://github.com/wine-mirror/wine/blob/wine-5.0/dlls/ws2_32/socket.c#L3469
[old5-init]: https://github.com/wine-mirror/wine/blob/wine-5.0/server/sock.c#L658
[old6-connect]: https://github.com/wine-mirror/wine/blob/wine-6.0/dlls/ws2_32/socket.c#L3315
[old6-init]: https://github.com/wine-mirror/wine/blob/wine-6.0/server/sock.c#L1042
[old7-connect]: https://github.com/wine-mirror/wine/blob/wine-7.0/server/sock.c#L2332
[old8-connect]: https://github.com/wine-mirror/wine/blob/wine-8.0/server/sock.c#L2604
[old9-connect]: https://github.com/wine-mirror/wine/blob/wine-9.0/server/sock.c#L2651
[old10-connect]: https://github.com/wine-mirror/wine/blob/wine-10.0/server/sock.c#L2677
[old11-connect]: https://github.com/wine-mirror/wine/blob/wine-11.0/server/sock.c#L2750
[p-fwd]: https://passt.top/passt/tree/fwd.c?id=6aa4f88bd9846411edff3ed70460475b538addca#n918
[p-old-fwd]: https://passt.top/passt/tree/fwd.c?id=a9c61ffaf15347b8dfcc2347c5440e4b0e82333b#n929
[p-tcp]: https://passt.top/passt/tree/tcp.c?id=6aa4f88bd9846411edff3ed70460475b538addca#n1689
[p-tcp-name]: https://passt.top/passt/tree/tcp.c?id=6aa4f88bd9846411edff3ed70460475b538addca#n1810
[p-udp]: https://passt.top/passt/tree/udp_flow.c?id=6aa4f88bd9846411edff3ed70460475b538addca#n70
[p-udp-name]: https://passt.top/passt/tree/udp_flow.c?id=6aa4f88bd9846411edff3ed70460475b538addca#n166
[p-log]: https://passt.top/passt/tree/flow.c?id=6aa4f88bd9846411edff3ed70460475b538addca#n311
[p-man]: https://passt.top/passt/tree/passt.1?id=6aa4f88bd9846411edff3ed70460475b538addca
[p-flow-commit]: https://passt.top/passt/commit/?id=e2ea10e246a4e4cd81f6fe53b323a4d2f57e464c
[p-udp-commit]: https://passt.top/passt/commit/?id=e0647ad80c63fcad6a9dc31541881fa02aeaac98
[p-name-commit]: https://passt.top/passt/commit/?id=52e57f9c9a6d8ae4153ac592d01d868b31c10171
[mail-migration]: https://archives.passt.top/passt-dev/?t=20250204064421
[mail-pesto]: https://archives.passt.top/passt-dev/aae07j0fhcXOFeab@zatzit/
[mail-udp]: https://lists.passt.top/hyperkitty/list/passt-dev%40passt.top/message/R7EH3PVQXBW4B56JS6KEN6TDNC5NJ7AT/
[mh-rules]: https://wiki.metacubex.one/en/config/rules/
[mh-socks-doc]: https://wiki.metacubex.one/en/config/inbound/listeners/socks/
[mh-socks-tcp]: https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/socks/tcp.go#L180
[mh-socks-udp]: https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/socks/udp.go#L82
[kernel-mark]: https://github.com/torvalds/linux/blob/v6.18/net/core/sock.c#L1514
[sockopt-doc]: https://docs.kernel.org/bpf/prog_cgroup_sockopt.html
[port-range]: https://man7.org/linux/man-pages/man2/IP_LOCAL_PORT_RANGE.2const.html
[slirp]: https://github.com/rootless-containers/slirp4netns
[hostname-live]: https://github.com/nosini/socketowner/blob/b93b7808d0e5b5e26dfec88b94b8515736f72e8f/experiments/hostname/SEND.md#L3
[hostname-code]: https://github.com/nosini/socketowner/blob/b93b7808d0e5b5e26dfec88b94b8515736f72e8f/experiments/hostname/bpf/send.c#L503
[dw-request]: https://dawn.wine/dawn-winery/wine-dwproton/src/commit/b75a4125963073b01d2b3bfce6060d697d02066b/server/request.c#L292
[dw-process]: https://dawn.wine/dawn-winery/wine-dwproton/src/commit/b75a4125963073b01d2b3bfce6060d697d02066b/server/process.h#L36
