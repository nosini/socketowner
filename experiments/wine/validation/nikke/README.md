# NIKKE launcher on the desktop, 2026-11-02

The first run against a real program: the user's own NIKKE launch in
`sandbox-game`, on their desktop and runner, with the observer started first and
no `-pin`, so routing was untouched. It covers about ten seconds of socket activity
and no process of the game itself. The raw events hold real addresses and are not
kept here.

The observer lost no events. Every record had a known status except DNS.

| Program | Client | Sockets | Routable TCP flows | Loopback TCP flows |
| --- | --- | ---: | ---: | ---: |
| `nikke_launcher.exe` | Name only, as for a 32-bit client | 60 | 7 | 52 |
| `intl_service.exe` | Full path, Windows PID | 49 | 13 | 24 |
| `tbs_browser.exe` | Full path, Windows PID | 9 | 6 | 0 |

- All 26 routable TCP flows joined their pasta socket with the right name. None
  was ambiguous or missed. On the host they reached a local redirect port, which
  shows them entering the proxy path.
- Loopback flows stay in the sandbox and never reach pasta or mihomo.
- All 27 UDP relays were DNS, status `no-inner-flow`. No inner Windows socket sent
  them: they came with pasta's `--dns-forward` translation, as predicted.
- 16 UDP sockets sent nothing. Two `server` events were one wineserver daemonizing;
  all sockets came from one process.
- `tbs_browser.exe` does make its own connections, on ports 80 and 443.
