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

## Routing by name on the desktop

The same day, on the user's desktop with SELinux enforcing, mihomo ran this branch
with `PROCESS-NAME,tbs_browser.exe,REJECT` as its first rule, and the observer ran
with `-pin`. The launch reached the game, over about 68 seconds of socket activity.
A temporary policy module let mihomo read maps from a sudo-started observer; the
service needs a proper answer to this. The test build lasted only for this test.

mihomo's own matches, and the observer's relays:

| Program | mihomo TCP | mihomo UDP | Relays | Identity |
| --- | ---: | ---: | --- | --- |
| `nikke.exe` | 54 | 2 | 54 TCP, 4 UDP | Full path, Windows PID |
| `intl_service.exe` | 16 | 0 | 16 TCP | Full path, Windows PID |
| `tbs_browser.exe` | 10, all REJECT | 0 | 10 TCP | Full path, Windows PID |
| `nikke_launcher.exe` | 8 | 0 | 8 TCP | Name only |

- All 90 routable inner flows joined a pasta socket with a known name, and no event
  was lost. There were no SELinux denials or mihomo errors.
- mihomo reported no `wine-unknown`. The 129 DNS relays stayed unknown in the
  observer, but this configuration did not send them through mihomo.
- mihomo named one flow `goddess-of-victory-nikke-pasta.avx2`, at about the time
  the first Windows socket appeared. Every TCP connect by a registered pasta emits
  a relay event, and this one has none, so it preceded registration. That makes it
  traffic from before wineserver's first request, not a Windows socket missed
  afterwards. The observer could not see what sent it. The user's existing rule
  for that pasta name matched it.
- `pasta.avx2` flows continued steadily from before the test began, so they belong
  to another pasta and are unrelated to this launch.

The user reported NIKKE worked normally with `tbs_browser.exe` blocked. Rollback
restored the original mihomo and config, verified, and removed the policy module.

