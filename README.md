# socketowner

socketowner records which Linux process owns an outgoing TCP or UDP connection, so
mihomo can match process rules without permission to inspect other processes.
A small privileged loader attaches the BPF programs and exits. mihomo reads the
resulting maps without BPF capabilities. Records can outlive both the socket and
the process, so short connections can still be identified.

The loader is installed and updated separately from mihomo. Before 2026-10-17 its
executable was named `mihomo-sockowner`; installations using that name can switch
by following the hardened-proxy-service update notes, or by detaching the old
binary, removing it and installing this one.

## Installing and using

On openSUSE Tumbleweed, the
[home:Nosini:proxy](https://build.opensuse.org/project/show/home:Nosini:proxy)
repository builds the loader from `main`, with its BPF programs compiled from source, as
`/usr/bin/socketowner`; `socketowner-wine-observer` holds the [Wine observer](wine/README.md):

```sh
sudo zypper ar -p 90 -f https://download.opensuse.org/repositories/home:/Nosini:/proxy/openSUSE_Tumbleweed/ nosini-proxy
sudo zypper ref nosini-proxy
sudo zypper in socketowner
```

The packages install only the executables. The units, reader permissions and SELinux
policy come with `hardened-proxy-service` from the same repository, which recommends
this package; see its
[installation notes](https://github.com/nosini/hardened-proxy-service#installing-on-opensuse-tumbleweed).
The repository's priority matters because its `mihomo` replaces openSUSE's. The commands
below use the path of a build installed by hand, `/usr/local/bin/socketowner`.

Elsewhere, install a separately built `socketowner` binary:

```sh
sudo install -m 755 socketowner /usr/local/bin/socketowner
```

For a sandboxed systemd setup with a reader group, read-only map mounts and SELinux
policy, follow [hardened-proxy-service](https://github.com/nosini/hardened-proxy-service#process-lookup).
That repository owns the service units and policy; it uses this loader as a
separate prerequisite.

To attach manually, with the existing `mihomo` group allowed to read the maps:

```sh
sudo /usr/local/bin/socketowner -reader-group mihomo -exec-paths attach
```

The default pin directory is `/sys/fs/bpf/mihomo`. `-pin` changes it; `-cgroup`
selects a cgroup v2 directory instead of `/sys/fs/cgroup`. Flags precede `attach`
or `detach`. bpffs must already be mounted at `/sys/fs/bpf`. `-reader-group` takes
a group name or a numeric GID; a GID needs no group entry.

`-exec-paths` requires kernel BTF and an active BPF LSM; the loader checks that
`bpf` appears in `/sys/kernel/security/lsm` and refuses the flag otherwise.
Without it, the loader records socket owners only, and mihomo needs `/proc`
access to resolve their executables. Attaching needs `CAP_BPF` and `CAP_NET_ADMIN`,
plus `CAP_CHOWN` for `-reader-group` and `CAP_PERFMON` for `-exec-paths`. The
loader exits after attach; pinned links keep the programs running. If attaching
fails after any program is attached, it removes its pins.

The loader also records the cgroup of each connection's owner, which lets mihomo
route by Flatpak app (`FLATPAK-APP` rules) or systemd unit. With `-exec-paths` it
records the cgroups' paths too, so mihomo needn't read `/sys/fs/cgroup`. Like a process name,
a cgroup name is chosen by the user's own processes: it identifies cooperative
applications and is not a security boundary.

Point mihomo's `find-process-bpf-map` at `maps/conn_owners` inside the pin directory
(or its read-only bind mount). Set `find-process-bpf-only: true` with `-exec-paths`
to prevent fallback to `/proc`. An unprivileged reader needs directory traversal
and map read permission; the systemd setup supplies both.

To stop recording, after stopping dependent readers:

```sh
sudo /usr/local/bin/socketowner detach
```

Use the same `-pin` for attach and detach if you changed it. Both commands preserve
the map directory so existing directory bind mounts keep working. Detach removes
the loader's pins and leaves Wine observer pins in place.

## Compatibility and updates

This loader publishes [map interface v1](docs/map-interface.md), with the
optional owner-cgroup map. Update it independently from mihomo, keeping a version
whose map interface the reader supports. A mihomo that knows `FLATPAK-APP`
still works with an older loader, but those rules never match until the loader
is updated. Installing mihomo must not build, install or replace this privileged
executable. A loader update takes effect when its service is restarted.

See [development](docs/development.md) for source builds and tests.

An optional [Wine observer](wine/README.md) identifies
Windows socket creators in unchanged Wine, needing no per-build data. It is a
separate command, which can also publish them for mihomo through a sandbox's
pasta. Run it continuously using the optional Wine observer unit in
[hardened-proxy-service](https://github.com/nosini/hardened-proxy-service),
or start it by hand before launching games.

## License

The userspace code is licensed under [GNU GPL v3](LICENSE).

The BPF sources in `bpf/` and `wine/bpf/`, and the research BPF programs
`wine/research/generic-capture/g.c`,
`wine/research/attribution-research-evidence/custom-sockopt.bpf.c` and
`wine/research/attribution-research-evidence/host-ebpf/observe.bpf.c`, are
licensed under [GNU GPL v2 only](LICENSE.bpf), as marked by their SPDX headers.
BPF object files retain the license of their sources.
