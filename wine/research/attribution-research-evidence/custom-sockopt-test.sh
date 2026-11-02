#!/bin/bash
set -eu
cd "$HOME/work/run-in-sandbox/attribution-research-20261028"
clang -O2 -g -target bpf -c custom-sockopt.bpf.c -o custom-sockopt.bpf.o
cg=/sys/fs/cgroup/ris-attribution-research-20261028
pin=/sys/fs/bpf/ris-attribution-research-20261028
cleanup() {
 sudo -n /usr/sbin/bpftool cgroup detach "$cg" setsockopt pinned "$pin/prog" 2>/dev/null || true
 sudo -n rm -f "$pin/prog" "$pin/maps/labels" "$pin/maps/observed"
 sudo -n rmdir "$pin/maps" "$pin" "$cg"
}
trap cleanup EXIT
sudo -n mkdir "$cg" "$pin" "$pin/maps"
sudo -n /usr/sbin/bpftool prog load custom-sockopt.bpf.o "$pin/prog" pinmaps "$pin/maps"
sudo -n /usr/sbin/bpftool cgroup attach "$cg" setsockopt pinned "$pin/prog"
sudo -n bash -c 'echo $$ > /sys/fs/cgroup/ris-attribution-research-20261028/cgroup.procs
exec setpriv --reuid=1000 --regid=1000 --init-groups bwrap --unshare-all --unshare-user --disable-userns --ro-bind / / --proc /proc python3 /home/agent/work/run-in-sandbox/attribution-research-20261028/custom-sockopt-client.py'
sudo -n /usr/sbin/bpftool map dump pinned "$pin/maps/observed"
bwrap --unshare-all --unshare-user --disable-userns --ro-bind / / --proc /proc python3 "$PWD/custom-sockopt-client.py"
