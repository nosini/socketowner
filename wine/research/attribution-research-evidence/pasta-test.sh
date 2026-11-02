#!/bin/bash
set -eu
cd "$HOME/work/run-in-sandbox/attribution-research-20261028"
strace -f -s 160 -e trace=network -o pasta-network.log pasta -f --config-net -4 -t none -u none -T none -U none --map-host-loopback none --map-guest-addr none -- python3 net-client.py >inner.jsonl 2>pasta-stderr.log &
job=$!
trap 'kill "$job" 2>/dev/null || true; wait "$job" 2>/dev/null || true' EXIT
sleep 8
sudo -n ss -ntupe >host-sockets.txt
wait "$job"
trap - EXIT
cat inner.jsonl
grep '1.1.1.1' host-sockets.txt
grep -E '1.1.1.1|sin_port=htons\((41234|58830)\)' pasta-network.log | tail -25
