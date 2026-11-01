#!/bin/bash
set -eu
cd "$HOME/work/run-in-sandbox/attribution-research-20261028"
runner="$HOME/work/run-in-sandbox/dwproton-15/install/bin"
"$runner/winegcc" -m64 -o winsock-probe.exe winsock-probe.c -lws2_32
mode=dw
if [ "$#" -gt 0 ]; then runner="$1"; mode=upstream; fi
python3 echo-server.py >echo.log 2>&1 &
echo_pid=$!
export WINEPREFIX="$PWD/prefix-$mode" WINEDEBUG=-all WINEDLLOVERRIDES=winemenubuilder.exe=d
trap 'kill "$echo_pid" 2>/dev/null || true; "$runner/wineserver" -k || true' EXIT
unset DISPLAY WAYLAND_DISPLAY
strace -ff -s 180 -e trace=network,process -o "$mode-trace" timeout 90 "$runner/wine" ./winsock-probe.exe.so >"$mode-result.txt" 2>"$mode-stderr.log"
cat "$mode-result.txt"
"$runner/wineserver" -k || true
"$runner/wineserver" -w
kill "$echo_pid"
wait "$echo_pid" 2>/dev/null || true
trap - EXIT
