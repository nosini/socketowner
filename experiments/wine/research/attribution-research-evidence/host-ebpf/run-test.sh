#!/bin/bash
set -eu
cd "$HOME/work/run-in-sandbox/host-wine-attribution"
runner="$HOME/work/run-in-sandbox/dwproton-15/install/bin"
export WINEPREFIX="$PWD/prefix" WINEDEBUG=-all WINEDLLOVERRIDES=winemenubuilder.exe=d
unset DISPLAY WAYLAND_DISPLAY
mkdir -p "$WINEPREFIX"
"$runner/wineserver" -f -p >server.log 2>&1 &
server_pid=$!
python3 echo-server.py >echo.log 2>&1 &
echo_pid=$!
observer_job=
cleanup() {
 touch observer.stop
 if [ -n "$observer_job" ]; then wait "$observer_job" 2>/dev/null || true; fi
 "$runner/wineserver" -k 2>/dev/null || true
 kill "$server_pid" "$echo_pid" 2>/dev/null || true
 wait "$server_pid" "$echo_pid" 2>/dev/null || true
}
trap cleanup EXIT
timeout 75 "$runner/wine" ./alpha.exe.so >initialization-result.txt 2>initialization-stderr.txt
kill -0 "$server_pid"
sudo -n cat "/proc/$server_pid/maps" >server-maps.txt
printf 'server_pid=%s\n' "$server_pid" >run-identity.txt
rm -f observer.stop observer.ready
sudo -n ./load-observer "$server_pid" 0x4abba0 >observations.txt 2>observer-stderr.txt &
observer_job=$!
for i in $(seq 1 100); do
 test ! -e observer.ready || break
 kill -0 "$observer_job"
 sleep .05
done
test -e observer.ready
timeout 30 "$runner/wine" ./alpha.exe.so >alpha-result.txt 2>alpha-stderr.txt
timeout 30 "$runner/wine" ./beta.exe.so >beta-result.txt 2>beta-stderr.txt
touch observer.stop
wait "$observer_job"
observer_job=
cat run-identity.txt observations.txt
