#!/bin/bash
# usage: run.sh NAME WINE_BIN_DIR
cd ~/work/socketowner/wine-generic; N=$1; W=$2; rm -rf $N; mkdir $N; cd $N
export WINEPREFIX=$PWD/prefix WINEDEBUG=-all WINEDLLOVERRIDES='winemenubuilder.exe=d;mscoree,mshtml='
unset DISPLAY WAYLAND_DISPLAY
for x in alpha beta; do cp ../stress.exe $x.exe; done
timeout 90 $W/wineboot -u >/dev/null 2>&1; $W/wineserver -k 2>/dev/null; sleep 1
python3 ../echo-server.py >/dev/null 2>&1 & E=$!
sudo -n ../gproto > events.jsonl 2> err.log & G=$!
for i in $(seq 50); do grep -q ready events.jsonl && break; sleep .1; done
$W/wineserver -p; sleep .3
timeout 100 $W/wine alpha.exe > a.log 2>&1 & A=$!
timeout 100 $W/wine beta.exe > b.log 2>&1 & B=$!
wait $A; echo alpha=$?; wait $B; echo beta=$?
$W/wineserver -k; sleep 1
sudo -n pkill -TERM -x gproto; sleep 2; kill $E
cat err.log | tail -5 | cut -c1-400; cat a.log b.log | tail -2
python3 - <<'P'
import json,collections
c=collections.Counter();t=None
for l in open('events.jsonl'):
    r=json.loads(l)
    if r['type']=='socket': c[(r['status'],r['image'][-40:])]+=1
    if r['type']=='counts': t=r['counts']
print(t); [print(v,k) for k,v in c.most_common(8)]
P
