#!/usr/bin/env python3
"""VM-only end-to-end test: real sandbox-game --net launches, with no pause.

Run as the ordinary VM user, with run-in-sandbox checked out at --sandbox. The
observer starts first and is told nothing. Two sandboxes then start at once, each
with its own wineserver and pasta, and race to one destination.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import threading
import time

HOST = '198.18.77.1'
PIN = '/sys/fs/bpf/wine-sandbox-test'
REDIR = 17892
MARK = 6666
PROGRAMS = (('alpha', 'DIRECT'), ('beta', 'REJECT'))

p = argparse.ArgumentParser()
p.add_argument('--sandbox', required=True, type=Path)
p.add_argument('--runner', required=True, type=Path, help='directory holding wine and wineserver')
p.add_argument('--observer', required=True, type=Path)
p.add_argument('--mihomo', required=True, type=Path)
p.add_argument('--work', required=True, type=Path)
p.add_argument('--observer-service', action='store_true', help='use the installed systemd observer and its shared maps; leaves it running')
p.add_argument('--bits', type=int, default=64, choices=(32, 64), help='mingw PE probes')
a = p.parse_args()
for name in ('sandbox', 'runner', 'observer', 'mihomo', 'work'):
    setattr(a, name, getattr(a, name).resolve())
a.work.mkdir(parents=True, exist_ok=True)
if a.observer_service:
    PIN = '/sys/fs/bpf/mihomo/maps'
source = Path(__file__).resolve().parent
proton = a.work / 'proton'
compiler = {32: 'i686-w64-mingw32-gcc', 64: 'x86_64-w64-mingw32-gcc'}[a.bits]
root = []
sandboxes = {}
echo = None


def sudo(*args, **kwargs):
    return subprocess.run(['sudo', '-n', *map(str, args)], check=True, **kwargs)


def sudo_ls(path):
    return subprocess.run(['sudo', '-n', 'ls', path], capture_output=True, text=True, check=True).stdout.split()


# scope host keeps it out of the addresses sandbox-game refuses.
sudo('ip', 'addr', 'add', HOST + '/32', 'scope', 'host', 'dev', 'lo')
sudo('mkdir', '-p', PIN)
sudo('nft', '-f', '-', input=f'''table inet wine_sandbox_test {{
  chain out {{
    type nat hook output priority -100;
    meta mark {MARK} return
    ip daddr {HOST} tcp dport 30443 redirect to :{REDIR}
  }}
}}
''', text=True)
try:
    (proton / 'files').mkdir(parents=True, exist_ok=True)
    shutil.copytree(a.runner.parent, proton / 'files', dirs_exist_ok=True, symlinks=True)
    (proton / 'proton').write_text('#!/bin/sh\nexit 0\n')
    (proton / 'proton').chmod(0o755)
    (proton / 'version').write_text('1 wineroute\n')
    for probe, _ in PROGRAMS:
        game = a.work / probe
        game.mkdir(exist_ok=True)
        subprocess.run([compiler, '-O1', '-o', game / (probe + '.exe'), source / 'winsock-probe.c',
                        '-lws2_32', '-lmswsock', '-static'], check=True)
        (game / 'run.sh').write_text(f'''#!/bin/sh
export WINEPREFIX=/tmp/prefix WINEDEBUG=-all WINEDLLOVERRIDES='winemenubuilder.exe=d;mscoree,mshtml='
export PROBE_HOST={HOST}
W=/proton/files/bin
timeout 90 $W/wine /game/{probe}.exe > /tmp/out.log 2>&1
echo "status=$?"; cat /tmp/out.log
$W/wineserver -k
''')
        (game / 'run.sh').chmod(0o755)

    (a.work / 'mihomo').mkdir(exist_ok=True)
    (a.work / 'mihomo' / 'config.yaml').write_text(f'''redir-port: {REDIR}
mode: rule
log-level: debug
ipv6: false
routing-mark: {MARK}
find-process-mode: always
find-process-bpf-map: {PIN}/conn_owners
rules:
  - WINE-PROCESS-NAME,beta.exe,REJECT
  - WINE-PROCESS-NAME,alpha.exe,DIRECT
  - WINE-PROCESS-NAME,wine-unknown,REJECT
  - MATCH,DIRECT
''')
    mihomo = subprocess.Popen(['sudo', '-n', str(a.mihomo), '-d', str(a.work / 'mihomo')],
                              stdout=(a.work / 'mihomo.log').open('w'), stderr=subprocess.STDOUT)
    root.append(mihomo)
    echo = subprocess.Popen(['python3', str(source / 'echo-server.py'), HOST],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    records = []
    if a.observer_service:
        # Restart first so the journal stream belongs to exactly one observer.
        sudo('systemctl', 'restart', 'socketowner-wine-observer.service')
        invocation = subprocess.run(['systemctl', 'show', '-p', 'InvocationID', '--value',
                                     'socketowner-wine-observer.service'],
                                    check=True, capture_output=True, text=True).stdout.strip()
        observer = subprocess.Popen(['sudo', '-n', 'journalctl', '-f', '-o', 'cat',
                                     '_SYSTEMD_INVOCATION_ID=' + invocation],
                                    stdout=subprocess.PIPE, text=True)
        root.append(observer)
    else:
        observer = subprocess.Popen(['sudo', '-n', str(a.observer), '-pin', PIN],
                                    stdout=subprocess.PIPE, stderr=(a.work / 'observer-stderr.log').open('w'), text=True)
        root.append(observer)
    ready = threading.Event()

    def collect():
        with (a.work / 'events.jsonl').open('w') as log:
            for line in observer.stdout:
                log.write(line)
                log.flush()
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                records.append(value)
                if records[-1]['type'] == 'ready':
                    ready.set()
    reader = threading.Thread(target=collect, daemon=True)
    reader.start()
    assert ready.wait(10), 'observer not ready; see events.jsonl or observer-stderr.log'
    time.sleep(.5)

    for probe, _ in PROGRAMS:
        sandboxes[probe] = subprocess.Popen(
            [str(a.sandbox / 'sandbox-game'), '--headless', '--net', '--name', 'wineroute-' + probe,
             f'--with-proton={proton}', str(a.work / probe), '/game/run.sh'],
            stdout=(a.work / (probe + '.log')).open('w'), stderr=subprocess.STDOUT)
    for process in sandboxes.values():
        process.wait(timeout=200)
    time.sleep(.5)

    log = (a.work / 'mihomo.log').read_text()
    print(*re.findall(r'\[TCP\] .*?using \w+', log), sep='\n', flush=True)
    for probe, rule in PROGRAMS:
        output = (a.work / (probe + '.log')).read_text()
        exe = probe + '.exe'
        pid = re.search(r'Windows PID=(\d+)', output)
        assert pid, output[-800:]
        matches = re.findall(rf'match WineProcessName\({exe}\) using {rule}', log)
        relays = [r for r in records if r['type'] == 'relay' and r.get('windows_name') == exe]
        print(exe, 'mihomo matches', len(matches), 'relays', len(relays), flush=True)
        assert len(matches) == 2 and len(relays) == 3
        if a.bits == 64:
            assert all(str(r['windows_pid']) == pid.group(1) for r in relays), (relays, pid.group(1))
    assert 'ConnectEx recv=14' in (a.work / 'alpha.log').read_text()
    pastas = {r['pasta_tgid'] for r in records if r['type'] == 'pasta'}
    servers = {r['server_tgid'] for r in records if r['type'] == 'relay' and r['status'] == 'known'}
    print('pastas', len(pastas), 'wineservers with traffic', len(servers), flush=True)
    assert len(pastas) >= 2 and len(servers) == 2
    unknown = [r for r in records if r['type'] == 'relay' and r['status'] != 'known']
    print('unknown relays', len(unknown), flush=True)
    assert not unknown, unknown
    assert 'wine-unknown' not in log
    subprocess.run(['sudo', '-n', 'pkill', '-TERM', '-P', str(observer.pid)], check=True)
    observer.wait(timeout=15)
    reader.join(timeout=5)
    if a.observer_service:
        assert 'wine_flows' in sudo_ls(PIN)
    else:
        assert sudo_ls(PIN) == []
        assert (a.work / 'observer-stderr.log').read_text() == ''
    print('PASS: two unpaused sandboxes routed by name.', flush=True)
finally:
    for probe, process in sandboxes.items():
        if process.poll() is None:
            subprocess.run([a.sandbox / 'sandbox-game', '--stop', 'wineroute-' + probe], check=False)
            process.wait(timeout=20)
    for process in root:
        if process.poll() is None:
            subprocess.run(['sudo', '-n', 'pkill', '-TERM', '-P', str(process.pid)], check=False)
            process.wait(timeout=8)
    if echo:
        echo.terminate()
        echo.wait(timeout=5)
    subprocess.run(['sudo', '-n', 'nft', 'delete', 'table', 'inet', 'wine_sandbox_test'], check=False)
    subprocess.run(['sudo', '-n', 'ip', 'addr', 'del', HOST + '/32', 'dev', 'lo'], check=False)
    if not a.observer_service:
        subprocess.run(['sudo', '-n', 'rm', '-rf', PIN], check=False)
