#!/usr/bin/env python3
"""VM-only end-to-end test: a Windows program inside real sandbox-game --net.

Run as the ordinary VM user, with run-in-sandbox checked out at --sandbox. The
program in the sandbox waits until the observer has attached from outside, by
polling a read-only directory; attaching is a manual stand-in for integration.
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

p = argparse.ArgumentParser()
p.add_argument('--sandbox', required=True, type=Path)
p.add_argument('--runner', required=True, type=Path, help='a Wine install; wineserver needs DWARF')
p.add_argument('--observer', required=True, type=Path)
p.add_argument('--mihomo', required=True, type=Path)
p.add_argument('--work', required=True, type=Path)
p.add_argument('--pe', action='store_true', help='build native PE probes with mingw')
a = p.parse_args()
for name in ('sandbox', 'runner', 'observer', 'mihomo', 'work'):
    setattr(a, name, getattr(a, name).resolve())
a.work.mkdir(parents=True, exist_ok=True)
source = Path(__file__).resolve().parent
game, control, proton = a.work / 'game', a.work / 'control', a.work / 'proton'
name = 'wineroute'
root = []
sandbox = None


def sudo(*args, **kwargs):
    return subprocess.run(['sudo', '-n', *map(str, args)], check=True, **kwargs)


def sudo_ls(path):
    return subprocess.run(['sudo', '-n', 'ls', path], capture_output=True, text=True, check=True).stdout.split()


def ns(pid):
    return subprocess.run(['sudo', '-n', 'readlink', f'/proc/{pid}/ns/net'], capture_output=True, text=True).stdout.strip()


def pgrep(*args):
    r = subprocess.run(['pgrep', *args], capture_output=True, text=True)
    return [int(x) for x in r.stdout.split()]


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
    game.mkdir(exist_ok=True)
    control.mkdir(exist_ok=True)
    (proton / 'files').mkdir(parents=True, exist_ok=True)
    shutil.copytree(a.runner.parent, proton / 'files', dirs_exist_ok=True, symlinks=True)
    (proton / 'proton').write_text('#!/bin/sh\nexit 0\n')
    (proton / 'proton').chmod(0o755)
    (proton / 'version').write_text('1 wineroute\n')
    for probe in ('alpha', 'beta'):
        if a.pe:
            subprocess.run(['x86_64-w64-mingw32-gcc', '-O1', '-o', game / (probe + '.exe'),
                            source / 'winsock-probe.c', '-lws2_32', '-lmswsock', '-static'], check=True)
        else:
            subprocess.run([a.runner / 'winegcc', '-m64', '-o', game / (probe + '.exe'),
                            source / 'winsock-probe.c', '-lws2_32'], cwd=game, check=True)
    suffix = '' if a.pe else '.so'
    (game / 'run.sh').write_text(f'''#!/bin/sh
export WINEPREFIX=/tmp/prefix WINEDEBUG=-all WINEDLLOVERRIDES='winemenubuilder.exe=d;mscoree,mshtml='
W=/proton/files/bin
timeout 60 $W/wineboot -u
$W/wineserver -k
$W/wineserver -p
sleep .5
echo prefix-ready
until [ -e /control/go ]; do sleep .1; done
for p in alpha beta; do
    PROBE_HOST={HOST} timeout 40 $W/wine /game/$p.exe{suffix} > /tmp/$p.log 2>&1
    echo "$p status=$?"; cat /tmp/$p.log
done
$W/wineserver -k
''')
    (game / 'run.sh').chmod(0o755)
    with (a.work / 'profile.json').open('w') as f:
        subprocess.run([a.observer, '-make-profile', a.runner / 'wineserver'], stdout=f, check=True)

    (a.work / 'mihomo').mkdir(exist_ok=True)
    (a.work / 'mihomo' / 'config.yaml').write_text(f'''redir-port: {REDIR}
mode: rule
log-level: debug
ipv6: false
routing-mark: {MARK}
find-process-mode: always
find-process-bpf-map: {PIN}/conn_owners
rules:
  - PROCESS-NAME,beta.exe,REJECT
  - PROCESS-NAME,alpha.exe,DIRECT
  - PROCESS-NAME,wine-unknown,REJECT
  - MATCH,DIRECT
''')
    mihomo = subprocess.Popen(['sudo', '-n', str(a.mihomo), '-d', str(a.work / 'mihomo')],
                              stdout=(a.work / 'mihomo.log').open('w'), stderr=subprocess.STDOUT)
    root.append(mihomo)
    echo = subprocess.Popen(['python3', str(source / 'echo-server.py'), HOST],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(.5)

    sandbox = subprocess.Popen([str(a.sandbox / 'sandbox-game'), '--headless', '--net', '--name', name,
                                f'--with-proton={proton}', '--ro', str(control), '/control',
                                str(game), '/game/run.sh'],
                               stdout=(a.work / 'sandbox.log').open('w'), stderr=subprocess.STDOUT)
    server = pasta = None
    deadline = time.time() + 120
    while time.time() < deadline and not (server and pasta):
        assert sandbox.poll() is None, 'sandbox ended early; see sandbox.log'
        if 'prefix-ready' not in (a.work / 'sandbox.log').read_text():
            time.sleep(.1)
            continue
        pasta = next(iter(pgrep('-u', str(os.getuid()), '-f', f'{name}-pasta')), None)
        if pasta:
            inner = subprocess.run(['sudo', '-n', 'sh', '-c', f'readlink /proc/{pasta}/fd/* | grep "^net:"'],
                                   capture_output=True, text=True).stdout.split()
            for pid in pgrep('-u', str(os.getuid()), '-x', 'wineserver'):
                if ns(pid) in inner:
                    server = pid
        time.sleep(.1)
    assert server and pasta, 'wineserver or pasta not found'
    print('wineserver', server, 'pasta', pasta, flush=True)

    records = []
    observer = subprocess.Popen(['sudo', '-n', str(a.observer), '-pid', str(server),
                                 '-profile', str(a.work / 'profile.json'),
                                 '-pasta-pid', str(pasta), '-pin', PIN],
                                stdout=subprocess.PIPE, stderr=(a.work / 'observer-stderr.log').open('w'), text=True)
    root.append(observer)
    ready = threading.Event()

    def collect():
        with (a.work / 'events.jsonl').open('w') as log:
            for line in observer.stdout:
                log.write(line)
                log.flush()
                records.append(json.loads(line))
                if records[-1]['type'] == 'ready':
                    ready.set()
    threading.Thread(target=collect, daemon=True).start()
    assert ready.wait(10), 'observer not ready: ' + (a.work / 'observer-stderr.log').read_text()
    (control / 'go').touch()
    sandbox.wait(timeout=120)
    observer.wait(timeout=15)
    time.sleep(.3)
    output = (a.work / 'sandbox.log').read_text()
    print(output[-1500:], flush=True)
    log = (a.work / 'mihomo.log').read_text()
    pids = dict(re.findall(r'(alpha|beta) status=\d+\nWindows PID=(\d+)', output))
    for probe, rule in (('alpha', 'DIRECT'), ('beta', 'REJECT')):
        exe = probe + '.exe'
        matches = re.findall(rf'match ProcessName\({exe}\) using {rule}', log)
        relays = [r for r in records if r['type'] == 'relay' and r.get('windows_name') == exe]
        print(exe, 'mihomo matches', len(matches), 'relays', len(relays), flush=True)
        assert len(matches) == 2 and len(relays) == 3
        assert all(str(r['windows_pid']) == pids[probe] for r in relays), (relays, pids)
    assert 'ConnectEx recv=14' in output
    assert any(r.get('reason') == 'target-exit' for r in records)
    assert sudo_ls(PIN) == []
    print('PASS: Windows programs in real sandbox-game routed by name.', flush=True)
finally:
    if sandbox and sandbox.poll() is None:
        subprocess.run([a.sandbox / 'sandbox-game', '--stop', name], check=False)
        sandbox.wait(timeout=20)
    for process in root:
        if process.poll() is None:
            subprocess.run(['sudo', '-n', 'pkill', '-TERM', '-P', str(process.pid)], check=False)
            process.wait(timeout=8)
    subprocess.run(['pkill', '-f', 'echo-server.py'], check=False)
    subprocess.run(['sudo', '-n', 'nft', 'delete', 'table', 'inet', 'wine_sandbox_test'], check=False)
    subprocess.run(['sudo', '-n', 'ip', 'addr', 'del', HOST + '/32', 'dev', 'lo'], check=False)
    subprocess.run(['sudo', '-n', 'rm', '-rf', PIN], check=False)
