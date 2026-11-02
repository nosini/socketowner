#!/usr/bin/env python3
"""VM-only smoke test: real unmodified Wine, two Winelib probes, host observer.

Run as the ordinary VM user. Only the observer is started through sudo -n.
All Wine state stays in --work; no installed runner/prefix is modified.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time

p = argparse.ArgumentParser()
p.add_argument('--runner', required=True, type=Path)
p.add_argument('--observer', required=True, type=Path)
p.add_argument('--work', required=True, type=Path)
a = p.parse_args()
a.runner = a.runner.resolve()
a.observer = a.observer.resolve()
a.work = a.work.resolve()
a.work.mkdir(parents=True, exist_ok=True)
source = Path(__file__).resolve().parent
env = dict(os.environ, WINEPREFIX=str(a.work / 'prefix'), WINEDEBUG='-all',
           WINEDLLOVERRIDES='winemenubuilder.exe=d;mscoree,mshtml=')
env.pop('DISPLAY', None)
env.pop('WAYLAND_DISPLAY', None)
env.pop('WINEARCH', None)
processes = []
observer = None

def command(args, **kwargs):
    return subprocess.run([str(x) for x in args], cwd=a.work, check=True, **kwargs)

def wine_stop():
    subprocess.run([str(a.runner / 'wineserver'), '-k'], env=env,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)

try:
    for name in ['alpha', 'beta']:
        command([a.runner / 'winegcc', '-m64', '-o', name+'.exe',
                 source / 'winsock-probe.c', '-lws2_32'])
    with (a.work / 'profile.json').open('w') as f:
        command([a.observer, '-make-profile', a.runner / 'wineserver'], stdout=f)
    # Prefix initialization is setup, not a networking assertion. Some Wine
    # builds leave boot services waiting; stop the task-only server afterwards.
    with (a.work / 'prefix-init.log').open('w') as f:
        boot = subprocess.Popen([str(a.runner / 'wineboot'), '-u'], env=env,
                                cwd=a.work, stdout=f, stderr=f)
        try:
            rc = boot.wait(timeout=60)
            if rc:
                raise RuntimeError('wineboot failed with status '+str(rc))
        except subprocess.TimeoutExpired:
            boot.kill()
            boot.wait()
            print('Prefix setup timed out; stopping boot services before the test.', flush=True)
        wine_stop()
    server_log = (a.work / 'server.log').open('w')
    server = subprocess.Popen([str(a.runner / 'wineserver'), '-f', '-p'], env=env,
                              cwd=a.work, stdout=server_log, stderr=server_log)
    processes.append(server)
    echo_log = (a.work / 'echo.log').open('w')
    echo = subprocess.Popen(['python3', str(source / 'echo-server.py')],
                            stdout=echo_log, stderr=echo_log)
    processes.append(echo)
    time.sleep(.3)
    if server.poll() is not None or echo.poll() is not None:
        raise RuntimeError('task-only wineserver or echo listener failed')
    stderr = (a.work / 'observer-stderr.log').open('w')
    observer = subprocess.Popen(['sudo', '-n', str(a.observer), '-pid', str(server.pid),
                                 '-profile', str(a.work / 'profile.json'), '-sends'],
                                stdout=subprocess.PIPE, stderr=stderr, text=True)
    records = []
    ready = threading.Event()
    def collect():
        with (a.work / 'events.jsonl').open('w') as log:
            for line in observer.stdout:
                log.write(line)
                log.flush()
                value = json.loads(line)
                records.append(value)
                if value['type'] == 'ready':
                    ready.set()
    reader = threading.Thread(target=collect)
    reader.start()
    if not ready.wait(10):
        raise RuntimeError('observer did not become ready; inspect observer-stderr.log')
    expected = {}
    for name in ['alpha', 'beta']:
        # Wine services may inherit stdout/stderr. Regular files let us wait
        # for the actual probe rather than EOF on pipes held by descendants.
        with (a.work / (name+'-stdout.log')).open('w') as stdout, (a.work / (name+'-stderr.log')).open('w') as stderr:
            command([a.runner / 'wine', './'+name+'.exe.so'], env=env,
                    stdout=stdout, stderr=stderr, timeout=40)
        output = (a.work / (name+'-stdout.log')).read_text()
        expected[name+'.exe'] = int(re.search(r'Windows PID=(\d+)', output).group(1))
        if 'WSARecv=-1 error=997' not in output or 'ConnectEx recv=14' not in output:
            raise RuntimeError('probe did not cover pending receive and ConnectEx')
    wine_stop()
    observer.wait(timeout=10)
    reader.join(timeout=10)
    if observer.returncode or reader.is_alive():
        raise RuntimeError('observer failed or did not stop after target exit')
    for name, pid in expected.items():
        rows = [r for r in records if r.get('windows_name') == name]
        creates = [r for r in rows if r['type'] == 'create']
        outgoing = [r for r in rows if r['type'] == 'first-egress']
        assert len(creates) == 3, (name, 'creations', creates)
        assert len(outgoing) == 3, (name, 'first packets', outgoing)
        assert all(r['windows_pid'] == pid and r['server_tgid'] == server.pid for r in rows)
        assert len({r['socket_id'] for r in creates}) == 3
        assert {r['socket_id'] for r in creates} == {r['socket_id'] for r in outgoing}
        assert all(r['tcp_flags'] & 2 for r in outgoing if r['network'] == 'tcp')
        assert sum(r['network'] == 'udp' for r in outgoing) == 1
        print(name, 'Windows PID', pid, 'PASS: 3 creations and 3 attributed first packets', flush=True)
    assert any(r['type'] == 'stopped' and r.get('reason') == 'target-exit' for r in records)
    assert (a.work / 'observer-stderr.log').read_text() == ''
    print('PASS: unchanged Wine, two Windows images, TCP SYN + unconnected UDP, clean observer exit.', flush=True)
finally:
    wine_stop()
    if observer is not None and observer.poll() is None:
        # Target exit should stop it even if startup/one assertion failed.
        try:
            observer.wait(timeout=5)
        except subprocess.TimeoutExpired:
            subprocess.run(['sudo', '-n', 'kill', '-TERM', str(observer.pid)], check=False)
            observer.wait(timeout=5)
    for proc in reversed(processes):
        if proc.poll() is None:
            proc.terminate()
        proc.wait(timeout=5)
