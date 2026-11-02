#!/usr/bin/env python3
"""VM-only end-to-end test: real Wine behind real pasta, routed by real mihomo.

Run as the ordinary VM user. Everything needing root goes through sudo -n: the
observer, mihomo and one nftables table. Wine and pasta stay unprivileged in
their own user and network namespaces, started the way sandbox-game starts them.
"""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import tempfile
import threading
import time

HOST = '198.18.77.1'
PIN = '/sys/fs/bpf/wine-route-test'
REDIR = 17892
MARK = 6666

p = argparse.ArgumentParser()
p.add_argument('--runner', required=True, type=Path)
p.add_argument('--observer', required=True, type=Path)
p.add_argument('--mihomo', required=True, type=Path)
p.add_argument('--work', required=True, type=Path)
p.add_argument('--control', action='store_true', help='no relay: rules must not match a Windows name')
a = p.parse_args()
for name in ('runner', 'observer', 'mihomo', 'work'):
    setattr(a, name, getattr(a, name).resolve())
a.work.mkdir(parents=True, exist_ok=True)
source = Path(__file__).resolve().parent
env = dict(os.environ, WINEPREFIX=str(a.work / 'prefix'), WINEDEBUG='-all',
           WINEDLLOVERRIDES='winemenubuilder.exe=d;mscoree,mshtml=', PROBE_HOST=HOST)
for name in ('DISPLAY', 'WAYLAND_DISPLAY', 'WINEARCH'):
    env.pop(name, None)
processes = []
root_processes = []
pasta = 0


def sudo(*args, **kwargs):
    return subprocess.run(['sudo', '-n', *map(str, args)], check=True, **kwargs)


def background(args, log, **kwargs):
    f = (a.work / log).open('w')
    process = subprocess.Popen([str(x) for x in args], cwd=a.work, stdout=f, stderr=f, **kwargs)
    return process


def stop_root(process):
    if process.poll() is None:
        subprocess.run(['sudo', '-n', 'pkill', '-TERM', '-P', str(process.pid)], check=False)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            subprocess.run(['sudo', '-n', 'pkill', '-KILL', '-P', str(process.pid)], check=False)
            process.wait(timeout=5)


# ---- setup ------------------------------------------------------------------
sudo('ip', 'addr', 'add', HOST + '/32', 'dev', 'lo')
sudo('mkdir', '-p', PIN)
ruleset = f'''table inet wine_route_test {{
  chain out {{
    type nat hook output priority -100;
    meta mark {MARK} return
    ip daddr {HOST} tcp dport 30443 redirect to :{REDIR}
  }}
}}
'''
sudo('nft', '-f', '-', input=ruleset, text=True)
try:
    for name in ('alpha', 'beta', 'gamma'):
        subprocess.run([a.runner / 'winegcc', '-m64', '-o', name + '.exe',
                        source / 'winsock-probe.c', '-lws2_32'], cwd=a.work, check=True)
    with (a.work / 'profile.json').open('w') as f:
        subprocess.run([a.observer, '-make-profile', a.runner / 'wineserver'], stdout=f, check=True)
    with (a.work / 'prefix-init.log').open('w') as f:
        boot = subprocess.Popen([str(a.runner / 'wineboot'), '-u'], env=env, cwd=a.work, stdout=f, stderr=f)
        try:
            boot.wait(timeout=60)
        except subprocess.TimeoutExpired:
            boot.kill()
            boot.wait()
        subprocess.run([a.runner / 'wineserver', '-k'], env=env, timeout=10,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

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
    root_processes.append(mihomo)
    echo = background(['python3', source / 'echo-server.py', HOST], 'echo.log')
    processes.append(echo)

    # The namespace holder stands in for the sandbox: pasta runs in the host's
    # network namespace and everything else inside this one.
    pidfile = a.work / 'holder.pid'
    holder = background(['unshare', '--user', '--map-current-user', '--net', 'sh', '-c',
                         f'echo $$ > {pidfile}; exec sleep 3600'], 'holder.log')
    processes.append(holder)
    for _ in range(50):
        if pidfile.exists() and pidfile.read_text().strip():
            break
        time.sleep(.05)
    inner = pidfile.read_text().strip()
    enter = ['nsenter', '-t', inner, '-U', '-n', '--preserve-credentials']
    time.sleep(.2)
    # pasta's confinement refuses to create files, so give it an existing one.
    pasta_pidfile = Path(tempfile.mkstemp()[1])
    subprocess.run(['pasta', '--quiet', '--config-net', '--netns-only', '--userns', f'/proc/{inner}/ns/user',
                    '--netns', f'/proc/{inner}/ns/net',
                    '--no-netns-quit', '-P', str(pasta_pidfile), '-4',
                    '-t', 'none', '-u', 'none', '-T', 'none', '-U', 'none',
                    '--map-host-loopback', 'none', '--map-guest-addr', 'none'], check=True)
    pasta = int(pasta_pidfile.read_text())
    os.unlink(pasta_pidfile)

    server = background([*enter, a.runner / 'wineserver', '-f', '-p'], 'server.log', env=env)
    processes.append(server)
    time.sleep(.5)
    assert server.poll() is None, 'wineserver failed'

    records = []

    def start_observer():
        relay = [] if a.control else ['-pasta-pid', str(pasta)]
        observer = subprocess.Popen(['sudo', '-n', str(a.observer), '-pid', str(server.pid),
                                     '-profile', str(a.work / 'profile.json'), *relay, '-pin', PIN],
                                    stdout=subprocess.PIPE, stderr=(a.work / 'observer-stderr.log').open('a'), text=True)
        root_processes.append(observer)
        ready = threading.Event()

        def collect():
            with (a.work / 'events.jsonl').open('a') as log:
                for line in observer.stdout:
                    log.write(line)
                    log.flush()
                    value = json.loads(line)
                    records.append(value)
                    if value['type'] == 'ready':
                        ready.set()
        reader = threading.Thread(target=collect, daemon=True)
        reader.start()
        assert ready.wait(10), 'observer did not become ready; see observer-stderr.log'
        return observer, reader

    observer, reader = start_observer()

    def wine(name, background_run=False):
        out = (a.work / (name + '-stdout.log')).open('w')
        args = [str(x) for x in [*enter, a.runner / 'wine', './' + name + '.exe.so']]
        run = subprocess.Popen(args, cwd=a.work, env=env, stdout=out, stderr=subprocess.STDOUT)
        if background_run:
            return run
        try:
            run.wait(timeout=60)
        except subprocess.TimeoutExpired:
            run.kill()
            run.wait()
        return run

    def native_connect():
        code = f"import socket;s=socket.create_connection(('{HOST}',30443),5);s.send(b'x');print(s.recv(9))"
        return subprocess.run([*enter, 'python3', '-c', code], capture_output=True, text=True, timeout=30)

    # ---- attribution through pasta ------------------------------------------
    assert wine('alpha').returncode == 0, 'alpha failed'
    output = (a.work / 'alpha-stdout.log').read_text()
    alpha_pid = int(re.search(r'Windows PID=(\d+)', output).group(1))
    assert 'ConnectEx recv=14' in output, 'alpha traffic did not pass DIRECT'
    if a.control:
        log = (a.work / 'mihomo.log').read_text()
        assert 'alpha.exe' not in log and 'wine-unknown' not in log and 'match Match using DIRECT' in log, log
        print('PASS control: without the relay no rule saw a Windows name:', flush=True)
        print(*re.findall(r'\[TCP\] .*?using \w+', log), sep='\n', flush=True)
        raise SystemExit(0)

    # A crashed publisher leaves its pins; the next one must replace them.
    subprocess.run(['sudo', '-n', 'pkill', '-KILL', '-P', str(observer.pid)], check=True)
    observer.wait(timeout=5)
    reader.join(timeout=5)
    pins = subprocess.run(['sudo', '-n', 'ls', PIN], capture_output=True, text=True, check=True).stdout.split()
    assert 'wine_flows' in pins, pins
    time.sleep(6)
    observer, reader = start_observer()
    print('crashed publisher replaced after its heartbeat expired', flush=True)

    wine('beta')
    native = native_connect()

    # ---- two owners waiting for one destination -----------------------------
    os.kill(pasta, signal.SIGSTOP)
    seen = len(records)
    gamma = wine('gamma', background_run=True)
    deadline = time.time() + 30
    def gamma_syn():
        return any(r['type'] == 'first-egress' and r.get('windows_name') == 'gamma.exe' for r in records[seen:])
    while not gamma_syn() and time.time() < deadline:
        time.sleep(.01)
    racing = gamma_syn()
    contender = subprocess.Popen([*enter, 'python3', '-c',
                                  f"import socket;socket.create_connection(('{HOST}',30443),5)"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(.3)
    os.kill(pasta, signal.SIGCONT)
    contender.wait(timeout=20)
    try:
        gamma.wait(timeout=30)
    except subprocess.TimeoutExpired:
        gamma.kill()
        gamma.wait()
    assert racing, 'gamma never sent its first SYN'

    pins = subprocess.run(['sudo', '-n', 'ls', PIN], capture_output=True, text=True, check=True).stdout.split()
    assert sorted(pins) == ['wine_abi', 'wine_flows', 'wine_heartbeat'], pins
    time.sleep(.5)

    # ---- assertions ---------------------------------------------------------
    log = (a.work / 'mihomo.log').read_text()
    relays = [r for r in records if r['type'] == 'relay']
    host = [r for r in records if r['type'] == 'first-egress' and r['server_tgid'] and
            r['source'].startswith(HOST + ':')]
    for name, rule in (('alpha.exe', 'DIRECT'), ('beta.exe', 'REJECT')):
        matches = re.findall(rf'match ProcessName\({re.escape(name)}\) using {rule}', log)
        print(name, 'mihomo TCP matches using', rule + ':', len(matches), flush=True)
        assert len(matches) == 2, (name, matches)
    alpha_relays = [r for r in relays if r.get('windows_name') == 'alpha.exe']
    assert len(alpha_relays) == 3 and {r['network'] for r in alpha_relays} == {'tcp', 'udp'}, alpha_relays
    assert all(r['windows_pid'] == alpha_pid and r['server_tgid'] == server.pid for r in alpha_relays)
    udp = [r for r in host if r['network'] == 'udp' and r.get('windows_name') in ('alpha.exe', 'beta.exe')]
    assert len(udp) == 2, udp
    print('UDP: first host packets attributed for', sorted(r['windows_name'] for r in udp), flush=True)
    assert any(r['status'] == 'not-wine' for r in relays), 'native flow was not distinguished'
    assert 'ProcessName(wine-unknown) using REJECT' in log, 'native flow did not reach the unknown rule'
    print('native program in the sandbox: not-wine, refused by the wine-unknown rule', flush=True)
    ambiguous = [r for r in relays if r['status'] == 'ambiguous-relay']
    print('ambiguous relays while pasta was stopped:', len(ambiguous), flush=True)
    assert len(ambiguous) == 2, relays
    assert all('windows_name' not in r for r in ambiguous), ambiguous

    # ---- lifecycle ----------------------------------------------------------
    subprocess.run([*enter, a.runner / 'wineserver', '-k'], env=env, timeout=10)
    server.wait(timeout=10)
    observer.wait(timeout=10)
    reader.join(timeout=10)
    assert any(r['type'] == 'stopped' and r.get('reason') == 'target-exit' for r in records)
    pins = subprocess.run(['sudo', '-n', 'ls', PIN], capture_output=True, text=True, check=True).stdout.split()
    assert pins == [], pins
    assert (a.work / 'observer-stderr.log').read_text() == ''
    assert not re.search(r'level=(error|fatal)', (a.work / 'mihomo.log').read_text())
    print('PASS: Windows images routed through pasta, ambiguity stayed unknown, pins removed on exit.', flush=True)
finally:
    subprocess.run([a.runner / 'wineserver', '-k'], env=env, timeout=10,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    for process in root_processes:
        stop_root(process)
    for process in reversed(processes):
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)
    if pasta:
        subprocess.run(['kill', str(pasta)], check=False, stderr=subprocess.DEVNULL)
    subprocess.run(['sudo', '-n', 'nft', 'delete', 'table', 'inet', 'wine_route_test'], check=False)
    subprocess.run(['sudo', '-n', 'ip', 'addr', 'del', HOST + '/32', 'dev', 'lo'], check=False)
    subprocess.run(['sudo', '-n', 'rm', '-rf', PIN], check=False)
