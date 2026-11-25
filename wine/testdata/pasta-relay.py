#!/usr/bin/env python3
"""VM-only relay test: mingw PE probes behind real pasta, routed by real mihomo.

Covers what pasta-route.py does not: IPv6 through the relay (--family 6),
32-bit programs under new-style WOW64 (--bits 32 --wow64) and relay load
(--load). Run as the ordinary VM user; the observer, mihomo, test addresses
and one nftables table use sudo -n. --baseline runs the load without the
observer, for timing only.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time

PIN = '/sys/fs/bpf/wine-relay-test'
REDIR = 17893
MARK = 6667
DUMMY = 'wrelay6'
LOAD_TCP = 31000
LOAD_UDP = 32000
MIXED = 99
TAGS = 41000

p = argparse.ArgumentParser()
p.add_argument('--runner', required=True, type=Path, help='directory holding wine and wineserver')
p.add_argument('--observer', required=True, type=Path)
p.add_argument('--mihomo', required=True, type=Path)
p.add_argument('--work', required=True, type=Path)
p.add_argument('--family', type=int, default=4, choices=(4, 6))
p.add_argument('--bits', type=int, default=64, choices=(32, 64), help='mingw PE probes')
p.add_argument('--wow64', action='store_true', help='WINEARCH=wow64 prefix: new-style WOW64')
p.add_argument('--load', action='store_true', help='add the load and mixed-destination phases')
p.add_argument('--baseline', action='store_true', help='load only, no observer: timing reference')
p.add_argument('--programs', type=int, default=4)
p.add_argument('--threads', type=int, default=8)
p.add_argument('--rounds', type=int, default=100, help='TCP connections and UDP sockets per thread')
a = p.parse_args()
if a.baseline:
    a.load = True
for name in ('runner', 'observer', 'mihomo', 'work'):
    setattr(a, name, getattr(a, name).resolve())
if a.work.exists():
    shutil.rmtree(a.work)
a.work.mkdir(parents=True)
source = Path(__file__).resolve().parent
HOST = '198.18.77.1' if a.family == 4 else 'fd77:78::1'
# pasta's host sockets leave from their own address. Sharing HOST would let a
# server's or mihomo's socket hold the same address and port as a live pasta
# socket, which removes its record by design (see the README's limitations).
SOURCE = '198.18.77.2' if a.family == 4 else 'fd77:78::2'
PREFIX = 32 if a.family == 4 else 128
IP = 'ip' if a.family == 4 else 'ip6'
env = dict(os.environ, WINEPREFIX=str(a.work / 'prefix'), WINEDEBUG='-all',
           WINEDLLOVERRIDES='winemenubuilder.exe=d;mscoree,mshtml=', PROBE_HOST=HOST,
           PROBE_LINGER='500')
for name in ('DISPLAY', 'WAYLAND_DISPLAY', 'WINEARCH'):
    env.pop(name, None)
if a.wow64:
    env['WINEARCH'] = 'wow64'
compiler = {32: 'i686-w64-mingw32-gcc', 64: 'x86_64-w64-mingw32-gcc'}[a.bits]
loads = [f'load{k}' for k in range(a.programs)]
processes = []
root_processes = []
pasta = 0
records = []


def sudo(*args, **kwargs):
    return subprocess.run(['sudo', '-n', *map(str, args)], check=True, **kwargs)


def sudo_ls(path):
    return subprocess.run(['sudo', '-n', 'ls', path], capture_output=True, text=True, check=True).stdout.split()


def background(args, log, **kwargs):
    f = (a.work / log).open('w')
    return subprocess.Popen([str(x) for x in args], cwd=a.work, stdout=f, stderr=f, **kwargs)


def stop_root(process):
    if process.poll() is None:
        subprocess.run(['sudo', '-n', 'pkill', '-TERM', '-P', str(process.pid)], check=False)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            subprocess.run(['sudo', '-n', 'pkill', '-KILL', '-P', str(process.pid)], check=False)
            process.wait(timeout=5)


def port_of(address):
    return int(address.rsplit(':', 1)[1])


class ArchWatch(threading.Thread):
    """Records which ntdll.so each running probe maps: x86_64 means a 64-bit Linux process.

    The latest observation wins: Wine's launcher may start in the other
    architecture and exec the right loader in the same process."""

    def __init__(self, names):
        super().__init__(daemon=True)
        self.names, self.seen, self.done = names, {}, threading.Event()

    def run(self):
        while not self.done.is_set():
            for pid in filter(str.isdigit, os.listdir('/proc')):
                try:
                    cmdline = Path(f'/proc/{pid}/cmdline').read_bytes()
                    name = next((n for n in self.names if (n + '.exe').encode() in cmdline), None)
                    if name:
                        maps = Path(f'/proc/{pid}/maps').read_text()
                        arch = re.search(r'/(x86_64|i386)-unix/ntdll\.so', maps)
                        if arch:
                            self.seen[name] = arch.group(1)
                except OSError:
                    pass
            time.sleep(.01)


# ---- setup ------------------------------------------------------------------
try:
    if a.family == 6:
        # pasta needs an IPv6 template interface; a dummy keeps the VM's own routes untouched.
        sudo('ip', 'link', 'add', DUMMY, 'type', 'dummy')
        sudo('ip', 'link', 'set', DUMMY, 'up')
        sudo('ip', 'addr', 'add', 'fd77:77::1/64', 'dev', DUMMY, 'nodad')
    for address in (HOST, SOURCE):
        sudo('ip', 'addr', 'add', f'{address}/{PREFIX}', 'dev', 'lo', *(['nodad'] if a.family == 6 else []))
    sudo('mkdir', '-p', PIN)
    sudo('nft', '-f', '-', input=f'''table inet wine_relay_test {{
      chain out {{
        type nat hook output priority -100;
        meta mark {MARK} return
        {IP} daddr {HOST} tcp dport {{ 30443, {LOAD_TCP}-{LOAD_TCP + MIXED} }} redirect to :{REDIR}
      }}
    }}
    ''', text=True)
    for name in ('alpha', 'beta'):
        subprocess.run([compiler, '-O1', '-o', a.work / (name + '.exe'), source / 'winsock-probe.c',
                        '-lws2_32', '-lmswsock', '-static'], check=True)
    subprocess.run([compiler, '-O1', '-o', a.work / 'load.exe', source / 'load-probe.c', '-lws2_32', '-static'],
                   check=True)
    for name in loads:
        shutil.copy(a.work / 'load.exe', a.work / (name + '.exe'))
    with (a.work / 'prefix-init.log').open('w') as f:
        boot = subprocess.Popen([str(a.runner / 'wineboot'), '-u'], env=env, cwd=a.work, stdout=f, stderr=f)
        try:
            boot.wait(timeout=120)
        except subprocess.TimeoutExpired:
            boot.kill()
            boot.wait()
        subprocess.run([a.runner / 'wineserver', '-k'], env=env, timeout=10,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    (a.work / 'mihomo').mkdir()
    rules = ['WINE-PROCESS-NAME,beta.exe,REJECT', 'WINE-PROCESS-NAME,alpha.exe,DIRECT',
             *(f'WINE-PROCESS-NAME,{n}.exe,{n}' for n in loads),
             'WINE-PROCESS-NAME,wine-unknown,DIRECT', 'MATCH,DIRECT']
    # Without allow-lan mihomo listens on 127.0.0.1 only; nftables redirects IPv6 to ::1.
    (a.work / 'mihomo' / 'config.yaml').write_text(f'''redir-port: {REDIR}
mode: rule
log-level: debug
ipv6: {'true' if a.family == 6 else 'false'}
{"allow-lan: true" + chr(10) + "bind-address: '*'" if a.family == 6 else ''}
routing-mark: {MARK}
find-process-mode: always
find-process-bpf-map: {PIN}/conn_owners
proxies:
''' + ''.join(f'  - {{name: {n}, type: socks5, server: 127.0.0.1, port: {TAGS + k}}}\n'
              for k, n in enumerate(loads)) + 'rules:\n' + ''.join(f'  - {r}\n' for r in rules))
    mihomo = subprocess.Popen(['sudo', '-n', str(a.mihomo), '-d', str(a.work / 'mihomo')],
                              stdout=(a.work / 'mihomo.log').open('w'), stderr=subprocess.STDOUT)
    root_processes.append(mihomo)
    processes.append(background(['python3', source / 'echo-server.py', HOST], 'echo.log'))
    processes.append(background(['python3', source / 'echo-server.py', HOST, '--delay', '0',
                                 '--tcp', *range(LOAD_TCP, LOAD_TCP + MIXED + 1),
                                 '--udp', *range(LOAD_UDP, LOAD_UDP + MIXED + 1)], 'echo-load.log'))
    # Each load program's rule names its own SOCKS outbound, which echoes and
    # logs the tag the connection carried: a misnamed flow shows a foreign tag.
    processes.append(background(['python3', source / 'tag-echo.py', '127.0.0.1', TAGS, a.programs], 'tags.log'))
    # mihomo closes connections it accepts before it is running; wait for one it logs.
    for _ in range(100):
        try:
            with socket.create_connection((HOST, 30443), 2) as probe:
                probe.sendall(b'ready')
                probe.recv(9)
        except OSError:
            pass
        if '[TCP]' in (a.work / 'mihomo.log').read_text():
            break
        time.sleep(.2)
    else:
        raise AssertionError('mihomo never routed a host connection; see mihomo.log')

    pidfile = a.work / 'holder.pid'
    processes.append(background(['unshare', '--user', '--map-current-user', '--net', 'sh', '-c',
                                 f'echo $$ > {pidfile}; exec sleep 7200'], 'holder.log'))
    for _ in range(50):
        if pidfile.exists() and pidfile.read_text().strip():
            break
        time.sleep(.05)
    inner = pidfile.read_text().strip()
    enter = ['nsenter', '-t', inner, '-U', '-n', '--preserve-credentials']
    time.sleep(.2)
    family = ['-4'] if a.family == 4 else ['-6', '-i', DUMMY, '-a', 'fd77:77::2', '-g', 'fd77:77::1']
    pasta_pidfile = Path(tempfile.mkstemp()[1])
    subprocess.run(['pasta', '--quiet', '--config-net', '--netns-only', '--userns', f'/proc/{inner}/ns/user',
                    '--netns', f'/proc/{inner}/ns/net', '--no-netns-quit', '-P', str(pasta_pidfile), *family,
                        '--outbound', SOURCE,
                    '-t', 'none', '-u', 'none', '-T', 'none', '-U', 'none',
                    '--map-host-loopback', 'none', '--map-guest-addr', 'none'], check=True)
    pasta = int(pasta_pidfile.read_text())
    os.unlink(pasta_pidfile)
    pasta_comm = Path(f'/proc/{pasta}/comm').read_text().strip()

    if not a.baseline:
        observer = subprocess.Popen(['sudo', '-n', str(a.observer), '-pin', PIN], stdout=subprocess.PIPE,
                                    stderr=(a.work / 'observer-stderr.log').open('w'), text=True)
        root_processes.append(observer)
        ready = threading.Event()

        def collect():
            with (a.work / 'events.jsonl').open('w') as log:
                for line in observer.stdout:
                    log.write(line)
                    value = json.loads(line)
                    records.append(value)
                    if value['type'] == 'ready':
                        ready.set()
        reader = threading.Thread(target=collect, daemon=True)
        reader.start()
        assert ready.wait(10), 'observer did not become ready; see observer-stderr.log'

    server = background([*enter, a.runner / 'wineserver', '-f', '-p'], 'server.log', env=env)
    processes.append(server)
    time.sleep(.5)
    assert server.poll() is None, 'wineserver failed'
    watch = ArchWatch(['alpha', 'beta', *loads])
    watch.start()

    def wine(name, *args):
        out = (a.work / (name + '-stdout.log')).open('w')
        return subprocess.Popen([str(x) for x in [*enter, a.runner / 'wine', name + '.exe', *args]],
                                cwd=a.work, env=env, stdout=out, stderr=subprocess.STDOUT)

    def finish(run, timeout):
        try:
            return run.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            run.kill()
            return run.wait()

    def mihomo_tcp(lines_from=0):
        """(source, destination port, rule) for each TCP connection mihomo logged."""
        lines = (a.work / 'mihomo.log').read_text().splitlines()[lines_from:]
        found = []
        for line in lines:
            m = re.search(r'\[TCP\] (\S+)\((.*?)\) --> (\S+) match (\S+) using (\w+)', line)
            if m:
                found.append((m.group(2), port_of(m.group(3)), m.group(4), m.group(5)))
        return found

    # ---- attribution: IPv6 and WOW64 ------------------------------------------
    if not a.baseline:
        pids = {}
        for name in ('alpha', 'beta'):
            finish(wine(name), 60)
            output = (a.work / (name + '-stdout.log')).read_text()
            pids[name] = int(re.search(r'Windows PID=(\d+)', output).group(1))
        assert 'ConnectEx recv=14' in (a.work / 'alpha-stdout.log').read_text(), 'alpha traffic did not pass DIRECT'
        time.sleep(.5)
        print('client processes:', watch.seen, flush=True)
        # Some runners are built for new-style WOW64 and use it without WINEARCH.
        arch = set(watch.seen.get(n) for n in ('alpha', 'beta'))
        assert len(arch) == 1 and None not in arch, watch.seen
        expected_arch = arch.pop()
        assert expected_arch == 'x86_64' or (a.bits == 32 and not a.wow64), watch.seen
        log = mihomo_tcp()
        for name, rule in (('alpha.exe', 'DIRECT'), ('beta.exe', 'REJECT')):
            matches = [m for m in log if m[2] == f'WineProcessName({name})' and m[3] == rule and m[1] == 30443]
            print(name, 'mihomo TCP matches using', rule + ':', len(matches), flush=True)
            assert len(matches) == 2, (name, log)
        assert all(HOST in line for line in (a.work / 'mihomo.log').read_text().splitlines() if '[TCP]' in line)
        # A 64-bit Linux process holds the 64-bit TEB in GS: full path and Windows PID.
        full_path = expected_arch == 'x86_64'
        for name in ('alpha', 'beta'):
            relays = [r for r in records if r['type'] == 'relay' and r.get('windows_name') == name + '.exe']
            assert len(relays) == 3 and {r['network'] for r in relays} == {'tcp', 'udp'}, (name, relays)
            assert all(r['server_tgid'] == server.pid for r in relays)
            if full_path:
                assert all(r['windows_pid'] == pids[name] for r in relays), relays
                assert all(re.fullmatch(rf'[A-Z]:\\.*\\{name}\.exe', r.get('windows_image', ''), re.I)
                           for r in relays), relays
            else:
                assert all('windows_image' not in r for r in relays), relays
            print(name, 'relays:', len(relays), 'image', relays[0].get('windows_image', '(name only)'),
                  'Windows PID', relays[0].get('windows_pid'), flush=True)
        host_udp = [r for r in records if r['type'] == 'first-egress' and r.get('actor_tgid') == pasta and
                    r['network'] == 'udp' and r.get('windows_name') in ('alpha.exe', 'beta.exe')]
        assert len(host_udp) == 2 and all(HOST in r['destination'] for r in host_udp), host_udp
        print('UDP host packets:', [(r['windows_name'], r['source'], r['destination']) for r in host_udp], flush=True)
        assert not [r for r in records if r['type'] == 'relay' and r['status'] != 'known'], 'unknown relay'
        assert 'wine-unknown' not in (a.work / 'mihomo.log').read_text()
        print(f'PASS attribution: IPv{a.family}, {a.bits}-bit{" new-style WOW64" if a.bits == 32 and expected_arch == "x86_64" else ""} probes on {expected_arch} '
              'Linux processes, routed by name through pasta.', flush=True)

    # ---- load ---------------------------------------------------------------
    def load_phase(label, ports, udp):
        start_line = len((a.work / 'mihomo.log').read_text().splitlines())
        start_tag = len((a.work / 'tags.log').read_text().splitlines())
        start_record = len(records)
        began = time.monotonic()
        runs = [wine(n, LOAD_TCP + port, LOAD_UDP + port if udp else 0, a.rounds, a.threads, f'L{k:03d}')
                for k, (n, port) in enumerate(zip(loads, ports))]
        codes = [finish(r, 900) for r in runs]
        elapsed = time.monotonic() - began
        totals = dict(tcp_ok=0, tcp_fail=0, udp_ok=0, udp_fail=0)
        for n in loads:
            m = re.search(r'load tcp_ok=(\d+) tcp_fail=(\d+) udp_ok=(\d+) udp_fail=(\d+) ms=(\d+)',
                          (a.work / (n + '-stdout.log')).read_text())
            assert m, (n, 'no result')
            for key, value in zip(totals, m.groups()):
                totals[key] += int(value)
        connections = totals['tcp_ok'] + totals['tcp_fail']
        print(f'{label}: {a.programs} programs x {a.threads} threads x {a.rounds} rounds in {elapsed:.1f} s, '
              f'{connections / elapsed:.0f} TCP connections/s{" plus as many UDP sockets" if udp else ""}, '
              f'{totals}, exit codes {codes}', flush=True)
        time.sleep(1)
        if a.baseline:
            return totals, None, None
        # TCP: the tagged outbound saw the sender's own tag, or another program's.
        tagged = [line.split() for line in (a.work / 'tags.log').read_text().splitlines()[start_tag:]]
        tcp = {'right': sum(x == y for x, y in tagged), 'wrong': sum(x != y for x, y in tagged)}
        rules = {}
        for _, port, rule, _ in mihomo_tcp(start_line):
            if LOAD_TCP <= port <= LOAD_TCP + MIXED:
                rules[rule] = rules.get(rule, 0) + 1
        tcp['wine-unknown'] = rules.get('WineProcessName(wine-unknown)', 0)
        tcp['no-record'] = sum(v for k, v in rules.items() if not k.startswith('WineProcessName('))
        # UDP: pasta's host packet named after the program owning that destination.
        owner = {LOAD_UDP + port: n + '.exe' for n, port in zip(loads, ports)}
        udp_result = {'right': 0, 'wrong': 0, 'unknown': 0}
        new = records[start_record:]
        for r in new:
            if r['type'] == 'first-egress' and r.get('actor_tgid') == pasta and r['network'] == 'udp':
                if r['status'] != 'known':
                    udp_result['unknown'] += 1
                else:
                    udp_result['right' if r.get('windows_name') == owner.get(port_of(r['destination'])) else 'wrong'] += 1
        relay = {}
        for r in new:
            if r['type'] == 'relay':
                relay[r['status']] = relay.get(r['status'], 0) + 1
        loss = sum(r.get('lost_events', 0) for r in new if r['type'] == 'loss')
        print(f'{label}: TCP {tcp}; mihomo rules {rules}', flush=True)
        print(f'{label}: host UDP events {udp_result}; relay events {relay}; lost events {loss}', flush=True)
        if tcp['wrong']:
            print('misnamed:', [t for t in tagged if t[0] != t[1]][:20], flush=True)
        return totals, tcp, udp_result

    if a.load:
        totals, tcp, udp = load_phase('separate destinations', list(range(a.programs)), True)
        # A UDP reply can still be lost after retries; attribution is checked from events.
        assert totals['tcp_fail'] == 0, totals
        if not a.baseline:
            assert tcp['wrong'] == 0 and udp['wrong'] == 0 and udp['unknown'] == 0, 'misattributed flow'
            # Rarely a TCP flow stays unknown (no-inner-flow) under concurrency; see the README.
            assert tcp['no-record'] == 0 and tcp['right'] + tcp['wine-unknown'] == totals['tcp_ok'], tcp
            # Concurrent owners of one destination: unknown is allowed, a wrong name is not.
            # TCP only: a reused UDP 4-tuple keeps pasta's flow and its earlier owner.
            totals, tcp, udp = load_phase('one shared destination', [MIXED] * a.programs, False)
            assert totals['tcp_fail'] == 0, totals
            assert tcp['wrong'] == 0, 'misattributed flow'
            assert tcp['right'] + tcp['wine-unknown'] == totals['tcp_ok'], tcp
            print('PASS load: no flow named after the wrong program.', flush=True)

    if not a.baseline:
        stop_root(observer)
        reader.join(timeout=10)
        assert any(r['type'] == 'stopped' and r.get('reason') == 'cancelled' for r in records)
        assert sudo_ls(PIN) == []
        assert (a.work / 'observer-stderr.log').read_text() == ''
    assert not re.search(r'level=(error|fatal)', (a.work / 'mihomo.log').read_text())
    print(f'PASS (pasta binary {pasta_comm}).', flush=True)
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
    subprocess.run(['sudo', '-n', 'nft', 'delete', 'table', 'inet', 'wine_relay_test'], check=False)
    for address in (HOST, SOURCE):
        subprocess.run(['sudo', '-n', 'ip', 'addr', 'del', f'{address}/{PREFIX}', 'dev', 'lo'], check=False)
    if a.family == 6:
        subprocess.run(['sudo', '-n', 'ip', 'link', 'del', DUMMY], check=False)
    subprocess.run(['sudo', '-n', 'rm', '-rf', PIN], check=False)
