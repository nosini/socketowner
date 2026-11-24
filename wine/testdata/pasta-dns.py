#!/usr/bin/env python3
"""VM-only end-to-end test: DNS through pasta's --dns-forward joins its client.

Run as the ordinary VM user. Only the observer is started through sudo -n. No
Wine and no mihomo are involved: a namespace holder stands in for the sandbox,
real pasta forwards it, and two processes inside imitate the Wine request
protocol over a FIFO, so the client's identity is its host TGID with the
no-image status rather than a Windows name. The relay join is the assertion.

pasta maps queries to its --dns-forward address onto --dns-host, so the inner
record must be keyed by that destination. A query to an address pasta does not
map must keep its own destination, and a process which never wrote a request
must stay not-wine.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import threading
import time

# Nothing listens at the resolver: the join happens when pasta connects, and
# a loopback port nobody bound refuses a TCP connection at once, so pasta never
# waits on it. --dns-host still names the destination pasta connects to.
FORWARD = '169.254.1.1'
RESOLVER = '127.0.0.1'
UNMAPPED = '198.18.99.99'

holder = None
pasta = 0
observer = None

p = argparse.ArgumentParser()
p.add_argument('--observer', required=True, type=Path)
p.add_argument('--work', required=True, type=Path)
a = p.parse_args()
for name in ('observer', 'work'):
    setattr(a, name, getattr(a, name).resolve())
a.work.mkdir(parents=True, exist_ok=True)
processes = []
root_processes = []
records = []


def background(args, log, **kwargs):
    f = (a.work / log).open('w')
    process = subprocess.Popen([str(x) for x in args], cwd=a.work, stdout=f, stderr=f, **kwargs)
    return process


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def stop_root(observer):
    if observer.poll() is None:
        subprocess.run(['sudo', '-n', 'pkill', '-TERM', '-P', str(observer.pid)], check=False)
        try:
            observer.wait(timeout=10)
        except subprocess.TimeoutExpired:
            subprocess.run(['sudo', '-n', 'pkill', '-KILL', '-P', str(observer.pid)], check=False)
            observer.wait(timeout=5)


def start_observer():
    o = subprocess.Popen(['sudo', '-n', str(a.observer)], stdout=subprocess.PIPE,
                         stderr=(a.work / 'observer-stderr.log').open('a'), text=True)
    root_processes.append(o)
    ready = threading.Event()

    def collect():
        with (a.work / 'events.jsonl').open('a') as log:
            for line in o.stdout:
                log.write(line)
                log.flush()
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                records.append(value)
                if value['type'] == 'ready':
                    ready.set()

    threading.Thread(target=collect, daemon=True).start()
    assert ready.wait(10), 'observer not ready; see observer-stderr.log'
    return o


def wait_for(predicate, timeout, what):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(.05)
    raise AssertionError(what)


FAKE_SERVER = '''
import ctypes, os, time
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl(15, ctypes.create_string_buffer(b"wineserver"), 0, 0, 0)
fd = os.open({fifo!r}, os.O_RDONLY | os.O_NONBLOCK)
os.read(fd, 1)
print("read", flush=True)
time.sleep(3600)
'''

FAKE_CLIENT = '''
import os, socket, time
fd = os.open({fifo!r}, os.O_WRONLY)
os.write(fd, b"request")
print("wrote", flush=True)
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.sendto(b"query", ({forward!r}, 53))
print("udp", udp.getsockname()[1], flush=True)
plain = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
plain.sendto(b"unmapped", ({unmapped!r}, 53))
print("unmapped", plain.getsockname()[1], flush=True)
tcp = socket.create_connection(({forward!r}, 53), timeout=10)
print("tcp", flush=True)
time.sleep(5)
'''

FAKE_PLAIN = '''
import socket, time
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.sendto(b"plain", ({forward!r}, 53))
print("plain", flush=True)
time.sleep(5)
'''

try:
    fifo = a.work / 'request'
    if not fifo.exists():
        os.mkfifo(fifo)
    pidfile = a.work / 'holder.pid'
    holder = background(['unshare', '--user', '--map-current-user', '--net', 'sh', '-c',
                         f'echo $$ > {pidfile}; exec sleep 3600'], 'holder.log')
    processes.append(holder)
    for _ in range(50):
        if pidfile.exists() and pidfile.read_text().strip():
            break
        time.sleep(.05)
    inner = int(pidfile.read_text().strip())
    enter = ['nsenter', '-t', str(inner), '-U', '-n', '--preserve-credentials']
    time.sleep(.2)
    # pasta's confinement refuses to create files, so give it an existing one.
    pasta_pidfile = Path(tempfile.mkstemp()[1])
    subprocess.run(['pasta', '--quiet', '--config-net', '--netns-only',
                    '--userns', f'/proc/{inner}/ns/user', '--netns', f'/proc/{inner}/ns/net',
                    '--no-netns-quit', '-P', str(pasta_pidfile), '-4',
                    '-t', 'none', '-u', 'none', '-T', 'none', '-U', 'none',
                    '--map-host-loopback', 'none', '--map-guest-addr', 'none',
                    '--dns-forward', FORWARD, '--dns-host', RESOLVER], check=True)
    pasta = int(pasta_pidfile.read_text())
    os.unlink(pasta_pidfile)

    observer = start_observer()
    server = background([*enter, 'python3', '-c',
                         FAKE_SERVER.format(fifo=str(fifo))], 'server.log')
    processes.append(server)

    def server_event():
        return any(r['type'] == 'server' and r['server_tgid'] == server.pid for r in records)

    wait_for(server_event, 15, 'no server event; see events.jsonl and server.log')

    def pasta_event():
        return any(r['type'] == 'pasta' and r['pasta_tgid'] == pasta for r in records)

    wait_for(pasta_event, 15, 'pasta not registered; see events.jsonl')

    client = background([*enter, 'python3', '-c',
                         FAKE_CLIENT.format(fifo=str(fifo), forward=FORWARD, unmapped=UNMAPPED)],
                        'client.log')
    processes.append(client)
    plain = background([*enter, 'python3', '-c',
                        FAKE_PLAIN.format(forward=FORWARD)], 'plain.log')
    processes.append(plain)
    wait_for(lambda: client.poll() is not None and plain.poll() is not None, 30,
             'client or plain did not finish; see client.log and plain.log')

    client_relays = [r for r in records if r['type'] == 'relay' and r.get('client_tgid') == client.pid]
    plain_relays = [r for r in records if r['type'] == 'relay' and r.get('status') == 'not-wine']
    unknown = [r for r in records if r['type'] == 'relay' and r['status'] == 'no-inner-flow']
    creates = [r for r in records if r['type'] == 'create' and r.get('creator') == 'client']

    def joined(relays, network):
        return [r for r in relays if r['network'] == network and r['status'] == 'no-image']

    print('client relays', json.dumps(client_relays), flush=True)
    print('plain relays', json.dumps(plain_relays), flush=True)
    print('client creates', json.dumps(creates), flush=True)
    assert len(joined(client_relays, 'udp')) >= 2, 'mapped and unmapped UDP queries must both join'
    assert len(joined(client_relays, 'tcp')) >= 1, 'the mapped TCP query must join'
    assert len(plain_relays) >= 1, 'a process which never wrote a request must stay not-wine'
    assert not unknown, unknown
    assert all(r.get('server_tgid') == server.pid for r in client_relays + creates), \
        'records must name the client\'s wineserver'
    assert len(creates) >= 3 and all(r['status'] == 'no-image' for r in creates), creates
    assert (a.work / 'observer-stderr.log').read_text() == ''
    print('PASS: DNS through pasta joins its client, not-wine stays not-wine, '
          'and unmapped destinations keep their own records.', flush=True)
finally:
    if observer is not None:
        stop_root(observer)
    for process in reversed(processes):
        stop(process)
    if pasta:
        os.kill(pasta, signal.SIGTERM)
    if holder is not None and holder.poll() is None:
        subprocess.run(['kill', str(inner)], check=False)
