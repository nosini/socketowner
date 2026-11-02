#!/usr/bin/env python3
"""VM-only native packet cost. Run with sudo; temporarily restarts the Wine service.

cc -O2 -Wall -Wextra native-cost.c -o native-cost
sudo python3 native-cost.py ./native-cost > native-cost.json
Native socketowner remains attached in both cases. The statistics pass measures
wine_egress only, with kernel BPF timing enabled through a scoped FD. The separate
alternating pass has timing disabled and measures send+receive cost, including
all Wine hooks. Neither pass measures the known-Wine or pasta publication path.
"""
import ctypes
import json
import os
import platform
from pathlib import Path
import statistics
import subprocess
import sys

SERVICE = 'socketowner-wine-observer.service'
binary = str(Path(sys.argv[1]).resolve())
cpu = min(os.sched_getaffinity(0))


def service(action):
    subprocess.run(['systemctl', action, SERVICE], check=True, stdout=subprocess.DEVNULL)


def run(family, size, count):
    return float(subprocess.check_output(['taskset', '-c', str(cpu), binary,
                                         str(family), str(size), str(count)], text=True))


def info():
    result = json.loads(subprocess.check_output(['bpftool', '-j', 'prog', 'show', 'name', 'wine_egress']))
    # Refuse to silently time another concurrent observer.
    if isinstance(result, list):
        assert len(result) == 1, result
        result = result[0]
    return result


assert platform.machine() == 'x86_64', 'observer and syscall number require Linux amd64'
assert os.geteuid() == 0
active = subprocess.run(['systemctl', 'is-active', '--quiet', SERVICE]).returncode == 0
results = {'cpu': cpu, 'round_trips': 1000000, 'samples': [], 'instrumented_egress': []}
try:
    for family in (4, 6):
        for size in (64, 1400):
            off, on = [], []
            for repeat in range(6):
                # Reverse pair order each time to reduce drift bias.
                for enabled in ((False, True) if repeat % 2 == 0 else (True, False)):
                    service('start' if enabled else 'stop')
                    run(family, size, 10000)
                    value = run(family, size, results['round_trips'])
                    (on if enabled else off).append(value)
            results['samples'].append(dict(family=family, payload=size, off_ns=off, on_ns=on,
                median_delta_ns=statistics.median(on)-statistics.median(off),
                median_percent=(statistics.median(on)/statistics.median(off)-1)*100))
    Path(binary + '.samples.json').write_text(json.dumps(results, indent=2))
    service('start')
    # x86-64 bpf(BPF_ENABLE_STATS, {type: BPF_STATS_RUN_TIME}, 4).
    # Closing its FD restores the previous global accounting state.
    libc = ctypes.CDLL(None, use_errno=True)
    attr = ctypes.c_uint32(0)
    statsfd = libc.syscall(321, 32, ctypes.byref(attr), 4)
    if statsfd < 0:
        raise OSError(ctypes.get_errno(), 'BPF_ENABLE_STATS')
    try:
        for family in (4, 6):
            for size in (64, 1400):
                before = info()
                run(family, size, results['round_trips'])
                after = info()
                assert before['id'] == after['id']
                count = after.get('run_cnt', 0)-before.get('run_cnt', 0)
                ns = after.get('run_time_ns', 0)-before.get('run_time_ns', 0)
                results['instrumented_egress'].append(dict(family=family, payload=size,
                    calls=count, ns_per_call=ns/count))
    finally:
        os.close(statsfd)
    print(json.dumps(results, indent=2))
finally:
    service('start' if active else 'stop')
