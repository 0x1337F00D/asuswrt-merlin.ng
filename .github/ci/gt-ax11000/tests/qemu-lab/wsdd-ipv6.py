"""IPv6 loopback protocol lifecycle; no claim of physical WAN isolation."""
import ast
import os
from pathlib import Path
import random
import signal
import socket
import subprocess
import sys
import time

if not os.environ.get('PARENT_NETNS') or os.readlink('/proc/self/ns/net') == os.environ['PARENT_NETNS']:
    raise SystemExit('fresh netns required')
if len(subprocess.check_output(['ip', '-o', 'link']).splitlines()) != 1:
    raise SystemExit('namespace not empty')
subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
tree = ast.parse(Path(__file__).parent.parent.joinpath('wsdd2-slow-client-netns.py').read_text())
probe = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
             and any(isinstance(t, ast.Name) and t.id == 'probe' for t in n.targets))
rng = random.Random(4908)
process = subprocess.Popen([sys.argv[1], '-w', '-6', '-i', 'lo', '-W'])
try:
    time.sleep(.2)
    if process.poll() is not None:
        raise AssertionError(('startup', process.returncode))
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as peer:
        peer.bind(('::1', 0)); peer.settimeout(2)
        def positive():
            peer.sendto(probe, ('::1', 3702))
            data, source = peer.recvfrom(20000)
            if b'ProbeMatches' not in data or source[1] != 3702:
                raise AssertionError('IPv6 positive control')
        positive()
        for size in (0, 1, 512, 8192, 8193):
            for _ in range(50): peer.sendto(rng.randbytes(size), ('::1', 3702))
        time.sleep(1.1)
        process.send_signal(signal.SIGHUP); time.sleep(.1)
        positive()
    if process.poll() is not None: raise AssertionError(('unexpected exit', process.returncode))
    process.terminate(); process.wait(timeout=3)
    if process.returncode not in (0, -signal.SIGTERM): raise AssertionError(('crash', process.returncode))
    print('WSDD_IPV6=PASS before/after 250 malformed datagrams and SIGHUP')
finally:
    if process.poll() is None:
        process.kill(); process.wait()
