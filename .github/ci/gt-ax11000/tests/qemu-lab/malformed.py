"""Deterministic malformed traffic against actual ARM daemons, isolated only."""
import ast
import json
import os
from pathlib import Path
import random
import signal
import socket
import struct
import subprocess
import sys
import time

if sys.flags.optimize:
    raise SystemExit('optimized Python refused')
if not os.environ.get('PARENT_NETNS') or os.readlink('/proc/self/ns/net') == os.environ['PARENT_NETNS']:
    raise SystemExit('fresh netns required')
if len(subprocess.check_output(['ip', '-o', 'link']).splitlines()) != 1:
    raise SystemExit('namespace not empty')
subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
subprocess.run(['ip', 'link', 'add', 'lan0', 'type', 'veth', 'peer', 'name', 'lanpeer'], check=True)
for device, address in [('lan0', '192.0.2.1/24'), ('lanpeer', '192.0.2.2/24')]:
    subprocess.run(['ip', 'addr', 'add', address, 'dev', device], check=True)
    subprocess.run(['ip', 'link', 'set', device, 'mtu', '20000', 'up'], check=True)
for name in ('all', 'lan0', 'lanpeer'):
    Path(f'/proc/sys/net/ipv4/conf/{name}/rp_filter').write_text('0')
    Path(f'/proc/sys/net/ipv4/conf/{name}/accept_local').write_text('1')

# Share the existing positive-control bytes without executing its test setup.
tree = ast.parse(Path(__file__).parent.parent.joinpath('wsdd2-slow-client-netns.py').read_text())
wsd = next(ast.literal_eval(node.value) for node in tree.body
           if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'probe' for t in node.targets))
seed, count = int(sys.argv[3]), int(sys.argv[4])
rng = random.Random(seed)
work = Path(os.environ['TMPDIR'])/f'malformed-{seed}'
work.mkdir()
summary = []

def packet(original, index):
    sizes = [0, 1, 3, 7, 8, 31, 511, 512, 513, 1400, 8191, 8192, 8193, 16384]
    if index % 3 == 0:
        return rng.randbytes(sizes[index % len(sizes)])
    if index % 3 == 1:
        return original[:rng.randrange(len(original)+1)]
    data = bytearray(original)
    for _ in range(1+index % 8):
        data[rng.randrange(len(data))] = rng.randrange(256)
    return bytes(data)

for label, binary, args, port, good in [
    ('infosvr', sys.argv[1], ['lan0'], 9999, bytes([12,21,31,0])+bytes(508)),
    ('wsdd2', sys.argv[2], ['-w','-4','-i','lo'], 3702, wsd)]:
    with (work/(label+'.stderr')).open('wb') as log:
        process = subprocess.Popen([binary, *args], stdout=log, stderr=log)
        try:
            time.sleep(.25)
            if process.poll() is not None:
                raise AssertionError((label, 'startup exit', process.returncode))
            baseline = len(list(Path(f'/proc/{process.pid}/fd').iterdir()))
            with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as wire, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
                wire.bind(('lanpeer', 0))
                if label == 'infosvr':
                    peer.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'lanpeer\0')
                peer.bind(('0.0.0.0', 0)); peer.settimeout(2)
                def send(data):
                    if label == 'wsdd2':
                        peer.sendto(data, ('127.0.0.1', port)); return
                    body = struct.pack('!HHHH', peer.getsockname()[1], port, 8+len(data), 0)+data
                    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(body), 0, 0, 64, 17, 0,
                                         socket.inet_aton('192.0.2.2'), socket.inet_aton('192.0.2.1'))
                    checksum = sum(struct.unpack('!10H', header))
                    while checksum >> 16: checksum = (checksum & 65535)+(checksum >> 16)
                    header = header[:10]+struct.pack('!H', (~checksum)&65535)+header[12:]
                    wire.send(b'\xff'*6+b'\x02\0\0\0\0\x22'+b'\x08\x00'+header+body)
                def positive():
                    # Drain old replies, then require a fresh real response.
                    peer.setblocking(False)
                    try:
                        while peer.recv(65535): pass
                    except BlockingIOError: pass
                    peer.settimeout(2)
                    send(good)
                    reply, source = peer.recvfrom(20000)
                    if source[1] != port or (label == 'infosvr' and len(reply) != 512) or (label == 'wsdd2' and b'ProbeMatches' not in reply):
                        raise AssertionError(label+' positive control')
                positive()
                for index in range(count):
                    data = packet(good, index)
                    # Last input survives even if the next call crashes.
                    (work/(label+'-last-input.bin')).write_bytes(data)
                    send(data)
                    if index % 64 == 0:
                        time.sleep(.004)
                        if process.poll() is not None:
                            raise AssertionError((label, 'unexpected exit', process.returncode, seed, index))
                time.sleep(2.2)  # expire duplicate / reply-rate windows
                positive()
                if label == 'wsdd2':
                    for shape in (b'POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n',
                                  b'POST / HTTP/1.1\r\nContent-Length: 999999999999999999999\r\n\r\n',
                                  b'GET / HTTP/9.9\r\n\r\n', b'X'*9000):
                        with socket.create_connection(('127.0.0.1', 3702), timeout=2) as stream:
                            stream.sendall(shape); stream.shutdown(socket.SHUT_WR)
                            try: stream.recv(65536)
                            except ConnectionResetError: pass
                    process.send_signal(signal.SIGHUP)
                    time.sleep(.15)
                    positive()
            time.sleep(.1)
            if process.poll() is not None:
                raise AssertionError((label, 'exited before shutdown', process.returncode))
            final = len(list(Path(f'/proc/{process.pid}/fd').iterdir()))
            if final != baseline:
                raise AssertionError((label, 'fd leak', baseline, final))
            process.terminate(); process.wait(timeout=3)
            if process.returncode not in (0, -signal.SIGTERM):
                raise AssertionError((label, 'shutdown crash', process.returncode))
            summary.append(dict(daemon=label, seed=seed, sent=count, fd_before=baseline, fd_after=final))
        finally:
            if process.poll() is None:
                process.kill(); process.wait()
    print(label, 'malformed ingress PASS', seed, count, flush=True)
(work/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
