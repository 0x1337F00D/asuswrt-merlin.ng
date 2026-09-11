#!/usr/bin/env python3
"""Bounded host-only descriptor/resource exercise of wsdd2."""
import os, socket, subprocess, sys, time, signal
from pathlib import Path
if not os.environ.get('PARENT_NETNS') or os.readlink('/proc/self/ns/net') == os.environ['PARENT_NETNS']:
    raise SystemExit('fresh netns required')
if len(subprocess.check_output(['ip','-o','link']).splitlines()) != 1:
    raise SystemExit('namespace is not empty')
subprocess.run(['ip','link','set','lo','up'],check=True)
p=subprocess.Popen([sys.argv[1],'-w','-4','-i','lo'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
def count(): return len(list(Path(f'/proc/{p.pid}/fd').iterdir()))
def rss():
    return next(int(line.split()[1]) for line in Path(f'/proc/{p.pid}/status').read_text().splitlines() if line.startswith('VmRSS:'))
try:
    time.sleep(.2)
    baseline=count(); memory=rss(); peak=baseline; refused=0; established=0
    for iteration in range(120):
        peers=[]
        try:
            for client in range(12):
                try:
                    peer=socket.create_connection(('127.0.0.1',3702),timeout=.2)
                except (TimeoutError, ConnectionRefusedError):
                    refused+=1
                    continue
                established+=1
                peers.append(peer)
                if client % 3 == 0:
                    try: peer.sendall(b'POST /partial HTTP/1.1\r\n')
                    except (ConnectionResetError,BrokenPipeError): pass
            time.sleep(.03)
            observed=count(); peak=max(peak,observed)
            if observed > baseline+8: raise AssertionError((baseline,observed))
            if iteration % 20 == 19:
                p.send_signal(signal.SIGHUP)
                time.sleep(.08)
        finally:
            for peer in peers: peer.close()
        time.sleep(.03)
        if p.poll() is not None: raise AssertionError('daemon exited')
    time.sleep(2.2)
    final=count(); final_memory=rss()
    if final != baseline: raise AssertionError(('fd leak',baseline,final))
    # QEMU RSS includes JIT/host allocations: record it, do not label it guest RAM.
    if established < 120: raise AssertionError('insufficient admitted connections')
    print(f'WSDD_RESOURCE_SOAK=PASS rounds=120 attempts=1440 established={established} refused={refused} reloads=6 fd_base={baseline} fd_peak={peak} fd_final={final} rss_base_kib={memory} rss_final_kib={final_memory}')
finally:
    p.terminate()
    p.wait(timeout=3)
    if p.returncode not in (0, -signal.SIGTERM):
        raise AssertionError(('daemon crash at shutdown', p.returncode))
