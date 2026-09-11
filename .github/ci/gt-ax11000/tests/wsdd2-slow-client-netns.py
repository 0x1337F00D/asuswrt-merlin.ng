#!/usr/bin/env python3
"""Disposable network-namespace test of the real daemon, no router access.
PARENT_NETNS=$(readlink /proc/self/ns/net) unshare -Urn python3 SCRIPT BINARY
"""
import os
import socket
import subprocess
import sys
import time
from contextlib import ExitStack

if not os.environ.get('PARENT_NETNS') or os.readlink('/proc/self/ns/net') == os.environ['PARENT_NETNS']:
    raise SystemExit('fresh network namespace required')
links = subprocess.check_output(['ip','-o','link'],text=True)
if len(links.splitlines()) != 1:
    raise SystemExit('namespace must have only loopback')
subprocess.run(['ip','link','set','lo','up'],check=True)
probe = b'''<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
xmlns:p="http://schemas.microsoft.com/windows/pub/2005/07">
<s:Header><a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>
<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>
<a:MessageID>urn:uuid:11112222-3333-4444-5555-666677778888</a:MessageID>
</s:Header><s:Body><d:Probe><d:Types>p:Computer</d:Types></d:Probe></s:Body></s:Envelope>'''
process = subprocess.Popen([sys.argv[1],'-w','-4','-i','lo'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
try:
    time.sleep(.15)
    if process.poll() is not None:
        raise RuntimeError(process.stderr.read().decode())
    with ExitStack() as cleanup:
        for _ in range(2):
            cleanup.enter_context(socket.create_connection(('127.0.0.1',3702), timeout=1))
        time.sleep(.05)  # allow the old synchronous handler to enter its read
        peer = cleanup.enter_context(socket.socket(socket.AF_INET,socket.SOCK_DGRAM))
        peer.settimeout(.5)
        started=time.monotonic()
        peer.sendto(probe,('127.0.0.1',3702))
        reply,_=peer.recvfrom(16384)
        if b'ProbeMatches' not in reply:
            raise AssertionError('missing discovery reply')
        print(f'WSDD_SLOW_CLIENT=PASS discovery_seconds={time.monotonic()-started:.3f}')
        # A signal must not wait for slow clients' two-second lifetimes.
        started=time.monotonic()
        process.terminate()
        process.wait(timeout=.75)
        print(f'WSDD_SHUTDOWN=PASS seconds={time.monotonic()-started:.3f}')
finally:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
