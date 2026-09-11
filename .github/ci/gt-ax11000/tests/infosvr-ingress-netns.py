#!/usr/bin/env python3
"""Run ONLY in a fresh user/network/mount namespace; never against a router.

Caller: PARENT_NETNS=$(readlink /proc/self/ns/net) unshare -Urnm
        python3 THIS_SCRIPT /absolute/path/to/native/infosvr
Creates disposable LAN/WAN veth pairs; spoofed LAN-source WAN unicast and
multicast must not trigger a reply. LAN discovery must retain source port 9999.
"""
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

def command(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)

def checksum(data):
    values = struct.unpack('!%dH' % (len(data)//2), data)
    value = sum(values)
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535

def main():
    # Refuse execution outside isolation or in an existing configured network.
    if not os.environ.get('PARENT_NETNS') or os.readlink('/proc/self/ns/net') == os.environ['PARENT_NETNS']:
        raise RuntimeError('a fresh network namespace is mandatory')
    if set(os.listdir('/sys/class/net')) - {'lo'}:
        # sysfs can reflect the parent namespace: ip is authoritative here.
        links = subprocess.check_output(['ip', '-o', 'link'], text=True)
        if len(links.splitlines()) != 1:
            raise RuntimeError('network namespace is not empty')
    command('mount', '--make-rprivate', '/')
    command('mount', '-t', 'tmpfs', 'tmpfs', '/run')
    command('ip', 'link', 'set', 'lo', 'up')
    for prefix, subnet in [('lan', '192.0.2'), ('wan', '198.51.100')]:
        command('ip', 'link', 'add', prefix+'0', 'type', 'veth', 'peer', 'name', prefix+'peer')
        for suffix, host in [('0','1'), ('peer','2')]:
            dev = prefix+suffix
            command('ip', 'addr', 'add', f'{subnet}.{host}/24', 'dev', dev)
            command('ip', 'link', 'set', dev, 'up')
    # Permit spoofed ingress in this disposable namespace: the application
    # binding, not the kernel's reverse-path filter, must reject the probe.
    for name in ['all','default','lan0','lanpeer','wan0','wanpeer']:
        Path(f'/proc/sys/net/ipv4/conf/{name}/rp_filter').write_text('0')
        Path(f'/proc/sys/net/ipv4/conf/{name}/accept_local').write_text('1')
    env = dict(os.environ, INFOSVR_LAN_IPADDR='192.0.2.1',
               INFOSVR_LAN_NETMASK='255.255.255.0')
    process = subprocess.Popen([str(Path(sys.argv[1]).resolve()), 'lan0'], env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        time.sleep(.1)
        if process.poll() is not None:
            raise RuntimeError(process.stderr.read().decode())
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'lanpeer\0')
            listener.bind(('0.0.0.0', 12345))
            listener.settimeout(.5)
            def probe(interface, destination):
                payload = bytes([12,21,31,0]) + bytes(508)
                udp = struct.pack('!HHHH',12345,9999,520,0)+payload
                header = struct.pack('!BBHHHBBH4s4s',0x45,0,540,0,0,64,17,0,
                    socket.inet_aton('192.0.2.2'), socket.inet_aton(destination))
                header = header[:10]+struct.pack('!H',checksum(header))+header[12:]
                # A broadcast Ethernet destination also delivers multicast IP
                # without relying on a router's switch multicast snooping.
                with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as wire:
                    wire.bind((interface,0))
                    wire.send(b'\xff'*6+b'\x02\x00\x00\x00\x00\x22'+b'\x08\x00'+header+udp)
            # WAN first: duplicate filtering must not hide a received attack.
            for destination in ['198.51.100.1','224.0.0.1']:
                probe('wanpeer', destination)
                try:
                    listener.recvfrom(2048)
                    raise AssertionError('WAN probe caused LAN discovery response')
                except socket.timeout:
                    pass
            probe('lanpeer','192.0.2.1')
            packet, source = listener.recvfrom(2048)
            if len(packet) != 512 or source != ('192.0.2.1',9999):
                raise AssertionError('LAN discovery/source-port compatibility failed')
        print('INFOSVR_INGRESS=PASS LAN reply, spoofed WAN unicast/multicast silent')
    finally:
        process.terminate()
        process.wait(timeout=3)

if __name__ == '__main__':
    main()
