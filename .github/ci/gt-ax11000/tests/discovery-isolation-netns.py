#!/usr/bin/env python3
"""Real wsdd2/lld2d positive LAN and negative WAN tests, isolated Linux only."""
import os, socket, struct, subprocess, sys, time
from pathlib import Path
def run(*args): subprocess.run(args,check=True,stdout=subprocess.DEVNULL)
for kind,key in [('net','PARENT_NETNS'),('mnt','PARENT_MNTNS')]:
    if not os.environ.get(key) or os.readlink('/proc/self/ns/'+kind)==os.environ[key]:
        raise SystemExit('fresh network and mount namespaces required')
if len(subprocess.check_output(['ip','-o','link']).splitlines())!=1:
    raise SystemExit('namespace not empty')
run('mount','--make-rprivate','/')
run('mount','-t','tmpfs','tmpfs','/run')
run('ip','link','set','lo','up')
for name,ip in [('lan','192.0.2.1/24'),('wan','198.51.100.1/24')]:
    run('ip','link','add',name+'0','type','veth','peer','name',name+'peer')
    run('ip','addr','add',ip,'dev',name+'0')
    run('ip','link','set',name+'0','up')
    run('ip','link','set',name+'peer','address','02:aa:bb:cc:dd:ee')
    run('ip','link','set',name+'peer','up')
for name in ['all','default','lan0','lanpeer','wan0','wanpeer']:
    Path(f'/proc/sys/net/ipv4/conf/{name}/rp_filter').write_text('0')
run('ip','neigh','replace','192.0.2.2','lladdr','02:aa:bb:cc:dd:ee','nud','permanent','dev','lan0')
mapper=bytes.fromhex('02aabbccddee')
base=bytes([255])*6+mapper
probe=b'''<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:p="http://schemas.microsoft.com/windows/pub/2005/07"><s:Header><a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To><a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action><a:MessageID>urn:uuid:11112222-3333-4444-5555-666677778888</a:MessageID></s:Header><s:Body><d:Probe><d:Types>p:Computer</d:Types></d:Probe></s:Body></s:Envelope>'''
def udp(destination):
    body=struct.pack('!HHHH',12345,3702,8+len(probe),0)+probe
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(body),0,0,64,17,0,socket.inet_aton('192.0.2.2'),socket.inet_aton(destination))
    value=sum(struct.unpack('!10H',ip))
    while value>>16: value=(value&65535)+(value>>16)
    ip=ip[:10]+struct.pack('!H',(~value)&65535)+ip[12:]
    return base+b'\x08\x00'+ip+body
lltd=(base+b'\x88\xd9'+bytes([1,0,0,0])+b'\xff'*6+mapper+b'\x00\x00\x12\x34\x00\x00').ljust(60,b'\0')
for label,binary,args,frames,valid in [
    ('wsdd2',sys.argv[1],['-w','-4','-i','lan0'],[udp('198.51.100.1'),udp('239.255.255.250')],lambda b:b'ProbeMatches' in b),
    ('lld2d',sys.argv[2],['-d','lan0'],[lltd],lambda b:len(b)>32 and b[12:14]==b'\x88\xd9' and b[17]==1)]:
    process=subprocess.Popen([binary,*args],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        time.sleep(.15)
        if process.poll() is not None: raise AssertionError(label+' startup')
        with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)) as capture:
            capture.bind(('lanpeer',0)); capture.settimeout(.35)
            def observe():
                until=time.monotonic()+.35
                while time.monotonic()<until:
                    capture.settimeout(max(.001,until-time.monotonic()))
                    try: packet=capture.recv(20000)
                    except TimeoutError:return False
                    if valid(packet):return True
                return False
            for frame in frames:
                with socket.socket(socket.AF_PACKET,socket.SOCK_RAW) as sender:
                    sender.bind(('wanpeer',0)); sender.send(frame)
                if observe():raise AssertionError(label+' answered WAN')
            with socket.socket(socket.AF_PACKET,socket.SOCK_RAW) as sender:
                sender.bind(('lanpeer',0)); sender.send(udp('239.255.255.250') if label=='wsdd2' else lltd)
            if not observe():raise AssertionError(label+' LAN positive control failed')
            print(label.upper()+'_INTERFACE_ISOLATION=PASS negative WAN and positive LAN')
    finally:
        process.terminate(); process.wait(timeout=3)
