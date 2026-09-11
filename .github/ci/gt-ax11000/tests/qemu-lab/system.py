#!/usr/bin/env python3
"""Boot a generic pinned ARM64 lab kernel, NOT the router kernel/image."""
import argparse
import ast
import gzip
import hashlib
import json
import lzma
import os
import resource
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from run import verify_manifest, digest

HERE = Path(__file__).resolve().parent

def newc(entries):
    result = bytearray()
    names = set()
    for inode, (name, mode, data, major, minor) in enumerate(entries+[('TRAILER!!!',0,b'',0,0)], 1):
        if not name or '\0' in name or Path(name).is_absolute() or '..' in Path(name).parts or name in names:
            raise ValueError('unsafe or duplicate archive path')
        names.add(name)
        encoded = name.encode()+b'\0'
        values = [inode,mode,0,0,1,0,len(data),0,0,major,minor,len(encoded),0]
        result.extend(b'070701'+b''.join(f'{value:08x}'.encode() for value in values))
        result.extend(encoded); result.extend(b'\0'*(-len(result)%4))
        result.extend(data); result.extend(b'\0'*(-len(result)%4))
    return bytes(result)

REQUIRED_MARKERS = ('pid1', 'real-kernel-timeout-abi', 'intentional-child-segv-detected',
                    'hwsim-phy0-present', 'hwsim-phy1-present', 'ipv6-before-malformed',
                    'ipv6-after-reload', 'ipv6-clean-exit')

def guest_passed(code, output):
    # Expected SIGSEGV belongs only to our negative-control child, never a daemon.
    return (code == 0 and 'LAB_COMPLETE PASS' in output
            and all('LAB_PASS '+name+'\n' in output for name in REQUIRED_MARKERS)
            and output.count('LAB_PASS firmware-arm-self-test\n') == 3
            and not any(marker in output for marker in ('LAB_FAIL', 'Kernel panic',
                                                        'BUG:', 'Oops:', 'panicked at')))

def main():
    if sys.flags.optimize:
        raise SystemExit('Python optimization disables fixture assertions; refused')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel-root', required=True, type=Path)
    parser.add_argument('--qemu-system', required=True, type=Path)
    parser.add_argument('--cc', required=True, type=Path)
    parser.add_argument('--rootfs', required=True, type=Path)
    parser.add_argument('--manifest', required=True, type=Path)
    args = parser.parse_args()
    if subprocess.check_output(['stat','-f','-c','%T','/tmp'], text=True).strip() != 'tmpfs' or len(Path('/proc/swaps').read_text().splitlines()) != 1:
        parser.error('tmpfs and disabled swap required')
    root = args.kernel_root.resolve(strict=True)
    firmware = args.rootfs.resolve(strict=True)
    consumer_hashes = verify_manifest(firmware, args.manifest)
    kernels = list((root/'boot').glob('vmlinuz-*'))
    if len(kernels) != 1: parser.error('exactly one kernel required')
    kernel = kernels[0]
    version = kernel.name.removeprefix('vmlinuz-')
    modules = root/'lib/modules'/version
    graph = {}
    for line in (modules/'modules.dep').read_text().splitlines():
        name, dependencies = line.split(':', 1)
        graph[name] = dependencies.split()
    hwsim = [name for name in graph if '/mac80211_hwsim.ko' in name]
    if len(hwsim) != 1: parser.error('exactly one hwsim module required')
    order, seen = [], set()
    def visit(name):
        if name in seen: return
        seen.add(name)
        for dependency in graph[name]: visit(dependency)
        order.append(name)
    visit(hwsim[0])
    work = Path(tempfile.mkdtemp(prefix='gt-system-lab-', dir='/tmp'))
    subprocess.run([str(args.cc.absolute()), '-static','-O2','-Wall','-Wextra','-Werror',
                    str(HERE/'kernel-init.c'),'-o',str(work/'init')], check=True, timeout=30)
    entries = [(name,stat.S_IFDIR|0o755,b'',0,0) for name in ['dev','proc','sys','tmp','modules','bin','lib','etc']]
    entries += [('dev/console',stat.S_IFCHR|0o600,b'',5,1),('dev/null',stat.S_IFCHR|0o666,b'',1,3),
                ('dev/urandom',stat.S_IFCHR|0o666,b'',1,9),
                ('etc/machine-id',stat.S_IFREG|0o644,b'11112222333344445555666677778888\n',0,0),
                ('init',stat.S_IFREG|0o755,(work/'init').read_bytes(),0,0)]
    tree = ast.parse((HERE.parent/'wsdd2-slow-client-netns.py').read_text())
    probe = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == 'probe' for t in n.targets))
    entries.append(('wsd-probe.xml',stat.S_IFREG|0o644,probe,0,0))
    for name in ('wsdd2','ntp','lld2d'):
        source = firmware/'usr/sbin'/name
        if 'usr/sbin/'+name not in consumer_hashes: raise ValueError('unmanifested guest binary')
        entries.append(('bin/'+name,stat.S_IFREG|0o755,source.read_bytes(),0,0))
    library_hashes = {}
    for name in ('ld-linux.so.3','libc.so.6','libgcc_s.so.1','libpthread.so.0','libdl.so.2','libm.so.6','librt.so.1'):
        source = (firmware/'lib'/name).resolve(strict=True)
        if not source.is_relative_to(firmware): raise ValueError('library escape')
        entries.append(('lib/'+name,stat.S_IFREG|0o755,source.read_bytes(),0,0))
        library_hashes[name] = digest(source)
    names = []
    for i, name in enumerate(order):
        path = (modules/name).resolve(strict=True)
        if not path.is_relative_to(root): raise ValueError('module path escape')
        data = path.read_bytes()
        if name.endswith('.xz'): data = lzma.decompress(data)
        elif name.endswith('.gz'): data = gzip.decompress(data)
        elif not name.endswith('.ko'): raise ValueError('unsupported module compression')
        target = f'modules/{i}.ko'; names.append('/'+target)
        entries.append((target,stat.S_IFREG|0o644,data,0,0))
    entries.append(('modules.list',stat.S_IFREG|0o644,('\n'.join(names)+'\n').encode(),0,0))
    archive = work/'initramfs.cpio'
    archive.write_bytes(newc(entries))
    command = [str(args.qemu_system.absolute()), '-machine','virt-8.2,gic-version=2',
               '-cpu','cortex-a53','-accel','tcg,thread=single','-smp','1','-m','512',
               '-display','none','-serial','stdio','-monitor','none','-nic','none','-no-reboot',
               '-kernel',str(kernel),'-initrd',str(archive),
               '-append','console=ttyAMA0 rdinit=/init panic=-1 oops=panic nokaslr']
    started = time.monotonic()
    def limits():
        resource.setrlimit(resource.RLIMIT_CORE, (0,0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (16*1024*1024,16*1024*1024))
    with (work/'console.log').open('wb') as log:
        try:
            completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=90, preexec_fn=limits)
            code = completed.returncode
        except subprocess.TimeoutExpired: code = 124
    output = (work/'console.log').read_text(errors='replace')
    success = guest_passed(code, output)
    report = dict(status='pass' if success else 'fail', scope='generic kernel, NOT Broadcom',
                  kernel_sha256=hashlib.sha256(kernel.read_bytes()).hexdigest(), version=version,
                  initramfs_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(), modules=order,
                  qemu_sha256=hashlib.sha256(args.qemu_system.read_bytes()).hexdigest(),
                  qemu_version=subprocess.check_output([str(args.qemu_system), '--version'], text=True, timeout=5).splitlines()[0],
                  firmware_manifest_sha256=digest(args.manifest), libraries=library_hashes,
                  consumers=consumer_hashes,
                  fixtures={p.name:digest(p) for p in (HERE/'system.py', HERE/'kernel-init.c', HERE.parent/'wsdd2-slow-client-netns.py')},
                  checks=list(REQUIRED_MARKERS)+['wsdd2-self-test','ntp-self-test','lld2d-self-test'],
                  command=command, seconds=round(time.monotonic()-started,3), exit_code=code)
    (work/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    suite = ET.Element('testsuite', name='generic-arm-system', tests='1', failures='0' if success else '1')
    case = ET.SubElement(suite, 'testcase', name='boot-image-userspace-ipv6-hwsim', time=str(report['seconds']))
    if not success: ET.SubElement(case, 'failure', message='guest failed').text = str(work/'console.log')
    ET.ElementTree(suite).write(work/'junit.xml', encoding='utf-8', xml_declaration=True)
    print('REPORT='+str(work/'report.json'))
    return 0 if success else 1

if __name__ == '__main__':
    raise SystemExit(main())
