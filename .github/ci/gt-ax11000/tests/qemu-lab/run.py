#!/usr/bin/env python3
"""Offline extracted-image regression runner; no router targets or credentials."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def verify_manifest(root, manifest):
    entries = {}
    for line in manifest.read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if not match:
            raise ValueError('malformed manifest entry')
        expected, name = match.groups()
        if Path(name).is_absolute() or '..' in Path(name).parts:
            raise ValueError('unsafe manifest path')
        path = (root / name).resolve()
        if not path.is_relative_to(root) or name in entries:
            raise ValueError('unsafe or duplicate manifest path')
        if digest(path) != expected:
            raise ValueError('manifest mismatch: ' + name)
        entries[name] = expected
    for name in ('usr/sbin/infosvr', 'usr/sbin/wsdd2', 'usr/sbin/lld2d', 'usr/lib/libmssl.so'):
        if name not in entries:
            raise ValueError('missing required consumer: ' + name)
    return entries

def bounded(command, log, timeout, env=None):
    started = time.monotonic()
    with log.open('wb') as output:
        def limits():
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_FSIZE, (16*1024*1024, 16*1024*1024))
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                   env=env, start_new_session=True, preexec_fn=limits)
        status = 'pass'
        try:
            if process.wait(timeout=timeout):
                status = 'fail'
        except subprocess.TimeoutExpired:
            status = 'timeout'
        finally:
            # Kill any leftover children even if the main fixture returned.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
    # A fixture must not turn a child crash into success through cleanup.
    crash = re.search(rb'uncaught target signal (?:6|7|11)|Segmentation fault|'
                      rb'panicked at|ERROR: AddressSanitizer|runtime error:|Kernel panic',
                      log.read_bytes())
    if status != 'timeout' and (process.returncode < 0 or crash):
        status = 'crash'
    return dict(status=status, seconds=round(time.monotonic()-started, 3),
                exit_code=process.returncode, log=str(log))

def main():
    if sys.flags.optimize:
        raise SystemExit('Python optimization disables fixture assertions; refused')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', required=True, type=Path)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--qemu', required=True, type=Path)
    parser.add_argument('--tls-qemu', type=Path, help='explicit separate emulator for TLS socket ABI; no automatic fallback')
    parser.add_argument('--cc', required=True, type=Path)
    parser.add_argument('--work-parent', type=Path, default=Path('/tmp'))
    parser.add_argument('--repeat', type=int, default=3)
    parser.add_argument('--seed', type=int, default=4908)
    parser.add_argument('--packets', type=int, default=2000)
    args = parser.parse_args()
    if not 1 <= args.repeat <= 100:
        parser.error('repeat must be 1..100')
    if not 100 <= args.packets <= 100000:
        parser.error('packets must be 100..100000')
    root = args.rootfs.resolve(strict=True)
    qemu = args.qemu.resolve(strict=True)
    tls_qemu = (args.tls_qemu or args.qemu).resolve(strict=True)
    # Broadcom's wrapper selects the compiler from argv[0]; retain its symlink name.
    cc = args.cc.absolute()
    if not cc.is_file():
        parser.error('compiler not found')
    if subprocess.check_output(['stat', '-f', '-c', '%T', str(args.work_parent)], text=True).strip() != 'tmpfs':
        parser.error('work-parent must be tmpfs')
    if len(Path('/proc/swaps').read_text().splitlines()) != 1:
        parser.error('swap must be disabled')
    entries = verify_manifest(root, args.manifest)
    version = subprocess.check_output([str(qemu), '--version'], text=True, timeout=5).splitlines()[0]
    match = re.search(r'version (\d+)\.', version)
    if not match or int(match[1]) < 10:
        parser.error('QEMU >=10 required for multicast socket emulation')
    work = Path(tempfile.mkdtemp(prefix='gt-qemu-lab-', dir=args.work_parent))
    results = []
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', TMPDIR=str(work),
               PARENT_NETNS=os.readlink('/proc/self/ns/net'),
               PARENT_MNTNS=os.readlink('/proc/self/ns/mnt'))
    # Isolated process/network/mount namespaces; no inherited network links.
    isolation = ['unshare', '-Urnmp', '--fork', '--kill-child=KILL', '--mount-proc']
    shim = work / 'nvram-fixture.so'
    compile_result = bounded([str(cc), '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
                              '-mfloat-abi=soft', str(HERE/'nvram-fixture.c'), '-o', str(shim)],
                             work/'compile.log', 30, env)
    results.append(dict(name='compile-readonly-nvram-model', **compile_result))
    crash_probe = work/'crash-probe'
    probe_compile = bounded([str(cc), '-O2', str(HERE/'crash-probe.c'), '-o', str(crash_probe)],
                            work/'crash-compile.log', 30, env)
    results.append(dict(name='compile-crash-control', **probe_compile))
    if probe_compile['status'] == 'pass':
        probe_result = bounded(isolation+[sys.executable, str(HERE/'crash-control.py'),
                                          str(qemu), '-L', str(root), str(crash_probe)],
                               work/'intentional-arm-segv.log', 10, env)
        results.append(dict(name='detect-intentional-arm-segv',
                            expected='crash', observed=probe_result['status'],
                            **{**probe_result, 'status': 'pass' if probe_result['status'] == 'crash' else 'fail'}))
    if compile_result['status'] == 'pass':
        wrappers = {}
        for name in ('infosvr', 'wsdd2', 'lld2d'):
            command = [str(qemu), '-cpu', 'cortex-a7', '-L', str(root),
                       '-E', 'LD_LIBRARY_PATH=/usr/lib:/lib']
            if name == 'infosvr':
                command += ['-E', 'LD_PRELOAD='+str(shim)]
            command += [str(root/'usr/sbin'/name)]
            wrapper = work/name
            wrapper.write_text('#!/bin/sh\nexec '+shlex.join(command)+' "$@"\n')
            wrapper.chmod(0o700)
            wrappers[name] = str(wrapper)
        tests = [
            ('infosvr-lan-wan', HERE.parent/'infosvr-ingress-netns.py', [wrappers['infosvr']]),
            ('infosvr-multiple-interfaces', HERE.parent/'infosvr-ingress-netns.py', [wrappers['infosvr'], '--multi']),
            ('wsdd-slow-peer', HERE.parent/'wsdd2-slow-client-netns.py', [wrappers['wsdd2']]),
            ('discovery-isolation', HERE.parent/'discovery-isolation-netns.py', [wrappers['wsdd2'], wrappers['lld2d']]),
            ('tls-image', HERE/'tls.py', [str(root), str(cc), str(tls_qemu)]),
            ('wsdd-resource-soak', HERE/'wsdd-soak.py', [wrappers['wsdd2']]),
            ('malformed-ingress', HERE/'malformed.py',
             [wrappers['infosvr'], wrappers['wsdd2'], str(args.seed), str(args.packets)]),
        ]
        for iteration in range(args.repeat):
            for name, script, extra in tests:
                label = f'{name}-{iteration+1}'
                if name == 'malformed-ingress':
                    extra = [wrappers['infosvr'], wrappers['wsdd2'], str(args.seed+iteration), str(args.packets)]
                result = bounded(isolation+[sys.executable, str(HERE/'isolate.py'), str(root), str(script), *extra],
                                 work/(label+'.log'), 180, env)
                results.append(dict(name=label, **result))
                print(label, result['status'], flush=True)
    report = dict(schema=2, seed=args.seed, packets_per_daemon=args.packets,
                  rootfs=str(root), manifest_sha256=digest(args.manifest),
                  fixture_hashes={str(p.relative_to(HERE.parent)): digest(p)
                                  for p in sorted(HERE.glob('*')) if p.is_file()},
                  consumers=entries, qemu=version, qemu_sha256=digest(qemu),
                  tls_qemu=subprocess.check_output([str(tls_qemu), '--version'], text=True, timeout=5).splitlines()[0],
                  tls_qemu_sha256=digest(tls_qemu),
                  compiler_sha256=digest(cc), tests=results,
                  limitations=['host kernel, not Broadcom Linux', 'IPv6 discovery requires separate system.py gate',
                               'infosvr NVRAM/SSID/capabilities are synthetic',
                               'no radio, flash, real credentials or VPN hardware coverage'])
    (work/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    suite = ET.Element('testsuite', name='extracted-arm-image', tests=str(len(results)),
                       failures=str(sum(r['status'] != 'pass' for r in results)))
    for result in results:
        case = ET.SubElement(suite, 'testcase', name=result['name'], time=str(result['seconds']))
        if result['status'] != 'pass':
            ET.SubElement(case, 'failure', message=result['status']).text = result['log']
    ET.ElementTree(suite).write(work/'junit.xml', encoding='utf-8', xml_declaration=True)
    print('REPORT='+str(work/'report.json'))
    return int(any(r['status'] != 'pass' for r in results))

if __name__ == '__main__':
    sys.exit(main())
