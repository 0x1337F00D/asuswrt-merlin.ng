#!/usr/bin/env python3
"""Offline gate only. Despite its name, this never installs or contacts a router."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from run import bounded, digest

HERE = Path(__file__).resolve().parent

def evidence_passed(name, payload):
    if name == 'system': return payload.get('status') == 'pass'
    tests = payload.get('tests', [])
    return bool(tests) and all(item.get('status') == 'pass' for item in tests)

def main():
    if sys.flags.optimize: raise SystemExit('Python optimization refused')
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('rootfs','manifest','cc','qemu','tls-qemu','kernel-root','qemu-system'):
        parser.add_argument('--'+key, required=True)
    parser.add_argument('--repeat', type=int, default=3)
    parser.add_argument('--packets', type=int, default=10000)
    parser.add_argument('--seed', type=int, default=4908)
    args = parser.parse_args()
    if not 1 <= args.repeat <= 10 or not 100 <= args.packets <= 100000:
        parser.error('repeat must be 1..10 and packets 100..100000')
    if subprocess.check_output(['stat','-f','-c','%T','/tmp'], text=True).strip() != 'tmpfs' or len(Path('/proc/swaps').read_text().splitlines()) != 1:
        parser.error('tmpfs and disabled swap required')
    work = Path(tempfile.mkdtemp(prefix='gt-preinstall-lab-', dir='/tmp'))
    env = dict(os.environ, TMPDIR=str(work), PYTHONDONTWRITEBYTECODE='1')
    common = ['--rootfs',args.rootfs,'--manifest',args.manifest,'--cc',args.cc]
    stages = [('usermode', 'run.py', common+['--qemu',args.qemu,'--tls-qemu',args.tls_qemu,
               '--repeat',str(args.repeat),'--packets',str(args.packets),'--seed',str(args.seed)],1800),
              ('system', 'system.py', common+['--kernel-root',args.kernel_root,'--qemu-system',args.qemu_system],120)]
    results = []
    for name, script, extra, deadline in stages:
        result = bounded([sys.executable,str(HERE/script),*extra], work/(name+'.log'), deadline, env)
        matches = re.findall(r'^REPORT=(.+)$', (work/(name+'.log')).read_text(), re.MULTILINE)
        if len(matches) == 1 and Path(matches[0]).is_file():
            report = Path(matches[0])
            result.update(report=str(report), report_sha256=digest(report))
            if not evidence_passed(name, json.loads(report.read_text())):
                result['status'] = 'fail'
        else:
            result['status'] = 'fail'
            result['reason'] = 'missing/ambiguous child report'
        results.append(dict(name=name,**result))
        print(name, result['status'], result.get('report', result['log']), flush=True)
    report = dict(status='pass' if all(r['status']=='pass' for r in results) else 'fail',
                  firmware_manifest_sha256=digest(Path(args.manifest)), stages=results,
                  limitations=['offline gate, not installation approval', 'no Broadcom kernel/radio/flash proof'])
    (work/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print('REPORT='+str(work/'report.json'))
    return int(report['status'] != 'pass')

if __name__ == '__main__': raise SystemExit(main())
