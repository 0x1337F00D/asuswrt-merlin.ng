"""Host namespace setup before a reviewed fixture; never a router command."""
import os
from pathlib import Path
import subprocess
import sys

for kind, key in [('net', 'PARENT_NETNS'), ('mnt', 'PARENT_MNTNS')]:
    if not os.environ.get(key) or os.readlink('/proc/self/ns/'+kind) == os.environ[key]:
        raise SystemExit('fresh namespaces required')
if len(subprocess.check_output(['ip', '-o', 'link']).splitlines()) != 1:
    raise SystemExit('namespace not empty')
root = str(Path(sys.argv[1]).resolve(strict=True))
subprocess.run(['mount', '--make-rprivate', '/'], check=True)
subprocess.run(['mount', '--bind', root, root], check=True)
subprocess.run(['mount', '-o', 'remount,bind,ro', root], check=True)
subprocess.run(['mount', '-t', 'tmpfs', 'tmpfs', '/run'], check=True)
os.execv(sys.executable, [sys.executable, *sys.argv[2:]])
