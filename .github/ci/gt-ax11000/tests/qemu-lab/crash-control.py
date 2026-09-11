"""Keep QEMU below PID 1: namespace init has special fatal-signal semantics."""
import os
import signal
import subprocess
import sys

if os.getpid() != 1:
    raise SystemExit('must be the disposable namespace init')
result = subprocess.run(sys.argv[1:], timeout=5)
if result.returncode != -signal.SIGSEGV:
    raise SystemExit('negative control did not die from SIGSEGV: '+str(result.returncode))
print('ARM child terminated by SIGSEGV, independently verified by waitpid', flush=True)
raise SystemExit(128+signal.SIGSEGV)
