"""Download pinned lab packages into tmpfs; never install them on the host."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import argparse
import re
from urllib.parse import urlsplit

def packages(lock):
    result = lock.get('packages', [lock])
    if not isinstance(result, list) or not 1 <= len(result) <= 20:
        raise ValueError('invalid package list')
    names = set()
    for item in result:
        name = item['package']
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+~-]*\.deb', name) or name in names:
            raise ValueError('unsafe or duplicate package name')
        names.add(name)
        if urlsplit(item['url']).scheme != 'https' or not re.fullmatch(r'[0-9a-f]{64}', item['sha256']):
            raise ValueError('HTTPS and SHA256 required')
        if type(item['bytes']) is not int or not 0 < item['bytes'] < 300_000_000:
            raise ValueError('invalid package size')
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lock', type=Path, default=Path(__file__).with_name('emulator.lock.json'))
    args = parser.parse_args()
    locked = packages(json.loads(args.lock.read_text()))
    if subprocess.check_output(['stat', '-f', '-c', '%T', '/tmp'], text=True).strip() != 'tmpfs':
        raise SystemExit('/tmp must be tmpfs')
    if len(Path('/proc/swaps').read_text().splitlines()) != 1:
        raise SystemExit('swap must be disabled')
    work = Path(tempfile.mkdtemp(prefix='gt-qemu-pinned-', dir='/tmp'))
    for item in locked:
        package = work/item['package']
        subprocess.run(['curl', '--fail', '--location', '--proto', '=https', '--proto-redir', '=https',
                        '--retry', '2', '--max-time', '120', '--max-filesize', str(item['bytes']),
                        item['url'], '-o', str(package)], check=True, timeout=400)
        with package.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if package.stat().st_size != item['bytes'] or digest != item['sha256']:
            raise SystemExit('package integrity mismatch: not extracted or executed')
    # Verify every package before extracting any of the set. No maintainer scripts.
    for item in locked:
        subprocess.run(['dpkg-deb', '-x', str(work/item['package']), str(work/'runtime')], check=True, timeout=60)
    print(work/'runtime')

if __name__ == '__main__':
    main()
