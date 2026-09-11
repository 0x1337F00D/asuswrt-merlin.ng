#!/usr/bin/env python3
"""Check the actual installed ARM shared link, not the static archive."""
import pathlib
import re
import subprocess
import sys

binary = pathlib.Path(sys.argv[1])
readelf = sys.argv[2] if len(sys.argv) > 2 else 'readelf'


def read(*arguments):
    return subprocess.check_output([readelf, *arguments, str(binary)], text=True)


header, attributes, segments, dynamic, symbols = (
    read('-hW'), read('-AW'), read('-lW'), read('-dW'), read('--dyn-syms', '-W'))
assert not binary.is_symlink() and binary.is_file()
assert binary.stat().st_size <= 1024 * 1024, 'linked TLS exceeds 1 MiB review budget'
assert 'ELF32' in header and 'Machine:                           ARM' in header
assert 'soft-float ABI' in header and 'DYN' in header
assert 'Tag_CPU_arch: v7' in attributes and 'Tag_ABI_VFP_args' not in attributes
assert 'INTERP' not in segments
assert 'GNU_RELRO' in segments
stack = next(line for line in segments.splitlines() if 'GNU_STACK' in line)
assert re.search(r'\sRW\s', stack) and not re.search(r'\sRWE\s', stack)
assert 'TEXTREL' not in dynamic
needed = set(re.findall(r'Shared library: \[([^]]+)\]', dynamic))
allowed = {'libgcc_s.so.1', 'libdl.so.2', 'libpthread.so.0', 'libc.so.6', 'ld-linux.so.3', 'libm.so.6'}
assert needed <= allowed, needed - allowed
public = set()
for line in symbols.splitlines():
    fields = line.split()
    if len(fields) >= 8 and fields[3] == 'FUNC' and fields[6] != 'UND':
        public.add(fields[7])
expected = {'mssl_init', 'mssl_init_ex', 'mssl_ctx_free', 'mssl_cert_key_match',
            'ssl_server_fopen', 'ssl_client_fopen', 'ssl_client_fopen_name'}
assert expected <= public and public <= expected | {'_init', '_fini'}, public
print(f'MSSL_INSTALLED_ELF=PASS size={binary.stat().st_size} needed={sorted(needed)}')
