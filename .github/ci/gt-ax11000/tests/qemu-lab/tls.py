#!/usr/bin/env python3
"""Exercise the libmssl.so extracted from the candidate, never the router."""
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time

if sys.flags.optimize:
    raise SystemExit('Python optimization disables fixture assertions; refused')
rootfs = Path(sys.argv[1]).resolve()
cc = sys.argv[2]
qemu = sys.argv[3]
environment = dict(os.environ)
if os.readlink('/proc/self/ns/net') == os.environ.get('PARENT_NETNS'):
    raise SystemExit('fresh network namespace required')
if len(subprocess.check_output(['ip', '-o', 'link']).splitlines()) != 1:
    raise SystemExit('network namespace must be empty')
subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
with tempfile.TemporaryDirectory(prefix='mssl-shared-arm-', dir=os.environ['TMPDIR']) as directory:
    work = Path(directory)
    probe = work / 'probe'
    subprocess.run([cc,
                    '-march=armv7-a', '-marm', '-mfloat-abi=soft',
                    str(Path(__file__).with_name('tls-probe.c')), '-o', str(probe),
                    f'-L{rootfs}/usr/lib', '-lmssl',
                    f'-Wl,-rpath-link,{rootfs}/usr/lib', f'-Wl,-rpath-link,{rootfs}/lib'],
                   check=True, env=environment, timeout=30)
    dynamic = subprocess.check_output(['readelf', '-dW', str(probe)], text=True)
    assert '[libmssl.so]' in dynamic
    for algorithm in ('rsa', 'ec'):
        cert, key = work / 'cert.pem', work / 'key.pem'
        params = ['rsa:2048'] if algorithm == 'rsa' else ['ec', '-pkeyopt', 'ec_paramgen_curve:P-256']
        subprocess.run(['openssl', 'req', '-x509', '-newkey', *params, '-nodes',
                        '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost',
                        '-addext', 'subjectAltName=DNS:localhost', '-addext', 'basicConstraints=critical,CA:FALSE'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            for repeat in range(3):
                process = subprocess.Popen([qemu, '-cpu', 'cortex-a7', '-L', str(rootfs),
                                            '-E', 'LD_LIBRARY_PATH=/usr/lib:/lib',
                                            str(probe), str(cert), str(key)],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    # Probe alarm bounds startup and all I/O, including this read.
                    port_line = process.stdout.readline()
                    if not port_line:
                        raise AssertionError(process.communicate(timeout=2))
                    port = int(port_line)
                    context = ssl.create_default_context(cafile=str(cert))
                    context.minimum_version = context.maximum_version = version
                    with socket.create_connection(('127.0.0.1', port), timeout=5) as raw:
                        with context.wrap_socket(raw, server_hostname='localhost') as client:
                            for byte in b'GET / HTTP/1.0\r\n\r\n':
                                client.sendall(bytes([byte]))
                            response = bytearray()
                            while chunk := client.recv(4096):
                                response.extend(chunk)
                            assert response == b'HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK', response
                    out, err = process.communicate(timeout=5)
                    assert process.returncode == 0, (process.returncode, out, err)
                    print(algorithm, version.name, repeat, 'extracted ARM shared TLS + glibc FILE PASS')
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
        for failure in ('idle', 'partial-record', 'plaintext', 'disconnect'):
            process = subprocess.Popen([qemu, '-cpu', 'cortex-a7', '-L', str(rootfs),
                                        '-E', 'LD_LIBRARY_PATH=/usr/lib:/lib',
                                        str(probe), str(cert), str(key), 'reject'],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                port_line = process.stdout.readline()
                if not port_line:
                    raise AssertionError(process.communicate(timeout=2))
                started = time.monotonic()
                with socket.create_connection(('127.0.0.1', int(port_line)), timeout=2) as raw:
                    if failure == 'partial-record':
                        raw.sendall(b'\x16\x03\x03\x00\x80\x01')
                    elif failure == 'plaintext':
                        raw.sendall(b'GET / HTTP/1.0\r\n\r\n')
                    elif failure == 'disconnect':
                        raw.shutdown(socket.SHUT_WR)
                    try:
                        out, err = process.communicate(timeout=2)
                    except subprocess.TimeoutExpired as error:
                        print('TIMEOUT_STDERR', (error.stderr or b'')[-8000:], flush=True)
                        raise
                assert process.returncode == 0, (failure, process.returncode, out, err)
                assert time.monotonic()-started < 2
                print(algorithm, failure, 'TLS rejection/short socket deadline PASS')
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
print('EXTRACTED_MSSL_RUNTIME=PASS cases=20')
