#!/usr/bin/env python3
"""Native ABI/stdio tests against the actual linked adapter (no router)."""
import ctypes
import concurrent.futures
import pathlib
import os
import socket
import struct
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

LIBRARY = pathlib.Path(sys.argv.pop(1)).resolve()
tls = ctypes.CDLL(str(LIBRARY), use_errno=True)
stdio = ctypes.CDLL(None, use_errno=True)
tls.mssl_init.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
tls.mssl_init.restype = ctypes.c_int
tls.mssl_cert_key_match.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
tls.mssl_cert_key_match.restype = ctypes.c_int
tls.ssl_server_fopen.argtypes = [ctypes.c_int]
tls.ssl_server_fopen.restype = ctypes.c_void_p
tls.ssl_client_fopen.argtypes = [ctypes.c_int]
tls.ssl_client_fopen.restype = ctypes.c_void_p
tls.mssl_ctx_free.argtypes = []
tls.mssl_ctx_free.restype = None
stdio.fgets.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
stdio.fgets.restype = ctypes.c_void_p
stdio.fputs.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
stdio.fflush.argtypes = [ctypes.c_void_p]
stdio.fclose.argtypes = [ctypes.c_void_p]


class Adapter(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="mssl-abi-", dir="/tmp")
        root = pathlib.Path(self.directory.name)
        self.cert, self.key = root / "cert.pem", root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(self.key), "-out", str(self.cert), "-days", "1",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                        "-addext", "basicConstraints=critical,CA:FALSE"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.assertEqual(tls.mssl_init(bytes(self.cert), bytes(self.key)), 1)

    def tearDown(self):
        tls.mssl_ctx_free()
        self.directory.cleanup()

    def test_matching_credentials_and_disabled_client(self):
        self.assertEqual(tls.mssl_cert_key_match(bytes(self.cert), bytes(self.key)), 1)
        with socket.socket() as sock:
            self.assertFalse(tls.ssl_client_fopen(sock.fileno()))
            self.assertGreater(sock.fileno(), -1)

    def test_nonregular_credentials_do_not_block(self):
        fifo = pathlib.Path(self.directory.name) / "not-a-key"
        os.mkfifo(fifo)
        start = time.monotonic()
        self.assertEqual(tls.mssl_init(bytes(self.cert), bytes(fifo)), 0)
        self.assertLess(time.monotonic() - start, 1)
        self.assertEqual(tls.mssl_cert_key_match(bytes(self.cert), bytes(fifo)), 0)

    def test_stdio_exchange_reload_and_descriptor_ownership(self):
        for _ in range(5):
            failures = []
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen()
                listener.settimeout(5)

                def serve():
                    try:
                        with listener.accept()[0] as sock:
                            stream = tls.ssl_server_fopen(sock.fileno())
                            self.assertTrue(stream)
                            try:
                                # A live TLS connection survives config destruction.
                                tls.mssl_ctx_free()
                                line = ctypes.create_string_buffer(256)
                                self.assertTrue(stdio.fgets(line, len(line), stream))
                                self.assertEqual(line.value, b"GET / HTTP/1.0\r\n")
                                self.assertTrue(stdio.fgets(line, len(line), stream))
                                self.assertEqual(line.value, b"\r\n")
                                self.assertGreaterEqual(stdio.fputs(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK", stream), 0)
                                self.assertEqual(stdio.fflush(stream), 0)
                            finally:
                                self.assertEqual(stdio.fclose(stream), 0)
                            self.assertEqual(sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE), socket.SOCK_STREAM)
                    except BaseException as error:
                        failures.append(error)

                thread = threading.Thread(target=serve)
                thread.start()
                context = ssl.create_default_context(cafile=str(self.cert))
                with socket.create_connection(listener.getsockname(), timeout=5) as raw:
                    with context.wrap_socket(raw, server_hostname="localhost") as client:
                        client.sendall(b"GET / HTTP/1.0\r\n\r\n")
                        response = bytearray()
                        while chunk := client.recv(4096):
                            response.extend(chunk)
                        self.assertTrue(response.endswith(b"\r\n\r\nOK"), repr(response))
                thread.join(6)
                self.assertFalse(thread.is_alive())
                if failures:
                    raise failures[0]
            self.assertEqual(tls.mssl_init(bytes(self.cert), bytes(self.key)), 1)

    def test_failed_handshake_keeps_descriptor(self):
        a, b = socket.socketpair()
        with a, b:
            b.sendall(b"this is not TLS\r\n")
            b.shutdown(socket.SHUT_WR)
            start = time.monotonic()
            self.assertFalse(tls.ssl_server_fopen(a.fileno()))
            self.assertLess(time.monotonic() - start, 1)
            self.assertEqual(a.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE), socket.SOCK_STREAM)

    def test_silent_handshake_respects_existing_socket_timeout(self):
        server, peer = socket.socketpair()
        with server, peer:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO,
                              struct.pack('@ll', 0, 100000))
            started = time.monotonic()
            self.assertFalse(tls.ssl_server_fopen(server.fileno()))
            elapsed = time.monotonic() - started
            self.assertGreaterEqual(elapsed, .07)
            self.assertLess(elapsed, .75)
            self.assertEqual(ctypes.get_errno(), 110)
            self.assertEqual(server.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE), socket.SOCK_STREAM)

    def test_failed_reload_and_explicit_ciphers_keep_valid_configuration(self):
        tls.mssl_init_ex.argtypes = [ctypes.c_char_p] * 3
        tls.mssl_init_ex.restype = ctypes.c_int
        for cipher in (b'', b'DEFAULT', b'AES128-SHA'):
            self.assertEqual(tls.mssl_init_ex(bytes(self.cert), bytes(self.key), cipher), 0)
        bad = pathlib.Path(self.directory.name) / 'bad.pem'
        bad.write_bytes(b'-----BEGIN CERTIFICATE-----\ninvalid\n')
        self.assertEqual(tls.mssl_init(bytes(bad), bytes(self.key)), 0)
        self.test_stdio_exchange_reload_and_descriptor_ownership()

    def test_parallel_https_and_rsa_to_ec_rotation(self):
        def exchange_batch(cert):
            failures = []
            workers = []
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                listener.listen(8)
                listener.settimeout(5)

                def server(sock):
                    with sock:
                        stream = tls.ssl_server_fopen(sock.fileno())
                        try:
                            self.assertTrue(stream)
                            line = ctypes.create_string_buffer(256)
                            self.assertTrue(stdio.fgets(line, len(line), stream))
                            self.assertEqual(line.value, b'GET / HTTP/1.0\r\n')
                            self.assertGreaterEqual(stdio.fputs(b'HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK', stream), 0)
                            self.assertEqual(stdio.fflush(stream), 0)
                        except BaseException as error:
                            failures.append(error)
                        finally:
                            if stream:
                                stdio.fclose(stream)

                def accept():
                    try:
                        for _ in range(6):
                            worker = threading.Thread(target=server, args=(listener.accept()[0],))
                            workers.append(worker)
                            worker.start()
                    except BaseException as error:
                        failures.append(error)

                def client(index):
                    context = ssl.create_default_context(cafile=str(cert))
                    version = ssl.TLSVersion.TLSv1_2 if index % 2 else ssl.TLSVersion.TLSv1_3
                    context.minimum_version = context.maximum_version = version
                    with socket.create_connection(listener.getsockname(), timeout=5) as raw:
                        with context.wrap_socket(raw, server_hostname='localhost') as peer:
                            self.assertEqual(peer.getpeercert(binary_form=True),
                                ssl.PEM_cert_to_DER_cert(cert.read_text()))
                            for part in (b'GET / ', b'HTTP/1.0\r\n'):
                                peer.sendall(part)
                            response = bytearray()
                            while chunk := peer.recv(4096):
                                response.extend(chunk)
                            self.assertTrue(response.endswith(b'\r\n\r\nOK'))
                acceptor = threading.Thread(target=accept)
                acceptor.start()
                try:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                        list(pool.map(client, range(6)))
                finally:
                    acceptor.join(6)
                    for worker in workers:
                        worker.join(6)
                    self.assertFalse(acceptor.is_alive())
                    self.assertFalse(any(worker.is_alive() for worker in workers))
                if failures:
                    raise failures[0]

        exchange_batch(self.cert)
        root = pathlib.Path(self.directory.name)
        cert, key = root/'ec-cert.pem', root/'ec-key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256',
                        '-nodes','-keyout',str(key),'-out',str(cert),'-days','1',
                        '-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost',
                        '-addext','basicConstraints=critical,CA:FALSE'],check=True,
                        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.assertEqual(tls.mssl_init(bytes(cert), bytes(key)), 1)
        # A mismatched replacement must not displace the current EC identity.
        self.assertEqual(tls.mssl_init(bytes(self.cert), bytes(key)), 0)
        exchange_batch(cert)


if __name__ == "__main__":
    unittest.main()
