#!/usr/bin/env python3
"""Native ABI/stdio tests against the actual linked adapter (no router)."""
import ctypes
import pathlib
import os
import socket
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


if __name__ == "__main__":
    unittest.main()
