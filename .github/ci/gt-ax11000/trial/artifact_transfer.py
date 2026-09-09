#!/usr/bin/env python3
"""Temporary LAN transfer for a router without SFTP; never exposes a directory.

Serve exactly one named regular file or receive exactly one new file. Verify
every transfer's SHA-256 over the authenticated SSH channel separately. Upload
configuration backups ONLY after encrypting them for the host's public key.
No SSH keys/passwords are read and no router configuration is changed here.
"""
import argparse
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import secrets
import stat
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", required=True)
    parser.add_argument("--peer", required=True)
    parser.add_argument("--file", required=True, type=Path)
    parser.add_argument("--receive", action="store_true")
    parser.add_argument("--lifetime", type=int, default=600)
    parser.add_argument("--max-bytes", type=int, default=128 * 1024 * 1024)
    args = parser.parse_args()
    for address in (args.bind, args.peer):
        if not ipaddress.IPv4Address(address).is_private or address == "0.0.0.0":
            parser.error("explicit private LAN addresses required")
    if not 1 <= args.lifetime <= 7200 or not 1 <= args.max_bytes <= 256 * 1024 * 1024:
        parser.error("invalid lifetime/size bound")
    os.umask(0o077)
    if args.receive:
        if args.file.exists() or args.file.is_symlink():
            parser.error("destination already exists")
        source = None
        digest = None
    else:
        fd = os.open(args.file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        source = os.fdopen(fd, "rb")
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= args.max_bytes:
            parser.error("source must be a bounded regular file")
        digest = hashlib.file_digest(source, "sha256").hexdigest()
        source.seek(0)
    endpoint = "/" + secrets.token_hex(24)
    complete = False

    class Handler(http.server.BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(15)

        def permitted(self):
            return self.client_address[0] == args.peer and self.path == endpoint

        def do_GET(self):
            nonlocal complete
            if args.receive or not self.permitted() or complete:
                self.send_error(404)
                return
            source.seek(0)
            self.send_response(200)
            self.send_header("Content-Length", str(info.st_size))
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            remaining = info.st_size
            sent = hashlib.sha256()
            while remaining:
                block = source.read(min(1024 * 1024, remaining))
                if not block:
                    raise OSError("source changed during transfer")
                sent.update(block)
                self.wfile.write(block)
                remaining -= len(block)
            if sent.hexdigest() != digest:
                raise OSError("source changed during transfer")
            complete = True

        def do_PUT(self):
            nonlocal complete
            if not args.receive or not self.permitted() or complete:
                self.send_error(404)
                return
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or not lengths[0].isdecimal() or self.headers.get("Transfer-Encoding"):
                self.send_error(400)
                return
            length = int(lengths[0])
            if not 0 < length <= args.max_bytes:
                self.send_error(413)
                return
            # Exclusive creation: never overwrite a prior backup, symlink or
            # concurrent transfer. Interrupted data is retained as .partial.
            partial = args.file.with_name(args.file.name + ".partial")
            received = hashlib.sha256()
            with partial.open("xb") as output:
                remaining = length
                while remaining:
                    block = self.rfile.read(min(1024 * 1024, remaining))
                    if not block:
                        raise OSError("incomplete upload")
                    output.write(block)
                    received.update(block)
                    remaining -= len(block)
                output.flush()
                os.fsync(output.fileno())
            # link() is an atomic no-replace publication of the complete file.
            os.link(partial, args.file, follow_symlinks=False)
            partial.unlink()
            complete = True
            body = (received.hexdigest() + "\n").encode()
            self.send_response(201)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            print(json.dumps({"received_sha256": received.hexdigest(), "bytes": length}), flush=True)

        def log_message(self, *_args):
            pass  # No paths/configuration data in access logs.

    with http.server.HTTPServer((args.bind, 0), Handler) as server:
        server.timeout = 0.5
        print(json.dumps({"url": f"http://{args.bind}:{server.server_port}{endpoint}",
                          "sha256": digest, "mode": "receive" if args.receive else "serve"}), flush=True)
        deadline = time.monotonic() + args.lifetime
        while not complete and time.monotonic() < deadline:
            server.handle_request()
    if source:
        source.close()
    if not complete:
        raise SystemExit("transfer expired without completion")


if __name__ == "__main__":
    main()
