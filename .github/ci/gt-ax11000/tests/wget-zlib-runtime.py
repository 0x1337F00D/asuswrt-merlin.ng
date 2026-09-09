#!/usr/bin/env python3
"""Exercise the shipped ARM wget's inflate AND gzwrite consumers offline.

Only a loopback HTTP fixture is used. Python's independent zlib implementation
produces the gzip response and verifies wget's compressed WARC output. No
router, credentials, public downloads or persistent user files are involved.
"""
import gzip
import http.server
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading


def main():
    rootfs, qemu = map(Path, sys.argv[1:])
    payload = bytes(range(256)) * 256 + b"independent gzip consumer fixture\n"
    compressed = gzip.compress(payload, mtime=0)

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            data = compressed if self.path == "/gzip" else payload
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            if self.path == "/gzip":
                self.send_header("Content-Encoding", "gzip")
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_args):
            pass

    with tempfile.TemporaryDirectory(prefix="wget-zlib-consumer-") as scratch:
        directory = Path(scratch)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            command = [str(qemu), "-cpu", "cortex-a7", "-L", str(rootfs),
                       "-E", f"LD_LIBRARY_PATH={rootfs}/lib:{rootfs}/usr/lib",
                       str(rootfs / "usr/sbin/wget"), "--no-config", "--no-proxy", "--no-hsts",
                       "--tries=1", "--timeout=4"]
            config = directory / "wgetrc"
            config.write_text("")
            environment = {**os.environ, "WGETRC": str(config)}
            url = f"http://127.0.0.1:{server.server_port}"
            for endpoint, options in [("gzip", ["--compression=auto"]),
                                      ("plain", [f"--warc-file={directory / 'capture'}"])]:
                target = directory / endpoint
                result = subprocess.run(command + options + ["-O", str(target), f"{url}/{endpoint}"],
                                        cwd=directory, env=environment, capture_output=True, timeout=15)
                if result.returncode:
                    raise RuntimeError(f"wget {endpoint} exited {result.returncode}: "
                                       + result.stderr.decode(errors="replace")[-2000:])
                if target.read_bytes() != payload:
                    raise RuntimeError(f"wget {endpoint} changed the response bytes")
            archive = gzip.decompress((directory / "capture.warc.gz").read_bytes())
            if b"WARC/1.0" not in archive or payload not in archive:
                raise RuntimeError("wget WARC gzip did not contain the complete response")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
    print("WGET_ZLIB_RUNTIME=PASS gzip-response=independent WARC-gzip=independent")


if __name__ == "__main__":
    main()
