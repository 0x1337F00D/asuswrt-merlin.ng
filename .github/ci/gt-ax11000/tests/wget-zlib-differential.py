#!/usr/bin/env python3
"""Compare actual ARM wget gzip/error behavior with the known-good C consumer.

Offline synthetic loopback traffic only. Compare status and downloaded bytes,
not version text, timing-dependent stderr or non-reproducible WARC timestamps.
This is a small consumer regression corpus, not coverage-guided fuzzing.
"""
import gzip
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading


def cases():
    payload = bytes(range(256)) * 128 + b"consumer parity\n"
    valid = gzip.compress(payload, mtime=0)
    bad_crc = bytearray(valid)
    bad_crc[-8] ^= 0x80
    bad_size = bytearray(valid)
    bad_size[-1] ^= 0x80
    bad_method = bytearray(valid)
    bad_method[2] = 0xff
    # Optional original filename/comment, as permitted by the gzip header.
    optional = valid[:3] + b"\x18" + valid[4:10] + b"fixture.bin\0comment\0" + valid[10:]
    return {
        "valid-binary": valid,
        "valid-empty": gzip.compress(b"", mtime=0),
        "optional-header": optional,
        "concatenated": valid + gzip.compress(b"second member", mtime=0),
        "trailing-garbage": valid + b"trailing bytes",
        "bad-crc": bytes(bad_crc),
        "bad-size": bytes(bad_size),
        "bad-method": bytes(bad_method),
        "wrong-magic": b"not gzip at all",
        **{f"truncated-{length}": valid[:length]
           for length in (0, 1, 9, len(valid) // 2, len(valid) - 8, len(valid) - 1)},
    }


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: wget-zlib-differential.py BASELINE_ROOTFS CANDIDATE_ROOTFS QEMU_ARM")
    baseline, candidate, qemu = map(Path, sys.argv[1:])
    corpus = cases()
    requests = {name: 0 for name in corpus}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            name = self.path.removeprefix("/")
            data = corpus[name]
            requests[name] += 1
            self.send_response(200)
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_args):
            pass

    with tempfile.TemporaryDirectory(prefix="wget-zlib-differential-") as scratch:
        directory = Path(scratch)
        config = directory / "wgetrc"
        config.write_text("")
        # UBIReader's default extraction drops executable permission. Run
        # private byte-identical copies; image permission checks are separate.
        programs = {}
        for label, rootfs in (("baseline", baseline), ("candidate", candidate)):
            program = directory / f"wget-{label}"
            shutil.copyfile(rootfs / "usr/sbin/wget", program)
            program.chmod(0o700)
            programs[label] = program
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        results = []
        try:
            for name in corpus:
                outputs = []
                for label, rootfs in (("baseline", baseline), ("candidate", candidate)):
                    target = directory / f"{name}-{label}"
                    command = [str(qemu), "-cpu", "cortex-a7", "-L", str(rootfs),
                               "-E", f"LD_LIBRARY_PATH={rootfs}/lib:{rootfs}/usr/lib",
                               str(programs[label]), "--no-config", "--no-proxy", "--no-hsts",
                               "--tries=1", "--timeout=3", "--compression=auto",
                               "-O", str(target), f"http://127.0.0.1:{server.server_port}/{name}"]
                    result = subprocess.run(command, cwd=directory, capture_output=True, timeout=10,
                                            env={**os.environ, "WGETRC": str(config)})
                    if result.returncode < 0 or result.returncode >= 126:
                        raise RuntimeError(f"{label}/{name}: abnormal exit {result.returncode}")
                    body = target.read_bytes() if target.exists() else None
                    if name in ("valid-binary", "valid-empty", "optional-header"):
                        expected = gzip.decompress(corpus[name])
                        if result.returncode != 0 or body != expected:
                            raise RuntimeError(f"{label}/{name}: positive control failed: "
                                               + result.stderr.decode(errors="replace")[-1000:])
                    outputs.append((result.returncode, body))
                if outputs[0] != outputs[1]:
                    raise RuntimeError(f"consumer mismatch: {name}; "
                                       f"statuses={outputs[0][0]},{outputs[1][0]}")
                code, body = outputs[1]
                if requests[name] != 2:
                    raise RuntimeError(f"{name}: both consumers must actually contact the fixture")
                results.append({"case": name, "exit": code,
                                "bytes": None if body is None else len(body),
                                "sha256": None if body is None else hashlib.sha256(body).hexdigest()})
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
    print(json.dumps({"WGET_ZLIB_DIFFERENTIAL": "PASS", "cases": results}, sort_keys=True))


if __name__ == "__main__":
    main()
