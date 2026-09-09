"""Host-only tests. No real router commands, keys or settings are used."""
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
import urllib.error
import urllib.request

from render_guard import render
from verify_backup import decode_cfg, members

ROOT = Path(__file__).parent
HASHES = {name: "a" * 64 for name in ("HTTPD", "RC", "SHARED", "WGET")}


class GuardTests(unittest.TestCase):
    def rendered(self, slot):
        return render((ROOT / "router-persistent-guard.sh").read_text(),
                      candidate=slot, web_hash="b" * 64, links_hash="c" * 64,
                      binaries=HASHES)

    def test_explicit_slot_orientations(self):
        for slot in (1, 2):
            text = self.rendered(slot)
            self.assertIn(f"CANDIDATE_STATE=BOOT_SET_PART{slot}_IMAGE\n", text)
            self.assertIn(f"FALLBACK_STATE=BOOT_SET_PART{3-slot}_IMAGE\n", text)
            self.assertNotIn("RENDER_REQUIRED", text)
            subprocess.run(["sh", "-n"], input=text, text=True, check=True)

    def test_reject_incomplete_identity(self):
        for hashes in ({}, {**HASHES, "WGET": "a; reboot"}):
            with self.assertRaises(ValueError):
                render((ROOT / "router-persistent-guard.sh").read_text(),
                       candidate=2, web_hash="b" * 64, links_hash="c" * 64,
                       binaries=hashes)

    def run_guard(self, slot, action, *, identity=True, healthy=True, hold=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = root / "calls"
            stub = root / "bootstate"
            stub.write_text(f'#!/bin/sh\nprintf "%s\\n" "$1" >> "{calls}"\n')
            stub.chmod(0o700)
            marker = root / "hold"
            if hold:
                marker.touch()
            text = self.rendered(slot).replace("/bin/bcm_bootstate", str(stub))
            # Exercise the real dispatch, replacing only external probes and
            # side effects. No absolute router commands can execute here.
            text = text.replace('case "${1:-}" in', f'''
is_candidate_identity() {{ {"true" if identity else "false"}; }}
healthy() {{ {"true" if identity and healthy else "false"}; }}
bootstate_has() {{ true; }}
set_state() {{ :; }}
log_guard() {{ :; }}
sync() {{ :; }}
PROMOTION_HOLD_FILE="{marker}"
case "${{1:-}}" in''').replace("(sleep 2; /sbin/reboot)", "(:)")
            result = subprocess.run(["sh", "-s", "--", action], input=text,
                                    text=True, capture_output=True, timeout=5)
            return result.returncode, calls.read_text().splitlines() if calls.exists() else []

    def test_baseline_never_rearms_candidate(self):
        for slot in (1, 2):
            for action in ("arm", "promote"):
                _, calls = self.run_guard(slot, action, identity=False)
                self.assertEqual(calls, [])

    def test_candidate_hold_arm_promote_failure(self):
        for slot in (1, 2):
            fallback = 3 - slot
            self.assertEqual(self.run_guard(slot, "arm"),
                             (0, [f"BOOT_SET_PART{fallback}_IMAGE_ONCE"]))
            self.assertEqual(self.run_guard(slot, "promote", hold=True),
                             (0, [f"BOOT_SET_PART{fallback}_IMAGE"]))
            self.assertEqual(self.run_guard(slot, "promote"),
                             (0, [f"BOOT_SET_PART{slot}_IMAGE"]))
            self.assertEqual(self.run_guard(slot, "promote", healthy=False),
                             (1, [f"BOOT_SET_PART{fallback}_IMAGE"]))


class BackupTests(unittest.TestCase):
    def cfg(self, payload):
        encoded = bytes(0xFF if byte == 0 else 255 - byte for byte in payload)
        return b"HDR2" + len(encoded).to_bytes(3, "little") + b"\0" + encoded

    def test_vendor_duplicate_last_wins(self):
        self.assertEqual(decode_cfg(self.cfg(b"key=\0key=value\0")), {b"key": b"value"})

    def test_reject_bad_header_length_and_entry(self):
        for data in (b"HDR2", self.cfg(b"key=value\0")[:-1], self.cfg(b"invalid\0")):
            with self.assertRaises(ValueError):
                decode_cfg(data)

    def test_reject_unsafe_archive_names(self):
        for name in ("../x", "/x", ".", "outside/x"):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w:gz") as archive:
                archive.addfile(tarfile.TarInfo(name))
            with self.assertRaises(ValueError):
                members(stream.getvalue(), "jffs")


class TransferTests(unittest.TestCase):
    def test_single_file_and_size_bound(self):
        for receive in (False, True):
            with self.subTest(receive=receive), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "artifact"
                payload = b"synthetic-test-content"
                if not receive:
                    path.write_bytes(payload)
                command = [sys.executable, str(ROOT / "artifact_transfer.py"),
                           "--bind", "127.0.0.1", "--peer", "127.0.0.1",
                           "--file", str(path), "--lifetime", "10", "--max-bytes", "32"]
                if receive:
                    command.append("--receive")
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    url = json.loads(process.stdout.readline())["url"]
                    with self.assertRaises(urllib.error.HTTPError) as error:
                        urllib.request.urlopen(url + "/wrong", timeout=3)
                    self.assertEqual(error.exception.code, 404)
                    if receive:
                        with self.assertRaises(urllib.error.HTTPError) as error:
                            urllib.request.urlopen(urllib.request.Request(url, data=b"X" * 33, method="PUT"), timeout=3)
                        self.assertEqual(error.exception.code, 413)
                        self.assertFalse(path.exists())
                        with urllib.request.urlopen(urllib.request.Request(url, data=payload, method="PUT"), timeout=3) as reply:
                            self.assertEqual(reply.status, 201)
                    else:
                        with urllib.request.urlopen(url, timeout=3) as reply:
                            self.assertEqual(reply.read(), payload)
                    _, stderr = process.communicate(timeout=5)
                    self.assertEqual(process.returncode, 0, stderr)
                    self.assertEqual(path.read_bytes(), payload)
                finally:
                    if process.poll() is None:
                        process.terminate()
                    process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
