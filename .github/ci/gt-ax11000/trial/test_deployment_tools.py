"""Host-only tests. No real router commands, keys or settings are used."""
import io
import hashlib
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

    def identity_fixture(self, slot, *, corrupt=None, old_bracket_bug=False):
        # Execute the actual identity predicate, not the dispatch's mock.
        # Only router paths/NVRAM/bootstate are redirected to synthetic data;
        # test/[ ], grep, awk, and OpenSSL really execute under POSIX sh.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {
                "www/Advanced_WAdvanced_Content.asp":
                    b'id="regulatory_lab_country" regulatory_lab_store_acknowledgement',
                "www/EN.dict": b"English dictionary fixture",
                "www/DE.dict": b"German dictionary fixture",
                "usr/share/codex/web-payload.sha256": b"payload fixture",
                "usr/share/codex/web-symlinks.manifest": b"links fixture",
                "usr/sbin/httpd": b"rust_regulatory_testlab_ack_v1",
                "sbin/rc": b"rc fixture", "usr/lib/libshared.so": b"shared fixture",
                "usr/sbin/wget": b"wget fixture",
            }
            for name, data in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            def digest(name):
                return hashlib.sha256(files[name]).hexdigest()
            text = render((ROOT / "router-persistent-guard.sh").read_text(),
                          candidate=slot,
                          web_hash=digest("usr/share/codex/web-payload.sha256"),
                          links_hash=digest("usr/share/codex/web-symlinks.manifest"),
                          binaries={name: digest(path) for name, path in {
                              "HTTPD": "usr/sbin/httpd", "RC": "sbin/rc",
                              "SHARED": "usr/lib/libshared.so", "WGET": "usr/sbin/wget"}.items()})
            text = text.split('case "${1:-}" in', 1)[0]
            if old_bracket_bug:
                text = text.replace('= "$EXPECTED_WGET_SHA256" ]',
                                    '= "$EXPECTED_WGET_SHA256"')
            for name in sorted(files, key=len, reverse=True):
                text = text.replace("/" + name, str(root / name))
            text = text.replace("/usr/sbin/openssl", "/usr/bin/openssl")
            text = text.replace("/bin/bcm_bootstate", "fixture_bootstate")
            label = "First" if slot == 1 else "Second"
            text += f'''
nvram() {{
    case "$2" in
        productid) echo GT-AX11000;; firmver) echo 3.0.0.6;;
        buildno) echo 102.9;; extendno) echo alpha1;; *) return 1;;
    esac
}}
fixture_bootstate() {{ echo 'Booted Partition: {label}'; }}
is_candidate_identity
'''
            if corrupt:
                (root / corrupt).write_bytes(b"tampered")
            return subprocess.run(["sh", "-s"], input=text, text=True,
                                  capture_output=True, timeout=5)

    def test_real_identity_predicate_accepts_both_slots(self):
        for slot in (1, 2):
            with self.subTest(slot=slot):
                result = self.identity_fixture(slot)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_real_identity_rejects_tampered_binaries(self):
        for path in ("usr/sbin/httpd", "sbin/rc", "usr/lib/libshared.so", "usr/sbin/wget"):
            with self.subTest(path=path):
                self.assertNotEqual(self.identity_fixture(2, corrupt=path).returncode, 0)

    def test_old_missing_bracket_fails_at_runtime(self):
        result = self.identity_fixture(2, old_bracket_bug=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing ]", result.stderr)

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
