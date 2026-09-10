#!/usr/bin/env python3
"""Check the actual supervisor's production macro, not the test override."""
import pathlib
import re
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def production_directories(patch):
    with tempfile.TemporaryDirectory(prefix="wlif-path-", dir="/tmp") as tmp:
        subprocess.run([
            "git", "apply", "--recount", "--unsafe-paths",
            "--include=release/src/router/shared/wlif_exec.c",
            "--include=release/src/router/shared/wlif_process.h",
        ], input=patch, cwd=tmp, check=True, capture_output=True)
        source = pathlib.Path(tmp) / "release/src/router/shared/wlif_exec.c"
        macros = subprocess.check_output(["cc", "-E", "-dM", str(source)], text=True)
        value = re.search(r'^#define WLIF_CLI_DIRS (.+)$', macros, re.M)
        if not value:
            raise AssertionError("missing production path definition")
        return value.group(1)


class SearchPath(unittest.TestCase):
    def test_only_firmware_directory(self):
        patch = (ROOT / "patches/wlif-shell-hardening.patch").read_bytes()
        self.assertEqual(production_directories(patch), '"/usr/sbin"')

    def test_old_fallback_is_detected(self):
        patch = (ROOT / "patches/wlif-shell-hardening.patch").read_bytes()
        old = patch.replace(b'#define WLIF_CLI_DIRS "/usr/sbin"',
                            b'#define WLIF_CLI_DIRS "/usr/sbin", "/opt/bin"')
        self.assertNotEqual(old, patch)
        self.assertNotEqual(production_directories(old), '"/usr/sbin"')


if __name__ == "__main__":
    unittest.main()
