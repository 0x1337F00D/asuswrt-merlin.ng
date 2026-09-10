#!/usr/bin/env python3
"""Execute the real inner build dispatch with a failure-injecting make stub."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class StageFailureTests(unittest.TestCase):
    def run_dispatch(self, mode, failure, *, old=False):
        source = (Path(__file__).parents[1] / "build.sh").read_text()
        body = source.split('cd "$ROOT/$SDK_PATH"\n', 1)[1].split('\nEOF\n', 1)[0]
        if old:
            body = body.replace(" || exit $?", "")
        stub = '''
make() {
    local goal="${!#}"
    printf 'MAKE_GOAL=%s\\n' "$goal"
    if [ "$goal" = "$FAILURE_GOAL" ]; then return 42; fi
}
'''
        with tempfile.TemporaryDirectory(prefix="build-dispatch-") as directory:
            result = subprocess.run(["bash", "-c", "set -euo pipefail\n" + stub + body],
                                    cwd=directory, text=True, capture_output=True, timeout=5,
                                    env={**os.environ, "BUILD_MODE": mode,
                                         "FAILURE_GOAL": failure, "FORCE_PROFILE": "0",
                                         "MAKE_JOBS": "1", "MAKE_TARGET": "gt-ax11000",
                                         "RUST_REPACK_MAKEFILE": "fixture.mk",
                                         "LOG_FILE": str(Path(directory) / "build.log")})
        return result

    def test_successful_clean_and_rust_fast(self):
        for mode in ("clean", "rust-fast"):
            with self.subTest(mode=mode):
                result = self.run_dispatch(mode, "no-failure")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("FIRMWARE_REPACK_SECONDS=", result.stdout)

    def test_clean_vendor_failure_skips_repack(self):
        result = self.run_dispatch("clean", "gt-ax11000")
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertNotIn("MAKE_GOAL=rust-firmware-repack", result.stdout)

    def test_repack_failure_is_never_masked_by_timing_echo(self):
        for mode in ("clean", "rust-fast"):
            with self.subTest(mode=mode):
                result = self.run_dispatch(mode, "rust-firmware-repack")
                self.assertEqual(result.returncode, 42, result.stderr)
                self.assertNotIn("FIRMWARE_REPACK_SECONDS=", result.stdout)

    def test_relink_failure_skips_repack(self):
        result = self.run_dispatch("rust-fast", "rust-components-relink")
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertNotIn("MAKE_GOAL=rust-firmware-repack", result.stdout)

    def test_original_clean_repack_failure_was_masked(self):
        result = self.run_dispatch("clean", "rust-firmware-repack", old=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("FIRMWARE_REPACK_SECONDS=", result.stdout)


if __name__ == "__main__":
    unittest.main()
