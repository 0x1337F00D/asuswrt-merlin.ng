#!/usr/bin/env python3
"""Run the real bootstrap function against a synthetic, checksum-bound tarball.

No network or compiler is needed. The fixture's configure creates a fake
installed make and a no-op Makefile; the real bootstrap performs extraction,
installation placement and version checks, including a nonexistent parent.
"""
import hashlib
import io
import os
from pathlib import Path
import shlex
import subprocess
import tarfile
import tempfile
import unittest


class BootstrapTests(unittest.TestCase):
    def run_bootstrap(self, directory, *, old=False, reuse=False):
        root = Path(directory)
        archive = root / "make-4.4.1.tar.gz"
        fixture = b'''#!/usr/bin/python3
from pathlib import Path
import sys
prefix = Path(next(arg[9:] for arg in sys.argv if arg.startswith("--prefix=")))
(prefix / "bin").mkdir(parents=True)
program = prefix / "bin/make"
program.write_text("#!/bin/sh\\nprintf 'GNU Make 4.4.1\\\\n'\\n")
program.chmod(0o755)
Path("Makefile").write_text("all install:\\n\\t@:\\n")
'''
        with tarfile.open(archive, "w:gz") as bundle:
            entry = tarfile.TarInfo("make-fixture/configure")
            entry.size, entry.mode = len(fixture), 0o755
            bundle.addfile(entry, io.BytesIO(fixture))
        source = (Path(__file__).parents[1] / "build.sh").read_text()
        body = source.split("ensure_gnu_make() {\n", 1)[1].split("\n}\n", 1)[0]
        if old:
            body = body.replace('\tmkdir -p "$(dirname "$GNU_MAKE_ROOT")"\n', "")
        destination = root / "not created parent" / "nested" / "make-4.4.1"
        values = {"GNU_MAKE_VERSION": "4.4.1", "GNU_MAKE_ROOT": str(destination),
                  "GNU_MAKE_BIN": str(destination / "bin/make"),
                  "GNU_MAKE_SHA256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                  "GNU_MAKE_URL": "https://invalid.invalid/must-not-download"}
        script = "set -euo pipefail\n"
        script += "\n".join(f"{key}={shlex.quote(value)}" for key, value in values.items())
        script += "\nrequire_cmd() { command -v \"$1\" >/dev/null; }\n"
        script += "ensure_gnu_make() {\n" + body + "\n}\nensure_gnu_make\n"
        if reuse:
            script += "ensure_gnu_make\n"
        result = subprocess.run(["bash", "-c", script], text=True, capture_output=True,
                                timeout=15, env={**os.environ, "TMPDIR": str(root),
                                                 "LC_ALL": "C"})
        return result, destination

    def test_missing_nested_parent_is_created(self):
        with tempfile.TemporaryDirectory(prefix="make-bootstrap-") as directory:
            result, destination = self.run_bootstrap(directory)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue((destination / "bin/make").is_file())
            self.assertIn("Built checksum-verified GNU Make 4.4.1", result.stdout)

    def test_existing_make_with_spaces_is_reused(self):
        with tempfile.TemporaryDirectory(prefix="make-bootstrap-reuse-") as directory:
            result, _ = self.run_bootstrap(directory, reuse=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Reusing GNU Make 4.4.1", result.stdout)

    def test_original_placement_reproduces_failure(self):
        with tempfile.TemporaryDirectory(prefix="make-bootstrap-old-") as directory:
            result, destination = self.run_bootstrap(directory, old=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cannot move", result.stderr)
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
