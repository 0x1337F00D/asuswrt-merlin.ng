#!/usr/bin/env python3
"""Check PNG staging precedes CMake generation and links under parallel Make.

Extract real package dependency headers, replacing only recipes with RAM
markers. A configured cache must not hide missing staging dependencies.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class PngDependencyTests(unittest.TestCase):
    def test_staging_precedes_configuration_and_link(self):
        source = Path(os.environ["PNG_ROUTER_MAKEFILE"]).read_text()
        targets = {"libpng", "libpng/build/Makefile", "qrencode", "qrencode/build/Makefile"}
        rules = [line for line in source.splitlines()
                 if ":" in line and line.split(":", 1)[0] in targets]
        self.assertTrue(rules)
        for jobs in (2, 8):
            for cached in (False, True):
                with self.subTest(jobs=jobs, cached=cached):
                    with tempfile.TemporaryDirectory(prefix="qrencode-dag-", dir=os.environ.get("TMPDIR", "/tmp")) as tmp:
                        root = Path(tmp)
                        for package in ("libpng", "qrencode"):
                            (root / package / "build").mkdir(parents=True)
                            if cached:
                                (root / package / "build/Makefile").touch()
                        makefile = ".PHONY: all qrencode libpng zlib\nall: qrencode libpng zlib\n"
                        makefile += "\n".join(rules) + "\n"
                        makefile += "zlib:\n\t@echo zlib >> calls; touch staged-zlib\n"
                        makefile += "libpng/build/Makefile:\n\t@test -f staged-zlib\n\t@echo configure-libpng >> calls; touch $@\n"
                        makefile += "libpng:\n\t@test -f staged-zlib\n\t@echo libpng >> calls; touch staged-libpng\n"
                        makefile += "qrencode/build/Makefile:\n\t@test -f staged-libpng -a -f staged-zlib\n\t@echo configure-qrencode >> calls; touch $@\n"
                        makefile += "qrencode:\n\t@test -f staged-libpng -a -f staged-zlib\n\t@echo qrencode >> calls\n"
                        (root / "Makefile").write_text(makefile)
                        result = subprocess.run([os.environ.get("MAKE", "make"), f"-j{jobs}", "all"], cwd=root, capture_output=True, text=True, timeout=10)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        calls = (root / "calls").read_text().splitlines()
                        for package in ("zlib", "libpng", "qrencode"):
                            self.assertEqual(calls.count(package), 1, calls)
                        for package in ("libpng", "qrencode"):
                            self.assertEqual(calls.count("configure-" + package), 0 if cached else 1, calls)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_qrencode_parallel.py PATCHED_ROUTER_MAKEFILE")
    os.environ["PNG_ROUTER_MAKEFILE"] = sys.argv.pop()
    unittest.main()
