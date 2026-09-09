#!/usr/bin/env python3
"""Run the actual LPRng top-level rules with a duplicate-writer detector."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class LprngTests(unittest.TestCase):
    def test_one_recursive_src_owner(self):
        source = Path(os.environ["LPRNG_SOURCE"])
        for name in ("Makefile", "Makefile.in"):
            with self.subTest(template=name), tempfile.TemporaryDirectory(prefix="lprng-dag-") as directory:
                root = Path(directory)
                (root / "src").mkdir()
                # GNU Make configures SET_MAKE as empty; other configure
                # placeholders are variable values outside the exercised path.
                text = (source / name).read_text().replace("@SET_MAKE@", "")
                (root / "vendor.mk").write_text(text)
                (root / "src/Makefile").write_text(
                    ".PHONY: all\nall:\n"
                    "\t@mkdir single-writer || exit 1; sleep 0.1; "
                    "echo produced >> ../calls; echo config > lpd.conf; rmdir single-writer\n"
                )
                for jobs in (2, 4, 8):
                    (root / "calls").unlink(missing_ok=True)
                    (root / "src/lpd.conf").unlink(missing_ok=True)
                    result = subprocess.run(
                        [os.environ.get("MAKE", "make"), "-f", "vendor.mk", f"-j{jobs}",
                         "SHELL=/bin/sh", "ALLDIRS=src", "USE_NLS=no", "src", "src/lpd.conf"],
                        cwd=root, capture_output=True, text=True, timeout=5,
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual((root / "calls").read_text().splitlines(), ["produced"])
                    self.assertEqual((root / "src/lpd.conf").read_text(), "config\n")
                # A producer that reports success without its promised output
                # must not make the alias silently succeed.
                (root / "src/lpd.conf").unlink()
                (root / "src/Makefile").write_text(".PHONY: all\nall:\n\t@true\n")
                missing = subprocess.run(
                    [os.environ.get("MAKE", "make"), "-f", "vendor.mk", "-j4",
                     "SHELL=/bin/sh", "ALLDIRS=src", "USE_NLS=no", "src/lpd.conf"],
                    cwd=root, capture_output=True, text=True, timeout=5,
                )
                self.assertNotEqual(missing.returncode, 0)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_lprng_parallel.py PATCHED_LPRNG_DIRECTORY")
    os.environ["LPRNG_SOURCE"] = sys.argv.pop()
    unittest.main()
