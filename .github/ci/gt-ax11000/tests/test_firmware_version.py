#!/usr/bin/env python3
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from firmware_version import generate

SOURCE = "KERNEL_VER=3.0\nFS_VER=0.6\nSERIALNO=102.9\nEXTENDNO=alpha1\nRCNO=0\n"


class VersionTests(unittest.TestCase):
    def test_override_only_changes_suffix(self):
        result, metadata = generate(SOURCE, "2\n")
        self.assertEqual(result, SOURCE.replace("alpha1", "alpha2"))
        self.assertEqual(metadata, dict(firmver="3.0.0.6", buildno="102.9", extendno="alpha2"))

    def test_reject_invalid_iterations(self):
        for value in ("0", "02", "-1", "2\n3", "2;id", "1000000", " 2", "", "2\n\n"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                generate(SOURCE, value)

    def test_fail_closed_on_upstream_layout_change(self):
        for source in (SOURCE + "EXTENDNO=foo\n", SOURCE.replace("EXTENDNO=", "EXTENDNO :="),
                       SOURCE.replace("SERIALNO=102.9", "SERIALNO=$(id)")):
            with self.assertRaises(ValueError):
                generate(source, "2")

    def test_vendor_make_include_and_recursive_export(self):
        override, _ = generate(SOURCE, "42")
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "version.conf").write_text(override)
            makefile = root / "Makefile"
            makefile.write_text('include $(ASUSWRTVERSIONCONFDIR)/version.conf\n'
                                'export EXTENDNO\n.PHONY: all child\n'
                                'all:\n\t@$(MAKE) --no-print-directory -f $(firstword $(MAKEFILE_LIST)) child\n'
                                'child:\n\t@test "$$EXTENDNO" = alpha42\n')
            subprocess.run(["make", "--no-print-directory", "-f", str(makefile),
                            f"ASUSWRTVERSIONCONFDIR={root}"], check=True, capture_output=True)


if __name__ == "__main__":
    unittest.main()
