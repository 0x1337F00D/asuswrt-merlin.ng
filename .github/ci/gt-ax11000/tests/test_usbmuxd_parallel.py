#!/usr/bin/env python3
"""Execute extracted USB dependency rules with RAM-only fake build/stage recipes."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PACKAGES = {
    "libplist-2.2.0": (),
    "libusbmuxd-2.0.2": ("libplist-2.2.0",),
    "libimobiledevice-1.3.0": ("libplist-2.2.0", "libusbmuxd-2.0.2", "openssl"),
    "usbmuxd-1.1.1": ("libplist-2.2.0", "libimobiledevice-1.3.0", "libusb10"),
}


class UsbDependencyTests(unittest.TestCase):
    def test_build_configure_and_install_wait_for_staged_producers(self):
        source = Path(os.environ["USB_ROUTER_MAKEFILE"]).read_text()
        targets = {p + suffix for p in PACKAGES for suffix in ("", "-configure", "-install", "/Makefile")}
        rules = []
        for line in source.splitlines():
            if line.startswith(("\t", "#")) or ":" not in line:
                continue
            left, right = line.split(":", 1)
            selected = set(left.split()) & targets
            if selected:
                rules.append(" ".join(sorted(selected)) + ":" + right)
        self.assertTrue(rules)
        for jobs in (2, 8):
            for cached in (False, True):
                for suffix in ("", "-install"):
                    with self.subTest(jobs=jobs, cached=cached, goal=suffix):
                        with tempfile.TemporaryDirectory(prefix="usbmuxd-dag-", dir=os.environ.get("TMPDIR", "/tmp")) as tmp:
                            root = Path(tmp)
                            goals = [p + suffix for p in reversed(PACKAGES)]
                            makefile = ".PHONY: all openssl libusb10 " + " ".join(sorted(targets - {p + "/Makefile" for p in PACKAGES})) + "\n"
                            makefile += "all: " + " ".join(goals) + "\n" + "\n".join(rules) + "\n"
                            for package, dependencies in PACKAGES.items():
                                (root / package).mkdir()
                                if cached:
                                    (root / package / "Makefile").touch()
                                check = "".join("\t@test -f staged-" + dep + "\n" for dep in dependencies)
                                makefile += package + "-configure:\n" + check + "\t@echo configure-" + package + " >> calls\n"
                                makefile += package + "/Makefile:\n\t+@$(MAKE) " + package + "-configure\n\t@touch $@\n"
                                makefile += package + ":\n" + check + "\t@echo $@ >> calls; touch staged-$@\n"
                                makefile += package + "-install:\n\t@test -f staged-" + package + "\n"
                            makefile += "openssl libusb10:\n\t@echo $@ >> calls; touch staged-$@\n"
                            (root / "Makefile").write_text(makefile)
                            result = subprocess.run([os.environ.get("MAKE", "make"), f"-j{jobs}", "all"], cwd=root, capture_output=True, text=True, timeout=10)
                            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                            calls = (root / "calls").read_text().splitlines()
                            for package in PACKAGES:
                                self.assertEqual(calls.count(package), 1, calls)
                                if cached:
                                    self.assertNotIn("configure-" + package, calls)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_usbmuxd_parallel.py PATCHED_ROUTER_MAKEFILE")
    os.environ["USB_ROUTER_MAKEFILE"] = sys.argv.pop()
    unittest.main()
