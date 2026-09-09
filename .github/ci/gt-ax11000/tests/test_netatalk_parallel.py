#!/usr/bin/env python3
"""Execute the netatalk dependency topology from the patched vendor Makefile.

Fake package recipes detect concurrent duplicate builds. No vendor tools,
router, network, credentials or persistent output are used.
"""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


class ParallelTests(unittest.TestCase):
    def test_shared_producers_and_single_stamp_owner(self):
        source = os.environ.get("NETATALK_MAKEFILE")
        if not source:
            self.skipTest("set NETATALK_MAKEFILE to the patched vendor Makefile")
        text = Path(source).read_text()
        targets = ["netatalk-3.0.5-dep", "netaconfig", "netatalk-3.0.5/stamp-h1"]
        lines = []
        for target in targets:
            found = re.findall(r"^" + re.escape(target) + r":[^\n]*$", text, re.M)
            self.assertEqual(len(found), 1, target)
            lines.append(found[0])
        recipe = text.split(lines[-1] + "\n", 1)[1].split("\nnetatalk-3.0.5:", 1)[0]
        self.assertNotIn("$(MAKE)", recipe)
        self.assertIn("set -e;", recipe)
        self.assertIn(".PHONY: netaconfig netatalk-3.0.5-dep", text)
        with tempfile.TemporaryDirectory(prefix="netatalk-dag-") as directory:
            root = Path(directory)
            # Request the same shared producers directly and through both
            # netaconfig/stamp consumers under one GNU jobserver.
            prefix = ".PHONY: all netaconfig netatalk-3.0.5-dep openssl libgcrypt-1.5.1 db-4.8.30 libevent-2.0.21\n"
            prefix += "all: netaconfig netatalk-3.0.5/stamp-h1 db-4.8.30 libgcrypt-1.5.1\n"
            suffix = "\t@test -f done-db-4.8.30 -a -f done-libgcrypt-1.5.1\n"
            suffix += "\t@mkdir -p netatalk-3.0.5; echo stamp >> calls; touch $@\n"
            suffix += "openssl libgcrypt-1.5.1 db-4.8.30 libevent-2.0.21:\n"
            suffix += "\t@mkdir running-$@; sleep 0.05; echo $@ >> calls; touch done-$@; rmdir running-$@\n"
            (root / "Makefile").write_text(prefix + "\n".join(lines) + "\n" + suffix)
            for jobs in (2, 4, 8):
                (root / "calls").unlink(missing_ok=True)
                (root / "netatalk-3.0.5/stamp-h1").unlink(missing_ok=True)
                subprocess.run([os.environ.get("MAKE", "make"), f"-j{jobs}"], cwd=root,
                               check=True, capture_output=True, timeout=5)
                calls = (root / "calls").read_text().splitlines()
                for target in ("stamp", "openssl", "libgcrypt-1.5.1", "db-4.8.30", "libevent-2.0.21"):
                    self.assertEqual(calls.count(target), 1, (jobs, calls))


if __name__ == "__main__":
    if len(sys.argv) == 2:
        os.environ["NETATALK_MAKEFILE"] = sys.argv.pop()
    unittest.main()
