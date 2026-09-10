#!/usr/bin/env python3
"""Exercise the real repack promotion recipe on a synthetic RAM staging tree."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SharedRepack(unittest.TestCase):
    def test_shared_install_precedes_consumers(self):
        recipe = (ROOT / "rust-repack.mk").read_text()
        self.assertLess(recipe.index("$(MAKE) -C router shared-install"),
                        recipe.index("$(MAKE) -C router www-install"))
        self.assertIn("usr/lib/libshared.so", (ROOT / "build.sh").read_text())

    def test_manifest_and_ci_consumer_sets_match(self):
        recipe = (ROOT / "rust-repack.mk").read_text()
        manifest = recipe.split("cd $(PROFILE_DIR)/fs.install; sha256sum", 1)[1]
        manifest = manifest.split("> $(RUST_CONSUMER_MANIFEST)", 1)[0]
        expected = set(manifest.replace("\\", " ").split())
        build = (ROOT / "build.sh").read_text()
        actual = set(build.split("rust_relinked_consumers=(", 1)[1].split(")", 1)[0].split())
        self.assertEqual(expected, actual)
        self.assertEqual(len(expected), 11)
        workflow = (ROOT.parents[1] / "workflows/build-gt-ax11000.yml").read_text()
        exclusions = re.findall(r"rootfs_excludes\+=\((.*?)\)", workflow, re.S)
        self.assertEqual(len(exclusions), 2)
        for block in exclusions:
            self.assertEqual(set(block.split()), expected)

    def test_actual_promotion_refreshes_cached_shared(self):
        recipe = (ROOT / "rust-repack.mk").read_text()
        start = recipe.index("\tpromote_artifact() {")
        end = recipe.index("\n\t# Package install", start)
        commands = recipe[start:end].replace("$$", "$")
        pairs = re.findall(r"promote_artifact \$\(PROFILE_DIR\)/fs.install/(\S+) \\\n\s*\$\(PROFILE_DIR\)/fs.install/(\S+)", commands)
        self.assertEqual(len(pairs), 11)
        with tempfile.TemporaryDirectory(prefix="shared-repack-", dir=os.environ.get("TMPDIR", "/tmp")) as tmp:
            stage = Path(tmp) / "fs.install"
            for source, dest in pairs:
                src = stage / source
                src.parent.mkdir(parents=True, exist_ok=True)
                src.write_bytes(b"fresh:" + source.encode())
                src.chmod(0o755)
                target = stage / dest.rstrip(";")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"stale")
            subprocess.run(["bash", "-eu", "-c", commands.replace("$(PROFILE_DIR)", tmp)], check=True)
            shared = stage / "usr/lib/libshared.so"
            self.assertEqual(shared.read_bytes(), b"fresh:shared/usr/lib/libshared.so")
            self.assertEqual(shared.stat().st_mode & 0o777, 0o755)


if __name__ == "__main__":
    unittest.main()
