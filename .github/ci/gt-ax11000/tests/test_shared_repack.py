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
        self.assertEqual(len(expected), 14)
        self.assertIn("usr/sbin/wlif-exec", expected)
        workflow = (ROOT.parents[1] / "workflows/build-gt-ax11000.yml").read_text()
        exclusions = re.findall(r"rootfs_excludes\+=\((.*?)\)", workflow, re.S)
        self.assertEqual(len(exclusions), 2)
        for block in exclusions:
            self.assertEqual(set(block.split()), expected)
        hashes = re.findall(r"sha256sum (usr/lib/libshared\.so .*?(?<!\\)\n)", workflow, re.S)
        self.assertEqual(len(hashes), 2)
        for block in hashes:
            self.assertEqual(set(block.replace("\\", " ").split()), expected)
        verifier = (ROOT / "tests/verify-rust-firmware.sh").read_text()
        executables = verifier.split("artifacts=(", 1)[1].split(")", 1)[0]
        self.assertIn('"usr/sbin/wlif-exec"', executables)

    def test_actual_promotion_refreshes_cached_shared(self):
        recipe = (ROOT / "rust-repack.mk").read_text()
        start = recipe.index("\tpromote_artifact() {")
        end = recipe.index("\n\t# Package install", start)
        commands = recipe[start:end].replace("$$", "$")
        pairs = re.findall(r"promote_artifact \$\(PROFILE_DIR\)/fs.install/(\S+) \\\n\s*\$\(PROFILE_DIR\)/fs.install/(\S+)", commands)
        self.assertEqual(len(pairs), 14)
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
            helper = stage / "usr/sbin/wlif-exec"
            self.assertEqual(helper.read_bytes(), b"fresh:shared/usr/sbin/wlif-exec")
            self.assertEqual(helper.stat().st_mode & 0o7777, 0o755)

    def test_promotion_rejects_symlinks_without_overwriting_referent(self):
        recipe = (ROOT / "rust-repack.mk").read_text()
        function = recipe.split("\tpromote_artifact() {", 1)[1].split("\n\tpromote_artifact ", 1)[0]
        commands = ("promote_artifact() {" + function).replace("$$", "$")
        commands += '\n promote_artifact "$1" "$2"'
        for location in ("source", "target"):
            for dangling in (False, True):
                with self.subTest(location=location, dangling=dangling):
                    with tempfile.TemporaryDirectory(prefix="shared-repack-", dir=os.environ.get("TMPDIR", "/tmp")) as tmp:
                        root = Path(tmp)
                        source, target, referent = (root / name for name in ("source", "target", "referent"))
                        source.write_bytes(b"fresh")
                        target.write_bytes(b"stale")
                        if not dangling:
                            referent.write_bytes(b"untouched")
                        link = root / location
                        link.unlink()
                        link.symlink_to(referent)
                        result = subprocess.run(["bash", "-eu", "-c", commands, "promotion", str(source), str(target)])
                        self.assertNotEqual(result.returncode, 0)
                        self.assertTrue(link.is_symlink())
                        if not dangling:
                            self.assertEqual(referent.read_bytes(), b"untouched")
                        else:
                            self.assertFalse(referent.exists())

    def test_actual_freshness_gate_requires_helper_in_both_modes(self):
        build = (ROOT / "build.sh").read_text()
        block = "rust_relinked_consumers=(" + build.split("rust_relinked_consumers=(", 1)[1]
        block = block.split('\nif [ "$build_rc" -eq 0 ]; then\n\tif ! bash', 1)[0]
        consumers = block.split("(", 1)[1].split(")", 1)[0].split()
        for mode in ("full", "rust-fast"):
            for state in ("fresh", "stale", "missing"):
                with self.subTest(mode=mode, helper=state):
                    with tempfile.TemporaryDirectory(prefix="shared-freshness-", dir=os.environ.get("TMPDIR", "/tmp")) as tmp:
                        root = Path(tmp)
                        marker = root / "started"
                        marker.touch()
                        os.utime(marker, (100, 100))
                        for consumer in consumers:
                            artifact = root / consumer
                            artifact.parent.mkdir(parents=True, exist_ok=True)
                            artifact.touch()
                            os.utime(artifact, (200, 200))
                        helper = root / "usr/sbin/wlif-exec"
                        if state == "stale":
                            os.utime(helper, (50, 50))
                        elif state == "missing":
                            helper.unlink()
                        commands = 'rootfs_dir="$1"; build_started_marker="$2"; BUILD_MODE="$3"; build_rc=0\n'
                        result = subprocess.run(["bash", "-eu", "-c", commands + block + '\nexit "$build_rc"', "freshness", tmp, str(marker), mode], capture_output=True, text=True)
                        self.assertEqual(result.returncode, 0 if state == "fresh" else 1)
                        if state != "fresh":
                            self.assertIn("usr/sbin/wlif-exec", result.stderr)


if __name__ == "__main__":
    unittest.main()
