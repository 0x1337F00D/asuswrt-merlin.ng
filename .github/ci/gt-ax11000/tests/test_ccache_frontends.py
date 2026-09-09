#!/usr/bin/env python3
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("ccache_frontends", Path(__file__).parents[1] / "tools/ccache_frontends.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FrontendTests(unittest.TestCase):
    def executable(self, path, text):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(0o755)

    def test_identical_basenames_preserve_exact_compiler_and_source(self):
        with tempfile.TemporaryDirectory(prefix="ccache-paths-") as directory:
            root = Path(directory)
            source, view, ccache = root / "source with spaces", root / "view", root / "fake-cache"
            self.executable(ccache, '#!/bin/sh\nexec "$@"\n')
            originals = {}
            for version in ("5.3", "5.5"):
                compiler = source / version / "bin/arm-linux-gcc"
                self.executable(compiler, f'#!/bin/sh\nprintf "%s\\n" "{version}"\n')
                originals[compiler] = compiler.read_bytes()
                compiler.with_name(compiler.name + ".br_real").write_text("real-" + version)
            for attempt in range(2):
                module.prepare(source, view, ccache)
                for compiler, original in originals.items():
                    self.assertEqual(compiler.read_bytes(), original)
                    target = view / compiler.relative_to(source)
                    result = subprocess.check_output([str(target), "-dumpversion"], text=True)
                    self.assertEqual(result.strip(), compiler.parents[1].name)
                    self.assertIn("CCACHE_EXTRAFILES=", target.read_text())
                    self.assertFalse(target.is_symlink())

    def test_stale_or_mutated_view_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="ccache-stale-") as directory:
            root = Path(directory)
            source, view, ccache = root / "source", root / "view", root / "cache"
            self.executable(source / "arm-linux-gcc", '#!/bin/sh\necho 5.5\n')
            self.executable(ccache, '#!/bin/sh\nexec "$@"\n')
            view.mkdir()
            with self.assertRaises(ValueError):
                module.prepare(source, view, ccache)
            view.rmdir()
            module.prepare(source, view, ccache)
            (view / "arm-linux-gcc").write_text("changed")
            with self.assertRaises(ValueError):
                module.prepare(source, view, ccache)
            with self.assertRaises(ValueError):
                module.prepare(source, source, ccache)


if __name__ == "__main__":
    unittest.main()
