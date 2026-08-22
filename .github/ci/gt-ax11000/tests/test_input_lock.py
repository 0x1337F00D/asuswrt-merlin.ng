#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import io
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path


sys.dont_write_bytecode = True
TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))
import input_lock  # noqa: E402


def git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ("git", "-C", str(repository), *arguments),
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


def create_repository(path: Path, filename: str = "file.txt") -> str:
    path.mkdir()
    git(path, "init", "-q")
    git(path, "config", "user.name", "Input Lock Test")
    git(path, "config", "user.email", "input-lock@example.invalid")
    (path / filename).write_text("base\n", encoding="utf-8")
    git(path, "add", "--", filename)
    git(path, "commit", "-q", "-m", "base")
    return git(path, "rev-parse", "HEAD")


def lock_text(upstream: str, toolchains: str, diff: str) -> str:
    return f'''format = 1
upstream_repo = "https://github.com/RMerl/asuswrt-merlin.ng.git"
upstream_sha = "{upstream}"
toolchains_repo = "https://github.com/RMerl/am-toolchains.git"
toolchains_sha = "{toolchains}"
rust_toolchain = "1.85.1"
rust_target = "armv7-unknown-linux-gnueabi"
rust_target_cpu = "cortex-a9"
patched_diff_sha256 = "{diff}"
'''


class InputLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def fixture(self) -> tuple[Path, Path, Path, Path, Path]:
        source = self.root / "source"
        toolchains = self.root / "toolchains"
        source_sha = create_repository(source)
        toolchains_sha = create_repository(toolchains, "compiler")
        (source / "file.txt").write_text("patched\n", encoding="utf-8")
        patch_root = self.root / "patches"
        patch_root.mkdir()
        (patch_root / "only.patch").write_text("fixture\n", encoding="utf-8")
        series = patch_root / "series"
        series.write_text("only.patch\n", encoding="utf-8")
        lock = self.root / "inputs.lock"
        diff = input_lock.patched_diff_hash(source)
        lock.write_text(lock_text(source_sha, toolchains_sha, diff), encoding="utf-8")
        return source, toolchains, patch_root, series, lock

    def test_verify_accepts_only_the_exact_source_diff(self) -> None:
        source, toolchains, patch_root, series, lock = self.fixture()
        arguments = types.SimpleNamespace(
            lock=lock,
            series=series,
            patch_root=patch_root,
            source=source,
            toolchains=toolchains,
            rust_toolchain="1.85.1",
            rust_target="armv7-unknown-linux-gnueabi",
            rust_target_cpu="cortex-a9",
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            input_lock.command_verify(arguments)
        self.assertIn("patched_diff_sha256=", output.getvalue())
        (source / "unexpected").write_text("unexpected untracked input\n")
        with self.assertRaisesRegex(input_lock.LockError, "diff does not match"):
            input_lock.command_verify(arguments)
        (source / "unexpected").unlink()
        (source / "file.txt").write_text("different patch\n", encoding="utf-8")
        with self.assertRaisesRegex(input_lock.LockError, "diff does not match"):
            input_lock.command_verify(arguments)

    def test_lock_rejects_unknown_keys(self) -> None:
        source, toolchains, _patch_root, _series, lock = self.fixture()
        del source, toolchains
        lock.write_text(lock.read_text() + 'moving_branch = "main"\n', encoding="utf-8")
        with self.assertRaisesRegex(input_lock.LockError, "keys mismatch"):
            input_lock.load_lock(lock)

    def test_lock_rejects_redirected_repositories_and_moving_rust(self) -> None:
        _source, _toolchains, _patch_root, _series, lock = self.fixture()
        original = lock.read_text(encoding="utf-8")
        lock.write_text(
            original.replace(
                "https://github.com/RMerl/asuswrt-merlin.ng.git",
                "https://attacker.invalid/upstream.git",
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(input_lock.LockError, "unexpected upstream_repo"):
            input_lock.load_lock(lock)
        lock.write_text(
            original.replace('rust_toolchain = "1.85.1"', 'rust_toolchain = "stable"'),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(input_lock.LockError, "unexpected Rust toolchain"):
            input_lock.load_lock(lock)

    def test_series_rejects_traversal_duplicates_and_unlisted_patches(self) -> None:
        _source, _toolchains, patch_root, series, _lock = self.fixture()
        series.write_text("../outside.patch\n", encoding="utf-8")
        with self.assertRaisesRegex(input_lock.LockError, "unsafe or duplicate"):
            input_lock.read_series(series, patch_root)
        series.write_text("only.patch\nonly.patch\n", encoding="utf-8")
        with self.assertRaisesRegex(input_lock.LockError, "unsafe or duplicate"):
            input_lock.read_series(series, patch_root)
        series.write_text("only.patch\n", encoding="utf-8")
        (patch_root / "forgotten.patch").write_text("fixture\n", encoding="utf-8")
        with self.assertRaisesRegex(input_lock.LockError, "missing from series"):
            input_lock.read_series(series, patch_root)

    def test_patch_set_hash_binds_order_names_and_contents(self) -> None:
        _source, _toolchains, patch_root, series, _lock = self.fixture()
        original = input_lock.patch_set_hash(series, patch_root)
        (patch_root / "only.patch").write_text("changed\n", encoding="utf-8")
        self.assertNotEqual(original, input_lock.patch_set_hash(series, patch_root))
        (patch_root / "second.patch").write_text("second\n", encoding="utf-8")
        series.write_text("second.patch\nonly.patch\n", encoding="utf-8")
        self.assertNotEqual(original, input_lock.patch_set_hash(series, patch_root))

    def test_clean_source_cannot_be_mistaken_for_patched_source(self) -> None:
        source = self.root / "clean"
        create_repository(source)
        with self.assertRaisesRegex(input_lock.LockError, "diff is empty"):
            input_lock.patched_diff_hash(source)

    def test_diff_hash_is_independent_of_git_abbreviation_config(self) -> None:
        source, _toolchains, _patch_root, _series, _lock = self.fixture()
        git(source, "config", "core.abbrev", "7")
        short_hash = input_lock.patched_diff_hash(source)
        git(source, "config", "core.abbrev", "40")
        self.assertEqual(short_hash, input_lock.patched_diff_hash(source))


if __name__ == "__main__":
    unittest.main()
