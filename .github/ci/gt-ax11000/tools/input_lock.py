#!/usr/bin/env python3
"""Validate and update the immutable GT-AX11000 build-input lock."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path


SHA1 = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
REQUIRED = {
    "format": int,
    "upstream_repo": str,
    "upstream_sha": str,
    "toolchains_repo": str,
    "toolchains_sha": str,
    "rust_toolchain": str,
    "rust_target": str,
    "rust_target_cpu": str,
    "patched_diff_sha256": str,
}


class LockError(RuntimeError):
    pass


def load_lock(path: Path) -> dict[str, object]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise LockError(f"cannot read input lock: {error}") from error
    if set(data) != set(REQUIRED):
        missing = sorted(set(REQUIRED) - set(data))
        extra = sorted(set(data) - set(REQUIRED))
        raise LockError(f"input lock keys mismatch: missing={missing} extra={extra}")
    for key, expected_type in REQUIRED.items():
        if type(data[key]) is not expected_type:
            raise LockError(f"invalid type for {key}")
    if data["format"] != 1:
        raise LockError("unsupported input lock format")
    for key in ("upstream_sha", "toolchains_sha"):
        if not SHA1.fullmatch(str(data[key])):
            raise LockError(f"invalid {key}")
    if not SHA256.fullmatch(str(data["patched_diff_sha256"])):
        raise LockError("invalid patched_diff_sha256")
    if data["rust_target"] != "armv7-unknown-linux-gnueabi":
        raise LockError("unexpected Rust target")
    if data["rust_target_cpu"] != "cortex-a9":
        raise LockError("unexpected Rust target CPU")
    return data


def run_git(
    repository: Path,
    *arguments: str,
    binary: bool = False,
    environment: dict[str, str] | None = None,
) -> bytes | str:
    result = subprocess.run(
        ("git", "-C", str(repository), *arguments),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", "replace").strip()
        raise LockError(f"git {' '.join(arguments)} failed: {message}")
    return result.stdout if binary else result.stdout.decode("utf-8").strip()


def read_series(series: Path, patch_root: Path) -> list[Path]:
    entries: list[Path] = []
    seen: set[str] = set()
    for line_number, raw in enumerate(series.read_text(encoding="utf-8").splitlines(), 1):
        name = raw.strip()
        if not name or name.startswith("#"):
            continue
        candidate = Path(name)
        if candidate.is_absolute() or candidate.name != name or name in seen:
            raise LockError(f"unsafe or duplicate patch at series line {line_number}")
        path = patch_root / candidate
        if not path.is_file() or path.is_symlink():
            raise LockError(f"missing regular patch: {name}")
        seen.add(name)
        entries.append(path)
    if not entries:
        raise LockError("empty patch series")
    unlisted = {
        path.name for path in patch_root.glob("*.patch") if path.is_file()
    } - seen
    if unlisted:
        raise LockError(f"patches missing from series: {sorted(unlisted)}")
    return entries


def patch_set_hash(series: Path, patch_root: Path) -> str:
    digest = hashlib.sha256()
    for patch in read_series(series, patch_root):
        digest.update(patch.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(patch.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def patched_diff_hash(source: Path) -> str:
    with tempfile.TemporaryDirectory(prefix="asuswrt-input-index-") as directory:
        environment = os.environ.copy()
        environment["GIT_INDEX_FILE"] = str(Path(directory) / "index")
        run_git(source, "read-tree", "HEAD", environment=environment)
        run_git(source, "add", "-A", "--", ".", environment=environment)
        diff = run_git(
            source,
            "diff",
            "--cached",
            "--binary",
            "--no-ext-diff",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            "HEAD",
            "--",
            binary=True,
            environment=environment,
        )
    assert isinstance(diff, bytes)
    if not diff:
        raise LockError("patched source diff is empty")
    return hashlib.sha256(diff).hexdigest()


def replace_lock_value(path: Path, key: str, value: str) -> None:
    text = path.read_text(encoding="utf-8")
    pattern = re.compile(rf'^{re.escape(key)} = "[^"]*"$', re.MULTILINE)
    replaced, count = pattern.subn(f'{key} = "{value}"', text)
    if count != 1:
        raise LockError(f"cannot uniquely update {key}")
    temporary = path.with_name(f".{path.name}.new")
    temporary.write_text(replaced, encoding="utf-8")
    temporary.replace(path)


def command_get(args: argparse.Namespace) -> None:
    data = load_lock(args.lock)
    if args.key not in data:
        raise LockError(f"unknown input lock key: {args.key}")
    print(data[args.key])


def command_hash(args: argparse.Namespace) -> None:
    print(patched_diff_hash(args.source))


def command_patch_set_hash(args: argparse.Namespace) -> None:
    print(patch_set_hash(args.series, args.patch_root))


def command_verify(args: argparse.Namespace) -> None:
    data = load_lock(args.lock)
    upstream = run_git(args.source, "rev-parse", "HEAD")
    toolchains = run_git(args.toolchains, "rev-parse", "HEAD")
    actual_diff = patched_diff_hash(args.source)
    actual_patch_set = patch_set_hash(args.series, args.patch_root)
    if upstream != data["upstream_sha"]:
        raise LockError("upstream HEAD does not match inputs.lock")
    if toolchains != data["toolchains_sha"]:
        raise LockError("toolchains HEAD does not match inputs.lock")
    if actual_diff != data["patched_diff_sha256"]:
        raise LockError("patched source diff does not match inputs.lock")
    if args.rust_toolchain != data["rust_toolchain"]:
        raise LockError("Rust toolchain does not match inputs.lock")
    if args.rust_target != data["rust_target"]:
        raise LockError("Rust target does not match inputs.lock")
    if args.rust_target_cpu != data["rust_target_cpu"]:
        raise LockError("Rust target CPU does not match inputs.lock")
    print(f"upstream_sha={upstream}")
    print(f"toolchains_sha={toolchains}")
    print(f"patched_diff_sha256={actual_diff}")
    print(f"patch_set_sha256={actual_patch_set}")
    print(f"input_lock_sha256={hashlib.sha256(args.lock.read_bytes()).hexdigest()}")


def command_update(args: argparse.Namespace) -> None:
    if not SHA1.fullmatch(args.upstream_sha):
        raise LockError("invalid upstream SHA for update")
    if not SHA256.fullmatch(args.patched_diff_sha256):
        raise LockError("invalid patched diff SHA for update")
    load_lock(args.lock)
    replace_lock_value(args.lock, "upstream_sha", args.upstream_sha)
    replace_lock_value(args.lock, "patched_diff_sha256", args.patched_diff_sha256)
    load_lock(args.lock)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    subparsers = result.add_subparsers(dest="command", required=True)

    get = subparsers.add_parser("get")
    get.add_argument("key")
    get.add_argument("--lock", type=Path, required=True)
    get.set_defaults(handler=command_get)

    diff_hash = subparsers.add_parser("diff-hash")
    diff_hash.add_argument("--source", type=Path, required=True)
    diff_hash.set_defaults(handler=command_hash)

    patch_hash = subparsers.add_parser("patch-set-hash")
    patch_hash.add_argument("--series", type=Path, required=True)
    patch_hash.add_argument("--patch-root", type=Path, required=True)
    patch_hash.set_defaults(handler=command_patch_set_hash)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--lock", type=Path, required=True)
    verify.add_argument("--series", type=Path, required=True)
    verify.add_argument("--patch-root", type=Path, required=True)
    verify.add_argument("--source", type=Path, required=True)
    verify.add_argument("--toolchains", type=Path, required=True)
    verify.add_argument("--rust-toolchain", required=True)
    verify.add_argument("--rust-target", required=True)
    verify.add_argument("--rust-target-cpu", required=True)
    verify.set_defaults(handler=command_verify)

    update = subparsers.add_parser("update")
    update.add_argument("--lock", type=Path, required=True)
    update.add_argument("--upstream-sha", required=True)
    update.add_argument("--patched-diff-sha256", required=True)
    update.set_defaults(handler=command_update)
    return result


def main() -> int:
    try:
        args = parser().parse_args()
        args.handler(args)
    except (LockError, OSError) as error:
        print(f"input-lock: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
