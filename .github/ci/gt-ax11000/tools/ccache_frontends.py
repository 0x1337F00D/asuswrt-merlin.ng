#!/usr/bin/env python3
"""Bind each cache frontend to its exact compiler, never a basename search."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess


def wrapper(compiler, ccache, runtime):
    # Buildroot dispatches from argv[0] to NAME.br_real: do not resolve the
    # compiler symlink to the generic toolchain-wrapper executable here.
    extra = compiler.with_name(compiler.name + ".br_real")
    text = "#!/bin/sh\nset -eu\n"
    if runtime:
        text += "export LD_LIBRARY_PATH=" + shlex.quote(str(runtime)) + '${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}\n'
    if extra.is_file():
        text += "export CCACHE_EXTRAFILES=" + shlex.quote(str(extra)) + '${CCACHE_EXTRAFILES:+:$CCACHE_EXTRAFILES}\n'
    text += 'exec ' + shlex.quote(str(ccache)) + ' ' + shlex.quote(str(compiler)) + ' "$@"\n'
    return text


def prepare(source, view, ccache, runtime=None):
    source, view, ccache = source.resolve(), view.absolute(), ccache.absolute()
    if view.resolve() == source or source in view.resolve().parents or view.resolve() in source.parents:
        raise ValueError("source and view must be separate trees")
    if view.is_symlink():
        raise ValueError("view must not be a symlink")
    if runtime is not None:
        runtime = runtime.resolve(strict=True)
        if not runtime.is_dir():
            raise ValueError("ccache runtime must be a directory")
    frontends = sorted(path for path in source.rglob("*")
                       if path.name.endswith(("-gcc", "-g++", "-cc", "-c++")) and path.is_file())
    if not frontends:
        raise ValueError("no compiler frontends")
    generated = {str(path.relative_to(source)): wrapper(path, ccache, runtime) for path in frontends}
    identity = hashlib.sha256(json.dumps(generated, sort_keys=True).encode()).hexdigest()
    marker = view / ".ccache-exact-frontends-v2"
    if view.exists():
        if not marker.is_file() or marker.is_symlink() or marker.read_text().strip() != identity:
            raise ValueError("stale/unbound ccache view; choose a new ASUSWRT_TOOLCHAIN_VIEW")
        for relative, text in generated.items():
            target = view / relative
            if target.is_symlink() or not target.is_file() or target.read_text() != text:
                raise ValueError("changed/missing exact compiler frontend")
    else:
        view.mkdir(parents=True)
        subprocess.run(["cp", "-al", str(source) + "/.", str(view) + "/"], check=True)
        for relative, text in generated.items():
            target = view / relative
            # cp -al cloned a hardlink/symlink; unlink before writing so the
            # immutable source compiler can never be overwritten.
            target.unlink()
            with target.open("x") as stream:
                stream.write(text)
            target.chmod(0o755)
        with marker.open("x") as stream:
            stream.write(identity + "\n")
    # Reused views are checked as rigorously as new ones. This catches the
    # former 5.5 -> 5.3 basename collision before the first object is built.
    for compiler in frontends:
        target = view / compiler.relative_to(source)
        direct = subprocess.check_output([str(compiler), "-dumpversion"], timeout=15)
        cached = subprocess.check_output([str(target), "-dumpversion"], timeout=15)
        if direct != cached:
            raise ValueError("cached compiler version differs from requested compiler")
    print(f"CCACHE_EXACT_FRONTENDS=PASS count={len(frontends)} identity={identity}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "view", "ccache"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--runtime", type=Path)
    args = parser.parse_args()
    prepare(args.source, args.view, args.ccache, args.runtime)
