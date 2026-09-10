#!/usr/bin/env python3
"""Check all zlib symbol/version imports of installed direct libz consumers.

Unversioned ELF imports do not record their provider. An independent vendor
export inventory attributes those names to zlib; versioned imports additionally
use the ELF version-needs provider, including names absent from the inventory.
This is a static direct-consumer gate, not a simulation of LD_PRELOAD or dlsym.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys


def readelf(tool, path, *args):
    return subprocess.check_output(
        [tool, *args, str(path)], text=True, stderr=subprocess.PIPE,
        env={**os.environ, "LC_ALL": "C"},
    )


def symbols(output, defined):
    for line in output.splitlines():
        fields = line.split()
        if (len(fields) >= 8 and fields[0].endswith(":")
                and fields[3] in {"FUNC", "OBJECT", "NOTYPE", "IFUNC"}
                and fields[4] in {"GLOBAL", "WEAK"}
                and (fields[6] != "UND") == defined
                and (not defined or fields[5] in {"DEFAULT", "PROTECTED"})):
            index = None
            if len(fields) > 8 and re.fullmatch(r"\(\d+\)", fields[8]):
                index = int(fields[8][1:-1])
            yield fields[7], index


def version_needs(output):
    """Map version indices to providers, reading only .gnu.version_r.

    Different providers may reuse a version name; the symbol's index, not
    the textual version name, disambiguates which library was recorded.
    """
    result = {}
    active = False
    provider = None
    for line in output.splitlines():
        if line.startswith("Version needs section"):
            active = True
        elif line.startswith("Version "):
            active = False
        if not active:
            continue
        match = re.search(r"\bFile: (\S+)", line)
        if match:
            provider = match[1]
        match = re.search(r"\bName: (\S+)\s+Flags:.*\bVersion: (\d+)", line)
        if match and provider:
            result[int(match[2])] = provider
    return result


def audit(root, library, tool, inventory):
    known = {line.split("@", 1)[0] for raw in inventory.read_text().splitlines()
             if (line := raw.strip()) and not line.startswith("#")}
    if not known:
        raise ValueError("empty vendor zlib export inventory")
    exported = {name for name, _ in symbols(
        readelf(tool, library, "--dyn-syms", "-W"), True)}
    exact = {name.replace("@@", "@") for name in exported}
    defaults = {name.split("@", 1)[0] for name in exported
                if "@" not in name or "@@" in name}
    consumers = imports = 0
    errors = []
    # Inspect all regular ELF files, including unusual plugin subdirectories;
    # do not follow rootfs absolute symlinks onto the host filesystem.
    for parent, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        for name in sorted(files):
            path = Path(parent) / name
            if path.is_symlink() or not path.is_file():
                continue
            with path.open("rb") as stream:
                if stream.read(4) != b"\x7fELF":
                    continue
            dynamic = readelf(tool, path, "-d", "-W")
            if "Shared library: [libz.so.1]" not in dynamic:
                continue
            consumers += 1
            needs = version_needs(readelf(tool, path, "-V", "-W"))
            required = symbols(readelf(tool, path, "--dyn-syms", "-W"), False)
            for symbol, index in required:
                parts = symbol.split("@", 1)
                base = parts[0]
                version = parts[1] if len(parts) == 2 else None
                if version:
                    provider = needs.get(index)
                    is_zlib = provider == "libz.so.1" or (
                        provider is None and (version.startswith("ZLIB_") or base in known))
                else:
                    is_zlib = base in known
                if not is_zlib:
                    continue
                imports += 1
                if (symbol not in exact if version else base not in defaults):
                    errors.append(f"{path.relative_to(root)} needs {symbol}, "
                                  "absent from libz.so.1")
    if errors:
        raise ValueError("\n".join(errors))
    return consumers, imports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("readelf")
    parser.add_argument("--library", type=Path,
                        help="replacement override for isolated review tests")
    args = parser.parse_args()
    root = args.rootfs.resolve(strict=True)
    library = args.library or root / "usr/lib/libz.so.1"
    try:
        consumers, imports = audit(
            root, library, args.readelf,
            Path(__file__).with_name("zlib-vendor-exports.txt"),
        )
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"zlib consumer ABI: {error}", file=sys.stderr)
        return 1
    print(f"libz.so.1 satisfies {imports} symbol/version imports "
          f"from {consumers} installed direct consumers")
    return 0


if __name__ == "__main__":
    sys.exit(main())
