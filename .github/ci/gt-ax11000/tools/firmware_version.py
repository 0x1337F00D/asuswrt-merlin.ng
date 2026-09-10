#!/usr/bin/env python3
"""Generate a vendor-supported version override, never edit vendor sources."""
import argparse
import json
from pathlib import Path
import re


def generate(source, iteration):
    if not re.fullmatch(r"[1-9][0-9]{0,5}\n?", iteration):
        raise ValueError("iteration must be an integer from 1 to 999999")
    version = {}
    for name in ("KERNEL_VER", "FS_VER", "SERIALNO", "EXTENDNO"):
        values = re.findall(rf"^{name}=([^\r\n]*)$", source, re.M)
        if len(values) != 1:
            raise ValueError(f"expected one {name} assignment")
        version[name] = values[0]
    for name in ("KERNEL_VER", "FS_VER", "SERIALNO"):
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", version[name]):
            raise ValueError(f"unsupported vendor {name}")
    suffix = "alpha" + iteration.strip()
    override = re.sub(r"^EXTENDNO=[^\r\n]*$", f"EXTENDNO={suffix}", source, flags=re.M)
    metadata = {"firmver": version["KERNEL_VER"] + "." + version["FS_VER"],
                "buildno": version["SERIALNO"], "extendno": suffix}
    return override, metadata


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--iteration", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    override, metadata = generate(args.source.read_text(), args.iteration.read_text())
    args.output.mkdir(parents=True, exist_ok=True)
    for name, content in (("version.conf", override),
                          ("firmware-version.json", json.dumps(metadata, sort_keys=True) + "\n")):
        path = args.output / name
        if not path.exists() or path.read_text() != content:
            path.write_text(content)
    print(metadata["extendno"])
