#!/usr/bin/env python3
"""Render fixed slot roles and exact candidate identity; never infer at boot."""
import argparse
import hashlib
from pathlib import Path
import re


def render(template, *, candidate, web_hash, links_hash, binaries):
    if candidate not in (1, 2):
        raise ValueError("candidate slot must be explicit")
    for digest in [web_hash, links_hash, *binaries.values()]:
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid artifact digest")
    if set(binaries) != {"HTTPD", "RC", "SHARED", "WGET"}:
        raise ValueError("all four candidate binaries must be bound")
    fallback = 3 - candidate
    values = {
        "CANDIDATE_STATE": f"BOOT_SET_PART{candidate}_IMAGE",
        "FALLBACK_STATE": f"BOOT_SET_PART{fallback}_IMAGE",
        "FALLBACK_ONCE_STATE": f"BOOT_SET_PART{fallback}_IMAGE_ONCE",
        "CANDIDATE_PARTITION": f"PART{candidate}",
        "CANDIDATE_BOOT_LABEL": "First" if candidate == 1 else "Second",
        "FALLBACK_PARTITION": f"PART{fallback}",
        "WEB_PAYLOAD_MANIFEST_SHA256": web_hash,
        "WEB_SYMLINK_MANIFEST_SHA256": links_hash,
        **{f"EXPECTED_{name}_SHA256": digest for name, digest in binaries.items()},
    }
    for name, value in values.items():
        template, count = re.subn(rf"^{name}=[^\n]*$", f"{name}={value}", template, flags=re.M)
        if count != 1:
            raise ValueError("guard template assignment missing/ambiguous")
    return template


def regular_hash(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("artifact must be a regular file")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-slot", type=int, choices=(1, 2), required=True)
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.rootfs
    text = render(Path(__file__).with_name("router-persistent-guard.sh").read_text(),
                  candidate=args.candidate_slot,
                  web_hash=regular_hash(root / "usr/share/codex/web-payload.sha256"),
                  links_hash=regular_hash(root / "usr/share/codex/web-symlinks.manifest"),
                  binaries={name: regular_hash(root / path) for name, path in {
                      "HTTPD": "usr/sbin/httpd", "RC": "sbin/rc",
                      "SHARED": "usr/lib/libshared.so", "WGET": "usr/sbin/wget"}.items()})
    # Never overwrite an already reviewed/deployed guard artifact.
    with args.output.open("x") as output:
        output.write(text)
    args.output.chmod(0o700)
