#!/usr/bin/env python3
"""Decrypt and inspect a backup in memory, without restoring router settings.

The HDR2 decoder follows nvram_save_new/nvram_restore_new at the pinned
upstream. Only counts and PASS states are printed, never configuration values.
This proves archive/decryption/CFG integrity, not a factory-reset hardware test.
"""
import argparse
import hashlib
import io
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile


def decode_cfg(data):
    if len(data) < 8 or data[:4] != b"HDR2":
        raise ValueError("unsupported settings header")
    length = int.from_bytes(data[4:7], "little")
    if length != len(data) - 8 or length > 1024 * 1024 or data[7] >= 30:
        raise ValueError("settings length/randomizer invalid")
    decoded = bytes(0 if byte >= 0xFD else (0xFF + data[7] - byte) & 0xFF for byte in data[8:])
    entries = {}
    for entry in decoded.split(b"\0"):
        if not entry:
            continue
        key, separator, value = entry.partition(b"=")
        if not separator or not key:
            raise ValueError("invalid settings key")
        # nvram_getall() can append JFFS-backed list values after their NVRAM
        # placeholders. The vendor restore loop applies them in order: last
        # occurrence wins. Rejecting duplicates would reject its own exports.
        entries[key] = value
    return entries


def members(data, prefix=None):
    archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    names = set()
    for entry in archive.getmembers():
        path = PurePosixPath(entry.name)
        if not path.parts or path.is_absolute() or ".." in path.parts or entry.name in names:
            raise ValueError("unsafe/duplicate archive member")
        if prefix and path.parts[0] != prefix:
            raise ValueError("archive member outside expected root")
        names.add(entry.name)
    return archive, names


def verify(encrypted, key, expected_cipher, expected_plain):
    if hashlib.sha256(encrypted).hexdigest() != expected_cipher:
        raise ValueError("encrypted backup digest mismatch")
    plain = subprocess.run(["openssl", "cms", "-decrypt", "-inform", "DER", "-binary",
                            "-inkey", str(key)], input=encrypted, capture_output=True, check=True).stdout
    if hashlib.sha256(plain).hexdigest() != expected_plain:
        raise ValueError("decrypted backup digest mismatch")
    archive, _ = members(plain)
    def read(name):
        member = archive.getmember(name)
        if not member.isfile() or member.size > 32 * 1024 * 1024:
            raise ValueError("unexpected backup member")
        return archive.extractfile(member).read()
    for line in read("members.sha256").decode("ascii").splitlines():
        match = re.fullmatch(r"SHA2?-256\(([^/)]+)\)= ([0-9a-f]{64})", line)
        if not match or hashlib.sha256(read(match[1])).hexdigest() != match[2]:
            raise ValueError("backup member digest mismatch")
    config = decode_cfg(read("Settings_GT-AX11000_1029.CFG"))
    raw = dict(line.split(b"=", 1) for line in read("nvram-raw.txt").splitlines() if b"=" in line)
    required = [b"productid", b"lan_ipaddr", b"lan_netmask", b"dhcp_enable_x",
                b"wan_proto", b"location_code", b"smart_connect_x",
                b"custom_clientlist", b"dhcp_staticlist"]
    required += [f"wl{i}_{name}".encode() for i in range(3) for name in ("ssid", "wpa_psk", "auth_mode_x")]
    for name in required:
        if name not in config or config[name] != raw.get(name):
            raise ValueError("essential saved setting is absent or differs from live snapshot")
    if config[b"productid"] != b"GT-AX11000" or len(config) < 500:
        raise ValueError("wrong model or incomplete settings export")
    jffs, jffs_names = members(read("jffs.tar.gz"), "jffs")
    data, data_names = members(read("data.tar.gz"), "data")
    for name in ("jffs/scripts/init-start", "jffs/scripts/services-start",
                 "jffs/scripts/firmware-persistent-guard.sh", "jffs/addons/link-health/control.sh"):
        if name not in jffs_names:
            raise ValueError("required persistent hook/add-on missing")
    print(f"BACKUP=PASS settings={len(config)} essential_compared={len(required)} "
          f"jffs_members={len(jffs_names)} data_members={len(data_names)} "
          "decryption=PASS hashes=PASS factory_reset_restore=NOT_TESTED")
    jffs.close(); data.close(); archive.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--encrypted", required=True, type=Path)
    parser.add_argument("--key", required=True, type=Path)
    parser.add_argument("--cipher-sha256", required=True)
    parser.add_argument("--plain-sha256", required=True)
    args = parser.parse_args()
    verify(args.encrypted.read_bytes(), args.key, args.cipher_sha256, args.plain_sha256)
