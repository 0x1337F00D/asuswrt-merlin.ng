#!/usr/bin/env python3
"""Compiled ELF negative controls for the installed zlib import verifier."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("zlib_consumer_abi", HERE / "zlib-consumer-abi.py")
abi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(abi)


class ConsumerABI(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zlib-consumer-abi-",
                                                dir=os.environ.get("TMPDIR", "/tmp"))
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.root = self.work / "root"
        (self.root / "usr/lib/plugins").mkdir(parents=True)
        self.inventory = HERE / "zlib-vendor-exports.txt"
        self.cc = os.environ.get("CC", "cc")
        self.readelf = os.environ.get("READELF", "readelf")

    def library(self, tag, exports, version_map):
        directory = self.work / tag
        directory.mkdir()
        source = directory / "lib.c"
        source.write_text("\n".join(f"int {name}(void) {{ return 1; }}" for name in exports))
        script = directory / "lib.map"
        script.write_text(version_map)
        output = directory / "libz.so.1"
        subprocess.run([self.cc, "-shared", "-fPIC", str(source), "-o", str(output),
                        "-Wl,-soname,libz.so.1", f"-Wl,--version-script={script}"], check=True)
        (directory / "libz.so").symlink_to("libz.so.1")
        return output

    def consumer(self, library, imports):
        source = self.work / "consumer.c"
        source.write_text("\n".join(f"extern int {name}(void);" for name in imports)
                          + "\nint probe(void) { return "
                          + "+".join(f"{name}()" for name in imports) + "; }\n")
        output = self.root / "usr/lib/plugins/consumer.so"
        subprocess.run([self.cc, "-shared", "-fPIC", str(source), "-o", str(output),
                        f"-L{library.parent}", "-Wl,--no-as-needed", "-lz"], check=True)

    def audit(self, library):
        return abi.audit(self.root, library, self.readelf, self.inventory)

    def test_complete_imports_pass(self):
        lib = self.library("good", ["crc32", "compressBound", "inflateValidate"],
                           "ZLIB_1.2.0 { global: compressBound; }; "
                           "ZLIB_1.2.9 { global: inflateValidate; } ZLIB_1.2.0;")
        self.consumer(lib, ["crc32", "compressBound", "inflateValidate"])
        self.assertEqual(self.audit(lib), (1, 3))

    def test_missing_unversioned_symbol_rejected(self):
        old = self.library("old", ["crc32", "compressBound"],
                           "ZLIB_1.2.0 { global: compressBound; };")
        self.consumer(old, ["crc32"])
        new = self.library("new", ["compressBound"],
                           "ZLIB_1.2.0 { global: compressBound; };")
        with self.assertRaisesRegex(ValueError, "needs crc32"):
            self.audit(new)

    def test_present_node_missing_member_rejected(self):
        old = self.library("old", ["inflateValidate", "adler32_z"],
                           "ZLIB_1.2.9 { global: inflateValidate; adler32_z; };")
        self.consumer(old, ["inflateValidate"])
        new = self.library("new", ["adler32_z"],
                           "ZLIB_1.2.9 { global: adler32_z; };")
        with self.assertRaisesRegex(ValueError, "inflateValidate@ZLIB_1.2.9"):
            self.audit(new)

    def test_wrong_version_rejected_even_when_both_nodes_exist(self):
        old = self.library("old", ["compressBound", "inflateValidate"],
                           "ZLIB_1.2.0 { global: compressBound; }; "
                           "ZLIB_1.2.9 { global: inflateValidate; } ZLIB_1.2.0;")
        self.consumer(old, ["compressBound"])
        new = self.library("new", ["compressBound", "inflateValidate"],
                           "ZLIB_1.2.0 { global: inflateValidate; }; "
                           "ZLIB_1.2.9 { global: compressBound; } ZLIB_1.2.0;")
        with self.assertRaisesRegex(ValueError, "compressBound@ZLIB_1.2.0"):
            self.audit(new)

    def test_printf_omission_rejected_when_used(self):
        old = self.library("old", ["gzprintf", "gzvprintf"],
                           "ZLIB_1.2.7.1 { global: gzvprintf; };")
        self.consumer(old, ["gzprintf", "gzvprintf"])
        new = self.library("new", ["inflateGetDictionary"],
                           "ZLIB_1.2.7.1 { global: inflateGetDictionary; };")
        with self.assertRaises(ValueError) as result:
            self.audit(new)
        self.assertIn("needs gzprintf", str(result.exception))
        self.assertIn("needs gzvprintf@ZLIB_1.2.7.1", str(result.exception))

    def test_new_versioned_name_uses_provider_not_inventory(self):
        old = self.library("old", ["future_zlib_api"],
                           "FUTURE_1 { global: future_zlib_api; };")
        self.consumer(old, ["future_zlib_api"])
        new = self.library("new", ["placeholder"], "FUTURE_1 { global: placeholder; };")
        with self.assertRaisesRegex(ValueError, "future_zlib_api@FUTURE_1"):
            self.audit(new)

    def test_invalid_elf_does_not_silently_skip(self):
        lib = self.library("good", ["compressBound"],
                           "ZLIB_1.2.0 { global: compressBound; };")
        (self.root / "broken").write_bytes(b"\x7fELFbroken")
        with self.assertRaises(subprocess.CalledProcessError):
            self.audit(lib)

    def test_symlinks_do_not_escape_root(self):
        lib = self.library("good", ["compressBound"],
                           "ZLIB_1.2.0 { global: compressBound; };")
        (self.root / "outside").symlink_to("/this-path-must-not-be-read")
        self.assertEqual(self.audit(lib), (0, 0))

    def test_version_index_disambiguates_equal_names(self):
        output = """Version needs section '.gnu.version_r' contains 2 entries:
  0x000000: Version: 1  File: libz.so.1  Cnt: 1
  0x000010:   Name: SHARED_1  Flags: none  Version: 2
  0x000020: Version: 1  File: libother.so  Cnt: 1
  0x000030:   Name: SHARED_1  Flags: none  Version: 3
"""
        self.assertEqual(abi.version_needs(output), {2: "libz.so.1", 3: "libother.so"})


if __name__ == "__main__":
    unittest.main()
