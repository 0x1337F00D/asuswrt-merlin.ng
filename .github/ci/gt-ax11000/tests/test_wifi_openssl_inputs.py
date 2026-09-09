#!/usr/bin/env python3
"""Exercise the vendor's actual flag preamble, without a firmware build."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class WifiOpenSSLTests(unittest.TestCase):
    def test_header_origin_and_missing_path_negative_control(self):
        source = os.environ.get("WIFI_OPENSSL_SOURCE")
        if not source:
            self.skipTest("set WIFI_OPENSSL_SOURCE to the patched source tree")
        source = Path(source)
        base = source / "release/src-rt-5.02axhnd/bcmdrivers/broadcom/net/wl/impl51/main/components/opensource/router_tools"
        include = "CFLAGS += -I$(TOP)/openssl/include\n"
        router_make = (source / "release/src/router/Makefile").read_text()
        self.assertIn("hostapd: libnl openssl ", router_make)
        self.assertIn("wpa_supplicant-2.7: libnl openssl ", router_make)
        for component in ("hostapd", "wpa_supplicant"):
            preamble = (base / component / component / "Makefile").read_text().split("-include .config", 1)[0]
            self.assertEqual(preamble.count(include), 1, component)
            self.assertIn("-L$(TOP)/openssl", preamble)
            with self.subTest(component=component), tempfile.TemporaryDirectory(prefix="wifi-ssl-input-") as directory:
                root = Path(directory)
                header = root / "openssl/include/openssl/x509.h"
                header.parent.mkdir(parents=True)
                header.write_text("#define CODEX_LOCKED_OPENSSL_FIXTURE 7391\n")
                (root / "probe.c").write_text(
                    "#include <openssl/x509.h>\n"
                    "#if CODEX_LOCKED_OPENSSL_FIXTURE != 7391\n"
                    '#error "foreign or missing OpenSSL headers"\n'
                    "#endif\nint fixture = CODEX_LOCKED_OPENSSL_FIXTURE;\n")
                for original in (False, True):
                    flags = preamble.replace(include, "") if original else preamble
                    (root / "probe.mk").write_text(flags + "\n.PHONY: probe\nprobe:\n"
                        "\t$(CC) $(CFLAGS) -E probe.c -o probe.i\n")
                    result = subprocess.run([os.environ.get("MAKE", "make"), "-f", "probe.mk",
                        "CC=cc", f"TOP={root}", "probe"], cwd=root, text=True,
                        capture_output=True, timeout=10)
                    if original:
                        self.assertNotEqual(result.returncode, 0, component)
                    else:
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertIn("int fixture = 7391;", (root / "probe.i").read_text())


if __name__ == "__main__":
    if len(sys.argv) == 2:
        os.environ["WIFI_OPENSSL_SOURCE"] = sys.argv.pop()
    unittest.main()
