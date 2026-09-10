#!/usr/bin/env python3
"""Prove the LLTD setup test detects immediate wildcard protocol activation."""
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

RUST = pathlib.Path(__file__).resolve().parents[1] / "rust"


class SocketMutation(unittest.TestCase):
    def test_early_activation_is_detected(self):
        with tempfile.TemporaryDirectory(prefix="lltd-mutation-", dir="/tmp") as tmp:
            root = pathlib.Path(tmp)
            crate = root / "lltd"
            shutil.copytree(RUST / "lltd", crate)
            config = crate / ".cargo"
            config.mkdir()
            (config / "config.toml").write_text(
                '[source.crates-io]\nreplace-with="vendored"\n'
                f'[source.vendored]\ndirectory="{RUST / "vendor"}"\n')
            env = dict(os.environ, CARGO_TARGET_DIR=str(root / "target"))
            command = ["cargo", "+1.85.1", "test", "--offline", "--bin", "lld2d",
                       "the_packet_socket_is_inactive_until_interface_and_protocol_bind_together"]
            good = subprocess.run(command, cwd=crate, env=env, capture_output=True, text=True)
            self.assertEqual(good.returncode, 0, good.stdout + good.stderr)
            source = crate / "src/sys.rs"
            original = source.read_text()
            self.assertEqual(original.count("let socket = open(0)?;"), 1)
            source.write_text(original.replace("let socket = open(0)?;", "let socket = open(0x88d9)?;"))
            bad = subprocess.run(command, cwd=crate, env=env, capture_output=True, text=True)
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("test result: FAILED", bad.stdout)


if __name__ == "__main__":
    unittest.main()
