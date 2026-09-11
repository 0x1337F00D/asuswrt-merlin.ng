#!/usr/bin/env python3
"""Execute the real overlay copy function; nested target dirs are source."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class OverlayCopy(unittest.TestCase):
    def test_state_hash_covers_nested_target_sources_not_workspace_output(self):
        script = Path(__file__).resolve().parents[1] / 'build.sh'
        function = 'compute_rust_state_id() {' + script.read_text().split(
            'compute_rust_state_id() {', 1)[1].split('\n}', 1)[0] + '\n}'
        with tempfile.TemporaryDirectory(prefix='rust-state-', dir='/tmp') as directory:
            root = Path(directory)
            (root / 'vendor/cc/src/target').mkdir(parents=True)
            (root / 'target').mkdir()
            source = root / 'vendor/cc/src/target/llvm.rs'
            source.write_text('version1')
            environment = dict(os.environ, RUST_OVERLAY=str(root))
            def state():
                return subprocess.check_output(
                    ['bash', '-eu', '-c', function + '\ncompute_rust_state_id'],
                    env=environment, text=True, timeout=10)
            before = state()
            source.write_text('version2')
            changed = state()
            self.assertNotEqual(before, changed)
            (root / 'target/output').write_text('compiled output')
            self.assertEqual(changed, state())

    def test_vendor_target_source_is_kept_but_build_output_is_not(self):
        script = Path(__file__).resolve().parents[1] / 'build.sh'
        function = 'install_rust_components() {' + script.read_text().split(
            'install_rust_components() {', 1)[1].split('\n}', 1)[0] + '\n}'
        with tempfile.TemporaryDirectory(prefix='rust-copy-', dir='/tmp') as directory:
            root = Path(directory)
            source = root / 'overlay'
            (source / 'vendor/cc/src/target').mkdir(parents=True)
            (source / 'target').mkdir()
            (source / 'Cargo.lock').write_text('fixture')
            (source / 'vendor/cc/src/target/llvm.rs').write_text('source')
            (source / 'target/build-output').write_text('must not copy')
            environment = dict(os.environ, ROOT=str(root / 'source'),
                               RUST_OVERLAY=str(source), ASUSWRT_RUST_STATE_ID='')
            subprocess.run(['bash', '-eu', '-c', function + '\ninstall_rust_components'],
                           check=True, env=environment, timeout=10)
            copied = root / 'source/release/src/router/rust-components'
            self.assertEqual((copied / 'vendor/cc/src/target/llvm.rs').read_text(), 'source')
            self.assertFalse((copied / 'target').exists())


if __name__ == '__main__':
    unittest.main()
