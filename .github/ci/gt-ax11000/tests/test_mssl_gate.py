#!/usr/bin/env python3
"""Security checks must not silently disappear under Python -O."""
from pathlib import Path
import subprocess
import sys
import unittest


class Gate(unittest.TestCase):
    def test_optimized_python_is_refused_before_examining_an_elf(self):
        gate = Path(__file__).with_name('verify-mssl-elf.py')
        result = subprocess.run([sys.executable, '-O', str(gate), '/bin/true'],
                                capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('without Python optimization', result.stderr)


if __name__ == '__main__':
    unittest.main()
