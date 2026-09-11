import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('lab', Path(__file__).with_name('run.py'))
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)

class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='qemu-runner-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.manifest = self.root/'manifest'
        self.names = ['usr/sbin/infosvr', 'usr/sbin/wsdd2', 'usr/sbin/lld2d', 'usr/lib/libmssl.so']
        for name in self.names:
            path = self.root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'fixture')
        self.lines = [lab.digest(self.root/name)+'  '+name for name in self.names]
        self.manifest.write_text('\n'.join(self.lines)+'\n')

    def test_manifest_pass(self):
        self.assertEqual(len(lab.verify_manifest(self.root, self.manifest)), 4)

    def test_tampered_payload(self):
        (self.root/self.names[0]).write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'mismatch'):
            lab.verify_manifest(self.root, self.manifest)

    def test_missing_consumer(self):
        self.manifest.write_text('\n'.join(self.lines[:-1]))
        with self.assertRaisesRegex(ValueError, 'missing required'):
            lab.verify_manifest(self.root, self.manifest)

    def test_duplicate(self):
        self.manifest.write_text('\n'.join(self.lines+[self.lines[0]]))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            lab.verify_manifest(self.root, self.manifest)

    def test_traversal_and_absolute(self):
        for name in ('../outside', '/etc/passwd'):
            with self.subTest(name=name):
                self.manifest.write_text('0'*64+'  '+name+'\n')
                with self.assertRaisesRegex(ValueError, 'unsafe'):
                    lab.verify_manifest(self.root, self.manifest)

    def test_symlink_escape(self):
        path = self.root/self.names[0]
        path.unlink()
        path.symlink_to('/etc/passwd')
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            lab.verify_manifest(self.root, self.manifest)

    def test_failure_not_pass(self):
        result = lab.bounded([sys.executable, '-c', 'raise SystemExit(7)'], self.root/'log', 2)
        self.assertEqual(result['status'], 'fail')
        self.assertEqual(result['exit_code'], 7)

    def test_optimized_python_rejected(self):
        result = lab.bounded([sys.executable, '-O', str(lab.HERE/'run.py'), '--help'], self.root/'log', 2)
        self.assertEqual(result['status'], 'fail')
        self.assertIn('optimization', (self.root/'log').read_text())

    def test_timeout_not_pass(self):
        result = lab.bounded([sys.executable, '-c', 'import time; time.sleep(10)'], self.root/'log', .1)
        self.assertEqual(result['status'], 'timeout')
        self.assertLess(result['seconds'], 2)

    def test_abort_is_classified_as_crash(self):
        result = lab.bounded([sys.executable, '-c', 'import os; os.abort()'], self.root/'log', 2)
        self.assertEqual(result['status'], 'crash')

    def test_swallowed_child_crash_is_not_green(self):
        result = lab.bounded([sys.executable, '-c', 'print("qemu: uncaught target signal 11")'], self.root/'log', 2)
        self.assertEqual(result['status'], 'crash')

    def test_no_network_namespace_is_rejected(self):
        for script in ('infosvr-ingress-netns.py', 'wsdd2-slow-client-netns.py', 'discovery-isolation-netns.py'):
            fixture = lab.HERE.parent/script
            self.assertTrue(fixture.is_file(), 'missing namespace fixture: '+script)
            env = dict(os.environ, PARENT_NETNS=os.readlink('/proc/self/ns/net'),
                       PARENT_MNTNS=os.readlink('/proc/self/ns/mnt'))
            result = lab.bounded([sys.executable, str(fixture)], self.root/'log', 2, env)
            self.assertEqual(result['status'], 'fail', script)
            self.assertIn('fresh network', (self.root/'log').read_text(), script)

if __name__ == '__main__':
    unittest.main()
