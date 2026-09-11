"""Host regressions for initramfs packaging and fail-closed guest verdicts."""
import importlib.util
from pathlib import Path
import stat
import unittest
import system
import preinstall

spec = importlib.util.spec_from_file_location('fetch', Path(__file__).with_name('fetch-emulator.py'))
fetch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch)

class SystemTests(unittest.TestCase):
    def test_cpio_roundtrip_alignment_and_devices(self):
        entries = [('abc', stat.S_IFREG|0o755, b'12345', 0, 0),
                   ('dev/null', stat.S_IFCHR|0o666, b'', 1, 3)]
        raw = system.newc(entries)
        offset, read = 0, []
        while offset < len(raw):
            self.assertEqual(offset % 4, 0)
            self.assertEqual(raw[offset:offset+6], b'070701')
            fields = [int(raw[i:i+8], 16) for i in range(offset+6, offset+110, 8)]
            offset += 110
            name = raw[offset:offset+fields[11]-1].decode()
            self.assertEqual(raw[offset+fields[11]-1], 0)
            offset = (offset+fields[11]+3) & ~3
            data = raw[offset:offset+fields[6]]
            offset = (offset+fields[6]+3) & ~3
            if name == 'TRAILER!!!': break
            read.append((name, fields[1], data, fields[9], fields[10]))
        self.assertEqual(read, entries)
        self.assertEqual(offset, len(raw))

    def test_cpio_unsafe_duplicate_paths(self):
        for name in ('/etc/passwd', '../oops', 'a/../oops', '', 'bad\0name', 'TRAILER!!!'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                system.newc([(name,stat.S_IFREG,b'',0,0)])
        entry = ('x',stat.S_IFREG,b'',0,0)
        with self.assertRaises(ValueError): system.newc([entry,entry])

    def good_log(self):
        return ''.join('LAB_PASS '+name+'\n' for name in system.REQUIRED_MARKERS)+(
            'LAB_PASS firmware-arm-self-test\n'*3)+'LAB_COMPLETE PASS\n'

    def test_guest_positive(self):
        self.assertTrue(system.guest_passed(0, self.good_log()))

    def test_guest_missing_check_rejected(self):
        for name in system.REQUIRED_MARKERS:
            self.assertFalse(system.guest_passed(0, self.good_log().replace('LAB_PASS '+name+'\n','')))

    def test_guest_panic_or_failure_not_masked_by_final_marker(self):
        for marker in ('LAB_FAIL','Kernel panic','BUG:','Oops:','panicked at'):
            self.assertFalse(system.guest_passed(0, self.good_log()+marker))
        for code in (1,124,-11): self.assertFalse(system.guest_passed(code, self.good_log()))
        self.assertFalse(system.guest_passed(0, 'LAB_COMPLETE PASS\n'))

    def test_package_locks(self):
        import json
        for path in Path(__file__).parent.glob('*.lock.json'):
            self.assertTrue(fetch.packages(json.loads(path.read_text())))

    def test_package_lock_rejects_unsafe(self):
        base = dict(package='a.deb',url='https://example.org/a.deb',bytes=10,sha256='0'*64)
        for key,value in [('package','../a.deb'),('url','http://example.org/a.deb'),
                          ('bytes',0),('sha256','123')]:
            with self.assertRaises(ValueError): fetch.packages({**base,key:value})
        with self.assertRaises(ValueError): fetch.packages({'packages':[base,base]})

    def test_combined_gate_needs_both_actual_verdicts(self):
        self.assertFalse(preinstall.evidence_passed('usermode', {'tests':[]}))
        self.assertFalse(preinstall.evidence_passed('usermode', {'tests':[{'status':'crash'}]}))
        self.assertFalse(preinstall.evidence_passed('system', {'status':'fail'}))
        self.assertTrue(preinstall.evidence_passed('usermode', {'tests':[{'status':'pass'}]}))
        self.assertTrue(preinstall.evidence_passed('system', {'status':'pass'}))

if __name__ == '__main__': unittest.main()
