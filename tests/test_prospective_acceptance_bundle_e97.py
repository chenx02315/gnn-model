"""Toy snapshots only: no actual producer, staging, jobs or remote operations."""
import gzip
import importlib.util
import io
import json
from pathlib import Path
import tarfile
from types import SimpleNamespace
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / 'scripts' / 'build_acceptance_bundle_e97.py'
spec = importlib.util.spec_from_file_location('e97_bundle_test', str(SOURCE))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def fixture():
    snapshot = {'src/__init__.py': b'', 'auth.json': b'approved',
                'e85.json': b'e85', 'e93.json': b'e93', 'src/a.py': b'x = 1\n'}
    entry = SimpleNamespace(FILES=frozenset(snapshot), EMPTY=('src/__init__.py',),
                            AUTH='auth.json', AUTH_SHA256=m.sha(b'approved'),
                            E85='e85.json', E93='e93.json')
    compiler = SimpleNamespace(E85_SHA256=m.sha(b'e85'), E93_SHA256=m.sha(b'e93'))
    return snapshot, entry, compiler


class BundleTests(unittest.TestCase):
    def test_determinism_exact_members_and_metadata(self):
        args = fixture()
        first = m.assemble(*args)
        second = m.assemble(*args)
        self.assertEqual(first, second)
        manifest = json.loads(first['manifest_bytes'])
        self.assertEqual(manifest['schema'], 'e97-code-manifest-v1')
        self.assertEqual(set(manifest['files']), set(args[0]))
        self.assertEqual(first['archive_bytes'][4:8], b'\x00' * 4)
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(first['archive_bytes']))) as tar:
            self.assertEqual(set(tar.getnames()), set(args[0]) | {'e97_code_manifest.json'})
            for member in tar:
                self.assertTrue(member.isfile())
                self.assertEqual((member.uid, member.gid, member.mtime, member.mode),
                                 (0, 0, 0, 0o600))
                raw = tar.extractfile(member).read()
                if member.name != 'e97_code_manifest.json':
                    self.assertEqual(raw, args[0][member.name])
        self.assertEqual(first['receipt']['archive_sha256'], m.sha(first['archive_bytes']))
        self.assertFalse(first['receipt']['execution_ready'])

    def test_missing_extra_and_empty_init(self):
        for mutation in ('missing', 'extra', 'init'):
            snapshot, entry, compiler = fixture()
            if mutation == 'missing':
                del snapshot['src/a.py']
            elif mutation == 'extra':
                snapshot['extra'] = b''
            else:
                snapshot['src/__init__.py'] = b'print(1)'
            with self.assertRaises(m.BundleError):
                m.assemble(snapshot, entry, compiler)

    def test_each_identity_pin(self):
        for name in ('auth.json', 'e85.json', 'e93.json'):
            snapshot, entry, compiler = fixture()
            snapshot[name] += b'changed'
            with self.assertRaisesRegex(m.BundleError, 'E97_IDENTITY_PIN'):
                m.assemble(snapshot, entry, compiler)

    def test_unsafe_names_even_if_in_allowset(self):
        for name in ('../escape', '/absolute', 'a//b', 'a/./b', 'a\\b', 'a:b', 'a/../b'):
            snapshot, entry, compiler = fixture()
            snapshot[name] = b''
            entry.FILES = frozenset(snapshot)
            with self.assertRaisesRegex(m.BundleError, 'E97_UNSAFE_MEMBER'):
                m.assemble(snapshot, entry, compiler)

    def test_every_output_bound(self):
        for cap, code in (('SOURCE_CAP', 'E97_SOURCE_CAP'),
                          ('TAR_CAP', 'E97_TAR_CAP'), ('GZIP_CAP', 'E97_GZIP_CAP')):
            with mock.patch.object(m, cap, 1):
                with self.assertRaisesRegex(m.BundleError, code):
                    m.assemble(*fixture())

    def test_build_synthesizes_inits_and_uses_fixed_allowset(self):
        snapshot, entry, compiler = fixture()
        with mock.patch.object(m, 'load_module', side_effect=[entry, compiler]), \
                mock.patch.object(m, 'read_source', side_effect=lambda name, cap: snapshot[name]) as read:
            result = m.build()
        self.assertEqual(set(c.args[0] for c in read.call_args_list), set(snapshot) - set(entry.EMPTY))
        self.assertEqual(result, m.assemble(snapshot, entry, compiler))

    def test_read_rejects_symlink_before_open(self):
        fake_root = mock.MagicMock()
        fake_root.is_symlink.return_value = False
        fake_root.is_dir.return_value = True
        child = fake_root.__truediv__.return_value
        child.lstat.return_value.st_mode = 0o120777
        with mock.patch.object(m, 'ROOT', fake_root):
            with self.assertRaisesRegex(m.BundleError, 'E97_SOURCE_SYMLINK'):
                m.read_source('auth.json', 100)
        child.open.assert_not_called()

    def test_windows_separate_ctime_views_must_each_be_stable(self):
        def row(ctime):
            return SimpleNamespace(st_dev=1, st_ino=2, st_mode=0o100600,
                                   st_nlink=1, st_size=4337, st_mtime_ns=50,
                                   st_ctime_ns=ctime)
        with mock.patch.object(m.os, 'name', 'nt'):
            self.assertTrue(m.stable_source(row(10), row(20), row(20), row(10)))
            self.assertFalse(m.stable_source(row(10), row(20), row(21), row(10)))
            self.assertFalse(m.stable_source(row(10), row(20), row(20), row(11)))
            changed = row(20)
            changed.st_ino = 3
            self.assertFalse(m.stable_source(row(10), row(20), changed, row(10)))
        with mock.patch.object(m.os, 'name', 'posix'):
            self.assertFalse(m.stable_source(row(10), row(20), row(20), row(10)))
            self.assertTrue(m.stable_source(row(10), row(10), row(10), row(10)))


if __name__ == '__main__':
    unittest.main()
