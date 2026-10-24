"""Bounded archive fixtures and mocked deployment only; never write actual ROOT."""
import ast
import base64
import gzip
import importlib.util
import io
import json
import stat
import types
from pathlib import Path
import sys
import tarfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / 'scripts/deploy_acceptance_bundle_e97.py'
SPEC = importlib.util.spec_from_file_location('e97_deploy_test', str(PATH))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def fixture(extra=None):
    contents = {name: b'' for name in m.FILES}
    contents[m.AUTH] = (ROOT / m.AUTH).read_bytes()
    hashes = {name: m.sha(raw) for name, raw in contents.items()}
    manifest = json.dumps(dict(schema='e97-code-manifest-v1', files=hashes)).encode('ascii')
    contents[m.MANIFEST] = manifest
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, value in sorted(contents.items()):
            member = tarfile.TarInfo(name); member.size = len(value)
            archive.addfile(member, io.BytesIO(value))
        if extra is not None:
            archive.addfile(extra, io.BytesIO(b'x' * extra.size))
    tar = buffer.getvalue()
    compressed = gzip.compress(tar)
    return dict(archive_b64=base64.b64encode(compressed).decode('ascii'),
        archive_sha256=m.sha(compressed), manifest_sha256=m.sha(manifest),
        manifest_files=hashes, tar_bytes=len(tar))


class DeployTests(unittest.TestCase):
    def test_unpack_valid(self):
        config = fixture()
        contents = m._unpack(config)
        self.assertEqual(set(contents), m.FILES | {m.MANIFEST})
        self.assertEqual(m.sha(contents[m.AUTH]), m.AUTH_SHA256)

    def test_wrong_archive_and_manifest_pins(self):
        for key in ('archive_sha256', 'manifest_sha256'):
            config = fixture(); config[key] = '0' * 64
            with self.assertRaises(m.DeployError):
                m._unpack(config)

    def test_invalid_base64_and_strict_keys(self):
        for value in ('%%%=', 'a' * (4 * ((m.ARCHIVE_CAP + 2) // 3) + 1), True):
            config = fixture(); config['archive_b64'] = value
            with self.assertRaises(m.DeployError):
                m._unpack(config)
        config = fixture(); config['extra'] = 1
        with self.assertRaises(m.DeployError):
            m._unpack(config)

    def test_tar_exact_bound_and_gzip_trailing(self):
        for delta in (-1, 1):
            config = fixture(); config['tar_bytes'] += delta
            with self.assertRaises(m.DeployError):
                m._unpack(config)
        config = fixture()
        raw = base64.b64decode(config['archive_b64']) + gzip.compress(b'extra')
        config.update(archive_b64=base64.b64encode(raw).decode('ascii'), archive_sha256=m.sha(raw))
        with self.assertRaisesRegex(m.DeployError, 'TRAILING'):
            m._unpack(config)

    def test_bad_member_names_duplicate_links_and_devices(self):
        for name, kind in (('../escape', tarfile.REGTYPE), ('/abs', tarfile.REGTYPE),
                           ('src/__init__.py', tarfile.REGTYPE),
                           ('src/__init__.py', tarfile.SYMTYPE),
                           ('src/__init__.py', tarfile.LNKTYPE),
                           ('src/__init__.py', tarfile.CHRTYPE),
                           ('unknown/', tarfile.DIRTYPE)):
            member = tarfile.TarInfo(name); member.type = kind; member.linkname = '/escape'
            with self.assertRaises(m.DeployError):
                m._unpack(fixture(member))

    def test_expected_member_map_and_auth_pin(self):
        config = fixture(); config['manifest_files'][m.AUTH] = '0' * 64
        with self.assertRaisesRegex(m.DeployError, 'EXPECTED'):
            m._unpack(config)
        config = fixture(); config['manifest_files']['../extra'] = '0' * 64
        with self.assertRaises(m.DeployError):
            m._unpack(config)

    def test_wrong_host_before_any_write(self):
        with mock.patch.object(m.platform, 'node', return_value='elsewhere'), \
                mock.patch.object(m.os, 'mkdir') as mkdir:
            with self.assertRaises(m.DeployError):
                m.deploy(fixture())
            mkdir.assert_not_called()

    def test_invalid_archive_before_any_write(self):
        config = fixture(); config['archive_sha256'] = '0' * 64
        with mock.patch.object(m.sys, 'platform', 'linux'), \
                mock.patch.object(m.platform, 'node', return_value='bupt-vncs2'), \
                mock.patch.object(m.os, 'mkdir') as mkdir:
            with self.assertRaises(m.DeployError):
                m.deploy(config)
            mkdir.assert_not_called()

    def test_root_collision_no_files_written(self):
        with mock.patch.object(m.sys, 'platform', 'linux'), \
                mock.patch.object(m.platform, 'node', return_value='bupt-vncs2'), \
                mock.patch.object(m, '_unpack', return_value={'x': b'y'}), \
                mock.patch.object(m, '_open_parent', return_value=10), \
                mock.patch.object(m.os, 'mkdir', side_effect=FileExistsError()), \
                mock.patch.object(m.os, 'close'), mock.patch.object(m, '_write_file') as write:
            with self.assertRaises(FileExistsError):
                m.deploy({})
            write.assert_not_called()

    def test_partial_failure_stops_without_retry_or_cleanup(self):
        with mock.patch.object(m.sys, 'platform', 'linux'), \
                mock.patch.object(m.platform, 'node', return_value='bupt-vncs2'), \
                mock.patch.object(m, '_unpack', return_value={'a': b'a', 'b': b'b', 'c': b'c'}), \
                mock.patch.object(m, '_open_parent', return_value=10), \
                mock.patch.object(m.os, 'O_DIRECTORY', 1, create=True), \
                mock.patch.object(m.os, 'O_NOFOLLOW', 2, create=True), \
                mock.patch.object(m.os, 'mkdir') as mkdir, \
                mock.patch.object(m.os, 'open', return_value=11), \
                mock.patch.object(m.os, 'fsync'), mock.patch.object(m.os, 'close'), \
                mock.patch.object(m, '_check_directory'), \
                mock.patch.object(m, '_write_file', side_effect=[None, OSError('fail')]) as write:
            with self.assertRaises(OSError):
                m.deploy({})
            self.assertEqual(write.call_count, 2)
            self.assertEqual(mkdir.call_count, 1)

    def test_file_exclusive_write_fsync_readback_and_identity(self):
        info = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_nlink=1,
            st_uid=1000, st_dev=1, st_ino=2, st_size=3)
        bad = types.SimpleNamespace(st_dev=1, st_ino=3)
        for named, accepted in ((info, True), (bad, False)):
            with mock.patch.object(m.os, 'dup', return_value=10), \
                    mock.patch.object(m, '_check_directory'), \
                    mock.patch.object(m.os, 'O_NOFOLLOW', 2, create=True), \
                    mock.patch.object(m.os, 'open', return_value=11) as opened, \
                    mock.patch.object(m.os, 'fstat', return_value=info), \
                    mock.patch.object(m.os, 'stat', return_value=named), \
                    mock.patch.object(m.os, 'getuid', return_value=1000, create=True), \
                    mock.patch.object(m.os, 'write', return_value=3), \
                    mock.patch.object(m.os, 'read', return_value=b'abc') as read, \
                    mock.patch.object(m.os, 'lseek'), mock.patch.object(m.os, 'fsync') as sync, \
                    mock.patch.object(m.os, 'close'):
                if accepted:
                    m._write_file(1, 'member', b'abc')
                    self.assertEqual(sync.call_count, 2)
                else:
                    with self.assertRaisesRegex(m.DeployError, 'IDENTITY'):
                        m._write_file(1, 'member', b'abc')
                self.assertTrue(opened.call_args[0][1] & m.os.O_EXCL)
                self.assertEqual(read.call_args_list, [mock.call(11, 3)])

    def test_python36_and_no_automatic_entry_or_commands(self):
        source = PATH.read_text()
        kwargs = {'feature_version': (3, 6)} if sys.version_info >= (3, 8) else {}
        ast.parse(source, **kwargs)
        for forbidden in ('subprocess', 'os.system', 'extractall(', '__main__', 'bsub', 'bresume'):
            self.assertNotIn(forbidden, source)


if __name__ == '__main__':
    unittest.main()
