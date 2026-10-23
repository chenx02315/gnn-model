"""Only synthetic inputs/mocks and temporary directories, never acquisition paths."""
import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from unittest import mock

from src.data import prospective_acceptance_materializer_v1 as m


def authorization():
    return dict(schema='e96-acceptance-authorization-v1', approved=True,
        job_id=123, memory_cap_bytes=1024, recipe_sha256=m.RECIPE_SHA256,
        scope='E94_FOUR_NO_PATTERN_ACCEPTANCE_ONLY')


class PolicyTests(unittest.TestCase):
    def test_pinned_size_rejected_before_open_or_allocation(self):
        info = mock.Mock(st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_size=1000)
        with mock.patch.object(m.os, 'stat', return_value=info), mock.patch.object(m.os, 'open') as opening:
            with self.assertRaisesRegex(ValueError, 'PINNED_SIZE_MISMATCH'):
                m._read_at(123, 'fixture', [0], expected_bytes=3)
            opening.assert_not_called()

    def test_e85_depth_first_digest_is_not_global_path_sort(self):
        rows = [['', 'directory', 0, None], ['a', 'directory', 0, None],
                ['a/z', 'file', 1, m.sha(b'z')], ['a.txt', 'file', 1, m.sha(b't')]]
        self.assertNotEqual(rows, sorted(rows))
        self.assertEqual(m._tree_digest(rows), hashlib.sha256(m.canonical(rows)).hexdigest())
        self.assertNotEqual(m._tree_digest(rows), m.sha(m.canonical(sorted(rows))))

    def recipe(self):
        return dict(recipe_sha256=m.RECIPE_SHA256, items=[])

    def test_missing_and_inexact_authority(self):
        with mock.patch.object(m.compiler, 'compile_acceptance', return_value=self.recipe()):
            for auth in (None, {}, dict(authorization(), approved=False),
                         dict(authorization(), extra=True), dict(authorization(), job_id=True),
                         dict(authorization(), memory_cap_bytes=None)):
                with self.assertRaises(ValueError):
                    m.Materializer(b'{}', b'{}', auth)

    def test_raw_compiler_called_with_production_pins(self):
        with mock.patch.object(m.compiler, 'compile_acceptance', return_value=self.recipe()) as compile_call:
            obj = m.Materializer(b'{"raw85":true}', b'{}', authorization())
            compile_call.assert_called_once_with(b'{"raw85":true}', b'{}', m.compiler.E85_SHA256, m.compiler.E93_SHA256)
            obj.close()

    def test_preflight_before_any_directory_or_write(self):
        with mock.patch.object(m.compiler, 'compile_acceptance', return_value=self.recipe()):
            obj = m.Materializer(b'{}', b'{}', authorization())
        with mock.patch.object(m, 'collect_preflight', return_value={'memory_preflight_passed': False}) as pf, mock.patch.object(m, '_directory') as directory, mock.patch.object(m, '_mkdir') as mkdir:
            with self.assertRaises(ValueError):
                obj.initialize_bundle()
            pf.assert_called_once_with(123, 1024)
            directory.assert_not_called()
            mkdir.assert_not_called()

    def test_exact_selector_before_preflight(self):
        with mock.patch.object(m.compiler, 'compile_acceptance', return_value=self.recipe()):
            obj = m.Materializer(b'{}', b'{}', authorization())
        obj.root_fd, obj.scratch_fd = 101, 102
        with mock.patch.object(m, 'collect_preflight') as pf:
            with self.assertRaises(ValueError):
                obj.materialize_item('../../other', 'H_TO_F')
            pf.assert_not_called()

    def test_production_raw_pin_rejection(self):
        with self.assertRaises(ValueError):
            m.Materializer(b'{}', b'{}', authorization())

    def test_mocked_public_flow_second_fourth_and_collision(self):
        bodies = dict(manifest=b'{"f_flat_instance_offset":0}', mapping=b'map',
                      source_mtfi=b'mtfi', target_basic=b'basic')
        items = []
        pins = []
        for circuit in ('aes_core', 'spi'):
            items.append(dict(circuit=circuit, transition='H_TO_F', target_mode='F',
                common_basic_path='/fixture/' + circuit + '/basic', expected_common_count=1,
                translated_status_sha256=m.sha(b'out'), translation_manifest_sha256=m.sha(b'manifest'),
                tsdb_source_root='/fixture/' + circuit + '/tree', tsdb_source_tree_sha256='tree',
                isolated_tsdb_copy='/fixture/' + circuit + '/copy', tcl_bytes=b'tcl'))
            items[-1].update(tsdb_source_regular_files=1, tsdb_source_directories=1)
            for role, body in bodies.items():
                pins.append(dict(circuit=circuit, role='F_basic' if role == 'target_basic' else role,
                                 bytes=len(body), sha256=m.sha(body)))
        recipe = dict(recipe_sha256=m.RECIPE_SHA256, items=items)
        e85 = dict(binary={'bytes': 8}, library={'bytes': 7},
                   tsdb_trees=[dict(root=item['tsdb_source_root'], body_bytes=7) for item in items])
        with mock.patch.object(m.compiler, 'compile_acceptance', return_value=recipe):
            obj = m.Materializer(json.dumps(e85).encode('ascii'), json.dumps(dict(input_files=pins)).encode('ascii'), authorization())
        obj.root_fd, obj.scratch_fd = 101, 102
        def read_fixture(path):
            if path in (m.compiler.LAUNCHER, m.compiler.LIBRARY):
                return b'identity'
            if path.endswith('manifest.json'):
                return bodies['manifest']
            if path.endswith('.tsv'):
                return bodies['mapping']
            if path.endswith('faults.mtfi'):
                return bodies['source_mtfi']
            return bodies['target_basic']
        real_sha = m.sha
        def synthetic_sha(raw):
            return m.compiler.LAUNCHER_SHA256 if raw == b'identity' else real_sha(raw)
        # Both external bodies get distinct pinned values; _read returns by exact role.
        def read(path, expected_bytes=None):
            if path == m.compiler.LIBRARY:
                return b'library'
            return read_fixture(path)
        def digest(raw):
            if raw == b'library':
                return m.compiler.LIBRARY_SHA256
            return synthetic_sha(raw)
        pf = dict(memory_preflight_passed=True, job_id=123, approved_memory_cap_bytes=1024)
        with mock.patch.object(m, 'collect_preflight', return_value=pf) as preflight, mock.patch.object(m.Materializer, '_owned_bundle'), mock.patch.object(m, '_read', side_effect=read), mock.patch.object(m, 'sha', side_effect=digest), mock.patch.object(m, '_mkdir', return_value=201) as mkdir, mock.patch.object(m, '_tree', return_value='tree'), mock.patch.object(m, '_publish') as publish, mock.patch.object(m, 'verify_materialized_item'), mock.patch.object(m.os, 'close'), mock.patch.object(m.translation, 'translate', return_value=dict(output_mtfi_sha256=real_sha(b'out'), manifest_sha256=real_sha(b'manifest'), output_mtfi_bytes=b'out', manifest_bytes=b'manifest')):
            self.assertEqual(obj.materialize_item('aes_core', 'H_TO_F'), items[0])
            self.assertEqual(obj.materialize_item('spi', 'H_TO_F'), items[1])
            self.assertEqual(preflight.call_count, 2)
            self.assertEqual(publish.call_count, 8)
            mkdir.side_effect = FileExistsError('collision')
            with self.assertRaises(FileExistsError):
                obj.materialize_item('aes_core', 'H_TO_F')
            self.assertTrue(obj.failed)


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux anchored dirfd IO required')
class PhysicalFixtureTests(unittest.TestCase):
    def test_nested_e85_order_and_pinned_bounds(self):
        with tempfile.TemporaryDirectory() as root:
            src, dst = root + '/src', root + '/dst'
            os.mkdir(src)
            os.mkdir(dst)
            os.mkdir(src + '/a')
            source_fd, child_fd, dest_fd = m._directory(src), m._directory(src + '/a'), m._directory(dst)
            try:
                m._publish(source_fd, 'a.txt', b't')
                m._publish(child_fd, 'z', b'z')
                rows = [['', 'directory', 0, None], ['a', 'directory', 0, None],
                        ['a/z', 'file', 1, m.sha(b'z')], ['a.txt', 'file', 1, m.sha(b't')]]
                self.assertEqual(m._tree(src, dest_fd, 2, 2, 2), m._tree_digest(rows))
                self.assertEqual(m._tree(dst, expected_bytes=2, expected_files=2,
                                         expected_directories=2), m._tree_digest(rows))
                with self.assertRaises(ValueError):
                    m._tree(src, expected_bytes=1, expected_files=2, expected_directories=2)
                with self.assertRaises(ValueError):
                    m._tree(src, expected_files=1, expected_directories=2)
                with self.assertRaises(ValueError):
                    m._tree(src, expected_files=2, expected_directories=1)
                with mock.patch.object(m.os, 'open') as open_file:
                    with self.assertRaises(ValueError):
                        m._read_at(source_fd, 'a.txt', [0], expected_bytes=100)
                    open_file.assert_not_called()
            finally:
                os.close(source_fd)
                os.close(child_fd)
                os.close(dest_fd)

    def test_exclusive_publication_and_reread(self):
        with tempfile.TemporaryDirectory() as root:
            fd = m._directory(root)
            try:
                m._publish(fd, 'test', b'fixed bytes')
                self.assertEqual(m._read(root + '/test'), b'fixed bytes')
                with self.assertRaises(FileExistsError):
                    m._publish(fd, 'test', b'overwrite forbidden')
            finally:
                os.close(fd)

    def test_copy_digest_and_symlink_rejection(self):
        with tempfile.TemporaryDirectory() as root:
            src, dst = root + '/src', root + '/dst'
            os.mkdir(src)
            os.mkdir(dst)
            source_fd, dest_fd = m._directory(src), m._directory(dst)
            try:
                m._publish(source_fd, 'body', b'fixture')
                expected = m.sha(m.canonical([['', 'directory', 0, None], ['body', 'file', 7, m.sha(b'fixture')]]))
                self.assertEqual(m._tree(src, dest_fd), expected)
                self.assertEqual(m._tree(dst), expected)
                os.symlink('body', src + '/link')
                with self.assertRaises(ValueError):
                    m._tree(src)
            finally:
                os.close(source_fd)
                os.close(dest_fd)

    def test_hardlink_rejection(self):
        with tempfile.TemporaryDirectory() as root:
            fd = m._directory(root)
            try:
                m._publish(fd, 'body', b'fixture')
                os.link(root + '/body', root + '/alias')
                with self.assertRaises(ValueError):
                    m._tree(root)
            finally:
                os.close(fd)

    def test_source_mutation_detected(self):
        with tempfile.TemporaryDirectory() as root:
            fd = m._directory(root)
            try:
                m._publish(fd, 'body', b'fixture')
                original = os.read
                def mutate(source_fd, length):
                    raw = original(source_fd, length)
                    out = os.open('body', os.O_WRONLY, dir_fd=fd)
                    try:
                        os.write(out, b'changed')
                        os.fsync(out)
                    finally:
                        os.close(out)
                    return raw
                with mock.patch.object(m.os, 'read', side_effect=mutate):
                    with self.assertRaises(ValueError):
                        m._read_at(fd, 'body', [0])
            finally:
                os.close(fd)
