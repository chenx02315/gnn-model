"""Offline mocks only: never open historical/private source paths."""
import ast
import copy
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

from src.data import prospective_generation_materializer_e111 as m


class FakeNamespace(object):
    def __init__(self):
        self.dirs = {'/temp/jiangchuanc': 1}
        self.files = {}
        self.next_fd = 2
        self.copies = []
        self.trees = []

    def path(self, fd):
        return next(path for path, value in self.dirs.items() if value == fd)

    def directory(self, path):
        if path not in self.dirs:
            raise FileNotFoundError(path)
        return self.dirs[path]

    def mkdir(self, fd, name):
        path = self.path(fd) + '/' + name
        if path in self.dirs or path in self.files:
            raise FileExistsError(path)
        self.dirs[path] = self.next_fd
        self.next_fd += 1
        return self.dirs[path]

    def publish(self, fd, name, raw):
        path = self.path(fd) + '/' + name
        if path in self.files or path in self.dirs:
            raise FileExistsError(path)
        self.files[path] = m._receipt(path, len(raw), m.sha(raw))

    def copy(self, source, destination, count, digest, destination_identity=None):
        if destination in self.files:
            raise FileExistsError(destination)
        self.copies.append((source, destination, count, digest))
        self.files[destination] = m._receipt(destination, count, digest)
        return copy.deepcopy(self.files[destination])

    def hash(self, path, count, parent_identity=None):
        if parent_identity is not None and (1, self.dirs[path.rsplit('/', 1)[0]]) != parent_identity:
            raise ValueError('BUNDLE_REPLACED')
        result = self.files[path]
        if result['bytes'] != count:
            raise ValueError('PINNED_SIZE_MISMATCH')
        return copy.deepcopy(result)

    def stat(self, name, dir_fd=None, follow_symlinks=False):
        path = self.path(dir_fd) + '/' + name
        if path not in self.files and path not in self.dirs:
            raise FileNotFoundError(path)
        return SimpleNamespace(st_dev=1, st_ino=self.dirs.get(path, 1000))


class Tests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]
        manifest = self.root / 'data/manifests'
        self.raws = [(manifest / ('ranking_v6_' + name + '_input_observation_20261023_r1.json')).read_bytes()
                     for name in ('e85', 'e88', 'e93')]
        self.common = (self.root / 'src/data/templates/e108_common_base.tcl').read_bytes()
        self.incremental = (self.root / 'src/data/templates/e108_incremental_base.tcl').read_bytes()
        self.authorize = mock.Mock(return_value=True)
        self.obj = self.construct()
        self.ns = FakeNamespace()
        self.patchers = [
            mock.patch.object(m.io, '_directory', side_effect=self.ns.directory),
            mock.patch.object(m.io, '_mkdir', side_effect=self.ns.mkdir),
            mock.patch.object(m.io, '_publish', side_effect=self.ns.publish),
            mock.patch.object(m, '_copy_file', side_effect=self.ns.copy),
            mock.patch.object(m, '_hash_file', side_effect=self.ns.hash),
            mock.patch.object(m.os, 'fstat', side_effect=lambda fd: SimpleNamespace(st_dev=1, st_ino=fd)),
            mock.patch.object(m.os, 'close'),
            mock.patch.object(m.os, 'stat', side_effect=self.ns.stat),
            mock.patch.object(m.io, '_tree', side_effect=self.tree)]

    def construct(self, raws=None, authorize=None):
        return m.Materializer(*(list(self.raws if raws is None else raws) +
            [self.common, self.incremental, self.authorize if authorize is None else authorize]))

    def tree(self, path, destination=None, **bounds):
        self.ns.trees.append((path, destination, bounds))
        if path.startswith(m.pins.PHASE4):
            return next(row['tree_sha256'] for row in self.obj.trees.values() if row['root'] == path)
        # Copy verification is immediately after the corresponding source copy.
        source = self.ns.trees[-2][0]
        return next(row['tree_sha256'] for row in self.obj.trees.values() if row['root'] == source)

    def start_io(self):
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def bindings(self, circuit='aes_core'):
        r = m.recipe
        plan = r.pilot.build_plan()
        freeze = r.requests.freeze_acquisition(plan, circuit, m.pins.COUNTS[circuit],
            self.obj.common[circuit]['manifest.json']['sha256'])
        binder = r.bindings.Binder(plan, circuit, freeze, 'tiny-' + circuit)
        for phase in plan['phases']:
            if phase['circuit'] != circuit:
                continue
            for node in phase['tasks']:
                binding = binder.bind_next(node['task_uid'])
                if node['kind'] == 'TESSENT':
                    yield freeze, binding
                elif self.obj.started:
                    self.obj.prepare_translation(freeze, binding)
                raw = ('opaque:' + node['task_uid']).encode('ascii')
                binder.commit_next(binding, dict(task_uid=node['task_uid'],
                    binding_sha256=binding['binding_sha256'], output_sha256=m.sha(raw),
                    status='SUCCESS', live_acknowledged_claim=True, output_authenticated_claim=True), raw)

    def test_pins_and_missing_callback_fail_before_io(self):
        with mock.patch.object(m.io, '_directory') as directory:
            for index in range(3):
                raws = list(self.raws)
                raws[index] += b' '
                with self.assertRaises(ValueError):
                    self.construct(raws)
            with self.assertRaises(ValueError):
                self.construct(authorize=False)
            directory.assert_not_called()

    def test_admission_before_any_write_literal_true_only(self):
        for decision in (False, 1, {}, None):
            self.authorize.return_value = decision
            with mock.patch.object(m.io, '_directory') as directory:
                with self.assertRaisesRegex(ValueError, 'CALLER_ADMISSION_REQUIRED'):
                    self.obj.initialize_bundle()
                directory.assert_not_called()

    def test_exact_shared_layout_receipts_and_no_execution_grant(self):
        self.start_io()
        with mock.patch('subprocess.Popen') as spawn:
            receipt = self.obj.initialize_bundle()
            spawn.assert_not_called()
        self.assertEqual(len(receipt['files']), 14)
        self.assertEqual(len(self.ns.copies), 12)
        for circuit in ('aes_core', 'spi'):
            base = m.recipe.ROOT + '/' + circuit
            self.assertIn(base + '/inputs/' + circuit + '/cells.lib', self.ns.files)
            self.assertIn(base + '/03_fault_universe/common_frozen/H_common_initial_faults.basic', self.ns.files)
        for flag in ('execution_ready', 'execution_authorized', 'training_release', 'caller_admission_authenticated'):
            self.assertIs(receipt[flag], False)
        receipt['files'].clear()
        self.assertEqual(len(self.obj.bundle_receipt['files']), 14)

    def test_all_48_fresh_trees_exact_bounds_and_attempt_layout(self):
        self.start_io()
        self.obj.initialize_bundle()
        count = 0
        paths = set()
        for circuit in ('aes_core', 'spi'):
            for freeze, binding in self.bindings(circuit):
                before = copy.deepcopy(binding)
                receipt = self.obj.materialize_attempt(freeze, binding)
                count += 1
                self.assertEqual(before, binding)
                self.assertNotIn(receipt['tsdb']['path'], paths)
                paths.add(receipt['tsdb']['path'])
                tree = self.obj.trees[(circuit, binding['target_mode'])]
                self.assertEqual(receipt['tsdb']['sha256'], tree['tree_sha256'])
                self.assertNotIn(receipt['result_dir'], self.ns.dirs)
                self.assertNotIn(receipt['log_path'], self.ns.files)
                self.assertIn(receipt['prereq_dir'], self.ns.dirs)
                self.assertFalse(receipt['translation_outputs_materialized'])
                self.assertIsNone(receipt['resource_budget'])
        self.assertEqual(count, 48)
        self.assertEqual(len(self.ns.trees), 144)
        self.assertEqual(self.authorize.call_count, 79)

    def test_duplicate_attempt_poisoned_no_retry_or_deletion(self):
        self.start_io()
        self.obj.initialize_bundle()
        freeze, binding = next(self.bindings())
        self.obj.materialize_attempt(freeze, binding)
        before = copy.deepcopy(self.ns.files)
        with self.assertRaises(FileExistsError):
            self.obj.materialize_attempt(freeze, binding)
        self.assertTrue(self.obj.failed)
        self.assertEqual(before, self.ns.files)
        with self.assertRaisesRegex(ValueError, 'BUNDLE_NOT_ACTIVE'):
            self.obj.materialize_attempt(freeze, binding)

    def test_collision_root_no_resume(self):
        self.start_io()
        self.ns.dirs[m.recipe.ROOT] = 99
        with self.assertRaises(FileExistsError):
            self.obj.initialize_bundle()
        self.assertTrue(self.obj.failed)
        self.assertEqual(self.ns.files, {})
        with self.assertRaisesRegex(ValueError, 'NO_RESUME'):
            self.obj.initialize_bundle()

    def test_failed_copy_retains_partial_tree_and_prevents_retry(self):
        self.start_io()
        self.obj.initialize_bundle()
        freeze, binding = next(self.bindings())
        with mock.patch.object(m.io, '_tree', return_value='bad'):
            with self.assertRaisesRegex(ValueError, 'SOURCE_TREE_SHA'):
                self.obj.materialize_attempt(freeze, binding)
        self.assertTrue(self.obj.failed)
        self.assertTrue(any('/tsdb/' in path for path in self.ns.dirs))

    def test_same_content_tsdb_root_replacement_before_or_during_readback_fails(self):
        self.start_io()
        self.obj.initialize_bundle()
        freeze, binding = next(self.bindings())
        target = m.recipe.compile_execution(freeze, binding, self.obj.sources)['env']['TSDB_INPUT_DIR']
        # A correct content SHA must not authenticate a replaced named root.
        original_tree = self.tree
        def replace_after_copy(path, destination=None, **bounds):
            digest = original_tree(path, destination, **bounds)
            if destination is not None:
                self.ns.dirs[target] += 100000
            return digest
        with mock.patch.object(m.io, '_tree', side_effect=replace_after_copy):
            with self.assertRaisesRegex(ValueError, 'BUNDLE_REPLACED'):
                self.obj.materialize_attempt(freeze, binding)
        self.assertTrue(self.obj.failed)
        self.assertEqual(len(self.ns.trees), 1)
        with self.assertRaisesRegex(ValueError, 'BUNDLE_NOT_ACTIVE'):
            self.obj.materialize_attempt(freeze, binding)

    def test_same_content_tsdb_root_replacement_during_readback_fails(self):
        self.start_io()
        self.obj.initialize_bundle()
        freeze, binding = next(self.bindings())
        target = m.recipe.compile_execution(freeze, binding, self.obj.sources)['env']['TSDB_INPUT_DIR']
        original_tree = self.tree
        def replace_during_readback(path, destination=None, **bounds):
            digest = original_tree(path, destination, **bounds)
            if path == target:
                self.ns.dirs[target] += 100000
            return digest
        with mock.patch.object(m.io, '_tree', side_effect=replace_during_readback):
            with self.assertRaisesRegex(ValueError, 'BUNDLE_REPLACED'):
                self.obj.materialize_attempt(freeze, binding)
        self.assertTrue(self.obj.failed)
        self.assertEqual(len(self.ns.trees), 2)
        with self.assertRaisesRegex(ValueError, 'BUNDLE_NOT_ACTIVE'):
            self.obj.materialize_attempt(freeze, binding)

    def test_tampered_shared_input_fails_before_clone(self):
        self.start_io()
        self.obj.initialize_bundle()
        item = self.obj.bundle_receipt['files'][0]
        self.ns.files[item['path']]['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'DEPLOYED_INPUT_CHANGED'):
            self.obj.materialize_attempt(*next(self.bindings()))
        self.assertFalse(self.ns.trees)

    def test_untrusted_envelope_or_path_traversal_binding_before_admission(self):
        self.start_io()
        self.obj.initialize_bundle()
        freeze, binding = next(self.bindings())
        binding['request']['run_uid'] = '../other'
        calls = self.authorize.call_count
        with self.assertRaises(ValueError):
            self.obj.materialize_attempt(freeze, binding)
        self.assertEqual(self.authorize.call_count, calls)
        self.assertFalse(self.ns.trees)

    def test_output_collision_and_replaced_owned_parent_fail_closed(self):
        self.start_io()
        self.obj.initialize_bundle()
        freeze, binding = next(self.bindings())
        self.ns.dirs[m.recipe.ROOT + '/aes_core/runs'] = 999
        with self.assertRaisesRegex(ValueError, 'BUNDLE_REPLACED'):
            self.obj.materialize_attempt(freeze, binding)
        self.assertTrue(self.obj.failed)

    def test_source_is_python36_and_contains_no_launch_or_cleanup_api(self):
        raw = (self.root / 'src/data/prospective_generation_materializer_e111.py').read_text()
        ast.parse(raw, feature_version=(3, 6))
        for forbidden in ('subprocess', 'shutil', 'unlink(', 'rmtree(', 'os.system', 'socket', 'import requests'):
            self.assertNotIn(forbidden, raw.replace('No resume, cleanup, subprocess,', ''))

    def test_translation_dag_preparation_before_incremental_and_no_clone(self):
        self.start_io()
        self.obj.initialize_bundle()
        initial_admission = self.authorize.call_args[0][0]
        self.assertIsNone(initial_admission['effective_envelope_sha256'])
        self.assertIsNone(initial_admission['semantic_binding_sha256'])
        r = m.recipe
        plan = r.pilot.build_plan()
        freeze = r.requests.freeze_acquisition(plan, 'aes_core', m.pins.COUNTS['aes_core'],
            self.obj.common['aes_core']['manifest.json']['sha256'])
        binder = r.bindings.Binder(plan, 'aes_core', freeze, 'explicit-run')
        nodes = plan['phases'][0]['tasks']
        def commit(binding):
            raw = b'opaque-reference-not-native-mtfi'
            binder.commit_next(binding, dict(task_uid=binding['task_uid'],
                binding_sha256=binding['binding_sha256'], output_sha256=m.sha(raw),
                status='SUCCESS', live_acknowledged_claim=True, output_authenticated_claim=True), raw)
        h = binder.bind_next(nodes[0]['task_uid'])
        h_preparation = self.obj.materialize_attempt(freeze, h)
        h_admission = self.authorize.call_args[0][0]
        self.assertEqual(h_admission['semantic_binding_sha256'], h['binding_sha256'])
        self.assertEqual(h_admission['effective_envelope_sha256'], h_preparation['effective_envelope_sha256'])
        self.assertNotEqual(h_admission['semantic_binding_sha256'], h_admission['effective_envelope_sha256'])
        commit(h)
        tr = binder.bind_next(nodes[1]['task_uid'])
        tree_calls = len(self.ns.trees)
        prep = self.obj.prepare_translation(freeze, tr)
        translation_admission = self.authorize.call_args[0][0]
        self.assertIsNone(translation_admission['effective_envelope_sha256'])
        self.assertEqual(translation_admission['semantic_binding_sha256'], tr['binding_sha256'])
        self.assertEqual(prep['semantic_binding_sha256'], tr['binding_sha256'])
        self.assertEqual(len(self.ns.trees), tree_calls)
        self.assertIn('/runs/explicit-run/attempts/_prereq/', prep['output_status_file'])
        self.assertFalse(prep['translation_reference_is_native_mtfi_hash'])
        commit(tr)
        incremental = binder.bind_next(nodes[2]['task_uid'])
        result = self.obj.materialize_attempt(freeze, incremental)
        self.assertEqual(result['prereq_dir'] + '/translated_status.mtfi', prep['output_status_file'])

    def test_external_existing_translation_prereq_never_adopted(self):
        self.start_io()
        self.obj.initialize_bundle()
        stream = self.bindings()
        self.obj.materialize_attempt(*next(stream))
        # Resuming the generator prepares translation before yielding target.
        with mock.patch.object(self.obj, 'prepare_translation', wraps=self.obj.prepare_translation) as prep:
            freeze, binding = next(stream)
            prep.assert_called_once()
        self.obj.prepared_translations.clear()
        before = len(self.ns.trees)
        with self.assertRaisesRegex(ValueError, 'TRANSLATION_PREPARATION_REQUIRED'):
            self.obj.materialize_attempt(freeze, binding)
        self.assertEqual(before, len(self.ns.trees))

    def test_translation_preparation_rejects_resigned_wrong_task_before_admission(self):
        self.start_io()
        self.obj.initialize_bundle()
        stream = self.bindings()
        self.obj.materialize_attempt(*next(stream))
        with mock.patch.object(self.obj, 'prepare_translation') as prep:
            next(stream)
        freeze, binding = prep.call_args[0]
        binding = copy.deepcopy(binding)
        binding['parent_task_uid'] = '../outside'
        binding['binding_sha256'] = m.sha(m.canonical({k: v for k, v in binding.items() if k != 'binding_sha256'}))
        calls = self.authorize.call_count
        with self.assertRaisesRegex(ValueError, 'EXACT_TRANSLATION_TASK'):
            self.obj.prepare_translation(freeze, binding)
        self.assertEqual(calls, self.authorize.call_count)

    def test_both_apis_reject_wrong_frozen_count_or_manifest_before_io(self):
        self.start_io()
        self.obj.initialize_bundle()
        stream = self.bindings()
        self.obj.materialize_attempt(*next(stream))
        with mock.patch.object(self.obj, 'prepare_translation') as prep:
            freeze, incremental = next(stream)
        translation_freeze, translation = prep.call_args[0]
        self.assertEqual(freeze, translation_freeze)
        r = m.recipe
        for count, manifest, error in (
                (20, self.obj.common['aes_core']['manifest.json']['sha256'], 'FROZEN_COMMON_COUNT_MISMATCH'),
                (m.pins.COUNTS['aes_core'], 'a' * 64, 'FROZEN_MANIFEST_SHA_MISMATCH')):
            wrong = r.requests.freeze_acquisition(r.pilot.build_plan(), 'aes_core', count, manifest)
            for operation, binding in ((self.obj.materialize_attempt, incremental),
                                       (self.obj.prepare_translation, translation)):
                before_files, before_dirs = copy.deepcopy(self.ns.files), dict(self.ns.dirs)
                calls = self.authorize.call_count
                with mock.patch.object(m.io, '_directory') as opening:
                    with self.assertRaisesRegex(ValueError, error):
                        operation(wrong, binding)
                    opening.assert_not_called()
                self.assertEqual(calls, self.authorize.call_count)
                self.assertEqual(before_files, self.ns.files)
                self.assertEqual(before_dirs, self.ns.dirs)
                self.assertFalse(self.obj.failed)

    def test_shared_input_parent_replaced_with_same_bytes_is_rejected(self):
        self.start_io()
        self.obj.initialize_bundle()
        path = self.obj.bundle_receipt['files'][0]['path']
        parent = path.rsplit('/', 1)[0]
        self.ns.dirs[parent] = 98765
        with self.assertRaisesRegex(ValueError, 'BUNDLE_REPLACED'):
            self.obj.materialize_attempt(*next(self.bindings()))
        self.assertTrue(self.obj.failed)
        self.assertFalse(self.ns.trees)


class CopyAdapterTests(unittest.TestCase):
    def test_hash_rejects_parent_replacement_before_opening_body(self):
        with mock.patch.object(m.io, '_directory', return_value=11), \
                mock.patch.object(m.os, 'fstat', return_value=SimpleNamespace(st_dev=1, st_ino=99)), \
                mock.patch.object(m.os, 'open') as opening, \
                mock.patch.object(m.os, 'close'), mock.patch.object(m.io, '_read_at') as read:
            with self.assertRaisesRegex(ValueError, 'BUNDLE_REPLACED'):
                m._hash_file('/fixture/file', 3, (1, 11))
            opening.assert_not_called()
            read.assert_not_called()

    def test_copy_destination_reread_retains_expected_parent_identity(self):
        digest = m.sha(b'abc')
        expected = m._receipt('/target/file', 3, digest)
        with mock.patch.object(m.io, '_directory', side_effect=[11, 12]), \
                mock.patch.object(m.os, 'fstat', return_value=SimpleNamespace(st_dev=1, st_ino=12)), \
                mock.patch.object(m.os, 'open', return_value=13), \
                mock.patch.object(m.os, 'O_NOFOLLOW', 131072, create=True), \
                mock.patch.object(m.io, '_read_at', return_value=(b'', 3, digest)), \
                mock.patch.object(m.os, 'fsync'), mock.patch.object(m.os, 'close'), \
                mock.patch.object(m, '_hash_file', side_effect=[expected, dict(expected, path='/source/file')]) as hashing:
            m._copy_file('/source/file', '/target/file', 3, digest, (1, 12))
            self.assertEqual(hashing.call_args_list[0], mock.call('/target/file', 3, (1, 12)))
            self.assertEqual(hashing.call_args_list[1], mock.call('/source/file', 3))

    def test_hash_only_uses_streaming_sink_and_exact_size(self):
        with mock.patch.object(m.io, '_directory', return_value=11), \
                mock.patch.object(m.os, 'O_NOFOLLOW', 131072, create=True), \
                mock.patch.object(m.os, 'open', return_value=12), \
                mock.patch.object(m.os, 'close'), \
                mock.patch.object(m.io, '_read_at', return_value=(b'', 3, 'a' * 64)) as read:
            self.assertEqual(m._hash_file('/fixture/file', 3), m._receipt('/fixture/file', 3, 'a' * 64))
            self.assertEqual(read.call_args[1], dict(sink=12, expected_bytes=3, max_bytes=3))

    def test_source_safety_failure_propagates_without_delete_or_retry(self):
        for reason in ('SOURCE_CHANGED', 'SINGLE_LINK_REGULAR_REQUIRED', 'PINNED_SIZE_MISMATCH'):
            with mock.patch.object(m.io, '_directory', side_effect=[11, 12]), \
                    mock.patch.object(m.os, 'O_NOFOLLOW', 131072, create=True), \
                    mock.patch.object(m.os, 'open', return_value=13), \
                    mock.patch.object(m.os, 'close'), \
                    mock.patch.object(m.io, '_read_at', side_effect=ValueError(reason)) as read, \
                    mock.patch.object(m, '_hash_file') as reread:
                with self.assertRaisesRegex(ValueError, reason):
                    m._copy_file('/fixture/source', '/fixture/copy', 3, 'a' * 64)
                self.assertEqual(read.call_count, 1)
                reread.assert_not_called()

    def test_copy_reuses_stream_sink_exclusive_and_stable_source_checks(self):
        expected = m._receipt('/target/file', 3, m.sha(b'abc'))
        with mock.patch.object(m.io, '_directory', side_effect=[11, 12]), \
                mock.patch.object(m.os, 'open', return_value=13) as opening, \
                mock.patch.object(m.os, 'O_NOFOLLOW', 131072, create=True), \
                mock.patch.object(m.io, '_read_at', return_value=(b'', 3, expected['sha256'])) as read, \
                mock.patch.object(m.os, 'fsync'), mock.patch.object(m.os, 'close'), \
                mock.patch.object(m, '_hash_file', side_effect=[expected, dict(expected, path='/source/file')]):
            self.assertEqual(m._copy_file('/source/file', '/target/file', 3, expected['sha256']), expected)
        self.assertTrue(opening.call_args[0][1] & os.O_EXCL)
        self.assertTrue(opening.call_args[0][1] & 131072)
        self.assertEqual(read.call_args[1], dict(sink=13, expected_bytes=3, max_bytes=3))

    def test_oversize_before_source_open(self):
        with mock.patch.object(m.io, '_directory') as directory:
            for size in (True, -1, 0, m.io.MAX_FILE + 1):
                with self.assertRaisesRegex(ValueError, 'FILE_SIZE_BOUND'):
                    m._copy_file('/fixture/source', '/fixture/target', size, 'a' * 64)
            directory.assert_not_called()
