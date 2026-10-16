"""Generated temp-only artifacts; no real model/data reader or training."""
import json
import os
import posixpath
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest.mock import patch
import uuid

from src.models import ranking_v6_materialized_freeze_store as module


class LoaderSpy:
    def __init__(self):
        self.calls = 0

    def __len__(self):
        raise AssertionError('LOADER_LEN')

    def __iter__(self):
        raise AssertionError('LOADER_ITER')

    def __call__(self):
        self.calls += 1
        return {'generated_outcomes': 'opaque_callback_payload'}


class FreezeStoreTests(unittest.TestCase):
    def setUp(self):
        # mkdtemp establishes the host temp selection; Store itself only uses
        # lexical environment configuration and does not probe temp locations.
        self.anchor = tempfile.mkdtemp(prefix='gnn_v6_freeze_fixture_test_')
        self.parent = os.path.dirname(self.anchor)
        self.environment = patch.dict(os.environ, {'TEMP': self.parent, 'TMP': self.parent,
                                                   'TMPDIR': self.parent})
        self.environment.start()
        self.roots = []
        self.model, self.normalizer = b'generated_opaque_model', b'generated_opaque_normalizer'
        self.options = dict(model_bytes=self.model, normalizer_bytes=self.normalizer,
                            feature_snapshot_sha256='a'*64, fitting_uids_sha256='b'*64,
                            held_family='iwls_spi', seed=20260824,
                            scores={'u002': -.2, 'u000': .4, 'u001': .4}, implementation_only=True)
        self.freeze = module.make_freeze(**self.options)
        self.spy = LoaderSpy()

    def tearDown(self):
        self.environment.stop()
        # Only explicitly recorded, validated temp test directories are cleaned.
        for root in self.roots + [self.anchor]:
            self.assertEqual(os.path.dirname(root), self.parent)
            self.assertTrue(os.path.basename(root).startswith('gnn_v6_freeze_fixture_'))
            if os.path.islink(root):
                os.unlink(root)
            elif os.path.isdir(root):
                shutil.rmtree(root)

    def new_root(self):
        root = os.path.join(self.parent, 'gnn_v6_freeze_fixture_' + uuid.uuid4().hex)
        self.roots.append(root)
        return root

    def store(self, persist=True):
        store = module.Store(self.new_root(), implementation_only=True)
        if persist:
            store.persist(self.model, self.normalizer, self.freeze)
        return store

    def release(self, store, model=None, normalizer=None, freeze=None):
        return store.release(self.model if model is None else model,
                             self.normalizer if normalizer is None else normalizer,
                             self.freeze if freeze is None else freeze, self.spy)

    def rewrite(self, store, name, raw):
        path = os.path.join(store._root, name)
        os.unlink(path)
        with open(path, 'xb') as stream:
            stream.write(raw)

    def test_actual_three_ordinary_files_readback_and_one_callback(self):
        with patch('socket.socket', side_effect=AssertionError('NETWORK')), \
                patch('random.Random', side_effect=AssertionError('SAMPLING')):
            store = self.store()
            result = self.release(store)
        self.assertEqual(self.spy.calls, 1)
        self.assertEqual(result['outcome'], {'generated_outcomes': 'opaque_callback_payload'})
        self.assertEqual(set(os.listdir(store._root)), {'model.bin', 'normalizer.json', 'freeze.json'})
        receipt = result['receipt']
        self.assertTrue(receipt['all_readbacks_before_loader_access'])
        self.assertEqual(receipt['loader_call_count_scope'], 'this_release_invocation_only')
        for key in ('real_held_release', 'model_ready', 'model_authenticity_verified',
                    'normalizer_authenticity_verified', 'os_sandbox',
                    'adversarial_concurrent_toctou_protection',
                    'directory_power_loss_durability_guaranteed', 'experiment_once_authorization_created'):
            self.assertFalse(receipt[key])

    def test_invalid_lexical_and_protected_roots_zero_io(self):
        invalid = [None, '', 'relative', self.anchor + '/child',
                   os.path.join(self.parent, 'wrong_prefix'), self.anchor + ':ads',
                   os.path.join(self.parent, '..', os.path.basename(self.anchor)),
                   '/ssd/gnn_v6_freeze_fixture_denied',
                   'C:\\ssd\\gnn_v6_freeze_fixture_denied',
                   '/temp/jiangchuanc/gnn_v6_freeze_fixture_denied',
                   '/ssd/cjc/multimode_ate_gnn_v1/gnn_v6_freeze_fixture_denied']
        with patch.object(module.os, 'lstat', side_effect=AssertionError('LSTAT')), \
                patch.object(module.os, 'mkdir', side_effect=AssertionError('MKDIR')), \
                patch.object(module.os, 'open', side_effect=AssertionError('OPEN')), \
                patch('builtins.open', side_effect=AssertionError('OPEN')):
            for root in invalid:
                with self.subTest(root=root), self.assertRaises(ValueError):
                    module.Store(root, implementation_only=True)
            with patch.object(module, '_temp_parent', return_value='/ssd/cjc'):
                with self.assertRaisesRegex(ValueError, 'PROTECTED_ROOT'):
                    module.Store(self.new_root(), implementation_only=True)

    def test_optin_exclusive_root_and_persist_once(self):
        root = self.new_root()
        for optin in (False, 1, None):
            with patch.object(module.os, 'lstat', side_effect=AssertionError('IO')):
                with self.assertRaises(ValueError):
                    module.Store(root, implementation_only=optin)
        store = module.Store(root, implementation_only=True)
        with self.assertRaises(FileExistsError):
            module.Store(root, implementation_only=True)
        store.persist(self.model, self.normalizer, self.freeze)
        with self.assertRaisesRegex(ValueError, 'PERSIST_ONCE'):
            store.persist(self.model, self.normalizer, self.freeze)
        self.assertEqual(Path(root, 'model.bin').read_bytes(), self.model)

    def test_posix_parent_is_case_sensitive_lexically_without_filesystem(self):
        with patch.object(module.os, 'name', 'posix'), \
                patch.object(module.os, 'path', posixpath), \
                patch.object(module, '_temp_parent', return_value='/tmp/Parent'), \
                patch.object(module.os, 'lstat', side_effect=AssertionError('IO')):
            self.assertEqual(module._lexical_root('/tmp/Parent/gnn_v6_freeze_fixture_exact'),
                             '/tmp/Parent/gnn_v6_freeze_fixture_exact')
            with self.assertRaisesRegex(ValueError, 'TEMP_DIRECT_CHILD'):
                module._lexical_root('/tmp/parent/gnn_v6_freeze_fixture_wrongcase')

    def test_bad_expected_bytes_caps_schema_hashes_and_ranking_before_io(self):
        store = self.store()
        bad_freezes = [b'{}', b'', self.freeze+b' ', b'['*1000,
                       self.freeze.replace(b'"schema":', b'"schema":"duplicate","schema":', 1)]
        for field, value in (('model_sha256', 'c'*64), ('normalizer_sha256', 'c'*64),
                             ('held_family', 'other'), ('seed', True), ('scores', [0., True, 1.]),
                             ('action_uids', ['u000', 'u000', 'u001']),
                             ('ranking', ['u002', 'u001', 'u000']), ('extra', 'forbidden')):
            payload = json.loads(self.freeze)
            payload[field] = value
            bad_freezes.append(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode())
        with patch.object(module.os, 'lstat', side_effect=AssertionError('IO')), \
                patch.object(module.os, 'listdir', side_effect=AssertionError('LISTDIR')), \
                patch('builtins.callable', side_effect=AssertionError('CALLABLE')):
            for freeze in bad_freezes:
                with self.subTest(size=len(freeze)), self.assertRaises(ValueError):
                    self.release(store, freeze=freeze)
            for model in (b'', bytearray(b'x'), b'x'*(module.MODEL_CAP+1)):
                with self.assertRaises(ValueError):
                    self.release(store, model=model)
            for norm in (b'', b'x'*(module.NORMALIZER_CAP+1), b'other'):
                with self.assertRaises(ValueError):
                    self.release(store, normalizer=norm)
            with self.assertRaises(ValueError):
                self.release(store, freeze=b'x'*(module.FREEZE_CAP+1))
        self.assertEqual(self.spy.calls, 0)

    def test_make_freeze_bounds_and_deterministic_tie_order(self):
        payload = json.loads(self.freeze)
        self.assertEqual(payload['ranking'], ['u000', 'u001', 'u002'])
        self.assertEqual(self.freeze, module.make_freeze(**dict(self.options,
                         scores=dict(reversed(list(self.options['scores'].items()))))))
        for changes in (dict(implementation_only=False), dict(seed=1), dict(held_family='other'),
                        dict(feature_snapshot_sha256='A'*64), dict(scores={'bad/id': 0.}),
                        dict(scores={'a': True}), dict(scores={'a': 21}),
                        dict(scores={'a': float('nan')}), dict(scores={'a': 10**1000}),
                        dict(scores={str(i):0. for i in range(1025)})):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                module.make_freeze(**dict(self.options, **changes))

    def test_each_file_tamper_extra_file_and_inconsistent_expectation_no_loader(self):
        for name in ('model.bin', 'normalizer.json', 'freeze.json'):
            store = self.store()
            self.rewrite(store, name, b'tampered')
            with patch('builtins.callable', side_effect=AssertionError('CALLABLE')):
                with self.assertRaisesRegex(ValueError, 'READBACK_MISMATCH'):
                    self.release(store)
        store = self.store()
        Path(store._root, 'outcomes.json').write_bytes(b'never read this')
        with self.assertRaisesRegex(ValueError, 'ARTIFACT_CONTENTS'):
            self.release(store)
        store = self.store()
        new_freeze = module.make_freeze(**dict(self.options, scores={'other': 0.}))
        with self.assertRaisesRegex(ValueError, 'PERSIST_ACK_HASH_MISMATCH'):
            self.release(store, freeze=new_freeze)
        self.assertEqual(self.spy.calls, 0)

    def test_file_directory_and_oversize_reject(self):
        store = self.store()
        os.unlink(os.path.join(store._root, 'model.bin'))
        os.mkdir(os.path.join(store._root, 'model.bin'))
        with self.assertRaisesRegex(ValueError, 'ORDINARY_FILE'):
            self.release(store)
        for name, cap in module._FILES:
            store = self.store()
            self.rewrite(store, name, b'x'*(cap+1))
            with self.assertRaisesRegex(ValueError, 'FILE_SIZE_CAP'):
                self.release(store)
        self.assertEqual(self.spy.calls, 0)

    def test_symlink_artifact_and_symlink_root_rejected(self):
        store = self.store()
        target = os.path.join(self.anchor, 'ordinary_target')
        Path(target).write_bytes(self.model)
        path = os.path.join(store._root, 'model.bin')
        os.unlink(path)
        try:
            os.symlink(target, path)
        except (OSError, NotImplementedError) as exc:
            self.skipTest('platform/permission cannot create symlinks: '+str(exc))
        with self.assertRaisesRegex(ValueError, 'LINK_OR_REPARSE'):
            self.release(store)
        linked_root = self.new_root()
        os.symlink(self.anchor, linked_root, target_is_directory=True)
        # Existing symlink must never be adopted as a new Store directory.
        with self.assertRaises((ValueError, FileExistsError)):
            module.Store(linked_root, implementation_only=True)
        self.assertEqual(self.spy.calls, 0)

    def test_hardlink_artifact_rejected_when_available(self):
        store = self.store()
        target = os.path.join(self.anchor, 'hardlink_target')
        Path(target).write_bytes(self.model)
        path = os.path.join(store._root, 'model.bin')
        os.unlink(path)
        try:
            os.link(target, path)
        except (OSError, NotImplementedError) as exc:
            self.skipTest('platform/permission cannot create hardlinks: '+str(exc))
        with self.assertRaisesRegex(ValueError, 'HARDLINK'):
            self.release(store)

    def test_reparse_metadata_rejected_without_platform_claim(self):
        class ReparseInfo:
            st_mode = stat.S_IFREG | 0o600
            st_file_attributes = 0x400
            st_nlink = 1
        with self.assertRaisesRegex(ValueError, 'LINK_OR_REPARSE'):
            module._ordinary(ReparseInfo(), directory=False)

    def test_replaced_ordinary_root_rejected(self):
        store = self.store()
        moved = self.new_root()
        os.rename(store._root, moved)
        os.mkdir(store._root)
        with self.assertRaisesRegex(ValueError, 'ROOT_IDENTITY'):
            self.release(store)
        self.assertEqual(self.spy.calls, 0)

    def test_descriptor_identity_and_size_mismatch_rejected(self):
        store = self.store()
        original = os.fstat
        def changed(descriptor):
            info = original(descriptor)
            class ChangedInfo:
                st_dev = info.st_dev
                st_ino = info.st_ino + 1
                st_mode = info.st_mode
                st_nlink = info.st_nlink
                st_size = info.st_size
                st_file_attributes = getattr(info, 'st_file_attributes', 0)
            return ChangedInfo()
        with patch.object(module.os, 'fstat', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'OPEN_IDENTITY_OR_SIZE'):
                self.release(store)
        self.assertEqual(self.spy.calls, 0)

    def test_failed_partial_persist_retains_file_and_no_overwrite(self):
        store = self.store(persist=False)
        original = store._write
        def write(name, raw):
            if name == 'normalizer.json':
                raise OSError('fabricated write failure')
            return original(name, raw)
        with patch.object(store, '_write', side_effect=write):
            with self.assertRaisesRegex(OSError, 'fabricated'):
                store.persist(self.model, self.normalizer, self.freeze)
        self.assertEqual(Path(store._root, 'model.bin').read_bytes(), self.model)
        with self.assertRaisesRegex(ValueError, 'PERSIST_ONCE'):
            store.persist(self.model, self.normalizer, self.freeze)
        with self.assertRaisesRegex(ValueError, 'PERSIST_ACK_REQUIRED'):
            self.release(store)

    def test_external_files_cannot_replace_successful_persist_ack(self):
        store = self.store(persist=False)
        for (name, _), raw in zip(module._FILES, (self.model, self.normalizer, self.freeze)):
            Path(store._root, name).write_bytes(raw)
        with patch.object(module.os, 'lstat', side_effect=AssertionError('IO')):
            with self.assertRaisesRegex(ValueError, 'PERSIST_ACK_REQUIRED'):
                self.release(store)
        self.assertEqual(self.spy.calls, 0)

    def test_persist_ack_binds_complete_original_bundle_before_any_release_io(self):
        store = self.store()
        original_ack = store._persist_ack_hashes
        self.assertIs(type(original_ack), tuple)
        # A remains releasable before substitution.
        self.release(store)
        self.assertEqual(self.spy.calls, 1)
        self.spy = LoaderSpy()
        model_b, normalizer_b = b'opaque_model_B', b'opaque_normalizer_B'
        freeze_b = module.make_freeze(**dict(self.options, model_bytes=model_b,
                                             normalizer_bytes=normalizer_b,
                                             scores={'other_uid': -1.}))
        for (name, _), raw in zip(module._FILES, (model_b, normalizer_b, freeze_b)):
            self.rewrite(store, name, raw)
        # Even a fully valid, internally consistent B on disk cannot borrow
        # the successful exclusive-write/fsync/readback acknowledgement of A.
        with patch.object(module.os, 'lstat', side_effect=AssertionError('LSTAT')), \
                patch.object(module.os, 'listdir', side_effect=AssertionError('LISTDIR')), \
                patch.object(module.os, 'open', side_effect=AssertionError('OPEN')), \
                patch('builtins.callable', side_effect=AssertionError('CALLABLE')):
            with self.assertRaisesRegex(ValueError, 'PERSIST_ACK_HASH_MISMATCH'):
                store.release(model_b, normalizer_b, freeze_b, self.spy)
        self.assertEqual(self.spy.calls, 0)
        self.assertEqual(store._persist_ack_hashes, original_ack)

    def test_failed_persist_has_no_hash_ack(self):
        store = self.store(persist=False)
        with patch.object(store, '_read', side_effect=OSError('fabricated readback failure')):
            with self.assertRaises(OSError):
                store.persist(self.model, self.normalizer, self.freeze)
        self.assertFalse(store._persisted)
        self.assertIsNone(store._persist_ack_hashes)

    def test_bad_persist_payload_before_creation_and_noncallable_after_gate(self):
        store = self.store(persist=False)
        with patch.object(module.os, 'lstat', side_effect=AssertionError('IO')):
            with self.assertRaises(ValueError):
                store.persist(self.model, self.normalizer, b'{}')
        self.assertEqual(os.listdir(store._root), [])
        store.persist(self.model, self.normalizer, self.freeze)
        with self.assertRaisesRegex(ValueError, 'OUTCOME_LOADER'):
            store.release(self.model, self.normalizer, self.freeze, object())


if __name__ == '__main__':
    unittest.main()
