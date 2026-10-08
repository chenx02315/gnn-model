"""Temporary synthetic artifacts only; no real fits, consent or package reads."""
import copy
import hashlib
import json
import os
import stat
from types import SimpleNamespace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.models import ranking_v5_train_artifact_readback as reader
from src.models import ranking_v5_execution_boundary as boundary
from src.models.ranking_v5_physical_worker import synthetic_request
from src.models.ranking_v5_training_kernel import log_record
from src.models.runtime_ranking_v3 import digest, freeze_ranking


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()+b'\n'


class ReadbackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'gnn_model_ranking_v5_train_synthetic'
        self.root.mkdir()
        self.enterContext(patch.object(reader, 'PRODUCTION_PREFIX',
            (Path(self.temp.name) / 'gnn_model_ranking_v5_train_').as_posix()))
        request = synthetic_request()
        fold, prepared, _, recipe = boundary.prepare_request(request)
        payload, freeze_sha = freeze_ranking({u: float(i) for i, u in enumerate(fold.heldout)}, fold)
        self.freeze = {'payload': payload, 'sha256': freeze_sha}
        scores = {u: float(i) for i, u in enumerate(prepared['fit_uids'])}
        self.records = [log_record(scores, recipe, prepared['pairs'], epoch=min(i, 120),
            phase='INITIAL' if i == 0 else 'FINAL' if i == 121 else 'EPOCH',
            request_sha256=digest(request)) for i in range(122)]
        self.raw = {'model.pt': b'SYNTHETIC_NOT_A_TORCH_CHECKPOINT',
                    'fitting.jsonl': b''.join(encode(r) for r in self.records),
                    'freeze.json': encode(self.freeze)}
        model_sha = hashlib.sha256(self.raw['model.pt']).hexdigest()
        self.receipt = dict(status='PASS_SINGLE_FIT_CALLBACK_ADAPTER_ONLY',
            caller_must_use_existing_resource_guard=True,
            input_identity=dict(package_receipt_sha256=boundary.PACKAGE_SHA256,
                source_sha256=boundary.SOURCE_SHA256, fold_manifest_sha256='a'*64,
                family=fold.family, seed=request['seed']),
            approval_integrity=dict(status='PASS_APPROVAL_BYTES_INTEGRITY_ONLY',
                authentic_user_consent_proven=False, training_authorized_by_this_function=False,
                release_sha256='b'*64, authorization_sha256='c'*64, review_sha256='d'*64,
                physical_gate_sha256='e'*64),
            observed_process_preconditions=dict(status='PASS_CHILD_PREREQUISITES_ONLY',
                address_space_limits=[8*1024**3]*2, core_limits=[0, 0], threads=1,
                parent_sampled_rss_enforcement_proven=False, authentic_user_consent_proven=False),
            boundary_receipt=dict(scope=boundary.SCOPE, family=fold.family, seed=request['seed'],
                model='candidate_mlp', model_ack_sha256=model_sha, expected_model_sha256=model_sha,
                freeze_sha256=freeze_sha, canonical_request_sha256=digest(request),
                release_sha256='b'*64, source_binding_sha256='f'*64,
                head_recipe_sha256=digest(recipe), held_labels_replayed=False, metrics=None),
            **{key: False for key in reader.FALSE_FIELDS})
        self.refresh()

    def refresh(self):
        self.receipt['fitting_log_sha256'] = hashlib.sha256(self.raw['fitting.jsonl']).hexdigest()
        self.receipt['worker_receipt_sha256'] = digest({k: v for k, v in self.receipt.items()
                                                       if k != 'worker_receipt_sha256'})
        self.raw['worker_receipt.json'] = encode(self.receipt)
        self.pins = {name: hashlib.sha256(raw).hexdigest() for name, raw in self.raw.items()}
        for name, raw in self.raw.items():
            (self.root / name).write_bytes(raw)

    def run_reader(self, **kwargs):
        args = dict(expected_receipt=self.receipt, expected_freeze=self.freeze,
                    trusted_file_sha256=self.pins)
        args.update(kwargs)
        return reader.validate_train_artifact_readback(self.root.as_posix(), **args)

    def test_complete_read_only_no_checkpoint_load_or_authority(self):
        before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.iterdir()}
        result = self.run_reader()
        self.assertEqual(result['status'], 'PASS_TRAIN_ARTIFACT_READBACK_INTEGRITY_ONLY')
        self.assertEqual(result['log_record_count'], 122)
        self.assertFalse(result['formal_training_authorized_by_this_function'])
        self.assertFalse(result['new_formal_18_fit_release'])
        self.assertEqual(before, {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.iterdir()})

    def test_arbitrary_protected_and_traversal_roots_zero_io(self):
        for root in ('/elsewhere', '/ssd/cjc/multimode_ate_gnn_v1',
                     '/ssd/cjc/multimode_ate_gnn_v1/anything',
                     '/SSD/CJC/MULTIMODE_ATE_GNN_V1/anything',
                     '/ssd/cjc/gnn_model_ranking_v5_train_x/../bad',
                     self.root.as_posix()+'/child', self.root.as_posix().replace('/', '\\')):
            with self.subTest(root=root), patch.object(Path, 'lstat') as stats, \
                    patch.object(os, 'open') as opened, self.assertRaises(ValueError):
                reader.validate_train_artifact_readback(root, expected_receipt=self.receipt,
                    expected_freeze=self.freeze, trusted_file_sha256=self.pins)
            stats.assert_not_called(); opened.assert_not_called()

    def test_forged_self_hash_cannot_replace_independent_pin(self):
        altered = copy.deepcopy(self.receipt)
        altered['boundary_receipt']['canonical_request_sha256'] = '0'*64
        altered['worker_receipt_sha256'] = digest({k: v for k, v in altered.items() if k != 'worker_receipt_sha256'})
        (self.root/'worker_receipt.json').write_bytes(encode(altered))
        with self.assertRaisesRegex(ValueError, 'FILE_SHA'):
            self.run_reader()

    def test_impossible_log_semantics_rejected_even_after_coherent_repins(self):
        original = copy.deepcopy(self.records)
        for key, value in (('actions', -1), ('first_positive_rank', 0), ('hit_at_10', 2),
                           ('positive_count', 0), ('negative_count', -1),
                           ('negatives_before_first_positive', -1), ('top10_cycle_regret', -.5),
                           ('head_softplus', -1), ('guaranteed_hit_by_size', False),
                           ('strict_score_hit_certificate', False), ('tie_at_boundary', True)):
            with self.subTest(key=key):
                self.records = copy.deepcopy(original)
                if type(value) is bool:
                    value = not self.records[0]['families'][0][key]
                self.records[0]['families'][0][key] = value
                self.raw['fitting.jsonl'] = b''.join(encode(r) for r in self.records)
                self.refresh()
                with self.assertRaisesRegex(ValueError, 'LOG_ROW_SEMANTICS'):
                    self.run_reader()

    def test_negative_replay_cost_or_regret_rejected_before_io(self):
        for key, value in (('charged_runtime_s', -5.), ('best_cycle_regret_at_10', -.5)):
            with self.subTest(key=key):
                self.receipt['boundary_receipt']['held_labels_replayed'] = True
                metrics = dict(hit_at_10=1, hit_found=True, attempt_count=1,
                               charged_runtime_s=5., best_cycle_regret_at_10=0.,
                               freeze_sha256=self.freeze['sha256'])
                metrics[key] = value
                self.receipt['boundary_receipt']['metrics'] = metrics
                self.refresh()
                with patch.object(Path, 'lstat') as stats, self.assertRaisesRegex(ValueError, 'METRICS'):
                    self.run_reader()
                stats.assert_not_called()

    def test_each_bad_file_sha(self):
        for name in self.raw:
            path = self.root/name
            original = path.read_bytes()
            path.write_bytes(original+b'x')
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'FILE_SHA'):
                self.run_reader()
            path.write_bytes(original)

    def test_wrong_seed_family_request_release_source_unknown_receipt(self):
        for field, value in [('seed', True), ('seed', 20260825), ('family', 'wrong'),
                             ('canonical_request_sha256', '0'*64),
                             ('release_sha256', '0'*64), ('source_binding_sha256', '0'*64)]:
            altered = copy.deepcopy(self.receipt)
            altered['boundary_receipt'][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.run_reader(expected_receipt=altered)
        altered = copy.deepcopy(self.receipt); altered['unknown'] = 1
        with self.assertRaisesRegex(ValueError, 'SCHEMA'):
            self.run_reader(expected_receipt=altered)

    def test_all_file_caps_before_open(self):
        for name, cap in reader.LIMITS.items():
            path = self.root/name
            original = path.read_bytes()
            path.write_bytes(b'x'*(cap+1))
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'FILE_BOUND'):
                self.run_reader()
            path.write_bytes(original)

    def test_log_unknown_fields_seedless_request_binding_strict_types_order_count(self):
        baseline = self.raw['fitting.jsonl']
        for mode in ('unknown', 'request', 'recipe', 'bool_K', 'bool_epoch', 'bool_row', 'float_count', 'family', 'phase', 'short'):
            records = copy.deepcopy(self.records)
            if mode == 'unknown': records[0]['unknown'] = 1
            elif mode in ('request', 'recipe'):
                records[0]['canonical_request_sha256' if mode == 'request' else 'recipe_sha256'] = '0'*64
            elif mode == 'bool_K': records[0]['K'] = True
            elif mode == 'bool_epoch': records[0]['epoch'] = False
            elif mode == 'bool_row': records[0]['families'][0]['actions'] = True
            elif mode == 'float_count': records[0]['macro_family_count'] = 5.0
            elif mode == 'family': records[0]['families'][0]['family'] = self.freeze['payload']['family']
            elif mode == 'phase': records[0]['phase'] = 'FINAL'
            else: records.pop()
            self.raw['fitting.jsonl'] = b''.join(encode(r) for r in records); self.refresh()
            with self.subTest(mode=mode), self.assertRaises(ValueError): self.run_reader()
        self.raw['fitting.jsonl'] = baseline; self.refresh()

    def test_bad_json_and_record_cap_with_repinned_logs(self):
        baseline = self.raw['fitting.jsonl']
        cases = [b'{"x":1,"x":2}\n', b'{"x":NaN}\n', b'{"x":1e999}\n',
                 b'['*70+b'0'+b']'*70+b'\n', b'{"x":'+b'1'*400+b'}\n',
                 b'{"x":"'+b'x'*2049+b'"}\n', b'['+b'0,'*1024+b'0]\n',
                 b'x'*(reader.LOG_RECORD_MAX_BYTES+1)+b'\n']
        remaining = b''.join(encode(r) for r in self.records[1:])
        for bad in cases:
            self.raw['fitting.jsonl'] = bad+remaining; self.refresh()
            with self.subTest(size=len(bad)), self.assertRaises(ValueError): self.run_reader()
        self.raw['fitting.jsonl'] = baseline; self.refresh()

    def test_freeze_duplicate_deep_nonfinite_canonical_and_schema(self):
        for bad in (b'{"payload":1,"payload":2}\n', b'['*1000+b'0'+b']'*1000+b'\n',
                    b'{"x":Infinity}\n', b'{ "x":1}\n'):
            with self.assertRaises(ValueError): reader._decode(bad)
        altered = copy.deepcopy(self.freeze); altered['payload']['top_k'] = True
        with self.assertRaises(ValueError): self.run_reader(expected_freeze=altered)
        altered = copy.deepcopy(self.freeze); altered['payload']['unknown'] = 1
        with self.assertRaises(ValueError): self.run_reader(expected_freeze=altered)

    def test_missing_empty_directory_files(self):
        path = self.root/'model.pt'
        original = path.read_bytes(); path.unlink()
        with self.assertRaises(ValueError): self.run_reader()
        path.write_bytes(b'')
        with self.assertRaisesRegex(ValueError, 'FILE_BOUND'): self.run_reader()
        path.unlink(); path.mkdir()
        with self.assertRaisesRegex(ValueError, 'ORDINARY_PATH'): self.run_reader()
        path.rmdir(); path.write_bytes(original)

    def test_symlink_files_and_root_if_platform_permits(self):
        target = Path(self.temp.name)/'outside.bin'; target.write_bytes(self.raw['model.pt'])
        link = Path(self.temp.name)/'probe_link'
        try:
            link.symlink_to(target)
        except OSError as error:
            self.skipTest('OS symlink privileges unavailable: '+str(error))
        link.unlink()
        path = self.root/'model.pt'; path.unlink(); path.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'SYMLINK'): self.run_reader()
        path.unlink(); path.write_bytes(self.raw['model.pt'])
        root_link = Path(self.temp.name)/'gnn_model_ranking_v5_train_link'
        root_link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'SYMLINK'):
            reader.validate_train_artifact_readback(root_link.as_posix(), expected_receipt=self.receipt,
                expected_freeze=self.freeze, trusted_file_sha256=self.pins)

    def test_link_modes_and_windows_reparse_points_fail_before_open(self):
        for info in (SimpleNamespace(st_mode=stat.S_IFLNK, st_file_attributes=0),
                     SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)):
            with self.subTest(info=info), patch.object(Path, 'lstat', return_value=info), \
                    patch.object(os, 'open') as opened, self.assertRaisesRegex(ValueError, 'SYMLINK'):
                self.run_reader()
            opened.assert_not_called()

    def test_expectations_snapshot_not_mutable_during_io(self):
        original = reader._read
        def mutate(root, name):
            self.receipt['boundary_receipt']['seed'] = 1
            self.pins.clear()
            return original(root, name)
        with patch.object(reader, '_read', side_effect=mutate):
            result = self.run_reader()
        self.assertEqual(result['seed'], 20260824)


if __name__ == '__main__':
    unittest.main()
