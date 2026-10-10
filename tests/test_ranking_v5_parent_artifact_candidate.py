"""Temporary synthetic files only; no ML, remote or production data access."""
from copy import deepcopy
import hashlib
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests import test_ranking_v5_independent_fit_context as context_tests
from tests.test_ranking_v5_serial_matrix import parent_receipt
from src.models import ranking_v5_parent_artifact_candidate as collector

encode = context_tests.encode


class ParentArtifactCandidateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source_root = (self.base/'gnn_model_ranking_v5_train_20261010_r1').as_posix()
        self.generated = context_tests.IndependentFitContextTests(); self.generated.setUp()
        self.context = self.generated.context
        self.output = self.source_root+'_'+self.context.family+'_'+str(self.context.seed)
        self.root = Path(self.output); self.root.mkdir()
        self.log_path = self.output+'.stdout.log'
        self.guard = parent_receipt()
        self.enterContext(patch.object(collector.cli, 'ROOT_PATTERN', re.escape(self.source_root)))
        self.enterContext(patch.object(collector.reader, 'PRODUCTION_PREFIX',
            (self.base/'gnn_model_ranking_v5_train_').as_posix()))
        self.raw = {'model.pt': self.generated.model_raw,
                    'fitting.jsonl': b''.join(encode(r) for r in self.generated.logs),
                    'freeze.json': encode(self.generated.freeze),
                    'worker_receipt.json': encode(self.generated.receipt)}
        for name, raw in self.raw.items(): (self.root/name).write_bytes(raw)
        Path(self.log_path).write_bytes(b'synthetic diagnostic\n'+self.raw['worker_receipt.json']+b'\n')

    def collect(self, **changes):
        kwargs = dict(context=self.context, guard_returned_receipt=self.guard,
                      guard_reread_receipt=deepcopy(self.guard))
        kwargs.update(changes)
        return collector.collect_parent_artifact_candidate(self.source_root, self.output,
                                                            self.log_path, **kwargs)

    def test_normal_bounded_candidate_checks_all_four_files_and_no_authority(self):
        before = {name: (self.root/name).read_bytes() for name in self.raw}
        result = self.collect()
        self.assertEqual(result['status'], 'PASS_PARENT_ARTIFACT_CANDIDATE_BINDING_ONLY')
        self.assertEqual(result['parent_measured_file_sha256'],
                         {name: hashlib.sha256(raw).hexdigest() for name, raw in self.raw.items()})
        self.assertEqual(result['fit_context_check']['status'], 'PASS_FIT_CONTEXT_BINDING_ONLY')
        self.assertEqual(result['candidate_worker_receipt'], self.generated.receipt)
        self.assertEqual(result['freeze_envelope'], self.generated.freeze)
        for field in ('numerical_model_predictions_verified', 'numerical_held_metrics_verified',
                      'guard_receipt_provenance_authenticated', 'authentic_user_consent_proven',
                      'formal_training_authorized_by_this_function', 'new_formal_18_fit_release'):
            self.assertIs(result[field], False)
        self.assertEqual(before, {name: (self.root/name).read_bytes() for name in self.raw})

    def test_failed_guard_even_with_valid_artifacts_refuses_before_any_io(self):
        for field, value in (('status', 'STOPPED_NO_RETRY'), ('exit_code', 1), ('sample_count', 0)):
            receipt = deepcopy(self.guard); receipt[field] = value
            with self.subTest(field=field), patch.object(Path, 'lstat') as stat, \
                 patch('os.open') as opened, patch.object(collector.reader, '_read') as read, \
                 self.assertRaises(ValueError):
                self.collect(guard_returned_receipt=receipt, guard_reread_receipt=deepcopy(receipt))
            stat.assert_not_called(); opened.assert_not_called(); read.assert_not_called()
        mismatch = deepcopy(self.guard); mismatch['process_group'] += 1
        with patch.object(Path, 'lstat') as stat, self.assertRaises(ValueError):
            self.collect(guard_reread_receipt=mismatch)
        stat.assert_not_called()

    def test_wrong_output_source_or_logpath_rejects_before_io(self):
        paths = [(self.source_root, self.output+'_wrong', self.log_path),
                 (self.source_root+'/../bad', self.output, self.log_path),
                 (self.source_root, self.output, self.log_path+'.wrong'),
                 (self.source_root, '/ssd/cjc/multimode_ate_gnn_v1/x', self.log_path)]
        for source, output, log in paths:
            with patch.object(Path, 'lstat') as stat, patch('os.open') as opened, self.assertRaises(ValueError):
                collector.collect_parent_artifact_candidate(source, output, log, context=self.context,
                    guard_returned_receipt=self.guard, guard_reread_receipt=deepcopy(self.guard))
            stat.assert_not_called(); opened.assert_not_called()

    def test_only_last_nonempty_line_never_falls_back_to_prior_success(self):
        valid = self.raw['worker_receipt.json']
        for contamination in (b'ERROR\n', b'{}\n', b'null\n', b'1\n', b'{"status":"PASS"}\n',
                              b'\x00\n', valid.rstrip(b'\n')):
            Path(self.log_path).write_bytes(valid+contamination)
            with self.subTest(contamination=contamination[:50]), self.assertRaises(ValueError): self.collect()

    def test_tail_cap_huge_preamble_allowed_without_reading_it(self):
        Path(self.log_path).write_bytes(b'x'*100000+b'\n'+self.raw['worker_receipt.json']+b'\n')
        original = collector.os.fdopen
        reads, seeks = [], []
        class ObservedStream:
            def __init__(self, stream): self.stream = stream
            def __enter__(self): return self
            def __exit__(self, *args): self.stream.close()
            def fileno(self): return self.stream.fileno()
            def seek(self, offset): seeks.append(offset); return self.stream.seek(offset)
            def read(self, limit): reads.append(limit); return self.stream.read(limit)
        with patch.object(collector.os, 'fdopen', side_effect=lambda *args: ObservedStream(original(*args))):
            result = collector._stdout_tail(Path(self.log_path))
        self.assertEqual(result, self.generated.receipt)
        self.assertEqual(reads, [collector.STDOUT_TAIL_CAP])
        self.assertEqual(len(seeks), 1); self.assertGreater(seeks[0], 0)
        self.collect()
        # Entire tail blanks obscures any complete last receipt: fail closed.
        Path(self.log_path).write_bytes(self.raw['worker_receipt.json']+b'\n'*30000)
        with self.assertRaisesRegex(ValueError, 'TAIL_INCOMPLETE'): self.collect()

    def test_long_last_line_and_empty_or_unterminated_stdout_reject(self):
        for raw in (b'', b'x'*(collector.STDOUT_TAIL_CAP+1)+b'\n',
                    self.raw['worker_receipt.json'].rstrip(b'\n'), b'\n'*30000):
            Path(self.log_path).write_bytes(raw)
            with self.subTest(length=len(raw)), self.assertRaises(ValueError): self.collect()

    def test_duplicate_deep_nonfinite_noncanonical_json_refused(self):
        for raw in (b'{"a":1,"a":2}\n', b'['*70+b'0'+b']'*70+b'\n',
                    b'{"a":NaN}\n', b'{"a":Infinity}\n', b'{"a":1e309}\n',
                    b'{ "a": 1 }\n', b'{}\r\n', b'\xff\n'):
            Path(self.log_path).write_bytes(self.raw['worker_receipt.json']+raw)
            with self.subTest(raw=raw[:35]), self.assertRaises(ValueError): self.collect()

    def test_stdout_receipt_canonical_type_mismatch(self):
        candidate = deepcopy(self.generated.receipt)
        candidate['boundary_receipt']['seed'] = float(self.context.seed)
        Path(self.log_path).write_bytes(encode(candidate))
        with self.assertRaisesRegex(ValueError, 'STDOUT_RECEIPT_MISMATCH'): self.collect()

    def test_regular_path_checks_directory_missing_oversized_artifact(self):
        target = self.root/'model.pt'
        target.unlink(); target.mkdir()
        with self.assertRaises(ValueError): self.collect()
        target.rmdir()
        with self.assertRaises(ValueError): self.collect()
        target.write_bytes(b'x'*(collector.reader.LIMITS['model.pt']+1))
        with self.assertRaises(ValueError): self.collect()

    def test_independent_context_rejection_before_final_readback(self):
        candidate = deepcopy(self.generated.receipt)
        candidate['input_identity']['fold_manifest_sha256'] = '0'*64
        candidate['worker_receipt_sha256'] = collector.fit_context.digest(
            {k: v for k, v in candidate.items() if k != 'worker_receipt_sha256'})
        (self.root/'worker_receipt.json').write_bytes(encode(candidate))
        Path(self.log_path).write_bytes(encode(candidate))
        with patch.object(collector.reader, 'validate_train_artifact_readback') as reread, \
             self.assertRaisesRegex(ValueError, 'INPUT_IDENTITY_BINDING'):
            self.collect()
        reread.assert_not_called()

    def test_stdout_symlink_reparse_and_change_checks(self):
        original = Path.lstat
        def changed(path):
            info = original(path)
            if path == Path(self.log_path):
                class Reparse:
                    st_mode = info.st_mode
                    st_file_attributes = 0x400
                return Reparse()
            return info
        with patch.object(Path, 'lstat', changed), self.assertRaises(ValueError): self.collect()
        original_fstat = collector.os.fstat
        calls = []
        def changed_after(descriptor):
            info = original_fstat(descriptor); calls.append(descriptor)
            if len(calls) == 2:
                return SimpleNamespace(st_size=info.st_size, st_mtime_ns=info.st_mtime_ns+1)
            return info
        with patch.object(collector.os, 'fstat', side_effect=changed_after), \
             self.assertRaisesRegex(ValueError, 'STDOUT_CHANGED'):
            collector._stdout_tail(Path(self.log_path))


if __name__ == '__main__':
    unittest.main()
