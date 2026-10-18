"""E54 synthetic metadata only; never read actual user handoff contents."""
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest.mock import patch

from scripts import project_ranking_v6_e54_source_binding as p


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def provenance(rows=None):
    if rows is None:
        rows = []
        for circuit in p.TRAIN:
            for stage in p.STAGES:
                rows.append(b'\t'.join((circuit, stage, b'1'*64, b'2'*64, b'3',
                                        sorted(p.BASENAMES[stage])[0])))
        # Unselected values are deliberately non-ASCII/private, but structurally flat.
        rows.insert(2, b's5378\tPRIVATE_NON_TRAIN\t\xffPRIVATE\tNOT_A_HASH\tPRIVATE_COUNT\tPRIVATE_NAME')
        rows.append(b'tv80\tPRIVATE_NON_TRAIN\t\xfePRIVATE\tNOT_A_HASH\tPRIVATE_COUNT\tPRIVATE_NAME')
    return p.HEADER + b'\n' + b'\n'.join(rows) + b'\n'


def receipt(provenance_raw, **updates):
    value = {
        'schema_version': 'formal-candidate-space-v2-receipt',
        'sha256': {'source_provenance': sha(provenance_raw),
                   'candidate_space': p.EXPECTED_CANDIDATES,
                   'normalized_measurements': p.EXPECTED_NORMALIZED},
        'ignored_quality': {'opaque': 'PRIVATE_RECEIPT_VALUE', 'number': 987654321},
    }
    value.update(updates)
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('ascii')


def pair(receipt_raw, provenance_raw):
    return p.project_pair(receipt_raw, provenance_raw, sha(receipt_raw), sha(provenance_raw))


class SourceBindingTests(unittest.TestCase):
    def test_positive_bound_chain_grid_ordinals_and_exclusions(self):
        raw = provenance()
        result = pair(receipt(raw), raw)
        rows = result['provenance']['rows']
        self.assertEqual(len(rows), 24)
        self.assertEqual(result['provenance']['excluded_non_train_rows'], 2)
        self.assertEqual(result['provenance']['logical_rows_scanned'], 26)
        self.assertEqual([r['logical_ordinal'] for r in rows[:4]], [1, 2, 4, 5])
        self.assertEqual(rows[2]['physical_line'], 5)
        self.assertEqual({(r['circuit'], r['stage']) for r in rows},
                         {(c.decode(), s.decode()) for c in p.TRAIN for s in p.STAGES})
        self.assertFalse(result['training_release'])
        self.assertNotIn('PRIVATE', json.dumps(result))
        self.assertNotIn('987654321', json.dumps(result))

    def test_receipt_mismatch_rejected_before_any_decode(self):
        raw = provenance()
        with patch.object(p, '_receipt_fields', side_effect=AssertionError('NO_DECODE')):
            with self.assertRaisesRegex(ValueError, 'RECEIPT_SHA_MISMATCH'):
                p.project_receipt(receipt(raw), '0'*64, sha(raw))

    def test_provenance_binding_mismatch_before_tsv_decode(self):
        raw = provenance()
        rec = receipt(raw)
        with patch.object(p, 'project_provenance', side_effect=AssertionError('NO_TSV')):
            with self.assertRaisesRegex(ValueError, 'PROVENANCE_BINDING_MISMATCH'):
                p.project_pair(rec, raw, sha(rec), '0'*64)

    def test_provenance_byte_mismatch_before_selected_decode(self):
        with patch.object(p, 'decode_selected', side_effect=AssertionError('NO_DECODE')):
            with self.assertRaisesRegex(ValueError, 'PROVENANCE_SHA_MISMATCH'):
                p.project_provenance(provenance(), '0'*64)

    def test_nonwhitelist_receipt_and_nontrain_values_poison(self):
        raw = provenance()
        rec = receipt(raw)
        original_loads = json.loads
        original_decode = p.decode_selected
        def safe_loads(value, *args, **kwargs):
            if 'PRIVATE' in value or '987654321' in value:
                raise AssertionError('NONWHITELIST_VALUE_DECODED')
            return original_loads(value, *args, **kwargs)
        def safe_decode(value):
            if b'PRIVATE' in value or any(c > 127 for c in value):
                raise AssertionError('NONTRAIN_VALUE_DECODED')
            return original_decode(value)
        with patch.object(p.json, 'loads', side_effect=safe_loads), patch.object(p, 'decode_selected', side_effect=safe_decode):
            result = pair(rec, raw)
        self.assertEqual(result['provenance']['train_rows_selected'], 24)

    def test_duplicate_json_keys_and_wrong_anchors_rejected(self):
        raw = provenance()
        rec = receipt(raw)
        duplicate = rec.replace(b'"schema_version":', b'"schema_version": "x", "schema_version":', 1)
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_KEY'):
            pair(duplicate, raw)
        altered = rec.replace(p.EXPECTED_CANDIDATES.encode(), b'0'*64)
        with self.assertRaisesRegex(ValueError, 'ANCHOR_MISMATCH'):
            pair(altered, raw)

    def test_flat_tsv_header_quotes_columns_and_newline_errors(self):
        raw = provenance()
        for bad in (raw.replace(b'circuit\tstage', b'stage\tcircuit', 1),
                    raw.replace(b'PRIVATE_COUNT', b'"quoted"', 1),
                    raw.replace(b'PRIVATE_COUNT', b'extra\tcolumn', 1),
                    raw.replace(b'PRIVATE_COUNT', b'broken\nrecord', 1),
                    raw.replace(b'PRIVATE_COUNT', b'carriage\rrecord', 1)):
            with self.assertRaises(ValueError):
                p.project_provenance(bad, sha(bad))

    def test_exact_24_grid_duplicates_missing_and_stage_aliases(self):
        raw = provenance()
        lines = raw.splitlines()
        for bad in (b'\n'.join(lines[:-2])+b'\n',
                    raw+lines[1]+b'\n',
                    raw.replace(b'\thf_coarse\t', b'\t02_hf_coarse\t', 1)):
            with self.assertRaises(ValueError):
                p.project_provenance(bad, sha(bad))

    def test_selected_field_shape_and_basename_fail_closed(self):
        raw = provenance()
        for bad in (raw.replace(b'1'*64, b'not-a-sha', 1),
                    raw.replace(b'\t3\t', b'\t03\t', 1),
                    raw.replace(b'02_hf_coarse__measurements.tsv', b'../measurements.tsv', 1)):
            with self.assertRaises(ValueError):
                p.project_provenance(bad, sha(bad))

    def info(self, **updates):
        value = dict(st_dev=1, st_ino=2, st_mode=stat.S_IFREG, st_nlink=1, st_size=4,
                     st_mtime_ns=5, st_ctime_ns=6, st_file_attributes=0)
        value.update(updates)
        return types.SimpleNamespace(**value)

    def test_stable_identity_windows_exception_only_cross_api(self):
        a, b = self.info(), self.info(st_ctime_ns=100)
        p.verify_identity(a, b, a, b, platform='win32')
        with self.assertRaisesRegex(ValueError, 'METADATA_CHANGED'):
            p.verify_identity(a, b, a, b, platform='linux')
        for position in (2, 3):
            items = [a, a, a, a]
            items[position] = self.info(st_ctime_ns=101)
            with self.assertRaisesRegex(ValueError, 'METADATA_CHANGED'):
                p.verify_identity(*items, platform='win32')

    def test_plain_singlelink_reparse_and_size_gate(self):
        for info in (self.info(st_mode=stat.S_IFLNK), self.info(st_nlink=2),
                     self.info(st_file_attributes=0x400), self.info(st_size=0), self.info(st_size=101)):
            with self.assertRaisesRegex(ValueError, 'PLAIN_SINGLE_LINK'):
                p.file_gate(info, 100)

    def test_stable_read_synthetic_file_and_no_growth(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'synthetic_receipt.json'
            path.write_bytes(b'1234')
            self.assertEqual(p.stable_read(path, 100, 4), b'1234')
            with self.assertRaisesRegex(ValueError, 'EXPECTED_BYTE_COUNT'):
                p.stable_read(path, 100, 5)
            real_lstat = p.os.lstat
            calls = 0
            def changed(candidate):
                nonlocal calls
                calls += 1
                value = real_lstat(candidate)
                if calls == 2:
                    fields = {key:getattr(value, key) for key in
                              ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
                    fields['st_mtime_ns'] += 1
                    return types.SimpleNamespace(**fields)
                return value
            with patch.object(p.os, 'lstat', side_effect=changed):
                with self.assertRaisesRegex(ValueError, 'METADATA_CHANGED'):
                    p.stable_read(path, 100, 4)

    def test_metadata_bounds_before_decode(self):
        with self.assertRaisesRegex(ValueError, 'RECEIPT_BOUND'):
            p.project_receipt(b'x'*(p.LIMIT+1))
        with self.assertRaisesRegex(ValueError, 'PROVENANCE_BOUND'):
            p.project_provenance(b'x'*(p.TSV_LIMIT+1))


if __name__ == '__main__':
    unittest.main()

