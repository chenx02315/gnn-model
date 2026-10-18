"""Synthetic metadata only; never open actual handoff or source snapshots."""
import copy
import unittest
from scripts import audit_ranking_v6_e55_original_sha_join as m


def fixture():
    rows, files = [], []
    for circuit in sorted(m.TRAIN):
        for stage in sorted(m.STAGES):
            ordinal = len(rows)+1
            digest = format(ordinal,'064x')
            row = dict(circuit=circuit,stage=stage,source_sha256=digest,
                normalized_sha256='f'*64,row_count=ordinal,source_basename='copied.tsv',
                logical_ordinal=ordinal,physical_line=ordinal+1)
            rows.append(row)
            root = '/temp/jiangchuanc/synthetic/'+circuit+'/v1'
            files.append(dict(circuit=circuit,stage_alias=stage,sha256=digest,
                path=root+'/'+stage+'.tsv',coverage_root=root,row_count=ordinal))
    for original in files[:8]:
        item = dict(original)
        item['coverage_root'] = item['coverage_root'].replace('/v1','/v2')
        item['path'] = item['path'].replace('/v1','/v2')
        item['sha256'] = 'e'*64
        files.append(item)
    return rows,files


class OriginalShaJoinTests(unittest.TestCase):
    def test_unique_raw_matches_preserve_order_and_all_inventory(self):
        rows, files = fixture()
        original = copy.deepcopy((rows,files))
        result = m.join_sources(rows,files)
        self.assertEqual(result['class_counts']['ONE_ORIGINAL_SHA_MATCH'],24)
        self.assertEqual(result['unused_inventory_count'],8)
        self.assertEqual(len(result['inventory_references']),32)
        self.assertEqual([r['formal']['logical_ordinal'] for r in result['rows']],list(range(1,25)))
        self.assertEqual((rows,files),original)
        self.assertFalse(result['training_release'])
        self.assertFalse(result['rows'][0]['matches'][0]['basename_equal'])

    def test_normalized_sha_never_rescues_raw_miss(self):
        rows, files = fixture()
        rows[0]['source_sha256'] = 'd'*64
        rows[0]['normalized_sha256'] = files[0]['sha256']
        result = m.join_sources(rows,files)
        self.assertEqual(result['class_counts']['ZERO_ORIGINAL_SHA_MATCH'],1)
        self.assertFalse(result['all_formal_bytes_found'])
        self.assertEqual(result['rows'][0]['matches'],[])

    def test_identical_bytes_multi_locations_not_collapsed(self):
        rows, files = fixture()
        files[24]['sha256'] = files[0]['sha256']
        result = m.join_sources(rows,files)
        self.assertEqual(result['class_counts']['MULTIPLE_IDENTICAL_BYTES_LOCATIONS'],1)
        self.assertEqual(len(result['rows'][0]['matches']),2)
        self.assertTrue(result['all_formal_bytes_found'])
        self.assertFalse(result['all_physical_locations_unique'])

    def test_rowcount_contradiction_fails_closed(self):
        rows, files = fixture()
        files[0]['row_count'] += 1
        with self.assertRaisesRegex(ValueError,'ROW_COUNT_CONTRADICTION'):
            m.join_sources(rows,files)

    def test_same_hash_different_circuit_stage_not_joined(self):
        rows, files = fixture()
        rows[0]['source_sha256'] = files[1]['sha256']
        result = m.join_sources(rows,files)
        self.assertEqual(result['rows'][0]['matches'],[])

    def test_grid_duplicate_and_inventory_path_duplicate_rejected(self):
        rows, files = fixture()
        rows[1] = dict(rows[0])
        with self.assertRaises(ValueError):
            m.join_sources(rows,files)
        rows, files = fixture()
        files[-1]['path'] = files[0]['path']
        files[-1]['coverage_root'] = files[0]['coverage_root']
        with self.assertRaises(ValueError):
            m.join_sources(rows,files)

    def test_bool_counts_are_not_integer_metadata(self):
        rows, files = fixture()
        rows[0]['row_count'] = True
        with self.assertRaises(ValueError):
            m.join_sources(rows,files)

    def test_unfrozen_pin_rejects_before_any_file_read(self):
        from unittest.mock import patch
        with patch.object(m,'stable_read',side_effect=AssertionError('no reads')):
            with self.assertRaisesRegex(ValueError,'PIN_NOT_FROZEN'):
                m.pinned_json('unused',None)


if __name__ == '__main__':
    unittest.main()
