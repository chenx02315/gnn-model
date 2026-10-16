"""Synthetic declaration-only fixtures; no source-file reads or CLI."""
import copy
import unittest
from unittest.mock import patch

from scripts import audit_ranking_v6_e36_roster as roster_audit


def fixture():
    inventory=[dict(circuit=c,stage_alias=a,source_file_sha256='a'*64,data_row_count='0')
               for c in roster_audit.CIRCUITS for a in roster_audit.ALIASES]
    rows=[]
    for alias in ('hf_coarse','hf_refine'):
        next(row for row in inventory if row['circuit']=='spi' and row['stage_alias']==alias)['data_row_count']='1'
        rows.append(dict(circuit='spi',stage_alias=alias,scheme='HF',h_patterns='64',m_patterns='',
            candidate_id='1',candidate_id_origin='explicit_candidate',source_candidate_uid='spi:'+alias+':H64-F4:1',
            action_uid='spi:HF:h64',source_file_sha256='a'*64,source_row='2'))
    edges=[dict(source_candidate_uid=rows[0]['source_candidate_uid'],action_uid='spi:HF:h64',circuit='spi')]
    return rows,edges,inventory


class RosterCoverageTests(unittest.TestCase):
    def setUp(self): self.inputs=fixture()
    def audit(self): return roster_audit.audit(*self.inputs)

    def test_24_files_zero_declarations_and_unmapped_sources_retained(self):
        result=self.audit()
        self.assertEqual(result['inventory_file_declaration_count'],24)
        self.assertEqual(result['declared_empty_file_count'],22)
        self.assertEqual(result['provided_roster_count'],2)
        self.assertEqual(result['mapped_source_count'],1)
        self.assertEqual(result['unmapped_source_count'],1)
        self.assertEqual(result['partially_mapped_action_count'],1)
        self.assertEqual(result['fully_mapped_action_count'],0)
        self.assertFalse(result['historical_source_completeness_certified'])

    def test_zero_edges_and_zero_declared_files_do_not_certify_history(self):
        self.inputs[1].clear()
        result=self.audit()
        self.assertEqual(result['unmapped_source_count'],2)
        self.assertEqual(result['fully_unmapped_action_count'],1)
        inventory=[dict(row,data_row_count='0') for row in self.inputs[2]]
        result=roster_audit.audit([],[],inventory)
        self.assertTrue(result['empty_declared_roster'])
        self.assertEqual(result['declared_empty_file_count'],24)
        self.assertFalse(result['pre_outcome_certified'])

    def test_row_omissions_duplicates_and_declared_counts_rejected(self):
        for kind in ('missing','duplicate','row_gap','count_mismatch','inventory_missing','inventory_duplicate'):
            self.inputs=fixture()
            rows,edges,inventory=self.inputs
            if kind=='missing': rows.pop()
            elif kind=='duplicate': rows.append(dict(rows[0]))
            elif kind=='row_gap': rows[0]['source_row']='3'
            elif kind=='count_mismatch': next(r for r in inventory if r['circuit']=='spi' and r['stage_alias']=='hf_coarse')['data_row_count']='2'
            elif kind=='inventory_missing': inventory.pop()
            else: inventory[-1]=dict(inventory[0])
            with self.subTest(kind=kind),self.assertRaises(roster_audit.RosterAuditError): self.audit()

    def test_coarse_and_refine_fallback_origin_and_explicit_zero(self):
        for row in self.inputs[0]: row['candidate_id_origin']='one_based_data_row'
        self.assertEqual(self.audit()['candidate_id_origin_counts']['one_based_data_row'],2)
        self.inputs[0][0]['candidate_id']='0'
        with self.assertRaisesRegex(roster_audit.RosterAuditError,'DATA_ROW_FALLBACK_JOIN'): self.audit()
        self.inputs[0][0].update(candidate_id_origin='explicit_candidate',source_candidate_uid='spi:hf_coarse:H64-F4:0')
        self.inputs[1][0]['source_candidate_uid']='spi:hf_coarse:H64-F4:0'
        self.assertEqual(self.audit()['mapped_source_count'],1)

    def test_hf_zero_normalized_and_hmf_canonical_action(self):
        self.inputs[0][0]['m_patterns']='0'
        self.assertEqual(self.audit()['provided_action_count'],1)
        self.inputs=fixture()
        row=self.inputs[0][0]
        row.update(stage_alias='hmf_coarse',scheme='HMF',m_patterns='16',
                   source_candidate_uid='spi:hmf_coarse:H64-M16-F4:1',action_uid='spi:HMF:h64:m16')
        for inv in self.inputs[2]:
            if inv['circuit']=='spi' and inv['stage_alias']=='hf_coarse': inv['data_row_count']='0'
            if inv['circuit']=='spi' and inv['stage_alias']=='hmf_coarse': inv['data_row_count']='1'
        self.inputs[1][0].update(source_candidate_uid=row['source_candidate_uid'],action_uid=row['action_uid'])
        self.assertEqual(self.audit()['provided_action_count'],2)

    def test_edges_orphans_duplicates_configuration_and_cross_circuit(self):
        for change in (dict(source_candidate_uid='spi:hf_coarse:H64-F4:999'),dict(action_uid='wrong'),dict(circuit='aes_core')):
            self.inputs=fixture()
            self.inputs[1][0].update(change)
            with self.assertRaises(roster_audit.RosterAuditError): self.audit()
        self.inputs=fixture()
        self.inputs[1].append(dict(self.inputs[1][0]))
        with self.assertRaisesRegex(roster_audit.RosterAuditError,'DUPLICATE_SOURCE_ACTION_EDGE'): self.audit()

    def test_unknown_quality_fields_noncanonical_bounds_and_roles_rejected(self):
        changes=[('h_patterns','064'),('candidate_id','01'),('source_row','02'),('h_patterns','1.0'),
                 ('m_patterns','00'),('source_file_sha256','A'*64),('candidate_id','1000000001'),
                 ('source_row','100002'),('circuit','s5378'),('circuit','s9234')]
        for field,value in changes:
            self.inputs=fixture()
            self.inputs[0][0][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(roster_audit.RosterAuditError): self.audit()
        for field in ('total_cycles','result_status','is_d95_feasible','role'):
            self.inputs=fixture()
            self.inputs[0][0][field]='forbidden'
            with self.assertRaisesRegex(roster_audit.RosterAuditError,'EXACT_METADATA_FIELDS'): self.audit()
        self.inputs=fixture()
        self.inputs[2][0]['data_row_count']='100001'
        with self.assertRaisesRegex(roster_audit.RosterAuditError,'COUNT_BOUND'): self.audit()

    def test_file_hash_binding_and_canonical_uid_join(self):
        for change in (dict(source_file_sha256='b'*64),dict(source_candidate_uid='spi:hf_coarse:H64-F4:2'),
                       dict(action_uid='spi:HF:h065'),dict(scheme='HMF')):
            self.inputs=fixture()
            self.inputs[0][0].update(change)
            with self.assertRaises(roster_audit.RosterAuditError): self.audit()

    def test_exact_builtin_types_and_no_io_no_mutation_order_stability(self):
        before=copy.deepcopy(self.inputs)
        with patch('builtins.open',side_effect=AssertionError('IO')),patch('os.open',side_effect=AssertionError('FD')):
            result=self.audit()
        self.assertEqual(before,self.inputs)
        for rows in self.inputs: rows.reverse()
        self.assertEqual(result,self.audit())
        with self.assertRaises(roster_audit.RosterAuditError): roster_audit.audit(tuple(self.inputs[0]),self.inputs[1],self.inputs[2])
        self.inputs[0][0]['source_row']=2
        with self.assertRaises(roster_audit.RosterAuditError): self.audit()
        for field in ('pre_outcome_certified','inventory_origin_authenticated','training_release','physical_files_read',
                      'source_quality_or_eligibility_accessed','costs_or_outcomes_computed','fit_targets_generated','online_claim'):
            self.assertFalse(result[field])


if __name__=='__main__': unittest.main()
