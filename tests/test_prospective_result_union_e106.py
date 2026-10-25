"""Synthetic in-memory fault sets and reports only; no data files or tools."""
import copy
import json
import unittest
from unittest.mock import patch

from src.data import prospective_result_union_e106 as m
from tests.test_prospective_tessent_stage_v1 import markers


class Tests(unittest.TestCase):
    def setUp(self):
        self.plan=m.pilot.build_plan()
        self.freeze=m.acquisition.freeze_acquisition(self.plan,'aes_core',20,'a'*64)
        lines=['stuck_value\tcanonical_core_path\tH_native_path\tM_native_path\tF_native_path']
        for i in range(20):
            core='/U%d/p'%(10+i);native='/U%d/p'%(9+i)
            lines.append('\t'.join(('0',core,core,core,native)))
        self.mapping=('\n'.join(lines)+'\n').encode('ascii')

    def rows(self,scheme='HMF',sets=None):
        action=next(r for r in self.freeze['requested_roster'] if r['scheme']==scheme)['action_uid']
        nodes=[n for n in self.plan['phases'][0]['tasks'] if n['action_uid']==action and n['kind']=='TESSENT']
        if sets is None:sets=[set(range(10)),set(range(5,15)),set(range(10,19))] if scheme=='HMF' else [set(range(10)),set(range(10,19))]
        rows=[];previous_sha=None;previous_uid=None;previous_count=None
        for node,detected in zip(nodes,sets):
            mode=node['stage']
            request=dict(run_uid='synthetic-e106',action_uid=action,attempt_uid=node['task_uid'],
                stage=mode,stage_index=node['stage_index'],freeze_sha256=self.freeze['freeze_sha256'],
                control=copy.deepcopy(node['control']),parent_attempt_uid=previous_uid,parent_result_sha256=previous_sha)
            recipe=m.reports.compile_stage(self.freeze,request)
            mtfi=list(m.faults.HEADER)
            for i in range(20):
                path='/U%d/p'%((9 if mode=='F' else 10)+i)
                cls=('DI.CLK' if i==0 else 'DS') if i in detected else 'RE'
                mtfi.append('   0, %s, "%s";\n'%(cls,path))
            mtfi.extend(m.faults.FOOTER)
            raw=dict(statistics=('#test_patterns 2\nFU 20\nDS %d\nDI 0\n'%len(detected)).encode('ascii'),
                stil=b'Header TesterCycle:7 Other TesterCycle:10\n',driver_log=markers(recipe).encode('ascii'),
                mtfi=''.join(mtfi).encode('ascii'),pre_statistics=(None if mode=='H' else
                    ('FU 20\nDS %d\nDI 0\n'%previous_count).encode('ascii')))
            reference=m.build_stage_reference(self.freeze,request,self.mapping,1,raw)
            previous_sha=reference['output_reference_sha256'];previous_uid=node['task_uid'];previous_count=len(detected)
            rows.append(dict(request=request,artifacts=raw))
        return rows

    def inspect(self,rows=None):
        return m.inspect_action(self.freeze,self.mapping,1,self.rows() if rows is None else rows)

    def test_hmf_union_deduplicates_and_retains_no_release_flags(self):
        rows=self.rows();before=copy.deepcopy(rows)
        with patch('builtins.open',side_effect=AssertionError('no file I/O')),patch('subprocess.Popen') as spawn:
            result=self.inspect(rows)
        self.assertEqual(before,rows)
        self.assertEqual(result['explicit_ds_di_union_count'],19)
        self.assertEqual(result['sum_stage_detection_counts'],29)
        self.assertTrue(result['meets_declared_d95_math'])
        self.assertEqual(result['sum_reported_stage_ate_cycles'],30)
        self.assertFalse(result['combined_pattern_cycles_qualified'])
        self.assertFalse(result['d95_verified'])
        self.assertIsNone(result['actual_atpg_wall_time_ns'])
        self.assertIsNone(result['positive_training_label'])
        self.assertFalse(result['training_release'])
        self.assertLess(len(result['stages'][0]['output_reference_bytes']),m.binding.MAX_OUTPUT_BYTES)
        spawn.assert_not_called()

    def test_incremental_reference_factory_pins_roles_sizes_and_request_not_qualification(self):
        row=self.rows()[0]
        reference=m.build_stage_reference(self.freeze,row['request'],self.mapping,1,row['artifacts'])
        manifest=json.loads(reference['output_reference_bytes'])
        self.assertEqual(manifest['qualification'],'UNQUALIFIED_BYTES_REFERENCE')
        self.assertEqual(manifest['task_uid'],row['request']['attempt_uid'])
        self.assertEqual(manifest['request_sha256'],m.reports.digest(row['request']))
        self.assertEqual(reference['output_reference_sha256'],m.sha(reference['output_reference_bytes']))
        for name,raw in row['artifacts'].items():
            self.assertEqual(manifest['artifact_bytes'][name],None if raw is None else len(raw))
            self.assertEqual(manifest['artifact_sha256'][name],None if raw is None else m.sha(raw))
        self.assertFalse(reference['qualified'])
        self.assertFalse(reference['training_release'])

    def test_hf_exact_95_and_below_95_not_positive(self):
        self.assertTrue(self.inspect(self.rows('HF'))['meets_declared_d95_math'])
        value=self.inspect(self.rows('HF',[set(range(10)),set(range(5,15))]))
        self.assertEqual(value['explicit_ds_di_union_count'],15)
        self.assertEqual(value['sum_stage_detection_counts'],20)
        self.assertFalse(value['meets_declared_d95_math'])
        self.assertIsNone(value['positive_training_label'])

    def test_parent_reference_artifact_tamper_or_run_change_rejected(self):
        for change in ('parent','bytes','run'):
            rows=self.rows()
            if change=='parent':rows[1]['request']['parent_result_sha256']='b'*64
            elif change=='bytes':rows[0]['artifacts']['stil']=b'TesterCycle:11\n'
            else:rows[1]['request']['run_uid']='other-run'
            with self.assertRaises(ValueError):self.inspect(rows)

    def test_wrong_counts_missing_fault_duplicate_or_unknown_class_rejected(self):
        for change in ('counts','missing','duplicate','unknown'):
            rows=self.rows();raw=rows[0]['artifacts']
            if change=='counts':raw['statistics']=b'#test_patterns 2\nFU 20\nDS 11\nDI 0\n'
            elif change=='missing':raw['mtfi']=raw['mtfi'].replace(b'   0, DS, "/U11/p";\n',b'')
            elif change=='duplicate':raw['mtfi']=raw['mtfi'].replace(b'"/U11/p"',b'"/U10/p"')
            else:raw['mtfi']=raw['mtfi'].replace(b'DI.CLK',b'DI.UNKNOWN')
            with self.assertRaises(ValueError):self.inspect(rows)

    def test_no_silent_zero_cycles_or_failed_marker(self):
        for text in (b'',b'TesterCycle:1x',b'No cycles for zero patterns'):
            rows=self.rows();rows[0]['artifacts']['stil']=text
            with self.assertRaises(ValueError):self.inspect(rows)
        rows=self.rows();rows[0]['artifacts']['driver_log']+=b'FATAL actual failure\n'
        with self.assertRaises(ValueError):self.inspect(rows)

    def test_incomplete_duplicate_reordered_and_foreign_task_rejected(self):
        rows=self.rows()
        cases=[rows[:2],[rows[0],rows[0],rows[2]],list(reversed(rows))]
        foreign=copy.deepcopy(rows);foreign[0]['request']['attempt_uid']='other-attempt';cases.append(foreign)
        for value in cases:
            with self.assertRaises(ValueError):self.inspect(value)

    def test_byte_and_offset_bounds_and_mapping_namespace(self):
        with self.assertRaises(ValueError):m.inspect_action(self.freeze,self.mapping,True,self.rows())
        with self.assertRaises(ValueError):m.inspect_action(self.freeze,self.mapping,0,self.rows())
        rows=self.rows();rows[0]['artifacts']['statistics']=b'X'*65537
        with self.assertRaises(ValueError):self.inspect(rows)

    def test_unmapped_wrong_mode_and_unjustified_pre_parent_rejected(self):
        rows=self.rows();rows[-1]['artifacts']['mtfi']=rows[-1]['artifacts']['mtfi'].replace(b'/U9/p',b'/U999/p')
        with self.assertRaises(ValueError):self.inspect(rows)
        rows=self.rows();rows[1]['artifacts']['pre_statistics']=b'FU 20\nDS 1\nDI 0\n'
        with self.assertRaises(ValueError):self.inspect(rows)

    def test_mismatched_frozen_denominator_and_outcome_field_rejected(self):
        wrong=m.acquisition.freeze_acquisition(self.plan,'aes_core',21,'a'*64)
        with self.assertRaises(ValueError):m.inspect_action(wrong,self.mapping,1,self.rows())
        rows=self.rows();rows[0]['request']['quality']=95
        with self.assertRaises(ValueError):self.inspect(rows)

    def test_changed_offset_or_duplicate_mapping_rejected(self):
        bad=self.mapping.replace(b'/U11/p',b'/U10/p')
        with self.assertRaises(ValueError):m.inspect_action(self.freeze,bad,1,self.rows())
        with self.assertRaises(ValueError):m.inspect_action(self.freeze,self.mapping,2,self.rows())
