"""Fabricated metadata only; no actual E35 CLI, tables or remote calls."""
import ast
import contextlib
import copy
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts import check_ranking_v6_e35_failed_exclusions as check


def fixture():
    manifests,exclusions=[],[]
    for i,(stage,reason) in enumerate((('01_probe','OUT_OF_SCOPE_STAGE'),
                                     ('02_hf_coarse','NON_ELIGIBLE_SOURCE_INVOCATION'))):
        row={field:'' for field in check.mapping.reader.MANIFEST_FIELDS}
        row.update(circuit='s38417',family='iscas89_s38417',role='TRAIN',attempt_id='SECRET'+str(i),
                   mode='F',stage=stage,wall_s=('10.580' if i==0 else '2'),attempt_outcome_class='FAILURE',
                   source_log_path='/never/read/log',source_log_sha256='a'*64,retry_group_id='SECRET_GROUP')
        manifests.append(row)
        exclusions.append(dict(circuit='s38417',stage=stage,mode='F',attempt_id=row['attempt_id'],exclusion_reason=reason))
    return manifests,exclusions


class FailedExclusionTests(unittest.TestCase):
    def setUp(self): self.inputs=fixture()
    def diagnose(self): return check.diagnose(*self.inputs)

    def test_exclusion_reasons_formal_flag_and_decimal_totals_not_eligibility(self):
        result=self.diagnose()
        self.assertEqual(result['failed_or_timeout_count'],2)
        self.assertEqual(result['failed_timeout_declared_wall_sum_s'],'12.580')
        self.assertEqual(result['by_exclusion_reason']['OUT_OF_SCOPE_STAGE']['declared_wall_sum_s'],'10.580')
        self.assertEqual({row['stage_is_formal'] for row in result['details']},{True,False})
        self.assertNotIn('SECRET',json.dumps(result))
        self.assertNotIn('/never/read',json.dumps(result))
        for flag in ('eligibility_inferred','formal_stage_is_eligibility_certificate','sessions_reassigned',
                     'formal_action_edges_added','original_E35_result_changed','candidate_quality_accessed'):
            self.assertFalse(result[flag])

    def test_missing_unknown_and_mismatched_exclusions_are_explicit_partial(self):
        self.inputs[1].pop()
        self.assertEqual(self.diagnose()['missing_failed_exclusion_count'],1)
        self.assertTrue(self.diagnose()['status'].startswith('PARTIAL'))
        self.inputs=fixture()
        self.inputs[0][1]['attempt_outcome_class']='UNKNOWN'
        self.assertEqual(self.diagnose()['unknown_process_class_count'],1)
        self.assertTrue(self.diagnose()['status'].startswith('PARTIAL'))
        self.inputs=fixture()
        self.inputs[1][0]['mode']='H'
        self.assertEqual(self.diagnose()['exclusion_stage_mode_mismatch_count'],1)
        self.inputs[1][0]['exclusion_reason']='UNKNOWN_REASON'
        self.assertEqual(self.diagnose()['unknown_exclusion_reason_count'],1)

    def test_duplicate_target_exclusion_and_manifest_rejected(self):
        self.inputs[1].append(dict(self.inputs[1][0]))
        with self.assertRaisesRegex(check.ExclusionDiagnosticError,'DUPLICATE_TARGET_EXCLUSION'): self.diagnose()
        self.inputs=fixture()
        self.inputs[0].append(dict(self.inputs[0][0]))
        with self.assertRaisesRegex(check.ExclusionDiagnosticError,'DUPLICATE_MANIFEST_ATTEMPT'): self.diagnose()

    def test_validation_filtered_early_other_train_excluded_and_blind_rejected(self):
        val={field:('tv80' if field=='circuit' else 'INVALID_NOT_PROCESSED') for field in check.mapping.EXCLUSION_FIELDS}
        self.inputs[1].append(val)
        self.assertEqual(self.diagnose()['validation_exclusions_filtered'],1)
        self.inputs[1][-1]['circuit']='s13207'
        self.assertEqual(self.diagnose()['other_train_exclusions_filtered'],1)
        self.inputs[1][-1]['circuit']='s9234'
        with self.assertRaisesRegex(check.mapping.MappingAuditError,'CIRCUIT_SCOPE'): self.diagnose()

    def test_no_quality_columns_and_no_io_no_mutation(self):
        before=copy.deepcopy(self.inputs)
        with patch('builtins.open',side_effect=AssertionError('IO')),patch('os.open',side_effect=AssertionError('FD')), \
                patch('socket.socket',side_effect=AssertionError('NETWORK')):
            result=self.diagnose()
        self.assertEqual(before,self.inputs)
        self.inputs[0].reverse()
        self.inputs[1].reverse()
        self.assertEqual(result,self.diagnose())
        self.inputs[0][0]['total_cycles']='forbidden'
        with self.assertRaisesRegex(check.mapping.MappingAuditError,'EXACT_METADATA_SCHEMA'): self.diagnose()

    def test_timeout_truncation_and_fixed_cli_no_path_override(self):
        self.inputs[0][0]['attempt_outcome_class']='TIMEOUT'
        with patch.object(check,'MAX_DETAILS',1): result=self.diagnose()
        self.assertEqual(result['omitted_detail_count'],1)
        self.assertTrue(result['status'].startswith('PARTIAL'))
        ast.parse(Path(check.__file__).read_text(),feature_version=(3,6))
        self.assertEqual(len(check.LOCAL_SPECS),2)
        self.assertEqual({spec['kind'] for spec in check.LOCAL_SPECS},{'manifest','exclusions'})
        with patch.object(check.sys,'argv',['check','/arbitrary']), \
                patch.object(check.mapping.local_reader,'_stable_bytes',side_effect=AssertionError('IO')), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(check.main(),2)
        self.assertIn('CLI_ARGUMENTS_FORBIDDEN',output.getvalue())


if __name__=='__main__': unittest.main()
