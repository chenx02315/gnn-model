import ast
import json
from pathlib import Path
import unittest
from unittest.mock import Mock,patch
from src.data import direct_tessent_acceptance_e101 as m


class Tests(unittest.TestCase):
    def authority(self):
        # Synthetic unit-test authority, never written as actual user consent.
        return dict(schema='direct-tessent-repair-authorization-e101-v1',
            user_authorization_received=True,approval_source='explicit_user_reply',user_reply='SYNTHETIC_TEST_ONLY',
            root=m.ROOT,predecessor_execution_response_sha256=m.FAILED_RESPONSE_SHA,
            additional_launch_attempts_max=4,workers=1,automatic_retries=0,
            sampled_rss_plus_swap_stop_bytes=536870912,per_case_seconds_including_cleanup=600,
            session_seconds=2700,combined_output_bytes=16777216,process_count_stop_threshold=64,
            scratch_stop_threshold_bytes=134217728,lsf_allowed=False,kernel_memory_cap_required=False,
            atpg_generation_allowed=False,training_allowed=False,blind_allowed=False)

    def raw(self,value):return json.dumps(value).encode('utf-8')

    def test_unapproved_proposal_and_old_authority_are_not_run_authority(self):
        root=Path(__file__).resolve().parents[1]
        for name in ('direct_tessent_repair_e101_proposal_v1.json','direct_tessent_authorization_e100_20261025.json'):
            with patch.object(m.base,'execute') as run,self.assertRaisesRegex(ValueError,'ADDITIONAL_RUN_AUTHORITY'):
                m.execute(b'',b'',(root/'contracts'/name).read_bytes())
            run.assert_not_called()

    def test_scope_budgets_and_boolean_numbers_are_not_widened(self):
        for key,bad in (('user_authorization_received',False),('root','/tmp/other'),
                        ('additional_launch_attempts_max',5),('workers',True),('session_seconds',2700.0),
                        ('lsf_allowed',True),('training_allowed',True),('automatic_retries',1)):
            value=self.authority();value[key]=bad
            with self.subTest(key=key),self.assertRaises(ValueError):m.validate_authority(self.raw(value))

    def test_sample_method_reuses_reviewed_helper(self):
        domain=object.__new__(m.RepairedDescendants)
        with patch.object(m.sampler,'sample_descendants',return_value='marker') as collect:
            self.assertEqual(domain.sample(),'marker')
            collect.assert_called_once_with(domain,m.base._identity,m.base._small)

    def test_source_bindings_before_base_execute(self):
        with patch.object(m.base,'execute') as run,self.assertRaisesRegex(ValueError,'PARENT_SOURCE_BINDING'):
            m.execute(b'',b'',self.raw(self.authority()))
        run.assert_not_called()

    def test_new_root_and_native_new_authority_restored_after_call(self):
        before=(m.base.ROOT,m.base.Descendants,m.base.DirectMaterializer,m.base.validate_authority,
                m.base.recipe.ROOT,m.base.material.RECIPE_SHA256)
        def run(a,b,raw):
            self.assertEqual(m.base.ROOT,m.ROOT)
            self.assertIs(m.base.Descendants,m.RepairedDescendants)
            self.assertIs(m.base.DirectMaterializer,m.RepairMaterializer)
            self.assertEqual(m.base.validate_authority(raw)['schema'],'direct-tessent-repair-authorization-e101-v1')
            return {'SYNTHETIC_TEST_ONLY':True}
        with patch.object(m.base,'__source_sha256__',m.BASE_SHA,create=True), \
             patch.object(m.sampler,'__source_sha256__',m.SAMPLER_SHA,create=True), \
             patch.object(m.base,'execute',side_effect=run):
            result=m.execute(b'85',b'93',self.raw(self.authority()))
            self.assertTrue(result['SYNTHETIC_TEST_ONLY'])
        after=(m.base.ROOT,m.base.Descendants,m.base.DirectMaterializer,m.base.validate_authority,
               m.base.recipe.ROOT,m.base.material.RECIPE_SHA256)
        self.assertEqual(before,after)

    def test_restore_also_on_failure_and_no_automatic_retry(self):
        root=m.base.ROOT
        with patch.object(m.base,'__source_sha256__',m.BASE_SHA,create=True), \
             patch.object(m.sampler,'__source_sha256__',m.SAMPLER_SHA,create=True), \
             patch.object(m.base,'execute',side_effect=RuntimeError('SYNTHETIC')) as run:
            with self.assertRaises(RuntimeError):m.execute(b'',b'',self.raw(self.authority()))
            run.assert_called_once()
        self.assertEqual(m.base.ROOT,root)

    def test_python36(self):ast.parse(Path(m.__file__).read_text(encoding='utf-8'),feature_version=(3,6))


if __name__=='__main__':unittest.main()
