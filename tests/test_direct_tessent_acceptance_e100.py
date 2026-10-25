import ast
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock,patch

from src.data import direct_tessent_acceptance_e100 as m
from scripts import run_direct_tessent_e100 as entry


class Tests(unittest.TestCase):
    def authority(self):
        return json.loads((Path(__file__).resolve().parents[1]/entry.AUTH).read_text(encoding='utf-8'))

    def test_explicit_removal_does_not_authorize_other_scope(self):
        self.assertFalse(m.validate_authority(json.dumps(self.authority()).encode())['kernel_memory_cap_required'])
        for key,value in (('user_instruction','continue'),('kernel_memory_cap_required',True),
                          ('lsf_allowed',True),('automatic_retries',1),('cases_max',5),
                          ('training_allowed',True),('blind_allowed',True)):
            changed=self.authority();changed[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):m.validate_authority(json.dumps(changed).encode())

    def test_preflight_is_explicitly_not_lsf_or_kernel_proof(self):
        result=m.DirectMaterializer._preflight(object())
        self.assertFalse(result['kernel_memory_cap_enforced']);self.assertFalse(result['lsf_used'])
        self.assertFalse(result['sampling_is_hard_memory_guarantee'])
        self.assertNotIn('job_id',result)

    def test_materializer_override_never_calls_lsf_preflight(self):
        authority=json.dumps(self.authority()).encode()
        old_root=m.recipe.ROOT;old_pin=m.material.RECIPE_SHA256
        try:
            with patch.object(m.material,'collect_preflight',side_effect=AssertionError('NO LSF')):
                value=m.DirectMaterializer((entry.ROOT/entry.E85).read_bytes(),(entry.ROOT/entry.E93).read_bytes(),authority)
                self.assertEqual(len(value.recipe['items']),4)
                self.assertTrue(all(x['future_scratch'].startswith(m.ROOT+'/') for x in value.recipe['items']))
                self.assertFalse(value._preflight()['kernel_memory_cap_enforced'])
        finally:m.recipe.ROOT=old_root;m.material.RECIPE_SHA256=old_pin

    def test_memory_stop_is_sampled_and_includes_coordinator(self):
        domain=object.__new__(m.Descendants);domain.pid=100;domain.peak=0
        domain.snapshot=lambda:{101:(101,1,'S')}
        with patch.object(m,'_identity',return_value=(100,1,'S',1,100,100)),patch.object(m,'_small',return_value=b'VmRSS: 100 kB\nVmSwap: 20 kB\n'):
            domain.sample();self.assertEqual(domain.peak,2*120*1024)
        with patch.object(m,'_identity',return_value=(100,1,'S',1,100,100)),patch.object(m,'_small',return_value=b'VmRSS: 600000 kB\nVmSwap: 0 kB\n'):
            with self.assertRaisesRegex(ValueError,'SAMPLED_MEMORY_STOP'):domain.sample()

    def test_missing_live_memory_is_not_zero(self):
        domain=object.__new__(m.Descendants);domain.pid=100;domain.peak=0;domain.snapshot=lambda:{}
        with patch.object(m,'_identity',return_value=(100,1,'S',1,100,100)),patch.object(m,'_small',return_value=b'VmRSS: 10 kB\n'):
            with self.assertRaisesRegex(ValueError,'MEMORY_STATUS'):domain.sample()

    def test_cleanup_does_not_reuse_overflowing_monitor_enumerator(self):
        domain=object.__new__(m.Descendants);domain.pid=100
        domain.snapshot=Mock(side_effect=AssertionError('monitor overflow must not block cleanup'))
        domain._direct_batch=Mock(side_effect=[([101],False),([],False)])
        proc=Mock();proc.pid=101;proc.returncode=0
        with patch.object(m,'_identity',return_value=(101,5,'S',100,101,101)),patch.object(m.signal,'SIGKILL',9,create=True),patch.object(m.os,'kill') as kill:
            self.assertTrue(domain.cleanup(proc,m.time.monotonic()+1))
            kill.assert_called_once_with(101,9)
        domain.snapshot.assert_not_called()

    def test_parent_reuse_and_foreign_parent_are_not_owned(self):
        domain=object.__new__(m.Descendants);domain.pid=100;domain.identity=(100,1,'S',1,100,100)
        with patch.object(m,'_identity',return_value=(100,2,'S',1,100,100)),patch.object(m,'_children') as children:
            with self.assertRaisesRegex(ValueError,'PARENT_IDENTITY_CHANGED'):domain.snapshot()
            children.assert_not_called()
        def identity(pid):return domain.identity if pid==100 else (101,9,'S',999,101,101)
        with patch.object(m,'_identity',side_effect=identity),patch.object(m,'_children',return_value={101}):
            self.assertEqual(domain.snapshot(),{})

    def test_zero_output_budget_never_launches(self):
        domain=Mock();domain._direct_batch.return_value=([],False);domain.peak=0
        with patch.object(m.subprocess,'Popen') as launch:
            result=m.supervise(['fixed'],'fixed',m.time.monotonic()+20,domain,[0])
        launch.assert_not_called();self.assertFalse(result['launch_attempted'])
        self.assertEqual(result['failure'],'OUTPUT_STOP')

    def test_prelaunch_sampling_cannot_spend_cleanup_reserve_then_spawn(self):
        domain=Mock();domain._direct_batch.return_value=([],False);domain.peak=0
        with patch.object(m.time,'monotonic',side_effect=[0,99]),patch.object(m.subprocess,'Popen') as launch:
            result=m.supervise(['fixed'],'fixed',100,domain,[100])
        launch.assert_not_called();self.assertEqual(result['failure'],'PRELAUNCH_TIMEOUT')

    def test_marker_is_exact_line_and_diagnostics_not_command_options(self):
        marker=b'E94_TRANSLATED_STATUS_ACCEPTANCE=PASS aes_core H_TO_M'
        self.assertTrue(m.accepts_log(b'read_faults -show_warnings\n'+marker+b'\n',marker))
        for log in (b'puts "'+marker+b'"\n',b'PREFIX '+marker+b'\n',marker+b' suffix\n',
                    marker+b'\n'+marker+b'\n',b'// Warning: real diagnostic\n'+marker+b'\n',
                    b'** Error: real diagnostic\n'+marker+b'\n',b'[license] WARNING: real diagnostic\n'+marker+b'\n'):
            self.assertFalse(m.accepts_log(log,marker))

    def test_setsid_readiness_requires_observed_child_identity(self):
        domain=Mock();domain.snapshot.return_value={101:(101,5,'S',100,101,101)}
        with patch.object(m,'_identity',return_value=(101,5,'S',100,101,101)):
            self.assertTrue(m._setsid_readiness(b'DIRECT_SETSID_READY 101\n',domain)['observed_from_own_descendant_tree'])
        domain.snapshot.return_value={}
        with self.assertRaisesRegex(ValueError,'NOT_DESCENDANT'):m._setsid_readiness(b'DIRECT_SETSID_READY 101\n',domain)

    def test_synthetic_setsid_never_passes_without_readiness(self):
        domain=Mock()
        replies=[dict(cleaned=True,returncode=0,failure=None,readiness=None),
                 dict(cleaned=True,returncode=-9,failure='CASE_TIMEOUT',readiness=None),
                 dict(cleaned=True,returncode=-9,failure='CASE_TIMEOUT',readiness=None)]
        with patch.object(m,'supervise',side_effect=replies):
            with self.assertRaisesRegex(ValueError,'READINESS_MISSING'):m.synthetic_gate(domain)

    def test_preparation_no_execution_exact_data_and_sources(self):
        with patch('subprocess.Popen') as spawn:
            result=entry.prepare()
        spawn.assert_not_called()
        self.assertEqual(result['input_sha256']['e85'],m.recipe.E85_SHA256)
        self.assertEqual(result['input_sha256']['e93'],m.recipe.E93_SHA256)
        self.assertLess(result['payload_bytes'],524288)
        compile(result['payload'],'<prepared not run>','exec')

    def test_wrong_review_pin_never_connects(self):
        with patch.object(sys,'argv',['entry','execute','bad']),patch.object(entry.control,'load_transport') as connect:
            with self.assertRaises(ValueError):entry.main()
            connect.assert_not_called()

    def test_sources_python36(self):
        for mod in (m,entry):ast.parse(Path(mod.__file__).read_text(encoding='utf-8'),feature_version=(3,6))


if __name__=='__main__':unittest.main()
