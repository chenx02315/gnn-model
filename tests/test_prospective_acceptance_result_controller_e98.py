import ast
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from scripts import execute_acceptance_result_observation_e98 as m


class Tests(unittest.TestCase):
    def test_bad_index_no_prepare(self):
        for index in ('0','-1','01','49','1000','1.0','17/../../resume'):
            with self.subTest(index=index), patch.object(sys,'argv',['controller','x','y',index]),patch.object(m.inspector,'prepare_payload') as prepare:
                with self.assertRaises(ValueError):m.main()
                prepare.assert_not_called()

    def test_exact_one_control_call_and_fixed_identity(self):
        value=dict(schema='e98-job-result-observation-v1',job_id=394238,
            scheduler_client_status='CLIENT_COMPLETE',scheduler_returncode=0,files=[])
        prepared=dict(payload=b'# fake',response_cap=262144)
        with patch.object(sys,'argv',['controller','a'*64,'b'*64,'1']), \
             patch.object(m.inspector,'prepare_payload',return_value=prepared), \
             patch.object(m.control,'execute_phase',return_value=dict(response=value,phase='mock-only')) as execute:
            m.main()
            execute.assert_called_once_with('job_observation_1',b'# fake','b'*64,262144)

    def test_extended_receipt_slots_preserve_exact_same_payload_and_one_call(self):
        value=dict(schema='e98-job-result-observation-v1',job_id=394238,
            scheduler_client_status='CLIENT_COMPLETE',scheduler_returncode=0,files=[])
        for index in ('17','48'):
            with self.subTest(index=index), patch.object(sys,'argv',['controller','a'*64,'b'*64,index]), \
                 patch.object(m.inspector,'prepare_payload',return_value=dict(payload=b'# unchanged',response_cap=262144)), \
                 patch.object(m.control,'execute_phase',return_value=dict(response=value,phase='mock-only')) as execute, \
                 patch('builtins.print'):
                m.main()
                execute.assert_called_once_with('job_observation_'+index,b'# unchanged','b'*64,262144)

    def test_python36(self):
        ast.parse(Path(m.__file__).read_text(),feature_version=(3,6))


if __name__=='__main__':unittest.main()
