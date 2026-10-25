import ast
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch
from scripts import acceptance_transport_e98 as m


class Tests(unittest.TestCase):
    def test_receipt_extension_is_bounded_and_not_a_job_operation(self):
        self.assertEqual(m.MAX_JOB_OBSERVATIONS,48)
        for index in range(1,49):
            self.assertIn('job_observation_'+str(index),m.OPERATIONS)
        for invalid in ('job_observation_0','job_observation_49','job_observation_01','resume_2','registration_2'):
            self.assertNotIn(invalid,m.OPERATIONS)

    def test_bad_pin_or_operation_never_loads(self):
        with patch.object(m,'load_transport') as load:
            for operation,pin in (('bad','0'*64),('retire_observe','0'*64)):
                with self.assertRaises(ValueError): m.execute_phase(operation,b'# mock',pin)
            load.assert_not_called()

    def test_exclusive_one_transport_unknown_not_retried(self):
        for failed in (False,True):
            with tempfile.TemporaryDirectory() as directory:
                helper=Mock()
                helper.verify_cached_host.return_value='mock-only'
                helper.decode.side_effect=json.loads
                helper.transport.return_value=dict(stdout=b'{"mock":true}',stderr=b'',exit_code=1 if failed else 0,
                    timeout=False,overflow=False,write_failed=False,threads_incomplete=False,remote_termination_verified=False)
                with patch.object(m,'STAGING',Path(directory)),patch.object(m,'load_transport',return_value=helper):
                    if failed:
                        with self.assertRaisesRegex(ValueError,'NO_RETRY'): m.execute_phase('retire_observe',b'x',m.sha(b'x'))
                    else: self.assertTrue(m.execute_phase('retire_observe',b'x',m.sha(b'x'))['response']['mock'])
                    with self.assertRaises(FileExistsError): m.execute_phase('retire_observe',b'x',m.sha(b'x'))
                helper.transport.assert_called_once()

    def test_python36(self):
        ast.parse(Path(m.__file__).read_text(),feature_version=(3,6))


if __name__=='__main__': unittest.main()
