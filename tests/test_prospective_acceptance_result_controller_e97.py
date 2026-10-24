"""Fake result transport only; no scheduler or remote calls."""
import ast
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch
from scripts import execute_acceptance_result_observation_e97 as m


class Tests(unittest.TestCase):
    def test_invalid_index_never_prepares(self):
        with patch.object(sys,'argv',['controller','x','5']), patch.object(m.inspector,'prepare_payload') as p:
            with self.assertRaises(ValueError): m.main()
            p.assert_not_called()

    def test_one_transport_exclusive_phase(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory)/'runtime_training_staging_20260928').mkdir()
            helper=Mock()
            helper.verify_cached_host.return_value='mock-only'
            helper.decode.side_effect=json.loads
            helper.transport.return_value=dict(stdout=b'{"schema":"e97-job-result-observation-v1","job_id":394230,"scheduler_client_status":"CLIENT_COMPLETE","scheduler_returncode":0,"files":[]}',stderr=b'',exit_code=0,timeout=False,overflow=False,write_failed=False,threads_incomplete=False,remote_termination_verified=False)
            prepared=dict(payload=b'# fake',payload_sha256='a'*64,response_cap=262144,phase_name='fixed-observation')
            with patch.object(sys,'argv',['controller','a'*64,'1']), \
                 patch.object(m.common,'ROOT',Path(directory)/'repo'), \
                 patch.object(m.common,'load_transport',return_value=helper), \
                 patch.object(m.inspector,'prepare_payload',return_value=prepared):
                m.main()
                with self.assertRaises(FileExistsError): m.main()
            helper.transport.assert_called_once()

    def test_python36(self):
        ast.parse(Path(m.__file__).read_text(),feature_version=(3,6))


if __name__=='__main__': unittest.main()
