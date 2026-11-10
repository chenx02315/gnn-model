"""Local tests only; never call run() or connect A."""
import ast
import contextlib
import io
import json
from pathlib import Path
import unittest
from unittest import mock
from scripts import probe_a_python_builtins_v1 as m


class Tests(unittest.TestCase):
    def test_payload_fixed_no_project_or_process_source(self):
        body=m.payload()
        self.assertEqual(len(body),961)
        self.assertEqual(m.hashlib.sha256(body).hexdigest(),'3633d18539a4f7fac817d50134922d06afb00864325ec2d63be2f2fe97b9441c')
        ast.parse(body,feature_version=(3,6))
        for text in (b'capture_runtime',b'PROFILE_B64',b'subprocess',b'open(',b'module load',b'LM_LICENSE_FILE'):
            self.assertNotIn(text,body)

    def test_local_generic_expression_no_child(self):
        out=io.StringIO()
        with mock.patch('socket.gethostname',return_value='bupt-vncs2'), contextlib.redirect_stdout(out), \
             mock.patch('subprocess.Popen') as child:
            exec(compile(m.payload(),'<local-generic-probe>','exec'),{})
        child.assert_not_called()
        value=json.loads(out.getvalue())
        self.assertEqual(value['results']['explicit_nine'],'BUILTINS_AVAILABLE')
        self.assertIs(value['project_source_sent'],False)

    def test_saved_target_observation_is_measured_not_local_emulation(self):
        p=Path(__file__).resolve().parents[1]/'data/manifests/a_python_builtins_readonly_observation_20261110.json'
        value=json.loads(p.read_bytes())
        self.assertEqual(value['status'],'VALIDATED_READONLY_PROBE')
        self.assertEqual(value['transport']['exit_code'],0)
        self.assertEqual(value['streams']['stderr']['bytes'],0)
        obs=value['observation']
        self.assertEqual(obs['version'],[3,6,8])
        self.assertEqual(obs['executable'],'/usr/bin/python3')
        self.assertEqual(obs['results'],dict(omitted='MISSING_REPR',explicit_nine='BUILTINS_AVAILABLE'))
        self.assertIs(obs['project_source_sent'],False)


if __name__=='__main__':unittest.main()
