"""E61 synthetic capabilities/fake SSH only; no real remote observation."""
import copy
from contextlib import ExitStack, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from scripts import observe_ranking_v6_e61_python_api as p
from scripts import run_ranking_v6_e61_readonly as t
from tests.test_ranking_v6_e59_driver_identity import FakeProcess

RESOURCE=dict(address_space_limit_bytes=512*1024*1024,cpu_limit_s=30,workers=1)


def fixture():
    return dict(status='PASS_FIXED_PYTHON_API_OBSERVATION_ONLY',platform='linux',
        python_version=[3,6,15],str_isascii_available=False,scandir_fd_advertised=False,
        resource=dict(RESOURCE),**{key:False for key in p.FALSE_FLAGS})


class PythonApiTests(unittest.TestCase):
    def test_unsupported_apis_valid_observation_not_data_audit(self):
        result=fixture()
        self.assertTrue(p.validate_response(result))
        self.assertTrue(t.validate_response(json.dumps(result).encode()))
        self.assertFalse(result['project_files_opened'])
        self.assertFalse(result['project_dirs_listed'])

    def test_schema_version_types_flags_and_unknown_fields_rejected(self):
        base=fixture()
        for key,value in (('platform','win32'),('python_version',[3,6]),('python_version',[3,True,1]),
                          ('str_isascii_available',0),('scandir_fd_advertised','false'),
                          ('project_dirs_listed',True),('training_release',True),('full_version','PRIVATE')):
            changed=copy.deepcopy(base);changed[key]=value
            self.assertFalse(p.validate_response(changed))

    def test_resource_caps_and_workers_strict(self):
        for values in (dict(RESOURCE,workers=2),dict(RESOURCE,cpu_limit_s=31),
                       dict(RESOURCE,address_space_limit_bytes=512*1024*1024+1),dict(RESOURCE,cpu_limit_s=True)):
            value=fixture();value['resource']=values
            self.assertFalse(p.validate_response(value))

    def test_mocked_main_version_apis_resources_with_zero_file_directory_probes(self):
        calls=[]
        resource=types.SimpleNamespace(RLIMIT_AS=1,RLIMIT_CPU=2,RLIM_INFINITY=-1,
            getrlimit=lambda kind:(-1,-1),setrlimit=lambda kind,value:calls.append((kind,value)))
        unavailable_str=type('SyntheticOldStr',(),{})
        output=io.StringIO()
        with ExitStack() as stack:
            stack.enter_context(patch.dict(sys.modules,{'resource':resource}))
            stack.enter_context(patch.object(p.sys,'platform','linux'))
            stack.enter_context(patch.object(p.sys,'argv',['-']))
            stack.enter_context(patch.object(p.sys,'version_info',(3,6,15)))
            stack.enter_context(patch.object(p,'str',unavailable_str,create=True))
            stack.enter_context(patch.object(p.os,'supports_fd',set()))
            mocks=[]
            for name in ('open','stat','scandir','listdir'):
                mocks.append(stack.enter_context(patch.object(p.os,name,side_effect=AssertionError('NO_FS_PROBE'))))
            stack.enter_context(patch('builtins.open',side_effect=AssertionError('NO_FILE_OPEN')))
            stack.enter_context(redirect_stdout(output))
            code=p.main()
        self.assertEqual(code,0)
        result=json.loads(output.getvalue())
        self.assertEqual(result,fixture())
        self.assertEqual(calls,[(1,(512*1024*1024,-1)),(2,(30,-1))])
        for call in mocks:call.assert_not_called()

    def test_main_wrong_platform_or_arguments_reject_before_observation(self):
        for platform,argv in (('linux',['-','override']),('win32',['-'])):
            with patch.object(p.sys,'platform',platform),patch.object(p.sys,'argv',argv), \
                 patch.object(p,'observe',side_effect=AssertionError('NO_OBSERVATION')),redirect_stdout(io.StringIO()) as output:
                self.assertEqual(p.main(),2)
            self.assertEqual(json.loads(output.getvalue())['status'],'FAIL_CLOSED_PYTHON_API_OBSERVATION')

    def test_transport_fixed_scope_caps_duplicate_json_and_pin(self):
        self.assertEqual(t.COMMAND,['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
            '-o','ConnectTimeout=8','vnc.buptic.top','/usr/bin/python3 -I -S -B -'])
        self.assertEqual(t.LIMIT,16384);self.assertEqual(t.TIMEOUT,60)
        raw=json.dumps(fixture()).encode()
        self.assertFalse(t.validate_response(raw[:-1]+b', "platform":"linux"}'))
        self.assertFalse(t.validate_response(b'x'*(t.LIMIT+1)))
        with patch.object(t.subprocess,'Popen',side_effect=AssertionError('NO_SSH')):
            with self.assertRaises(ValueError):t.run('bad','unused')
            with self.assertRaises(ValueError):t.run('0'*64,'unused')

    def fake_transport(self,process):
        source=t.SOURCE.read_bytes()
        output=Path(t.__file__).resolve().parents[2]/'runtime_training_staging_20260928/v6_e61_python_api_synthetic'
        texts={};logs={}
        def text(path,value,**kwargs):texts[path.name]=value
        def binary(path,value):logs[path.name]=value
        with patch.object(Path,'mkdir',autospec=True),patch.object(Path,'write_text',autospec=True,side_effect=text), \
             patch.object(Path,'write_bytes',autospec=True,side_effect=binary), \
             patch.object(t.subprocess,'Popen',return_value=process) as call,patch('builtins.print'):
            code=t.run(hashlib.sha256(source).hexdigest(),output)
        self.assertEqual(call.call_count,1)
        self.assertEqual(json.loads(texts['request.json'])['automatic_retries'],0)
        return code,json.loads(texts['transport.json']),logs

    def test_mock_transport_false_capabilities_accepted_once(self):
        code,result,_=self.fake_transport(FakeProcess(stdout=json.dumps(fixture()).encode()))
        self.assertEqual(code,0)
        self.assertTrue(result['accepted_metadata_receipt'])
        self.assertFalse(result['remote_termination_verified'])

    def test_mock_transport_error_timeout_or_overflow_fail_no_retry(self):
        raw=json.dumps(fixture()).encode()
        for process in (FakeProcess(stdout=raw,code=255),FakeProcess(stdout=raw,stderr=b'error'),
                        FakeProcess(stdout=raw,timeout=True),FakeProcess(stdout=b'x'*(t.LIMIT+1))):
            code,result,logs=self.fake_transport(process)
            self.assertEqual(code,2)
            self.assertFalse(result['accepted_metadata_receipt'])
            self.assertLessEqual(len(logs['stdout.log']),t.LIMIT)

    def test_isolated_validator_import_only(self):
        raw=json.dumps(fixture())
        code=(
            "import importlib.util,json,sys\n"
            "before=list(sys.path)\n"
            "spec=importlib.util.spec_from_file_location('synthetic_e61',"+repr(str(Path(t.__file__).resolve()))+")\n"
            "m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)\n"
            "assert sys.path==before and sys.flags.isolated and sys.flags.no_site\n"
            "assert m.validate_response("+repr(raw)+".encode('ascii'))\n"
            "print(json.dumps({'validated':True}))\n"
        )
        with tempfile.TemporaryDirectory() as unrelated:
            result=subprocess.run([sys.executable,'-I','-S','-B','-c',code],cwd=unrelated,capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout),{'validated':True})


if __name__=='__main__':
    unittest.main()
