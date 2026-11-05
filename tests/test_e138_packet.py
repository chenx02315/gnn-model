"""Compile and execute packets only with fake stdin/stdout; no remote calls."""
import copy
import io
import json
import shlex
from pathlib import Path
import sys
import types
import unittest
from unittest import mock
from scripts import e138_packet as m
from scripts import e138_reviewed_envelope as envelope

REPO=Path(__file__).resolve().parents[1]


class Tests(unittest.TestCase):
    def setUp(self):
        from tests.test_worker_e138_batch import Tests as WorkerTests
        self.case=WorkerTests();self.addCleanup(self.case.doCleanups);self.case.setUp()
        self.template=copy.deepcopy(self.case.freeze);self.template.pop('payload_sha256')
        self.inputs=dict(self.case.package);self.sources=dict(self.case.bodies)
        self.loader=self.case.loader;self.worker=(REPO/'scripts/worker_e138_batch.py').read_bytes()
        self.env=(REPO/'scripts/e138_reviewed_envelope.py').read_bytes()
        self.pin()

    def pin(self):
        expected=dict(compiler_sha256=m.sha(Path(m.__file__).read_bytes()),worker_sha256=m.sha(self.worker),
            loader_sha256=m.sha(self.loader),envelope_sha256=m.sha(self.env),template_sha256=m.sha(m.canonical(self.template)),
            source_sha256={k:m.sha(raw) for k,raw in self.sources.items()},source_order=tuple(self.sources),
            input_sha256={k:m.sha(raw) for k,raw in self.inputs.items()})
        patch=mock.patch.object(m,'EXPECTED',expected);patch.start();self.addCleanup(patch.stop)

    def prepare(self):return m.prepare(self.template,self.inputs,self.sources,self.worker,self.loader,self.env)

    def run_packet(self,plan,output=None,intent=None):
        buffer=io.BytesIO() if output is None else output
        original=intent or envelope.intent(self.template['role'],m.sha(plan['payload']))
        ns=dict(__role_intent__=original,__payload_sha256__=m.sha(plan['payload']),__connection_start__=1000.)
        with mock.patch.object(sys,'stdout',types.SimpleNamespace(buffer=buffer)),mock.patch('subprocess.Popen') as spawn:
            exec(compile(plan['payload'],'<test-reviewed-packet>','exec'),ns)
        spawn.assert_not_called()
        return buffer.getvalue()

    def test_default_denial_before_io_or_compile(self):
        with mock.patch.object(m,'EXPECTED',None),mock.patch('builtins.open') as opened,mock.patch('builtins.compile') as compile:
            with self.assertRaisesRegex(ValueError,'EXTERNAL_PINS_REQUIRED'):self.prepare()
        opened.assert_not_called();compile.assert_not_called()

    def test_generated_packet_reaches_real_worker_loader_contract_and_one_frame(self):
        plan=self.prepare();raw=self.run_packet(plan);value=json.loads(raw)
        self.assertEqual(value['role'],'capture');self.assertTrue(value['capture']['synthetic'])
        self.assertEqual(plan['projection']['payload_sha256'],m.sha(plan['payload']))
        self.assertEqual(plan['projection_sha256'],m.sha(m.canonical(plan['projection'])))
        self.assertFalse(plan['execution_ready'])

    def test_supplied_source_drift_rejected_before_compile(self):
        for key in ('worker','loader','env'):
            original=getattr(self,key);setattr(self,key,original+b' ')
            with mock.patch('builtins.compile') as compile:
                with self.assertRaisesRegex(ValueError,'ENTRY_SOURCE_PIN'):self.prepare()
            compile.assert_not_called();setattr(self,key,original)

    def test_bad_runtime_intent_yields_fixed_frame_without_private_text(self):
        plan=self.prepare();intent=envelope.intent('capture','d'*64)
        raw=self.run_packet(plan,intent=intent)
        self.assertEqual(json.loads(raw)['error_code'],'E138_ENTRYPOINT_FAILED')

    def test_outer_exception_sanitized_and_output_written_once(self):
        self.worker=b'def safe_dispatch(*args):raise OSError("PRIVATE_SENTINEL")\n';self.pin()
        buffer=io.BytesIO();output=mock.Mock(wraps=buffer)
        raw=self.run_packet(self.prepare(),output=output)
        self.assertNotIn(b'PRIVATE_SENTINEL',raw);self.assertEqual(json.loads(raw)['error_code'],'E138_ENTRYPOINT_FAILED')
        self.assertEqual(output.write.call_count,1)

    def test_partial_write_never_retries_and_exits_without_private_context(self):
        output=mock.Mock();output.write.side_effect=OSError('PRIVATE_SENTINEL')
        with self.assertRaises(SystemExit) as caught:self.run_packet(self.prepare(),output=output)
        self.assertEqual(caught.exception.code,73);self.assertIsNone(caught.exception.__context__)
        self.assertEqual(output.write.call_count,1)

    def test_template_and_input_drift_are_not_learned(self):
        self.inputs['authority']=b'changed'
        with self.assertRaisesRegex(ValueError,'STATIC_INPUTS'):self.prepare()

    def test_exact_command_bootstrap_to_generated_payload_to_worker(self):
        plan=self.prepare();argv=shlex.split(plan['remote_command'])
        output=io.BytesIO();wrapped=mock.Mock(wraps=output)
        with mock.patch.object(sys,'argv',['-c',argv[6]]), \
                mock.patch.object(sys,'stdin',types.SimpleNamespace(buffer=io.BytesIO(plan['payload']))), \
                mock.patch.object(sys,'stdout',types.SimpleNamespace(buffer=wrapped)), \
                mock.patch('subprocess.Popen') as spawn:
            exec(compile(argv[5],'<exact-command-bootstrap>','exec'),{})
        spawn.assert_not_called();self.assertEqual(wrapped.write.call_count,1)
        self.assertEqual(json.loads(output.getvalue())['role'],'capture')

    def test_exact_command_rejects_changed_payload_before_worker_compile(self):
        plan=self.prepare();argv=shlex.split(plan['remote_command']);output=io.BytesIO()
        with mock.patch.object(sys,'argv',['-c',argv[6]]), \
                mock.patch.object(sys,'stdin',types.SimpleNamespace(buffer=io.BytesIO(plan['payload']+b' '))), \
                mock.patch.object(sys,'stdout',types.SimpleNamespace(buffer=output)):
            with self.assertRaisesRegex(ValueError,'E138_BOOT_PAYLOAD_CHANGED'):
                exec(compile(argv[5],'<exact-command-bootstrap>','exec'),{})
        self.assertEqual(output.getvalue(),b'')


if __name__=='__main__':unittest.main()
