"""RAM compiler self-identity tests; fixtures are synthetic, not E139 release."""
import ast
import copy
import io
import json
from pathlib import Path
import shlex
import sys
import types
import unittest
from unittest import mock

from scripts import e139_packet_candidate as m
from scripts import e138_reviewed_envelope as envelope

REPO = Path(__file__).resolve().parents[1]


class Tests(unittest.TestCase):
    def setUp(self):
        from tests.test_worker_e138_batch import Tests as WorkerTests
        self.case = WorkerTests(); self.addCleanup(self.case.doCleanups); self.case.setUp()
        self.origin = (REPO / 'scripts/e138_packet.py').read_bytes()
        self.raw = m.build(self.origin).private_sources()[m.KEY]
        self.compiler = m.compiler(self.raw)
        self.template = copy.deepcopy(self.case.freeze); self.template.pop('payload_sha256')
        self.inputs = dict(self.case.package); self.sources = dict(self.case.bodies)
        self.loader = self.case.loader
        self.worker = (REPO / 'scripts/worker_e138_batch.py').read_bytes()
        self.envelope = (REPO / 'scripts/e138_reviewed_envelope.py').read_bytes()
        c = self.compiler
        self.expected = dict(compiler_sha256=m.EFFECTIVE_SHA256, worker_sha256=c.sha(self.worker),
            loader_sha256=c.sha(self.loader), envelope_sha256=c.sha(self.envelope),
            template_sha256=c.sha(c.canonical(self.template)),
            source_sha256={name:c.sha(raw) for name,raw in self.sources.items()},
            source_order=tuple(self.sources), input_sha256={name:c.sha(raw) for name,raw in self.inputs.items()})

    def prepare(self):
        return self.compiler.prepare(self.template,self.inputs,self.sources,
                                     self.worker,self.loader,self.envelope)

    def test_default_deny_before_provider_io_or_compile(self):
        self.assertIsNone(self.compiler.EXPECTED)
        with mock.patch.object(self.compiler,'SOURCE_BYTES') as provider, \
             mock.patch('builtins.open') as opened, mock.patch('builtins.compile') as compiled:
            with self.assertRaisesRegex(ValueError,'EXTERNAL_PINS_REQUIRED'): self.prepare()
        provider.assert_not_called(); opened.assert_not_called(); compiled.assert_not_called()

    def test_compiled_effective_bytes_self_checked_not_historical_path(self):
        self.compiler.EXPECTED=self.expected
        self.assertNotIn('__file__',vars(self.compiler))
        with mock.patch.object(Path,'read_bytes',side_effect=AssertionError('unexpected disk self-read')):
            plan=self.prepare()
        self.assertEqual(plan['projection']['schema'],'e139-exact-packet-projection-v1')
        self.assertEqual(plan['projection']['compiler_sha256'],m.EFFECTIVE_SHA256)
        self.assertNotEqual(m.EFFECTIVE_SHA256,m.ORIGIN_SHA256)
        self.assertFalse(plan['execution_ready'])

    def test_exact_source_key_tamper_and_origin_hash_not_accepted(self):
        with self.assertRaisesRegex(ValueError,'EXACT_SOURCE_KEY'): self.compiler.SOURCE_BYTES('other')
        for raw in (self.origin,self.raw+b' '):
            with self.assertRaisesRegex(ValueError,'EFFECTIVE_SOURCE_PIN'): m.compiler(raw)
        self.compiler.EXPECTED=self.expected
        with mock.patch.object(self.compiler,'SOURCE_BYTES',return_value=self.origin):
            with self.assertRaisesRegex(ValueError,'COMPILER_DRIFT'): self.prepare()
        self.expected['compiler_sha256']=m.ORIGIN_SHA256
        with self.assertRaisesRegex(ValueError,'COMPILER_DRIFT'): self.prepare()

    def test_exact_command_envelope_worker_loader_synthetic_capture(self):
        self.compiler.EXPECTED=self.expected; plan=self.prepare()
        argv=shlex.split(plan['remote_command']); output=io.BytesIO()
        with mock.patch.object(sys,'argv',['-c',argv[6]]), \
             mock.patch.object(sys,'stdin',types.SimpleNamespace(buffer=io.BytesIO(plan['payload']))), \
             mock.patch.object(sys,'stdout',types.SimpleNamespace(buffer=output)), \
             mock.patch('subprocess.Popen') as spawn:
            exec(compile(argv[5],'<e139-test-command>','exec'),{})
        spawn.assert_not_called()
        value=json.loads(output.getvalue())
        self.assertEqual(value['role'],'capture'); self.assertTrue(value['capture']['synthetic'])

    def test_finite_changes_reverse_to_origin_and_python36_syntax(self):
        restored=self.raw
        for old,new,count in m.REPLACEMENTS:
            self.assertEqual(self.origin.count(old.encode()),count)
            self.assertEqual(self.raw.count(new.encode()),count)
            restored=restored.replace(new.encode(),old.encode())
        self.assertEqual(restored,self.origin)
        ast.parse(self.raw,feature_version=(3,6))
        self.assertEqual((REPO/'scripts/e138_packet.py').read_bytes(),self.origin)

    def test_private_compile_has_no_registry_install_or_execution_release(self):
        before=dict(sys.modules)
        with mock.patch('subprocess.Popen') as spawn, mock.patch('builtins.open') as opened:
            private=m.compiler(self.raw)
        self.assertEqual(before,dict(sys.modules)); spawn.assert_not_called(); opened.assert_not_called()
        self.assertIsNone(private.EXPECTED)


if __name__=='__main__': unittest.main()
