"""Self-contained supplemental transport tests; mocks never establish real PASS."""
import ast
import copy
import hashlib
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def external(name, path):
    module = ModuleType(name)
    module.__file__ = str(ROOT / path)
    exec(compile((ROOT / path).read_bytes(), module.__file__, 'exec'), module.__dict__)
    return module


gate = external('synthetic_fx_gate', 'scripts/run_v5_fx2trt_optimizer_gate.py')


class OptimizerTests(unittest.TestCase):
    root = gate.FIXED_ROOT

    def pins(self):
        return {n: 'a'*64 for n in (gate.PROGRAM, gate.TRANSPORT, gate.OBS, gate.CONTEXT,
                gate.AUTH, gate.JIT, gate.SNAPSHOT, gate.PROBE)} | {gate.SNAPSHOT: gate.SNAPSHOT_SHA}

    def proof(self):
        return dict(probe_verified=True, probe_name='fx2trt_oss', probe_invocations=15,
            negative_probe_names=list(gate.NEGATIVE_NAMES), probe_counts={n: 1 for n in gate.NEGATIVE_NAMES},
            trace_source_bytes=140951, trace_source_sha256=gate.TRACE_SHA,
            trace_origin=gate.SEARCH_PATHS[-1]+'/torch/_dynamo/trace_rules.py',
            search_paths=list(gate.SEARCH_PATHS), formal_training_release=False,
            actual_linux_resource_proof=False)

    def worker(self):
        return dict(status=gate.CHILD_STATUS, supplemental_sha256=self.pins(), core_manifest_sha256=gate.CORE_SHA,
            authorization_raw_sha256='a'*64, authentic_user_consent_proven=False,
            torch_version='2.5.1+cu124', numpy_version='2.1.3',
            torch_origin=gate.SEARCH_PATHS[-1]+'/torch/__init__.py',
            numpy_origin=gate.SEARCH_PATHS[-1]+'/numpy/__init__.py',
            threads=1, interop_threads=1, cuda_available=False,
            child_prerequisites=dict(status='PASS_CHILD_PREREQUISITES_ONLY', address_space_limits=[8*1024**3]*2,
                core_limits=[0, 0], threads=1, parent_sampled_rss_enforcement_proven=False,
                authentic_user_consent_proven=False), synthetic_optimizer_fits=1,
            optimizer_steps=120, fitting_log_records=122, actual_formal_fits=0,
            production_package_reads=0, held_label_reads=0, formal_training_release=False,
            automatic_retries=0, request_sha256=gate.SYNTHETIC_REQUEST_SHA,
            model_sha256='b'*64, fitting_log_sha256='c'*64, model_bytes=100, fitting_log_bytes=1000,
            initial_head_loss=1., final_head_loss=.1, initial_pair_reference=1., final_pair_reference=.1,
            jit_admission=dict(jit_template_proven=True, generated_source_sha256=gate.SNAPSHOT_SHA,
                generated_source_bytes=2355, jit_root=self.root+'/jit_tmp',
                jit_temp_dir=self.root+'/jit_tmp/tmpabcd1234', installed_source_pins=dict(gate.INSTALLED_PINS),
                formal_training_release=False, actual_linux_resource_proof=False), fx2trt_probe=self.proof())

    def test_probe_receipt_strict_types_full_names_and_each_count(self):
        gate.validate_probe_receipt(self.proof())
        changes = [('probe_verified', 1), ('probe_name', 'generic'), ('probe_invocations', True),
            ('probe_invocations', 14), ('trace_source_bytes', True), ('trace_source_sha256', 'a'*64),
            ('trace_origin', '/tmp/trace_rules.py'), ('search_paths', list(gate.SEARCH_PATHS)+['/tmp']),
            ('negative_probe_names', ['fx2trt_oss']), ('probe_counts', {'fx2trt_oss': 15}),
            ('formal_training_release', True), ('actual_linux_resource_proof', True), ('extra', 0)]
        for key, value in changes:
            item = self.proof(); item[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): gate.validate_probe_receipt(item)
        for name in gate.NEGATIVE_NAMES:
            for count in (0, True, -1):
                item = self.proof(); item['probe_counts'][name] = count
                with self.subTest(name=name, count=count), self.assertRaises(ValueError):
                    gate.validate_probe_receipt(item)
        for key in gate.PROBE_FIELDS:
            item = self.proof(); del item[key]
            with self.subTest(missing=key), self.assertRaises(ValueError): gate.validate_probe_receipt(item)

    def test_child_requires_both_jit_and_probe_proof_no_release(self):
        gate.validate_child(self.worker(), self.pins())
        for section, key, value in [('fx2trt_probe', 'probe_verified', False),
                ('jit_admission', 'jit_template_proven', False), ('fx2trt_probe', 'probe_invocations', 0)]:
            worker = self.worker(); worker[section][key] = value
            with self.subTest(section=section), self.assertRaises(ValueError): gate.validate_child(worker, self.pins())
        for key, value in [('optimizer_steps', 121), ('fitting_log_records', 121), ('actual_formal_fits', 1),
                ('held_label_reads', 1), ('production_package_reads', 1), ('formal_training_release', True),
                ('automatic_retries', 1), ('threads', 2), ('model_bytes', True), ('final_head_loss', float('nan'))]:
            worker = self.worker(); worker[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): gate.validate_child(worker, self.pins())

    def test_fixed_fresh_root_only_and_bootstrap_new_program(self):
        code = gate.bootstrap(self.root, 'a'*64)
        compile(code, '<bootstrap>', 'exec')
        self.assertIn(self.root+'/'+gate.PROGRAM, code)
        for root in ('/tmp/x', self.root+'/', self.root.replace('_r1', '_r2'),
                     self.root.replace('20261011', '20261010')):
            self.assertFalse(gate.root_valid(root))
            with self.assertRaises(ValueError): gate.bootstrap(root, 'a'*64)

    def test_exact_eight_source_pins_before_io(self):
        flags = SimpleNamespace(no_site=1, isolated=1)
        with patch.object(gate.sys, 'platform', 'linux'), patch.object(gate.sys, 'executable', gate.INTERPRETER), \
                patch.object(gate.sys, 'version_info', (3, 11, 2)), patch.object(gate.sys, 'flags', flags), \
                patch.object(gate.os, 'getcwd', return_value='/ssd/cjc'), \
                patch.object(gate.sys, 'path', list(gate.SEARCH_PATHS)), \
                patch.dict(gate.os.environ, {'SETUPTOOLS_USE_DISTUTILS': 'stdlib'}):
            gate.preconditions(self.root, self.pins())
            for kind in ('missing', 'extra', 'bad', 'snapshot'):
                pins = self.pins()
                if kind == 'missing': del pins[gate.PROBE]
                if kind == 'extra': pins['unknown.py'] = 'a'*64
                if kind == 'bad': pins[gate.PROBE] = 'not a hash'
                if kind == 'snapshot': pins[gate.SNAPSHOT] = 'b'*64
                with self.subTest(kind=kind), patch.object(gate, 'read') as read, self.assertRaises(ValueError):
                    gate.load(self.root, pins)
                read.assert_not_called()

    def test_transport_hash_rejected_before_compile(self):
        with patch.object(gate, 'preconditions'), patch.object(gate, 'read', return_value=b'pass'), \
                patch.object(gate, 'external') as execute:
            with self.assertRaisesRegex(ValueError, 'TRANSPORT_SHA'): gate.load(self.root, self.pins())
            execute.assert_not_called()

    def test_new_helper_and_wrapper_constants_and_cli_agree(self):
        helper = external('synthetic_probe_contract', gate.PROBE)
        self.assertEqual(tuple(helper.NEGATIVE_NAMES), gate.NEGATIVE_NAMES)
        self.assertEqual(helper.PROOF_FIELDS, gate.PROBE_FIELDS)
        self.assertEqual(helper.TRACE_SHA256, gate.TRACE_SHA)
        source = (ROOT/gate.PROGRAM).read_text()
        self.assertIn("(PROBE, 'probe')", source)
        self.assertIn('PROBE: args.probe_sha256', source)
        self.assertIn('jit_admission=jit_admission', source)

    def test_startup_no_ml_and_original_kernel_functions_identical(self):
        newer = ast.parse((ROOT/gate.PROGRAM).read_text())
        older = ast.parse((ROOT/'scripts/run_v5_jit_optimizer_gate.py').read_text())
        functions = lambda tree: {n.name: ast.dump(n, include_attributes=False)
                    for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
        new, old = functions(newer), functions(older)
        for name in ('request_for', 'expected_bindings', 'log_bytes', 'finite_tree',
                     'BoundedBuffer', 'persist', 'global_worker_lock', 'claim_once', 'verify_started'):
            self.assertEqual(new[name], old[name], name)
        for node in newer.body:
            if isinstance(node, ast.Import): self.assertFalse({'torch', 'numpy'} & {a.name for a in node.names})
            if isinstance(node, ast.ImportFrom): self.assertNotIn(node.module, ('torch', 'numpy'))
        self.assertEqual(gate.SYNTHETIC_REQUEST_SHA, 'db1fde590c5fea061b5cbf3a551dbe2e045eae63cdfc3317df93f1321ddb4814')

    def test_parent_validator_rejects_incomplete_proof_even_rehashed_child(self):
        import json
        worker = self.worker()
        payload = dict(status=gate.FINAL_STATUS, root=self.root, supplemental_sha256=self.pins(),
            core_manifest_sha256=gate.CORE_SHA, child_receipt_sha256=gate.sha(json.dumps(worker, sort_keys=True).encode()),
            child_receipt=worker, parent_guard_receipt={}, actual_linux_resource_proof=True,
            formal_training_release=False, automatic_retries=0, worker_count=1)
        transport = SimpleNamespace(typed_equal=lambda a, b: a == b)
        receipt = SimpleNamespace(validate_parent_guard_receipt=lambda *a: None)
        gate.validate_final(payload, self.pins(), transport, receipt)
        for name in gate.NEGATIVE_NAMES:
            changed = copy.deepcopy(payload)
            changed['child_receipt']['fx2trt_probe']['probe_counts'][name] = 0
            changed['child_receipt_sha256'] = gate.sha(json.dumps(changed['child_receipt'], sort_keys=True).encode())
            with self.subTest(name=name), self.assertRaises(ValueError):
                gate.validate_final(changed, self.pins(), transport, receipt)


if __name__ == '__main__':
    unittest.main()
