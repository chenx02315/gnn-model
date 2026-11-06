"""Finite entry derivation checks, not a complete private graph or run test.

Test-only compilation resolves unchanged imports to historical local modules.
No production compiler/provider loader, grant, clock or physical run is made.
"""
import ast
from contextlib import nullcontext
import hashlib
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

from scripts import e139_entry_candidate as m

REPO = Path(__file__).resolve().parents[1]


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.origin = (REPO / 'scripts/run_physical_f_clean_replay_e138.py').read_bytes()
        cls.result = m.build(cls.origin)
        cls.effective = cls.result.private_sources()[m.KEY]

    def test_exact_frozen_origin_effective_pins_and_reversible_rules(self):
        self.assertEqual(hashlib.sha256(self.origin).hexdigest(), m.ORIGIN_SHA256)
        self.assertEqual(hashlib.sha256(self.effective).hexdigest(), m.EFFECTIVE_SHA256)
        forward = self.origin
        for old, new, count in m.REPLACEMENTS:
            self.assertEqual(forward.count(old.encode('ascii')), count)
            forward = forward.replace(old.encode('ascii'), new.encode('ascii'))
        self.assertEqual(forward, self.effective)
        reverse = self.effective
        for old, new, count in reversed(m.REPLACEMENTS):
            self.assertEqual(reverse.count(new.encode('ascii')), count)
            reverse = reverse.replace(new.encode('ascii'), old.encode('ascii'))
        self.assertEqual(reverse, self.origin)
        ast.parse(self.effective, feature_version=(3, 6))

    def test_build_zero_io_compile_and_registry_mutation_failclosed_on_origin(self):
        before = dict(sys.modules)
        with mock.patch('builtins.open') as opened, mock.patch('builtins.compile') as compiled, \
             mock.patch('pathlib.Path.open') as path_open:
            result = m.build(self.origin)
            with self.assertRaises(ValueError):
                m.build(self.origin + b' ')
        for operation in (opened, compiled, path_open):
            operation.assert_not_called()
        self.assertEqual(before, dict(sys.modules))
        self.assertEqual(result.private_sources()[m.KEY], self.effective)

    def test_source_io_joins_exact_keys_no_origin_disk_reads_in_prepare_or_manifest(self):
        tree = ast.parse(self.effective)
        functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
        prepare = functions['_prepare']
        calls = [n for n in ast.walk(prepare) if isinstance(n, ast.Call)]
        providers = [n.args[0].value for n in calls if isinstance(n.func, ast.Name)
                     and n.func.id == 'SOURCE_BYTES']
        self.assertEqual(tuple(providers), m.SOURCE_KEYS)
        for name in ('_prepare', '_entry_sources'):
            for node in ast.walk(functions[name]):
                if isinstance(node, ast.Attribute):
                    self.assertNotIn(node.attr, ('_read', '__file__', 'read_bytes'))
        text = self.effective.decode('ascii')
        self.assertIn('materials=E139_MATERIALS', text)
        self.assertNotIn('from scripts import e138_deployment_materials as materials', text)
        self.assertIn("'e139-independent-exact-packet-review-request-v1'", text)
        self.assertIn("'e139-independent-exact-packet-review-v1'", text)
        self.assertIn('physical_f_clean_replay_authorization_e139.json', text)
        self.assertIn('physical_f_clean_replay_proposal_e139_v1.json', text)

    def test_testonly_compiled_default_authority_denies_before_repo_or_any_io(self):
        # Historical imports are stand-ins here, not proof of graph integration.
        facade = mock.Mock(name='TEST_ONLY_E139_MATERIALS_FACADE')
        namespace = dict(__name__='_TEST_ONLY_effective_entry', E139_MATERIALS=facade)
        exec(compile(self.effective, '<TEST_ONLY_effective_entry>', 'exec'), namespace)
        self.assertIsNone(namespace['AUTH_SHA256'])
        self.assertEqual(namespace['PROPOSAL_SHA256'], m.PROPOSAL_SHA256)
        self.assertIsNone(namespace['REVIEW_PINS'])
        self.assertIsNone(namespace['SOURCE_BYTES'])
        self.assertIsNone(namespace['SOURCE_MANIFEST'])
        # No __file__ supplied: the authority guard must precede _repo().
        repo = mock.Mock(side_effect=AssertionError('REPO MUST NOT BE ACCESSED'))
        namespace['_repo'] = repo
        with mock.patch('builtins.open') as opened, mock.patch('subprocess.Popen') as spawn, \
             mock.patch('time.monotonic') as clock:
            with self.assertRaisesRegex(ValueError, 'E139_ENTRY_AUTHORITY_PINS_REQUIRED'):
                namespace['prepare_capture']()
        repo.assert_not_called(); facade.assert_not_called(); facade._read.assert_not_called()
        for operation in (opened, spawn, clock):
            operation.assert_not_called()

    def test_testonly_manifest_provider_required_and_no_provider_authority_claim(self):
        namespace = dict(__name__='_TEST_ONLY_manifest_entry', E139_MATERIALS=mock.Mock())
        exec(compile(self.effective, '<TEST_ONLY_effective_entry>', 'exec'), namespace)
        with self.assertRaisesRegex(ValueError, 'E139_ENTRY_SOURCE_MANIFEST_REQUIRED'):
            namespace['_entry_sources']()
        provider = mock.Mock(return_value={'TEST_ONLY_NOT_A_RELEASE': 'a'*64})
        namespace['SOURCE_MANIFEST'] = provider
        self.assertEqual(namespace['_entry_sources'](), provider.return_value)
        provider.assert_called_once_with()
        self.assertIsNone(namespace['AUTH_SHA256'])
        self.assertIsNone(namespace['REVIEW_PINS'])

    def test_actual_proposal_hash_and_no_production_compiler_or_dispatch(self):
        raw = (REPO / 'contracts/physical_f_clean_replay_proposal_e139_v1.json').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), m.PROPOSAL_SHA256)
        tree = ast.parse((REPO / 'scripts/e139_entry_candidate.py').read_bytes())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, ('compile', 'exec', 'eval'))
        self.assertFalse(hasattr(m, 'compiler'))
        self.assertFalse(hasattr(m, 'start'))

    def test_start_keeps_scoped_run_role_and_has_no_legacy_clock_loader_call(self):
        tree = ast.parse(self.effective)
        start = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'start')
        for node in ast.walk(start):
            if isinstance(node, ast.Attribute):
                self.assertNotEqual(node.attr, 'run_role')
            if isinstance(node, ast.Name):
                self.assertNotEqual(node.id, '_private_capture_clock')

    def test_testonly_start_lifecycle_source_identity_guards_preserve_bound_method(self):
        # Controlled lifecycle doubles only, not actual ScopedController integration.
        namespace = dict(__name__='_TEST_ONLY_start_entry', E139_MATERIALS=mock.Mock())
        exec(compile(self.effective, '<TEST_ONLY_effective_entry>', 'exec'), namespace)
        keys = ('physical_e138_contract', 'physical_replay_capture_e138', 'physical_e138_runtime_primitives')
        pins = {key: str(i + 1)*64 for i, key in enumerate(keys)}
        namespace['_check_review'] = mock.Mock()
        namespace['_configuration'] = lambda release: nullcontext()
        namespace['_staging'] = lambda: 'TEST_ONLY_NO_FILES'
        execute = mock.Mock()
        namespace['ReviewedRun'].execute = execute
        for failure in (None, 'contract_pin', 'capture_pin', 'runtime_pin', 'contract_identity', 'build_identity'):
            with self.subTest(failure=failure):
                contract = types.SimpleNamespace(__source_sha256__=pins[keys[0]])
                capture = types.SimpleNamespace(contract=contract, __source_sha256__=pins[keys[1]])
                runtime = types.SimpleNamespace(contract=contract, __source_sha256__=pins[keys[2]])
                # A real Python function exposes the exact globals used at call time.
                clock_globals = dict(contract=contract, capture=capture, runtime=runtime)
                exec('def build(): pass', clock_globals)
                clock = types.SimpleNamespace(contract=contract, capture=capture, runtime=runtime,
                                              build=clock_globals['build'])
                if failure == 'contract_pin': contract.__source_sha256__ = '0'*64
                if failure == 'capture_pin': capture.__source_sha256__ = '0'*64
                if failure == 'runtime_pin': runtime.__source_sha256__ = '0'*64
                if failure == 'contract_identity': capture.contract = object()
                if failure == 'build_identity': clock_globals['runtime'] = object()
                instance = mock.Mock()
                original_run_role = instance.run_role
                factory = mock.Mock(return_value=instance)
                namespace['controller'] = types.SimpleNamespace(clock=clock,
                    Controller=types.SimpleNamespace(create_pinned=factory))
                namespace['contract'] = contract
                prepared = namespace['Prepared']()
                prepared._role='capture'; prepared._owner=None; prepared._release={}
                prepared._authority=b'TEST_ONLY_NOT_AUTHORITY'; prepared._proposal=b'TEST_ONLY'
                prepared._descriptor=dict(packet=dict(source_sha256=pins))
                if failure is None:
                    result = namespace['start'](prepared, b'TEST_ONLY_NOT_REVIEW')
                    self.assertIs(result._controller, instance)
                    instance.store.remaining.assert_called_once_with()
                    instance._stop.assert_not_called()
                else:
                    with self.assertRaisesRegex(ValueError, 'E138_LOCAL_VALIDATOR_BINDING_FAILED'):
                        namespace['start'](prepared, b'TEST_ONLY_NOT_REVIEW')
                    instance._stop.assert_called_once_with('CONTROLLER_STOP')
                    instance.store.remaining.assert_not_called()
                self.assertIs(instance.run_role, original_run_role)
                original_run_role.assert_not_called()


if __name__ == '__main__':
    unittest.main()
