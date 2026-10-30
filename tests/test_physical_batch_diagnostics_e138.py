"""Pure diagnostic redaction and finite-state tests; no remote operations."""
import ast
import json
from pathlib import Path
import unittest
from src.data import physical_batch_diagnostics_e138 as m


class DiagnosticTests(unittest.TestCase):
    def test_each_stage_is_attempted_not_verified(self):
        for stage in m.STAGES:
            with self.subTest(stage=stage):
                state=m.DiagnosticState();state.checkpoint(stage)
                result=state.failure(ValueError('SENTINEL_ENV=/private/script'))
                self.assertEqual(result['stage_attempted'],stage)
                self.assertEqual(result['error_code'],'REDACTED_UNKNOWN_ERROR')
                self.assertNotIn('SENTINEL',json.dumps(result))
                for key in ('stage_completion_verified','cleanup_verified',
                        'evidence_durability_verified','retry_allowed','execution_ready','physical_d95_verified'):
                    self.assertIs(result[key],False)

    def test_exact_whitelist_only_no_prefix_or_nonstring_acceptance(self):
        for code in m.ERROR_CODES:
            self.assertEqual(m.safe_error(ValueError(code))['error_code'],code)
        for args in (('BATCH_FIXED_HOST_PLATFORM:/SECRET',),('BATCH_FIXED_HOST_PLATFORM','SECRET'),
                (b'BATCH_FIXED_HOST_PLATFORM',),({'SECRET':'value'},),('X'*1048576,),()):
            self.assertEqual(m.safe_error(ValueError(*args))['error_code'],'REDACTED_UNKNOWN_ERROR')

    def test_custom_exception_and_metaclass_are_never_formatted_or_hashed(self):
        class HostileMeta(type):
            def __hash__(self):raise AssertionError('must not hash custom class')
            def __eq__(self,other):raise AssertionError('must not compare custom class')
        class Hostile(ValueError,metaclass=HostileMeta):
            def __getattribute__(self,name):raise AssertionError('must not read custom attributes')
            def __str__(self):raise AssertionError('must not stringify')
            def __repr__(self):raise AssertionError('must not represent')
        value=m.safe_error(Hostile('BATCH_FIXED_HOST_PLATFORM'))
        self.assertEqual(value,dict(error_kind='OTHER_EXCEPTION',error_code='REDACTED_UNKNOWN_ERROR'))

    def test_debit_and_constructed_instance_survive_failure(self):
        state=m.DiagnosticState();state.checkpoint('INSTANCE_BUILD')
        state.instance_constructed('a'*64);state.checkpoint('ROOT_SERVICES')
        early=state.failure(ValueError('unknown'))
        self.assertEqual(early['instance_sha256'],'a'*64);self.assertEqual(early['launch_debit'],0)
        state=m.DiagnosticState();state.checkpoint('LAUNCH_DEBIT');state.consume_launch()
        state.checkpoint('TOOL_OBSERVATION')
        self.assertEqual(state.failure(OSError('PRIVATE_PATH'))['launch_debit'],1)

    def test_state_is_bounded_terminal_and_cannot_regress_or_double_debit(self):
        state=m.DiagnosticState();state.checkpoint('LAUNCH_DEBIT');state.consume_launch()
        for call in (lambda:state.checkpoint('ADMISSION'),state.consume_launch,
                lambda:state.checkpoint('PRIVATE_PATH'),lambda:state.instance_constructed('x'*64)):
            with self.assertRaises(ValueError):call()
        state.failure(ValueError('unknown'))
        for call in (lambda:state.failure(ValueError('second')),lambda:state.checkpoint('ROOT_RECEIPT'),state.consume_launch):
            with self.assertRaises(ValueError):call()
        self.assertFalse(hasattr(state,'__dict__'))

    def test_python36_syntax_and_no_io_imports(self):
        raw=Path(m.__file__).read_text(encoding='utf-8')
        tree=ast.parse(raw,feature_version=(3,6))
        self.assertFalse(any(isinstance(node,(ast.Import,ast.ImportFrom)) for node in ast.walk(tree)))
