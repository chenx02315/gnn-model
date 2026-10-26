"""Mock processes, /proc, select and clock only; never spawn a real process."""
import ast
import copy
from contextlib import ExitStack
import os
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from src.data import prospective_generation_process_e113 as m
from tests import test_prospective_generation_supervision_e109 as fixtures


WORKER = (700, 100, 'S', 500, 700, 700)
CHILD = (701, 200, 'R', 700, 701, 701)
BOOT = b'12345678-1234-1234-1234-123456789abc\n'


class Domain(m.direct.Descendants):
    def __init__(self):
        self.pid, self.identity = 700, WORKER
        self.peak, self.samples, self.cleanups = 123, 0, 0
        self.fail_sample, self.fail_cleanup, self.pending = None, False, False
        self.members = {701: CHILD}

    def snapshot(self):
        return self.members

    def sample(self):
        self.samples += 1
        if self.samples == self.fail_sample:
            raise ValueError('SAMPLED_MEMORY_STOP')
        return self.snapshot()

    def cleanup(self, proc, end):
        self.cleanups += 1
        if self.fail_cleanup:
            raise RuntimeError('private-cleanup-detail')
        return True

    def _direct_batch(self):
        return ([701] if self.pending else []), False


class Tests(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.Tests()
        fixture.setUp()
        # Real E112 capture lacks MGC_HOME/ROOT. E109 explicitly permits that.
        self.launch = fixture.prepare(runtime=dict(PATH='/usr/bin:/bin', LD_LIBRARY_PATH='/vendor/lib',
            LM_LICENSE_FILE='1717@synthetic-license.invalid', MGLS_LICENSE_FILE='1717@synthetic-license.invalid'))
        self.domain = Domain()
        self.proc = fixtures.Process()
        self.proc.pid = 701
        self.on_spawn = Mock(return_value=True)

    def small(self, path, cap=65536):
        if path == m.BOOT_PATH:
            return BOOT
        if path == '/proc/self/status':
            return b'Threads:\t1\n'
        raise AssertionError('unexpected system read')

    def identity(self, pid):
        return WORKER if pid == 700 else CHILD

    def observe(self, budget=None, clock=None, spawn_error=None, identity=None, small=None,
                read=None, scratch=None):
        budget = [100] if budget is None else budget
        with ExitStack() as stack:
            spawn = stack.enter_context(patch.object(m.subprocess, 'Popen', return_value=self.proc, side_effect=spawn_error))
            stack.enter_context(patch.object(m.selectors, 'DefaultSelector', return_value=fixtures.Selector()))
            stack.enter_context(patch.object(m.os, 'read', side_effect=[b'PREFIX', b''] if read is None else read))
            stack.enter_context(patch.object(m.os, 'getpid', return_value=700))
            stack.enter_context(patch.object(m.direct.base, '_identity', side_effect=self.identity if identity is None else identity))
            stack.enter_context(patch.object(m.direct.base, '_small', side_effect=self.small if small is None else small))
            stack.enter_context(patch.object(m.time, 'monotonic', return_value=1, side_effect=clock))
            result = m.observe_tessent(self.launch, 100, self.domain, budget, self.on_spawn, scratch)
        return result, spawn, budget

    def test_real_handle_pid_double_proc_reads_and_callback_before_final_return(self):
        result, spawn, budget = self.observe()
        self.assertEqual(result['output'], b'PREFIX')
        self.assertIsNone(result['failure'])
        self.assertTrue(result['physical_process_identity_observed'])
        self.assertFalse(result['physical_process_identity_authenticated'])
        identity = result['spawn_identity']
        self.assertEqual(identity['child_pid'], self.proc.pid)
        self.assertEqual(identity['child_start_ticks'], 200)
        self.assertEqual(identity['worker_start_ticks'], 100)
        self.assertEqual(identity['child_pgrp'], self.proc.pid)
        self.assertEqual(identity['child_session'], self.proc.pid)
        self.assertEqual(identity['boot_id'], BOOT.decode('ascii').strip())
        self.on_spawn.assert_called_once_with(identity)
        self.assertTrue(result['spawn_identity_persisted_claim'])
        self.assertEqual(budget, [94])
        self.assertEqual(self.domain.cleanups, 1)
        self.proc.stdout.close.assert_called_once()
        self.assertNotIn('synthetic-license', repr(result))
        self.assertIsNone(result['actual_atpg_runtime_ns'])
        self.assertFalse(result['execution_ready'])

    def test_explicit_environment_no_shell_or_ambient_poison(self):
        with patch.dict(os.environ, {'LD_PRELOAD': '/poison.so', 'BASH_ENV': '/poison'}):
            result, spawn, _ = self.observe()
        argv, kwargs = spawn.call_args
        self.assertEqual(argv[0], self.launch['argv'])
        self.assertEqual(kwargs['env'], self.launch['env'])
        self.assertNotIn('shell', kwargs)
        self.assertTrue(kwargs['start_new_session'])
        self.assertNotIn('LD_PRELOAD', kwargs['env'])
        self.assertNotIn('MGC_HOME', kwargs['env'])

    def test_identity_callback_gets_copy_not_mutable_internal_proof(self):
        def corrupt(value):
            value['child_pid'] = 999
            return True
        self.on_spawn.side_effect = corrupt
        result, _, _ = self.observe()
        self.assertEqual(result['spawn_identity']['child_pid'], 701)

    def test_pid_reuse_or_membership_change_cleanup_preserves_pending_prefix(self):
        sequences = (
            [WORKER, CHILD, WORKER, (701, 201, 'R', 700, 701, 701)],
            [WORKER, CHILD, (700, 101, 'S', 500, 700, 700), CHILD])
        for sequence in sequences:
            self.domain = Domain()
            result, _, _ = self.observe(identity=[WORKER, WORKER] + sequence)
            self.assertIsNone(result['spawn_identity'])
            self.assertTrue(result['known_process_handle'])
            self.assertTrue(result['cleaned'])
            self.assertEqual(result['output'], b'PREFIX')
            self.assertFalse(result['spawn_identity_persisted_claim'])
            self.assertTrue(result['post_failure_prefix_drain_attempted'])
        self.on_spawn.assert_not_called()

    def test_unowned_or_non_session_child_never_becomes_identity_receipt(self):
        for child, members in ((CHILD, {}), ((701, 200, 'R', 700, 999, 999), {701: (701, 200, 'R', 700, 999, 999)})):
            self.domain = Domain()
            self.domain.members = members
            result, _, _ = self.observe(identity=lambda pid: WORKER if pid == 700 else child)
            self.assertFalse(result['physical_process_identity_observed'])
            self.assertIsNone(result['spawn_identity'])
            self.assertTrue(result['cleaned'])

    def test_fast_exit_identity_missing_does_not_fabricate_pid(self):
        def missing(pid):
            if pid == 701:
                raise FileNotFoundError()
            return WORKER
        result, _, _ = self.observe(identity=missing)
        self.assertTrue(result['known_process_handle'])
        self.assertIsNone(result['spawn_identity'])
        self.assertEqual(result['failure'], 'FileNotFoundError')
        self.assertEqual(result['output'], b'PREFIX')

    def test_boot_change_or_multiple_worker_threads_fail_closed(self):
        boots = iter([BOOT, b'87654321-1234-1234-1234-123456789abc\n'])
        result, _, _ = self.observe(small=lambda path, cap=65536: next(boots) if path == m.BOOT_PATH else b'Threads: 1\n')
        self.assertEqual(result['failure'], 'WORKER_OR_BOOT_CHANGED')
        self.assertIsNone(result['spawn_identity'])
        result, _, _ = self.observe(small=lambda path, cap=65536: BOOT if path == m.BOOT_PATH else b'Threads: 2\n')
        self.assertEqual(result['failure'], 'SINGLE_WORKER_THREAD_REQUIRED')

    def test_wrong_worker_or_multiple_threads_rejected_before_popen(self):
        self.domain.pid = 999
        result, spawn, _ = self.observe()
        spawn.assert_not_called()
        self.assertFalse(result['launch_attempted'])
        self.assertEqual(result['failure'], 'CURRENT_WORKER_REQUIRED')
        self.assertIsNone(result['spawn_identity'])
        self.domain = Domain()
        result, spawn, _ = self.observe(small=lambda path, cap=65536: b'Threads: 2\n')
        spawn.assert_not_called()
        self.assertFalse(result['launch_attempted'])
        self.assertEqual(result['failure'], 'SINGLE_WORKER_THREAD_REQUIRED')

    def test_worker_identity_changes_before_popen_are_not_launch_attempts(self):
        result, spawn, _ = self.observe(identity=[WORKER, (700, 101, 'S', 500, 700, 700)])
        spawn.assert_not_called()
        self.assertEqual(result['failure'], 'WORKER_IDENTITY_CHANGED')
        self.assertFalse(result['launch_attempted'])
        self.assertIsNone(result['observed_wrapper_interval_seconds'])

    def test_callback_failure_retains_identity_and_prefix_without_secret_text(self):
        self.on_spawn.side_effect = ValueError('private-license-token')
        result, _, _ = self.observe()
        self.assertEqual(result['failure'], 'SPAWN_IDENTITY_CALLBACK_FAILED')
        self.assertEqual(result['identity_callback_error'], 'ValueError')
        self.assertEqual(result['output'], b'PREFIX')
        self.assertIsNotNone(result['spawn_identity'])
        self.assertFalse(result['spawn_identity_persisted_claim'])
        self.assertNotIn('private-license-token', repr(result))

    def test_literal_callback_ack_required(self):
        for value in (False, None, 1, {}):
            self.on_spawn.return_value = value
            result, _, _ = self.observe()
            self.assertEqual(result['failure'], 'SPAWN_IDENTITY_PERSISTENCE_REQUIRED')
            self.assertFalse(result['spawn_identity_persisted_claim'])
            self.assertEqual(result['output'], b'PREFIX')

    def test_cleanup_failure_preserves_already_read_output(self):
        self.domain.fail_cleanup = True
        result, _, _ = self.observe()
        self.assertEqual(result['output'], b'PREFIX')
        self.assertFalse(result['cleaned'])
        self.assertEqual(result['cleanup_error'], 'RuntimeError')
        self.assertEqual(result['failure'], 'CLEANUP_UNCONFIRMED')

    def test_output_bound_not_refunded_and_no_retry(self):
        result, spawn, budget = self.observe(budget=[6])
        self.assertEqual(result['output'], b'PREFIX')
        self.assertEqual(result['failure'], 'OUTPUT_STOP')
        self.assertEqual(budget, [0])
        self.assertEqual(spawn.call_count, 1)

    def test_sample_failure_still_uses_known_handle_cleanup(self):
        self.domain.fail_sample = 2
        result, _, _ = self.observe()
        self.assertEqual(result['failure'], 'SAMPLED_MEMORY_STOP')
        self.assertEqual(self.domain.cleanups, 1)
        self.assertEqual(result['output'], b'PREFIX')

    def test_spawn_error_no_pid_or_retry_no_exception_detail(self):
        result, spawn, _ = self.observe(spawn_error=OSError('secret-environment-detail'))
        self.assertTrue(result['launch_attempted'])
        self.assertFalse(result['known_process_handle'])
        self.assertIsNone(result['spawn_identity'])
        self.assertEqual(spawn.call_count, 1)
        self.assertEqual(result['failure'], 'OSError')
        self.assertNotIn('secret-environment-detail', repr(result))

    def test_prelaunch_insufficient_cleanup_window_no_spawn(self):
        result, spawn, _ = self.observe(clock=[95, 96])
        self.assertEqual(result['failure'], 'PRELAUNCH_TIMEOUT')
        self.assertFalse(result['launch_attempted'])
        self.assertIsNone(result['observed_wrapper_interval_seconds'])
        spawn.assert_not_called()

    def test_timeout_after_read_preserves_prefix_and_cleanup_window(self):
        result, _, _ = self.observe(clock=[0, 1, 2, 3, 4, 95, 96, 97])
        self.assertEqual(result['failure'], 'CASE_TIMEOUT')
        self.assertEqual(result['output'], b'PREFIX')
        self.assertEqual(self.domain.cleanups, 1)
        self.assertTrue(result['spawn_identity_persisted_claim'])

    def test_state_only_change_does_not_look_like_pid_reuse(self):
        result, _, _ = self.observe(identity=[WORKER, WORKER, WORKER, CHILD,
            (700, 100, 'R', 500, 700, 700), (701, 200, 'S', 700, 701, 701)])
        self.assertIsNone(result['failure'])
        self.assertTrue(result['physical_process_identity_observed'])

    def test_invalid_or_resigned_unfixed_commands_fail_before_popen(self):
        for command in (['/bin/bash', '-lc', 'anything'], ['/usr/bin/python3', '-c', 'print(1)']):
            value = copy.deepcopy(self.launch)
            value['argv'] = command
            value['launch_spec_sha256'] = m.sha(m.canonical({k: v for k, v in value.items() if k != 'launch_spec_sha256'}))
            with patch.object(m.subprocess, 'Popen') as spawn:
                with self.assertRaises(ValueError):
                    m.observe_tessent(value, 100, self.domain, [100], self.on_spawn)
                spawn.assert_not_called()

    def test_unfrozen_translation_helper_failclosed_no_spawn(self):
        with patch.object(m.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(ValueError, 'FIXED_TRANSLATION_HELPER_NOT_FROZEN'):
                m.observe_translation()
            spawn.assert_not_called()

    def test_python36_ast(self):
        root = Path(__file__).resolve().parents[1]
        for path in ('src/data/prospective_generation_process_e113.py', 'tests/test_prospective_generation_process_e113.py'):
            ast.parse((root / path).read_text(), feature_version=(3, 6))
