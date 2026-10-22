"""E77 mocks only: Popen, preflight, prctl and scratch are never real."""
import contextlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from src.data import prospective_linux_journal_v3 as m
from src.data import prospective_lifecycle_journal_v2 as v2

BOOT_ID = '11111111-2222-3333-4444-555555555555'


class Clock:
    def __init__(self):
        self.next_ns = 10

    def capture(self):
        value = self.next_ns
        self.next_ns += 10
        return 'fixed-coordinator', value


class Scratch:
    name = '/tmp/fake-e77'
    def __init__(self): self.cleaned = False
    def cleanup(self): self.cleaned = True


class Proc:
    def __init__(self, pid, profile):
        self.pid = pid
        self.profile = profile
        self.returncode = None
        self.wait_calls = 0

    def poll(self): return self.returncode

    def wait(self, timeout=None):
        self.wait_calls += 1
        if self.profile == 'timeout_group' and self.returncode is None:
            raise subprocess.TimeoutExpired(['fixed'], timeout)
        self.returncode = 0 if self.profile == 'success' else 7
        return self.returncode


class FakeLinux:
    def __init__(self):
        self.calls = []
        self.procs = []
        self.scratch = []
        self.spawn_error = None
        self.metadata_error = None
        self.cleanup_error = None

    def preflight(self):
        self.calls.append('preflight')
        return dict(platform='linux',memory_limit_bytes=134217728,swap_limit_bytes=0,
                    pids_max=16,oom_group=0,host='fixed-host',boot_id=BOOT_ID)

    def popen(self, argv, **kwargs):
        self.calls.append('Popen')
        if self.spawn_error is not None:
            raise self.spawn_error
        profile = m.FIXED_PROFILES[len(self.procs)]
        proc = Proc(7+len(self.procs),profile)
        self.procs.append(proc)
        self.last_argv = argv
        self.last_kwargs = kwargs
        return proc

    def small_read(self, path, limit=4096):
        if str(path).startswith('/proc/'):
            return str(path).split('/')[2]
        return '10'

    def parse_stat(self, text):
        if self.metadata_error is not None:
            raise self.metadata_error
        pid = int(text)
        return dict(pid=pid,pgrp=pid,start_ticks=100+pid)

    def cleanup(self, proc):
        self.calls.append('cleanup')
        if self.cleanup_error is not None:
            raise self.cleanup_error
        if proc.returncode is None:
            proc.returncode = -9

    def new_scratch(self, **kwargs):
        self.calls.append('scratch')
        scratch = Scratch()
        self.scratch.append(scratch)
        return scratch

    @contextlib.contextmanager
    def patched(self):
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(m.gate,'preflight',side_effect=self.preflight))
            stack.enter_context(mock.patch.object(m.subprocess,'Popen',side_effect=self.popen))
            stack.enter_context(mock.patch.object(m.tempfile,'TemporaryDirectory',side_effect=self.new_scratch))
            stack.enter_context(mock.patch.object(m.gate,'small_read',side_effect=self.small_read))
            stack.enter_context(mock.patch.object(m.gate,'parse_proc_stat',side_effect=self.parse_stat))
            stack.enter_context(mock.patch.object(m.gate,'cleanup_group',side_effect=self.cleanup))
            stack.enter_context(mock.patch.object(m.gate,'group_members',return_value=[{'pid':10}]))
            stack.enter_context(mock.patch.object(m.Path,'exists',return_value=True))
            fake_lib = mock.Mock()
            fake_lib.prctl.return_value = 0
            stack.enter_context(mock.patch.object(m.ctypes,'CDLL',return_value=fake_lib))
            yield self


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name)/'j.jsonl')

    def test_full_three_profiles_fixed_backend_and_replay_boundary(self):
        fake = FakeLinux()
        with fake.patched(), m.Journal.create(self.path) as journal:
            backend = m.FixedLinuxBackend()
            clock = Clock()
            for index,profile in enumerate(m.FIXED_PROFILES,1):
                live = journal.run('a'+str(index),profile,backend,clock)
                self.assertEqual(live['complete_live_acknowledged'],index==3)
                self.assertEqual(live['structural_complete'],index==3)
                self.assertTrue(live['terminated_prefix_complete'])
                if index < 3:
                    self.assertIsNone(live['observed_interval_ns_sum_or_None'])
            self.assertEqual(live['observed_interval_ns_sum_or_None'],30)
            self.assertEqual(live['observed_identity_records'],3)
            self.assertEqual(live['launch_attempt_count'],3)
            self.assertFalse(live['os_authenticated'])
            self.assertEqual(live['real_atpg_jobs'],0)
            self.assertEqual(fake.calls.count('Popen'),3)
            self.assertEqual(fake.calls.count('cleanup'),3)
            self.assertEqual(fake.last_argv[:4],[m.sys.executable,'-I','-S','-B'])
            self.assertEqual(fake.last_argv[4],'-c')
            self.assertEqual(fake.last_argv[5],m.gate.payload('timeout_group',
                             Path('/tmp/fake-e77/timeout_group.child')))
            self.assertEqual(fake.last_kwargs['cwd'],'/tmp/fake-e77')
            self.assertTrue(fake.last_kwargs['start_new_session'])
            self.assertFalse(fake.last_kwargs['shell'])
            for stream in ('stdin','stdout','stderr'):
                self.assertIs(fake.last_kwargs[stream],subprocess.DEVNULL)
            self.assertTrue(all(s.cleaned for s in fake.scratch))
            head = live['head_sha256']
        replay=m.load(self.path)
        self.assertEqual(replay['head_sha256'],head)
        self.assertTrue(replay['structural_complete'])
        self.assertFalse(replay['fsync_acknowledgments_verified'])
        self.assertIsNone(replay['observed_interval_ns_sum_or_None'])

    def test_windows_preflight_before_scratch_or_popen(self):
        backend=m.FixedLinuxBackend()
        with mock.patch.object(m.gate.sys,'platform','win32'), \
             mock.patch.object(m.subprocess,'Popen',side_effect=AssertionError('SPAWN')) as popen, \
             mock.patch.object(m.tempfile,'TemporaryDirectory',side_effect=AssertionError('SCRATCH')) as scratch:
            with m.Journal.create(self.path) as journal:
                with self.assertRaisesRegex(ValueError,'LINUX_REQUIRED'):
                    journal.run('a1','success',backend,Clock())
                self.assertEqual(journal.snapshot()['event_count'],0)
        popen.assert_not_called()
        scratch.assert_not_called()

    def test_exact_profile_order_and_same_backend_binding(self):
        fake=FakeLinux()
        with fake.patched(),m.Journal.create(self.path) as journal:
            rejected=m.FixedLinuxBackend()
            with self.assertRaisesRegex(ValueError,'BACKEND_UNAVAILABLE_OR_ORDER'):
                journal.run('a1','failure',rejected,Clock())
            self.assertTrue(rejected._disabled)
            self.assertIsNone(journal.snapshot()['observed_interval_ns_sum_or_None'])
            with self.assertRaisesRegex(ValueError,'UNRESOLVED_OR_DUPLICATE'):
                journal.run('a1','success',m.FixedLinuxBackend(),Clock())
            self.assertEqual(fake.calls.count('Popen'),0)
        fresh=str(Path(self.tmp.name)/'fresh.jsonl')
        with fake.patched(),m.Journal.create(fresh) as journal:
            one=m.FixedLinuxBackend()
            journal.run('a1','success',one,Clock())
            with self.assertRaisesRegex(ValueError,'UNRESOLVED_OR_DUPLICATE'):
                journal.run('a2','failure',m.FixedLinuxBackend(),Clock())
            self.assertEqual(fake.calls.count('Popen'),1)

    def test_e76_fake_backend_rejected(self):
        with m.Journal.create(self.path) as journal:
            with self.assertRaisesRegex(ValueError,'EXACT_FIXED_LINUX_BACKEND'):
                journal.run('a1','success',object(),Clock())

    def test_unknown_spawn_stops_phase_without_cleanup_none(self):
        fake=FakeLinux();fake.spawn_error=OSError('unknown')
        with fake.patched(),m.Journal.create(self.path) as journal:
            backend=m.FixedLinuxBackend()
            with self.assertRaises(OSError):
                journal.run('a1','success',backend,Clock())
            self.assertEqual(fake.calls.count('Popen'),1)
            self.assertEqual(fake.calls.count('cleanup'),0)
            self.assertTrue(journal.snapshot()['unknown_spawn'])
            with self.assertRaisesRegex(ValueError,'UNRESOLVED_OR_DUPLICATE'):
                journal.run('a2','failure',backend,Clock())

    def test_none_popen_handle_is_unknown_and_not_cleaned(self):
        fake=FakeLinux()
        with fake.patched(),m.Journal.create(self.path) as journal:
            backend=m.FixedLinuxBackend()
            with mock.patch.object(m.subprocess,'Popen',return_value=None):
                with self.assertRaisesRegex(ValueError,'UNKNOWN_SPAWN_HANDLE'):
                    journal.run('a1','success',backend,Clock())
            self.assertEqual(fake.calls.count('cleanup'),0)
            self.assertTrue(journal.snapshot()['unknown_spawn'])
            self.assertIsNone(journal.snapshot()['observed_interval_ns_sum_or_None'])

    def test_intent_ack_failure_never_spawns_and_disables_backend(self):
        fake=FakeLinux()
        with fake.patched(),m.Journal.create(self.path) as journal:
            backend=m.FixedLinuxBackend()
            with mock.patch.object(journal,'append',side_effect=OSError('intent ack')):
                with self.assertRaises(OSError):
                    journal.run('a1','success',backend,Clock())
            self.assertEqual(fake.calls.count('Popen'),0)
            self.assertTrue(backend._disabled)
            self.assertIsNone(journal.snapshot()['observed_interval_ns_sum_or_None'])

    def test_cleanup_failure_blocks_and_preserves_incomplete(self):
        fake=FakeLinux();fake.cleanup_error=RuntimeError('cleanup')
        with fake.patched(),m.Journal.create(self.path) as journal:
            backend=m.FixedLinuxBackend()
            with self.assertRaisesRegex(RuntimeError,'cleanup'):
                journal.run('a1','success',backend,Clock())
            self.assertTrue(backend._disabled)
            self.assertIsNone(journal.snapshot()['observed_interval_ns_sum_or_None'])

    def test_postlaunch_baseexception_always_cleans(self):
        fake=FakeLinux()
        with fake.patched(),m.Journal.create(self.path) as journal:
            backend=m.FixedLinuxBackend()
            with mock.patch.object(backend,'finish',side_effect=KeyboardInterrupt('cancel')):
                with self.assertRaises(KeyboardInterrupt):
                    journal.run('a1','success',backend,Clock())
            self.assertEqual(fake.calls.count('cleanup'),1)
            self.assertTrue(backend._disabled)

    def test_postlaunch_exception_always_cleans(self):
        fake=FakeLinux()
        with fake.patched(),m.Journal.create(self.path) as journal:
            backend=m.FixedLinuxBackend()
            with mock.patch.object(backend,'finish',side_effect=RuntimeError('wait failed')):
                with self.assertRaisesRegex(RuntimeError,'wait failed'):
                    journal.run('a1','success',backend,Clock())
            self.assertEqual(fake.calls.count('cleanup'),1)
            self.assertIsNone(journal.snapshot()['observed_interval_ns_sum_or_None'])

    def test_metadata_failure_known_proc_is_cleaned_internally(self):
        fake=FakeLinux();fake.metadata_error=RuntimeError('metadata')
        with fake.patched(),m.Journal.create(self.path) as journal:
            backend=m.FixedLinuxBackend()
            with self.assertRaisesRegex(RuntimeError,'metadata'):
                journal.run('a1','success',backend,Clock())
            self.assertEqual(fake.calls.count('cleanup'),1)
            self.assertTrue(fake.scratch[0].cleaned)
            self.assertIsNone(journal.snapshot()['observed_interval_ns_sum_or_None'])

    def test_pgrp_identity_mismatch_cleans_known_proc(self):
        fake=FakeLinux()
        with fake.patched(),m.Journal.create(self.path) as journal:
            with mock.patch.object(m.gate,'parse_proc_stat',return_value={
                'pid':7,'pgrp':999,'start_ticks':107}):
                with self.assertRaisesRegex(ValueError,'LEADER_NEW_SESSION'):
                    journal.run('a1','success',m.FixedLinuxBackend(),Clock())
            self.assertEqual(fake.calls.count('cleanup'),1)
            self.assertIsNone(journal.snapshot()['observed_interval_ns_sum_or_None'])

    def test_metadata_and_cleanup_error_preserve_primary_cause(self):
        fake=FakeLinux();fake.metadata_error=KeyboardInterrupt('metadata')
        fake.cleanup_error=RuntimeError('cleanup')
        with fake.patched(),m.Journal.create(self.path) as journal:
            with self.assertRaises(RuntimeError) as raised:
                journal.run('a1','success',m.FixedLinuxBackend(),Clock())
            self.assertIsInstance(raised.exception.__cause__,KeyboardInterrupt)

    def test_launched_ack_failure_cleans_known_handle(self):
        fake=FakeLinux()
        with fake.patched(),m.Journal.create(self.path) as journal:
            original=journal.append
            def fail(kind,aid,payload):
                if kind=='LAUNCHED': raise OSError('ack')
                return original(kind,aid,payload)
            with mock.patch.object(journal,'append',side_effect=fail):
                with self.assertRaises(OSError):
                    journal.run('a1','success',m.FixedLinuxBackend(),Clock())
            self.assertEqual(fake.calls.count('cleanup'),1)
            self.assertIsNone(journal.snapshot()['observed_interval_ns_sum_or_None'])

    def test_terminal_fullrow_fsync_failure_replay_not_ack(self):
        fake=FakeLinux()
        with fake.patched(),m.Journal.create(self.path) as journal:
            backend=m.FixedLinuxBackend();clock=Clock()
            journal.run('a1','success',backend,clock)
            journal.run('a2','failure',backend,clock)
            real_fsync=os.fsync
            calls=[0]
            def fail(fd):
                calls[0]+=1
                if calls[0]==3: raise OSError('terminal ACK uncertain')
                return real_fsync(fd)
            with mock.patch.object(m.os,'fsync',side_effect=fail):
                with self.assertRaises(OSError):
                    journal.run('a3','timeout_group',backend,clock)
            self.assertIsNone(journal.snapshot()['observed_interval_ns_sum_or_None'])
        replay=m.load(self.path)
        self.assertTrue(replay['structural_complete'])
        self.assertFalse(replay['fsync_acknowledgments_verified'])
        self.assertIsNone(replay['observed_interval_ns_sum_or_None'])

    def test_replay_torn_and_tampered_rejected(self):
        fake=FakeLinux()
        with fake.patched(),m.Journal.create(self.path) as journal:
            journal.run('a1','success',m.FixedLinuxBackend(),Clock())
        raw=Path(self.path).read_bytes()
        with open(self.path,'ab') as stream: stream.write(b'{"torn":')
        with self.assertRaisesRegex(ValueError,'TORN_OR_OVERSIZE_LINE'): m.load(self.path)
        Path(self.path).write_bytes(raw.replace(b'"SUCCESS"',b'"FAILURE"'))
        with self.assertRaisesRegex(ValueError,'EVENT_CHAIN'): m.load(self.path)

    def test_replay_rejects_wrong_or_repeated_profile_and_pid1(self):
        self.assertFalse(m.identity_valid(dict(host='fixed-host',boot_id=BOOT_ID,
                                               pid=1,pgrp=1,start_ticks=100)))
        state=m.State()
        def apply(kind,aid,payload):
            body=state.event(kind,aid,payload)
            state.apply(dict(body,sha256=m.base.sha(m.base.canonical(body))))
        with self.assertRaisesRegex(ValueError,'INTENT_STATE'):
            apply('INTENT','a1',dict(profile='failure',clock_session='clock',prelaunch_ns=10))
        identity=dict(host='fixed-host',boot_id=BOOT_ID,pid=7,pgrp=7,start_ticks=107)
        apply('INTENT','a1',dict(profile='success',clock_session='clock',prelaunch_ns=10))
        apply('LAUNCHED','a1',dict(identity=identity))
        apply('REAPED','a1',dict(identity=identity,clock_session='clock',end_ns=20,
             interval_ns=10,status='SUCCESS',returncode=0,timed_out=False,
             leader_reaped=True,observed_group_empty=True))
        with self.assertRaisesRegex(ValueError,'INTENT_STATE'):
            apply('INTENT','a2',dict(profile='success',clock_session='clock',prelaunch_ns=20))

    def test_phase_host_or_boot_drift_cleans_second_and_replay_rejects(self):
        for changed in ('host','boot_id'):
            class Drift(FakeLinux):
                def preflight(self):
                    value=super().preflight()
                    if self.procs:
                        value[changed] = ('other-host' if changed=='host' else
                                          'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
                    return value

            fake=Drift()
            path=str(Path(self.tmp.name)/('drift-'+changed+'.jsonl'))
            with fake.patched(),m.Journal.create(path) as journal:
                backend=m.FixedLinuxBackend();clock=Clock()
                first=journal.run('a1','success',backend,clock)
                self.assertIsNone(first['observed_interval_ns_sum_or_None'])
                with self.assertRaisesRegex(ValueError,'LAUNCHED_STATE'):
                    journal.run('a2','failure',backend,clock)
                self.assertEqual(fake.calls.count('Popen'),2)
                self.assertEqual(fake.calls.count('cleanup'),2)
                self.assertIsNone(journal.snapshot()['observed_interval_ns_sum_or_None'])
                with self.assertRaisesRegex(ValueError,'UNRESOLVED_OR_DUPLICATE'):
                    journal.run('a3','timeout_group',backend,clock)
                self.assertEqual(fake.calls.count('Popen'),2)
                second_identity=dict(host='fixed-host',boot_id=BOOT_ID,
                                     pid=8,pgrp=8,start_ticks=108)
                second_identity[changed]=('other-host' if changed=='host' else
                                          'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
                body=journal._state.event('LAUNCHED','a2',dict(identity=second_identity))
                forged=dict(body,sha256=m.base.sha(m.base.canonical(body)))
            with open(path,'ab') as stream:
                stream.write(m.base.canonical(forged)+b'\n')
            with self.assertRaisesRegex(ValueError,'LAUNCHED_STATE'):
                m.load(path)


if __name__=='__main__': unittest.main()
