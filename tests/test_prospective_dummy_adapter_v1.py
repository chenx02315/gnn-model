"""Only three tiny local Python children; every other failure is synthetic."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from src.data import prospective_attempt_ledger_v1 as ledger
from src.data import prospective_dummy_adapter_v1 as adapter

FROZEN_LEDGER_SHA = 'b82869c4060f009c4a30906aada92dad7b7721f1a8474e8905e6bb7687672aec'


class FakeClock:
    session='synthetic-clock'
    def __init__(self):self.ns=0
    def capture(self):
        self.ns+=100
        return dict(clock_session=self.session,monotonic_ns=self.ns,utc='2030-01-01T00:00:00Z')


class FakeProcess:
    pid=12345
    def __init__(self, timeout=False, kill_failure=False, reap_failure=False, interrupt=False):
        self.returncode=None;self.timeout=timeout;self.kill_failure=kill_failure
        self.reap_failure=reap_failure;self.interrupt=interrupt;self.waits=0;self.kills=0
    def wait(self,timeout):
        self.waits+=1
        if self.waits==1 and self.interrupt:raise KeyboardInterrupt()
        if self.waits==1 and self.timeout:raise subprocess.TimeoutExpired('FIXED_TOY',timeout)
        if self.waits>1 and self.reap_failure:raise subprocess.TimeoutExpired('FIXED_TOY',timeout)
        self.returncode=-9 if self.kills else 0
        return self.returncode
    def kill(self):
        self.kills+=1
        if self.kill_failure:raise OSError('synthetic-kill-error')


class DummyAdapterTests(unittest.TestCase):
    def setUp(self):
        poison=patch.object(adapter,'_UNREAPED_CHILD',False)
        poison.start();self.addCleanup(poison.stop)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'dummy.jsonl'
        self.writer=ledger.Journal.create(self.path,adapter.SYNTHETIC_PLAN_SHA256)
        self.addCleanup(self.writer.close)

    def test_real_success_failure_timeout_local_only(self):
        for index,profile in enumerate(('success','failure','timeout')):
            began=time.monotonic()
            receipt=adapter.run_dummy(self.writer,'real-toy-%d'%index,profile,
                timeout_s=0.05 if profile=='timeout' else 1.0)
            self.assertLess(time.monotonic()-began,5)
            self.assertEqual(receipt['status'],'DUMMY_TERMINAL_RECORDED')
            self.assertTrue(receipt['child_reaped'])
            self.assertTrue(receipt['ledger_terminal_recorded'])
            self.assertEqual(receipt['timing_scope'],adapter.TIMING_SCOPE)
            self.assertIs(type(receipt['pid']),int)
            self.assertFalse(receipt['execution_ready'])
            self.assertFalse(receipt['real_atpg_integration'])
            item=self.writer.snapshot()['attempts']['real-toy-%d'%index]
            self.assertEqual(item['state'],dict(success='SUCCESS',failure='FAILED',timeout='TIMEOUT')[profile])
            self.assertIsNone(item['start']['execution_identity']['pid'])
            for field in ('d95','ate_cycles','output_artifact_sha256'):
                self.assertIsNone(item['end'][field])
            if profile!='timeout':self.assertEqual(receipt['returncode'],0 if profile=='success' else 7)

    def test_exact_fixed_command_no_shell_env_or_external_cwd(self):
        proc=FakeProcess();seen={}
        def spawn(argv,**kwargs):
            seen.update(argv=argv,kwargs=kwargs)
            self.assertEqual(list(Path(kwargs['cwd']).iterdir()),[])
            state=self.writer.snapshot()['attempts']['toy']
            self.assertEqual(state['state'],'RUNNING')
            self.assertEqual(ledger.load(self.path).snapshot()['attempts']['toy']['state'],'RUNNING')
            self.assertEqual(state['provenance']['command_sha256'],ledger.digest(argv))
            return proc
        with patch.object(adapter.subprocess,'Popen',side_effect=spawn) as call:
            adapter.run_dummy(self.writer,'toy','success',clock=FakeClock())
        self.assertEqual(call.call_count,1)
        self.assertEqual(seen['argv'],[adapter.sys.executable,'-I','-S','-B','-c','raise SystemExit(0)'])
        self.assertEqual(set(seen['kwargs']),{'shell','stdin','stdout','stderr','cwd'})
        self.assertFalse(seen['kwargs']['shell'])
        for key in ('stdin','stdout','stderr'):self.assertEqual(seen['kwargs'][key],subprocess.DEVNULL)

    def test_plan_or_start_fsync_failure_never_launches(self):
        for failing_call in (1,2):
            path=Path(self.temp.name)/('failure-%d.jsonl'%failing_call)
            with ledger.Journal.create(path,adapter.SYNTHETIC_PLAN_SHA256) as writer:
                original=ledger.os.fsync;count=[0]
                def fsync(fd):
                    count[0]+=1
                    if count[0]==failing_call:raise OSError('synthetic-fsync')
                    return original(fd)
                with patch.object(ledger.os,'fsync',side_effect=fsync),patch.object(adapter.subprocess,'Popen') as spawn:
                    with self.assertRaises(OSError):adapter.run_dummy(writer,'toy','success',clock=FakeClock())
                    spawn.assert_not_called()
                with self.assertRaises(ValueError):writer.aggregate(['dummy-success'])

    def test_spawn_failure_leaves_running_without_terminal(self):
        with patch.object(adapter.subprocess,'Popen',side_effect=OSError('synthetic-spawn')) as spawn:
            receipt=adapter.run_dummy(self.writer,'toy','success',clock=FakeClock())
        self.assertEqual(spawn.call_count,1)
        self.assertEqual(receipt['status'],'SPAWN_FAILED_RUNNING_INCOMPLETE')
        self.assertFalse(receipt['ledger_terminal_recorded'])
        self.assertIsNone(receipt['pid'])
        self.assertEqual(self.writer.snapshot()['attempts']['toy']['state'],'RUNNING')
        self.assertFalse(self.writer.aggregate(['dummy-success'])['complete'])

    def test_end_write_failure_child_reaped_no_extra_append(self):
        proc=FakeProcess();original=self.writer.append;calls=[]
        def append(kind,payload):
            calls.append(kind)
            if kind=='END':
                with patch.object(ledger.os,'fsync',side_effect=OSError('synthetic-end-fsync')):
                    return original(kind,payload)
            return original(kind,payload)
        with patch.object(self.writer,'append',side_effect=append),patch.object(adapter.subprocess,'Popen',return_value=proc):
            with self.assertRaises(OSError):adapter.run_dummy(self.writer,'toy','success',clock=FakeClock())
        self.assertEqual(calls,['PLAN','START','END'])
        self.assertEqual(proc.waits,1)
        self.assertEqual(proc.returncode,0)
        self.assertEqual(proc.kills,0)
        with self.assertRaises(ValueError):self.writer.aggregate(['dummy-success'])

    def test_kill_or_reap_failure_never_completes_ledger(self):
        for index,options in enumerate((dict(kill_failure=True),dict(reap_failure=True))):
            proc=FakeProcess(timeout=True,**options)
            with patch.object(adapter,'_UNREAPED_CHILD',False),ledger.Journal.create(Path(self.temp.name)/('cleanup-%d.jsonl'%index),adapter.SYNTHETIC_PLAN_SHA256) as writer:
                with patch.object(adapter.subprocess,'Popen',return_value=proc):
                    result=adapter.run_dummy(writer,'toy-%d'%index,'timeout',clock=FakeClock())
                self.assertEqual(writer.snapshot()['attempts']['toy-%d'%index]['state'],'RUNNING')
                self.assertTrue(adapter._UNREAPED_CHILD)
            self.assertEqual(result['status'],'CLEANUP_FAILED_RUNNING_INCOMPLETE')
            self.assertFalse(result['ledger_terminal_recorded'])
            self.assertEqual(proc.kills,1)
            self.assertEqual(proc.waits,2)
        with patch.object(adapter,'_UNREAPED_CHILD',True),patch.object(adapter.subprocess,'Popen') as spawn:
            with self.assertRaisesRegex(ValueError,'PROCESS_POISON'):
                adapter.run_dummy(self.writer,'blocked','success',clock=FakeClock())
            spawn.assert_not_called()

    def test_interrupt_after_child_exists_kills_reaps_and_propagates(self):
        proc=FakeProcess(interrupt=True)
        with patch.object(adapter.subprocess,'Popen',return_value=proc):
            with self.assertRaises(KeyboardInterrupt):adapter.run_dummy(self.writer,'toy','success',clock=FakeClock())
        self.assertEqual((proc.kills,proc.waits),(1,2))
        self.assertEqual(self.writer.snapshot()['attempts']['toy']['state'],'RUNNING')

    def test_bad_profile_timeout_and_real_plan_never_spawn(self):
        with patch.object(adapter.subprocess,'Popen') as spawn:
            for profile,timeout in (('arbitrary',0.1),('success',True),('success',0.01),('success',2),('success',float('nan'))):
                with self.assertRaises(ValueError):adapter.run_dummy(self.writer,'toy',profile,timeout)
            with ledger.Journal.create(Path(self.temp.name)/'real-plan.jsonl','a'*64) as other:
                with self.assertRaisesRegex(ValueError,'SYNTHETIC_PLAN_ONLY'):adapter.run_dummy(other,'toy','success')
            spawn.assert_not_called()
        with self.assertRaises(TypeError):adapter.PROFILES['success']='arbitrary'
        self.assertEqual(self.writer.snapshot()['attempts'],{})

    def test_single_worker_busy_has_no_journal_or_spawn_side_effect(self):
        adapter._WORKER.acquire()
        try:
            with patch.object(adapter.subprocess,'Popen') as spawn:
                with self.assertRaisesRegex(ValueError,'SINGLE_DUMMY_WORKER_BUSY'):
                    adapter.run_dummy(self.writer,'toy','success')
                spawn.assert_not_called()
        finally:adapter._WORKER.release()
        self.assertEqual(self.writer.snapshot()['attempts'],{})

    def test_lock_released_after_spawn_failure(self):
        with patch.object(adapter.subprocess,'Popen',side_effect=OSError('synthetic')):
            adapter.run_dummy(self.writer,'toy','success',clock=FakeClock())
        self.assertTrue(adapter._WORKER.acquire(False))
        adapter._WORKER.release()
        with patch.object(adapter.subprocess,'Popen') as spawn:
            with self.assertRaisesRegex(ValueError,'PROCESS_POISON'):
                adapter.run_dummy(self.writer,'retry-forbidden','success',clock=FakeClock())
            spawn.assert_not_called()

    def test_spawn_interrupt_or_error_poison_blocks_new_journal(self):
        for index,error in enumerate((KeyboardInterrupt(),SystemExit(9),OSError('synthetic-spawn'))):
            with patch.object(adapter,'_UNREAPED_CHILD',False):
                with ledger.Journal.create(Path(self.temp.name)/('spawn-%d.jsonl'%index),adapter.SYNTHETIC_PLAN_SHA256) as writer:
                    with patch.object(adapter.subprocess,'Popen',side_effect=error) as spawn:
                        if isinstance(error,Exception):
                            receipt=adapter.run_dummy(writer,'toy','success',clock=FakeClock())
                            self.assertEqual(receipt['status'],'SPAWN_FAILED_RUNNING_INCOMPLETE')
                        else:
                            with self.assertRaises(type(error)):
                                adapter.run_dummy(writer,'toy','success',clock=FakeClock())
                        self.assertEqual(spawn.call_count,1)
                    self.assertEqual(writer.snapshot()['attempts']['toy']['state'],'RUNNING')
                    self.assertTrue(adapter._UNREAPED_CHILD)
                    with patch.object(adapter.subprocess,'Popen') as blocked:
                        with self.assertRaisesRegex(ValueError,'PROCESS_POISON'):
                            adapter.run_dummy(self.writer,'blocked','success',clock=FakeClock())
                        blocked.assert_not_called()

    def test_post_spawn_pre_cleanup_interrupt_keeps_global_poison(self):
        proc=FakeProcess()
        source=Path(adapter.__file__).read_text().splitlines()
        target=next(i for i,line in enumerate(source,1)
                    if i>adapter._run.__code__.co_firstlineno and line=='        reaped = False')
        previous=sys.gettrace()
        def interrupt(frame,event,arg):
            if frame.f_code is adapter._run.__code__ and event=='line' and frame.f_lineno==target:
                raise KeyboardInterrupt()
            return interrupt
        try:
            with patch.object(adapter.subprocess,'Popen',return_value=proc) as spawn:
                sys.settrace(interrupt)
                with self.assertRaises(KeyboardInterrupt):
                    adapter.run_dummy(self.writer,'toy','success',clock=FakeClock())
                self.assertEqual(spawn.call_count,1)
        finally:
            sys.settrace(previous)
        self.assertEqual((proc.waits,proc.kills),(0,0))
        self.assertTrue(adapter._UNREAPED_CHILD)
        with ledger.Journal.create(Path(self.temp.name)/'new-after-gap.jsonl',adapter.SYNTHETIC_PLAN_SHA256) as other:
            with patch.object(adapter.subprocess,'Popen') as spawn:
                with self.assertRaisesRegex(ValueError,'PROCESS_POISON'):
                    adapter.run_dummy(other,'blocked','success',clock=FakeClock())
                spawn.assert_not_called()

    def test_existing_unresolved_records_block_new_dispatch(self):
        from tests.test_prospective_attempt_ledger_v1 import plan,start,end,provenance
        for index,state in enumerate(('PLANNED','RUNNING','UNVERIFIED_TIMEOUT')):
            with ledger.Journal.create(Path(self.temp.name)/('leftover-%d.jsonl'%index),adapter.SYNTHETIC_PLAN_SHA256) as writer:
                writer.append('PLAN',plan(provenance=provenance(plan_sha256=adapter.SYNTHETIC_PLAN_SHA256)))
                if state!='PLANNED':writer.append('START',start())
                if state=='UNVERIFIED_TIMEOUT':writer.append('END',end(state='TIMEOUT',termination_verified=False))
                with patch.object(adapter.subprocess,'Popen') as spawn:
                    with self.assertRaisesRegex(ValueError,'UNRESOLVED_JOURNAL_ATTEMPT'):
                        adapter.run_dummy(writer,'blocked','success',clock=FakeClock())
                    spawn.assert_not_called()

    def test_frozen_e65_source_unchanged(self):
        self.assertEqual(hashlib.sha256(Path(ledger.__file__).read_bytes()).hexdigest(),FROZEN_LEDGER_SHA)


if __name__=='__main__':
    unittest.main()
