"""Pure local synthetic bridge checks; no process, network, or ATPG data."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from src.data import prospective_task_lifecycle_bridge_v1 as m


def plan():
    return [dict(task_uid='h',kind='TESSENT_STAGE',stage='H',request_sha256='a'*64,
                 depends_on=[],timeout_ns=10,cleanup_ns=2),
            dict(task_uid='translate-m',kind='STATUS_TRANSLATION',stage='M',
                 request_sha256='b'*64,depends_on=[],timeout_ns=10,cleanup_ns=2),
            dict(task_uid='m',kind='TESSENT_STAGE',stage='M',request_sha256='b'*64,
                 depends_on=['translate-m'],timeout_ns=10,cleanup_ns=2)]


def create(root, profiles=None, **caps):
    return m.Bridge.create(root,'synthetic-phase',plan(),
        max_tessent_calls=caps.get('max_tessent_calls',2),
        max_translation_calls=caps.get('max_translation_calls',1),
        phase_envelope_ns=caps.get('phase_envelope_ns',36),
        profiles=profiles or {'h':'success','translate-m':'success','m':'success'},
        clock_session='synthetic-clock')


class Clock:
    def __init__(self,start=10,end=15,session='synthetic-clock'):
        self.values=iter(((session,start),(session,end)))
    def capture(self):
        return next(self.values)


class Backend:
    synthetic_only=True
    os_authenticated=False
    actual_processes=0
    def __init__(self,number=1):
        self.number=number
        self.calls=[]
        self.on_launch=None
        self.on_finish=None
        self.cleanup_error=None
        self.host='synthetic-local'
        self.boot='synthetic-boot'
    def launch(self,profile):
        self.calls.append('launch')
        if self.on_launch:self.on_launch()
        return object(),dict(host=self.host,boot_id=self.boot,pid=self.number,
                             start_ticks=self.number)
    def finish(self,handle,profile):
        self.calls.append('finish')
        if self.on_finish:self.on_finish()
        status,code,timed_out=m.life.EXPECTED[profile]
        return dict(status=status,returncode=code,timed_out=timed_out)
    def cleanup(self,handle):
        self.calls.append('cleanup')
        if self.cleanup_error:raise self.cleanup_error
        return dict(leader_reaped=True,observed_group_empty=True)


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'phase'

    def test_success_translation_dependency_live_then_replay_no_ack(self):
        with create(self.root) as bridge:
            states=[]
            for i,uid in enumerate(('h','translate-m','m')):
                states.append(bridge.run(uid,'success',Backend(i+1),Clock(10+i*20,15+i*20)))
            self.assertFalse(states[0]['complete_live_acknowledged'])
            self.assertFalse(states[1]['complete_live_acknowledged'])
            self.assertTrue(states[2]['complete_live_acknowledged'])
            self.assertEqual(states[2]['observed_interval_ns_sum_or_None'],15)
            self.assertEqual(states[2]['paired_task_count'],3)
            self.assertFalse(states[2]['execution_ready'])
        replay=m.load(self.root)
        self.assertTrue(replay['structural_full_success'])
        self.assertFalse(replay['fsync_acknowledgments_verified'])
        self.assertIsNone(replay['observed_interval_ns_sum_or_None'])
        self.assertEqual(replay['binding_sha256'],states[-1]['binding_sha256'])
        with self.assertRaises(FileExistsError):create(self.root)

    def test_wrong_uid_or_profile_poison_before_debit_or_launch(self):
        for bad_uid,bad_profile in (('m','success'),('h','failure')):
            root=Path(self.tmp.name)/(bad_uid+bad_profile)
            with create(root) as bridge:
                backend=Backend()
                with self.assertRaisesRegex(ValueError,'EXACT_NEXT_SYNTHETIC_TASK'):
                    bridge.run(bad_uid,bad_profile,backend,Clock())
                self.assertEqual(backend.calls,[])
                self.assertTrue(bridge.snapshot()['bridge_poisoned'])
            self.assertEqual(m.load(root)['paired_task_count'],0)

    def test_budget_cap_denial_before_launch_and_no_retry(self):
        with create(self.root,max_tessent_calls=1) as bridge:
            bridge.run('h','success',Backend(1),Clock(10,15))
            bridge.run('translate-m','success',Backend(2),Clock(30,35))
            backend=Backend(3)
            with self.assertRaisesRegex(ValueError,'CENSORED_DECLARED_BUDGET_EXHAUSTED'):
                bridge.run('m','success',backend,Clock(50,55))
            self.assertEqual(backend.calls,[])
            self.assertIsNone(bridge.snapshot()['observed_interval_ns_sum_or_None'])
            with self.assertRaisesRegex(ValueError,'BRIDGE_UNAVAILABLE'):
                bridge.run('m','success',backend,Clock(50,55))

    def test_unknown_spawn_and_finish_error_are_fail_closed(self):
        class Unknown(Backend):
            def launch(self,profile):
                self.calls.append('launch')
                raise RuntimeError('unknown spawn')
        with create(self.root) as bridge:
            backend=Unknown()
            with self.assertRaisesRegex(RuntimeError,'unknown spawn'):
                bridge.run('h','success',backend,Clock())
            self.assertEqual(backend.calls,['launch'])
            self.assertTrue(bridge.snapshot()['bridge_poisoned'])
        self.assertFalse(m.load(self.root)['structural_full_success'])

        root=Path(self.tmp.name)/'finish'
        with create(root) as bridge:
            backend=Backend()
            def fail():raise KeyboardInterrupt('finish')
            backend.on_finish=fail
            with self.assertRaises(KeyboardInterrupt):
                bridge.run('h','success',backend,Clock())
            self.assertEqual(backend.calls,['launch','finish','cleanup'])
            self.assertTrue(bridge.snapshot()['bridge_poisoned'])

    def test_cleanup_error_and_bad_clock_poison(self):
        with create(self.root) as bridge:
            backend=Backend()
            backend.cleanup_error=RuntimeError('cleanup')
            with self.assertRaisesRegex(RuntimeError,'cleanup'):
                bridge.run('h','success',backend,Clock())
            self.assertEqual(backend.calls,['launch','finish','cleanup'])
        root=Path(self.tmp.name)/'clock'
        with create(root) as bridge:
            backend=Backend()
            with self.assertRaisesRegex(ValueError,'BRIDGE_CLOCK_SESSION'):
                bridge.run('h','success',backend,Clock(session='wrong'))
            self.assertEqual(backend.calls,[])

    def test_host_boot_and_identity_reuse_stop_after_known_cleanup(self):
        for change in ('host','boot','identity'):
            root=Path(self.tmp.name)/change
            with create(root) as bridge:
                bridge.run('h','success',Backend(1),Clock(10,15))
                backend=Backend(1 if change=='identity' else 2)
                if change=='host':backend.host='synthetic-other'
                if change=='boot':backend.boot='synthetic-otherboot'
                with self.assertRaisesRegex(ValueError,'BRIDGE_HOST_BOOT_CHANGED|BRIDGE_IDENTITY_REUSE|BRIDGE_IDENTITY_PHASE|LAUNCHED_STATE'):
                    bridge.run('translate-m','success',backend,Clock(30,35))
                self.assertEqual(backend.calls,['launch','cleanup'])
                self.assertIsNone(bridge.snapshot()['observed_interval_ns_sum_or_None'])
                with self.assertRaisesRegex(ValueError,'BRIDGE_UNAVAILABLE'):
                    bridge.run('m','success',Backend(3),Clock(50,55))

    def test_reentrant_snapshot_poison_and_known_handle_cleanup(self):
        with create(self.root) as bridge:
            backend=Backend()
            backend.on_finish=lambda:self.assertTrue(bridge.snapshot()['bridge_poisoned'])
            with self.assertRaisesRegex(ValueError,'LIFECYCLE_ACK_UNAVAILABLE'):
                bridge.run('h','success',backend,Clock())
            self.assertEqual(backend.calls,['launch','finish','cleanup'])
            self.assertIsNone(bridge.snapshot()['observed_interval_ns_sum_or_None'])

    def test_manifest_tamper_or_crossphase_swap_rejected(self):
        with create(self.root):pass
        original=(self.root/'binding.json').read_bytes()
        row=json.loads(original)
        row['attempts'][0]['request_sha256']='f'*64
        (self.root/'binding.json').write_bytes(m.canonical(row))
        with self.assertRaisesRegex(ValueError,'BINDING_PIN'):
            m.load(self.root)
        (self.root/'binding.json').write_bytes(original)
        self.assertFalse(m.load(self.root)['structural_full_success'])

    def test_profiles_and_bool_alias_rejected_before_directory(self):
        with self.assertRaisesRegex(ValueError,'FIXED_PROFILE_MAP'):
            create(self.root,profiles={'h':'success'})
        self.assertFalse(self.root.exists())
        caps=dict(max_tessent_calls=True,max_translation_calls=1,phase_envelope_ns=36)
        with self.assertRaisesRegex(ValueError,'DECLARED_CAPS'):
            create(self.root,**caps)
        self.assertFalse(self.root.exists())

    def test_binding_path_independent_across_fresh_roots(self):
        first=Path(self.tmp.name)/'first'
        second=Path(self.tmp.name)/'second'
        with create(first):pass
        with create(second):pass
        self.assertEqual((first/'binding.json').read_bytes(),
                         (second/'binding.json').read_bytes())

    def test_five_runtime_fsync_ack_windows_stop_without_retry(self):
        expected={1:[],2:[],3:['launch','cleanup'],
                  4:['launch','finish','cleanup'],
                  5:['launch','finish','cleanup']}
        for fail_at in range(1,6):
            root=Path(self.tmp.name)/('ack'+str(fail_at))
            with create(root) as bridge:
                backend=Backend()
                original=os.fsync
                calls=[0]
                def fault(fd):
                    calls[0]+=1
                    original(fd)  # Full bytes can exist without a returned ACK.
                    if calls[0]==fail_at:
                        raise OSError('injected fsync')
                with mock.patch.object(m.os,'fsync',side_effect=fault):
                    with self.assertRaises(OSError):
                        bridge.run('h','success',backend,Clock())
                self.assertEqual(calls[0],fail_at)
                self.assertEqual(backend.calls,expected[fail_at])
                self.assertTrue(bridge.snapshot()['bridge_poisoned'])
                self.assertIsNone(bridge.snapshot()['observed_interval_ns_sum_or_None'])
                with self.assertRaisesRegex(ValueError,'BRIDGE_UNAVAILABLE'):
                    bridge.run('h','success',Backend(),Clock())
            replay=m.load(root)
            self.assertFalse(replay['fsync_acknowledgments_verified'])
            self.assertIsNone(replay['observed_interval_ns_sum_or_None'])

    def test_binding_fsync_failure_preserves_exclusive_partial_root(self):
        original=os.fsync
        def fault(fd):
            original(fd)
            raise OSError('binding fsync')
        with mock.patch.object(m.os,'fsync',side_effect=fault):
            with self.assertRaisesRegex(OSError,'binding fsync'):
                create(self.root)
        self.assertTrue(self.root.exists())
        self.assertTrue((self.root/'binding.json').exists())
        with self.assertRaises(FileExistsError):
            create(self.root)

    def test_expected_failure_and_timeout_settle_then_stop(self):
        for profile in ('failure','timeout_group'):
            root=Path(self.tmp.name)/profile
            fixed={'h':profile,'translate-m':'success','m':'success'}
            with create(root,profiles=fixed) as bridge:
                backend=Backend()
                state=bridge.run('h',profile,backend,Clock())
                self.assertEqual(backend.calls,['launch','finish','cleanup'])
                self.assertIsNone(state['observed_interval_ns_sum_or_None'])
                self.assertEqual(state['paired_task_count'],1)
                with self.assertRaisesRegex(ValueError,'STOPPED_ACTIVE_OR_FINISHED'):
                    bridge.run('translate-m','success',Backend(2),Clock(30,35))
            self.assertEqual(m.load(root)['paired_task_count'],1)

    def test_cross_phase_lifecycle_swap_after_attempt_rejected(self):
        first=Path(self.tmp.name)/'first-phase'
        second=Path(self.tmp.name)/'second-phase'
        with create(first) as bridge:
            bridge.run('h','success',Backend(1),Clock())
        with m.Bridge.create(second,'different-phase',plan(),
                             max_tessent_calls=2,max_translation_calls=1,
                             phase_envelope_ns=36,
                             profiles={'h':'success','translate-m':'success','m':'success'},
                             clock_session='synthetic-clock') as bridge:
            bridge.run('h','success',Backend(1),Clock())
        first_life=(first/'lifecycle.jsonl').read_bytes()
        (first/'lifecycle.jsonl').write_bytes((second/'lifecycle.jsonl').read_bytes())
        with self.assertRaisesRegex(ValueError,'BRIDGE_ATTEMPT_BINDING'):
            m.load(first)
        (first/'lifecycle.jsonl').write_bytes(first_life)
        self.assertEqual(m.load(first)['paired_task_count'],1)

    def test_budget_header_swap_with_different_caps_rejected(self):
        first=Path(self.tmp.name)/'budget-first'
        second=Path(self.tmp.name)/'budget-second'
        with create(first):pass
        with create(second,max_tessent_calls=1):pass
        original=(first/'budget.jsonl').read_bytes()
        (first/'budget.jsonl').write_bytes((second/'budget.jsonl').read_bytes())
        with self.assertRaisesRegex(ValueError,'BRIDGE_BUDGET_HEADER_BINDING'):
            m.load(first)
        (first/'budget.jsonl').write_bytes(original)
        self.assertEqual(m.load(first)['paired_task_count'],0)

    def test_reaped_identity_numeric_alias_rejected_despite_rehash(self):
        with create(self.root) as bridge:
            bridge.run('h','success',Backend(1),Clock())
        path=self.root/'lifecycle.jsonl'
        original=path.read_bytes()
        for alias in (True,1.0):
            rows=[json.loads(line) for line in original.splitlines()]
            terminal=rows[-1]
            self.assertEqual(terminal['kind'],'REAPED')
            terminal['payload']['identity']['pid']=alias
            body={key:terminal[key] for key in
                  ('seq','kind','attempt_id','payload','prev')}
            terminal['sha256']=m.life.sha(m.life.canonical(body))
            path.write_bytes(b''.join(m.canonical(row)+b'\n' for row in rows))
            with self.assertRaisesRegex(ValueError,'BRIDGE_REAPED_IDENTITY_ALIAS'):
                m.load(self.root)
        path.write_bytes(original)
        self.assertEqual(m.load(self.root)['paired_task_count'],1)

    def test_binding_tamper_after_debit_blocks_launch(self):
        with create(self.root) as bridge:
            backend=Backend()
            original=bridge._budget.reserve
            def tamper(uid):
                token=original(uid)
                path=self.root/'binding.json'
                path.write_bytes(path.read_bytes()+b' ')
                return token
            with mock.patch.object(bridge._budget,'reserve',side_effect=tamper):
                with self.assertRaisesRegex(ValueError,'BINDING_CHANGED'):
                    bridge.run('h','success',backend,Clock())
            self.assertEqual(backend.calls,[])
            self.assertTrue(bridge.snapshot()['bridge_poisoned'])

    def test_launch_callback_tamper_blocks_finish_but_still_cleans_handle(self):
        with create(self.root) as bridge:
            backend=Backend()
            def tamper():
                path=self.root/'binding.json'
                path.write_bytes(path.read_bytes()+b' ')
            backend.on_launch=tamper
            with self.assertRaisesRegex(ValueError,'BINDING_CHANGED'):
                bridge.run('h','success',backend,Clock())
            self.assertEqual(backend.calls,['launch','cleanup'])
            self.assertTrue(bridge.snapshot()['bridge_poisoned'])

    def test_creation_failure_attempts_both_writer_closes_even_if_one_raises(self):
        budget_close=m.budget.Journal.close
        life_close=m.life.Journal.close
        closed=[]
        def close_budget(writer):
            closed.append('budget')
            budget_close(writer)
        def close_life(writer):
            life_close(writer)
            raise OSError('life close')
        with mock.patch.object(m.Bridge,'_check',side_effect=ValueError('postcreate')):
            with mock.patch.object(m.life.Journal,'close',new=close_life):
                with mock.patch.object(m.budget.Journal,'close',new=close_budget):
                    with self.assertRaisesRegex(OSError,'life close'):
                        create(self.root)
        self.assertEqual(closed,['budget'])
        self.assertTrue(self.root.exists())
        with self.assertRaises(FileExistsError):create(self.root)

    def test_caller_profile_mutation_during_binding_hash_cannot_rebind(self):
        profiles={'h':'success','translate-m':'success','m':'success'}
        original_sha=m.sha
        changed=[False]
        def mutate(raw):
            if not changed[0]:
                profiles['h']='failure'
                changed[0]=True
            return original_sha(raw)
        with mock.patch.object(m,'sha',side_effect=mutate):
            with create(self.root,profiles=profiles):pass
        self.assertEqual(profiles['h'],'failure')
        self.assertEqual(m.load(self.root)['paired_task_count'],0)
        row=json.loads((self.root/'binding.json').read_bytes())
        self.assertEqual(row['profiles']['h'],'success')
