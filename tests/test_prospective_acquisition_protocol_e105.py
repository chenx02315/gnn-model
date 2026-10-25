"""Local temporary-file integration; synthetic callbacks never start processes."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.data import prospective_acquisition_protocol_e105 as m
from tests import test_prospective_task_lifecycle_bridge_v1 as fixtures


class Clock:
    def __init__(self):self.value=0
    def capture(self):
        self.value+=10
        return 'e105-clock',self.value


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'package'
        self.plan=m.pilot.build_plan()
        self.freezes={c:m.requests.freeze_acquisition(self.plan,c,100,'a'*64) for c in m.pilot.CIRCUITS}
        self.caps=dict(timeout_ns=100,cleanup_ns=20,phase_reservation_ns=39*120,setup_timeout_ns=100)
        self.profiles={p['circuit']:{n['task_uid']:'success' for n in p['tasks']} for p in self.plan['phases']}
        self.clock=Clock()

    def create(self):
        value=m.Package.create(self.root,'test-e105',self.plan,self.freezes,self.caps,
                               self.profiles,'e105-clock',self.clock)
        self.addCleanup(value.close)
        return value

    def setup_phase(self,value,circuit):
        value.begin_setup(circuit);value.end_setup(circuit,'SUCCESS',True)

    def output(self,binding,attempt):
        raw=('synthetic-output-reference:'+binding['task_uid']).encode('ascii')
        receipt=dict(task_uid=binding['task_uid'],binding_sha256=binding['binding_sha256'],
                     output_sha256=m.sha(raw),status='SUCCESS',
                     live_acknowledged_claim=True,output_authenticated_claim=True)
        return receipt,raw

    def test_projection_preserves_e86_full_dependencies_and_caps(self):
        original=copy.deepcopy(self.plan)
        for circuit in m.pilot.CIRCUITS:
            rows=m.budget_projection(self.plan,circuit,self.caps)
            self.assertEqual(len(rows),39)
            self.assertEqual(sum(r['kind']=='TESSENT_STAGE' for r in rows),24)
            self.assertEqual(sum(r['kind']=='STATUS_TRANSLATION' for r in rows),15)
        self.assertEqual(original,self.plan)
        with self.create() as value:
            self.setup_phase(value,'aes_core')
            tasks=self.plan['phases'][0]['tasks']
            for i,node in enumerate(tasks[:2]):
                value.run('aes_core',node['task_uid'],fixtures.Backend(i+1),self.output)
            bound=value._binders['aes_core'].bind_next(tasks[2]['task_uid'])
            self.assertEqual(bound['parent_task_uid'],tasks[0]['task_uid'])
            self.assertEqual(bound['translation_task_uid'],tasks[1]['task_uid'])

    def test_all_78_tasks_18_actions_single_package_and_session_cost(self):
        with patch('subprocess.Popen') as spawn,self.create() as value:
            number=0
            for phase in self.plan['phases']:
                circuit=phase['circuit'];self.setup_phase(value,circuit)
                for node in phase['tasks']:
                    number+=1
                    value.run(circuit,node['task_uid'],fixtures.Backend(number),self.output)
            result=value.finish()
            self.assertEqual(len(result['task_status']),78)
            self.assertEqual(set(result['task_status'].values()),{'SUCCESS'})
            self.assertEqual(len(result['action_status']),18)
            self.assertEqual(set(result['action_status'].values()),{'SUCCESS_SYNTHETIC_ONLY'})
            self.assertEqual(sum(v['TESSENT_STAGE'] for v in result['consumed_counts'].values()),48)
            self.assertEqual(sum(v['STATUS_TRANSLATION'] for v in result['consumed_counts'].values()),30)
            self.assertEqual(result['observed_task_intervals_ns_sum'],78*10)
            self.assertGreater(result['recorded_synthetic_session_ns'],78*10)
            self.assertFalse(result['full_cost_qualified'])
            self.assertIsNone(result['actual_atpg_runtime_ns'])
            self.assertFalse(result['training_release'])
            session=json.loads((self.root/'session.json').read_text())
            self.assertEqual(session['scope'],'SYNTHETIC_PRE_HEADER_TO_POST_LAST_TASK_RECEIPT_PRE_SESSION_ACK')
            spawn.assert_not_called()
        with self.assertRaises(FileExistsError):self.create()

    def test_failed_or_timeout_retains_paid_prefix_then_allows_second_circuit(self):
        task=self.plan['phases'][0]['tasks'][0]['task_uid']
        self.profiles['aes_core'][task]='timeout_group'
        with self.create() as value:
            self.setup_phase(value,'aes_core')
            result=value.run('aes_core',task,fixtures.Backend(1),self.output)
            self.assertEqual(result['status'],'TIMEOUT')
            snapshot=value.snapshot()
            self.assertEqual(snapshot['consumed_counts']['aes_core']['TESSENT_STAGE'],1)
            self.assertEqual(snapshot['observed_task_intervals_ns_sum'],10)
            self.assertEqual(snapshot['task_status'][task],'TIMEOUT')
            self.assertEqual(sum(s=='NOT_ATTEMPTED' for s in snapshot['task_status'].values()),77)
            self.setup_phase(value,'spi')
            value.run('spi',self.plan['phases'][1]['tasks'][0]['task_uid'],fixtures.Backend(2),self.output)

    def test_unknown_spawn_stops_entire_package_keeps_debit(self):
        class Unknown(fixtures.Backend):
            def launch(self,profile):raise RuntimeError('unknown handle')
        with self.create() as value:
            self.setup_phase(value,'aes_core')
            uid=self.plan['phases'][0]['tasks'][0]['task_uid']
            with self.assertRaises(RuntimeError):value.run('aes_core',uid,Unknown(1),self.output)
            snapshot=value.snapshot()
            self.assertTrue(snapshot['poisoned'])
            self.assertEqual(snapshot['consumed_counts']['aes_core']['TESSENT_STAGE'],1)
            self.assertEqual(snapshot['task_status'][uid],'UNRESOLVED')
            self.assertIsNone(snapshot['recorded_synthetic_session_ns'])
            with self.assertRaises(ValueError):value.begin_setup('spi')

    def test_semantic_receipt_failure_after_cleaned_attempt_never_refunds(self):
        def bad(binding,attempt):
            receipt,raw=self.output(binding,attempt);receipt['output_sha256']='f'*64
            return receipt,raw
        with self.create() as value:
            self.setup_phase(value,'aes_core')
            uid=self.plan['phases'][0]['tasks'][0]['task_uid'];backend=fixtures.Backend(1)
            with self.assertRaisesRegex(ValueError,'UNVERIFIED'):value.run('aes_core',uid,backend,bad)
            self.assertEqual(backend.calls,['launch','finish','cleanup'])
            snapshot=value.snapshot()
            self.assertEqual(snapshot['observed_task_intervals_ns_sum'],10)
            self.assertEqual(snapshot['consumed_counts']['aes_core']['TESSENT_STAGE'],1)
            self.assertEqual(value._binders['aes_core'].snapshot()['next_slot'],0)

    def test_setup_failure_is_charged_and_not_marked_task_attempt(self):
        with self.create() as value:
            value.begin_setup('aes_core');record=value.end_setup('aes_core','FAILED',True)
            self.assertEqual(record['elapsed_ns'],10)
            snapshot=value.snapshot()
            self.assertEqual(snapshot['consumed_counts']['aes_core']['TESSENT_STAGE'],0)
            self.setup_phase(value,'spi')

    def test_bad_backend_rejected_before_budget_debit(self):
        with self.create() as value:
            self.setup_phase(value,'aes_core');backend=fixtures.Backend(1);backend.synthetic_only=False
            with self.assertRaisesRegex(ValueError,'SYNTHETIC_BACKEND_ONLY'):
                value.run('aes_core',self.plan['phases'][0]['tasks'][0]['task_uid'],backend,self.output)
            self.assertEqual(backend.calls,[])
            self.assertEqual(value.snapshot()['consumed_counts']['aes_core']['TESSENT_STAGE'],0)

    def test_receipts_are_outside_unchanged_bridge_roots_and_tamper_stops(self):
        with self.create() as value:
            self.setup_phase(value,'aes_core')
            self.assertEqual(set(p.name for p in (self.root/'aes_core').iterdir()),set(m.paired.FILES))
            path=self.root/'setup_aes_core_result.json'
            with path.open('ab') as stream:stream.write(b'changed')
            with self.assertRaisesRegex(ValueError,'RECEIPT_CHANGED'):
                value.run('aes_core',self.plan['phases'][0]['tasks'][0]['task_uid'],fixtures.Backend(1),self.output)
            self.assertTrue(value.snapshot()['poisoned'])

    def test_terminal_fsync_error_poisoned_but_known_cleanup_and_debit_kept(self):
        with self.create() as value:
            self.setup_phase(value,'aes_core');original=value._publish
            def fail(name,row):
                if name=='aes_core_00_result.json':raise OSError('uncertain receipt fsync')
                return original(name,row)
            backend=fixtures.Backend(1)
            with patch.object(value,'_publish',side_effect=fail),self.assertRaises(OSError):
                value.run('aes_core',self.plan['phases'][0]['tasks'][0]['task_uid'],backend,self.output)
            self.assertEqual(backend.calls,['launch','finish','cleanup'])
            self.assertEqual(value.snapshot()['consumed_counts']['aes_core']['TESSENT_STAGE'],1)
            self.assertEqual(value._binders['aes_core'].snapshot()['next_slot'],0)

    def test_cross_phase_identity_reuse_is_not_counted_as_new_physical_success(self):
        first=self.plan['phases'][0]['tasks'][0]['task_uid'];self.profiles['aes_core'][first]='failure'
        with self.create() as value:
            self.setup_phase(value,'aes_core');value.run('aes_core',first,fixtures.Backend(1),self.output)
            self.setup_phase(value,'spi')
            with self.assertRaisesRegex(ValueError,'PACKAGE_IDENTITY_REUSE'):
                value.run('spi',self.plan['phases'][1]['tasks'][0]['task_uid'],fixtures.Backend(1),self.output)
            snapshot=value.snapshot()
            self.assertEqual(snapshot['observed_task_intervals_ns_sum'],20)
            self.assertEqual(snapshot['consumed_counts']['spi']['TESSENT_STAGE'],1)

    def test_verified_budget_denial_does_not_launch_and_only_stops_one_phase(self):
        self.caps['phase_reservation_ns']=1
        with self.create() as value:
            for phase in self.plan['phases']:
                circuit=phase['circuit'];self.setup_phase(value,circuit);backend=fixtures.Backend(1)
                result=value.run(circuit,phase['tasks'][0]['task_uid'],backend,self.output)
                self.assertEqual(result['status'],'NOT_ATTEMPTED')
                self.assertIsNone(result['observed_interval_ns'])
                self.assertEqual(backend.calls,[])
            result=value.finish()
            self.assertEqual(result['observed_task_intervals_ns_sum'],0)
            self.assertTrue(all(c['TESSENT_STAGE']==0 for c in result['consumed_counts'].values()))

    def test_backend_cannot_fake_prelaunch_denial_by_error_text(self):
        class FakeDenial(fixtures.Backend):
            def finish(self,handle,profile):raise ValueError('CENSORED_DECLARED_BUDGET_EXHAUSTED')
        with self.create() as value:
            self.setup_phase(value,'aes_core');backend=FakeDenial(1)
            with self.assertRaises(ValueError):
                value.run('aes_core',self.plan['phases'][0]['tasks'][0]['task_uid'],backend,self.output)
            self.assertTrue(value.snapshot()['poisoned'])
            self.assertEqual(backend.calls,['launch','cleanup'])

    def test_monotonic_clock_is_shared_between_setup_and_all_attempts(self):
        with self.create() as value:
            self.setup_phase(value,'aes_core');tasks=self.plan['phases'][0]['tasks']
            value.run('aes_core',tasks[0]['task_uid'],fixtures.Backend(1),self.output)
            self.clock.value=0;backend=fixtures.Backend(2)
            with self.assertRaisesRegex(ValueError,'PACKAGE_CLOCK'):
                value.run('aes_core',tasks[1]['task_uid'],backend,self.output)
            self.assertEqual(backend.calls,[])
            self.assertTrue(value.snapshot()['poisoned'])

    def test_intent_and_exactly_one_debit_exist_before_synthetic_launch(self):
        with self.create() as value:
            self.setup_phase(value,'aes_core');backend=fixtures.Backend(1)
            def inspect():
                self.assertTrue((self.root/'aes_core_00_intent.json').is_file())
                observed=m.paired.budget.load(self.root/'aes_core'/'budget.jsonl')
                self.assertEqual(observed['consumed_counts']['TESSENT_STAGE'],1)
            backend.on_launch=inspect
            value.run('aes_core',self.plan['phases'][0]['tasks'][0]['task_uid'],backend,self.output)

    def test_unknown_paired_storage_poison_keeps_known_cost_and_blocks_setup(self):
        with self.create() as value:
            self.setup_phase(value,'aes_core')
            uid=self.plan['phases'][0]['tasks'][0]['task_uid']
            value.run('aes_core',uid,fixtures.Backend(1),self.output)
            with patch.object(m.paired,'load',side_effect=OSError('unreadable paired journals')):
                snapshot=value.snapshot()
            self.assertTrue(snapshot['poisoned'])
            self.assertTrue(snapshot['counts_unknown'])
            self.assertEqual(snapshot['consumed_counts'],{'aes_core':None,'spi':None})
            self.assertEqual(snapshot['observed_task_intervals_ns_sum'],10)
            with self.assertRaisesRegex(ValueError,'PACKAGE_UNAVAILABLE'):value.begin_setup('spi')

    def test_wrong_binding_cannot_supply_known_counts(self):
        with self.create() as value:
            original=m.paired.load
            def changed(path):
                state=original(path)
                if str(path).endswith('aes_core'):state['binding_sha256']='f'*64
                return state
            with patch.object(m.paired,'load',side_effect=changed):snapshot=value.snapshot()
            self.assertTrue(snapshot['poisoned'])
            self.assertTrue(snapshot['counts_unknown'])
            self.assertIsNone(snapshot['consumed_counts']['aes_core'])
            self.assertEqual(snapshot['consumed_counts']['spi']['TESSENT_STAGE'],0)

    def test_create_inputs_are_frozen_before_first_io(self):
        original=m.Package._publish
        def mutate(value,name,row):
            result=original(value,name,row)
            if name=='package.json':
                self.caps['phase_reservation_ns']=1
                uid=self.plan['phases'][0]['tasks'][0]['task_uid']
                self.profiles['aes_core'][uid]='failure'
            return result
        with patch.object(m.Package,'_publish',new=mutate),self.create() as value:
            header=json.loads((self.root/'package.json').read_text())
            self.assertEqual(header['caps']['phase_reservation_ns'],4680)
            for circuit in m.pilot.CIRCUITS:
                state=m.paired.load(self.root/circuit)
                self.assertEqual(state['binding_sha256'],header['phase_binding_sha256'][circuit])
            self.setup_phase(value,'aes_core')
            row=value.run('aes_core',self.plan['phases'][0]['tasks'][0]['task_uid'],fixtures.Backend(1),self.output)
            self.assertEqual(row['status'],'SUCCESS')
