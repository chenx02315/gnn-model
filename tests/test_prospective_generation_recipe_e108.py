"""Read two tiny versioned Tcl fixtures; never execute Tcl or Tessent."""
import copy
from pathlib import Path
import unittest
from unittest.mock import patch

from src.data import prospective_generation_recipe_e108 as m


class Tests(unittest.TestCase):
    def setUp(self):
        root=Path(__file__).resolve().parents[1]/'src/data/templates'
        self.common=(root/'e108_common_base.tcl').read_bytes()
        self.incremental=(root/'e108_incremental_base.tcl').read_bytes()
        self.sources=m.freeze_sources(self.common,self.incremental)
        self.plan=m.pilot.build_plan()

    def binder(self,circuit='aes_core'):
        freeze=m.requests.freeze_acquisition(self.plan,circuit,20,'a'*64)
        return freeze,m.bindings.Binder(self.plan,circuit,freeze,'e108-test-'+circuit)

    def advance(self,binder,node):
        binding=binder.bind_next(node['task_uid']);raw=('opaque:'+node['task_uid']).encode('ascii')
        receipt=dict(task_uid=node['task_uid'],binding_sha256=binding['binding_sha256'],
            output_sha256=m.sha(raw),status='SUCCESS',live_acknowledged_claim=True,output_authenticated_claim=True)
        binder.commit_next(binding,receipt,raw)
        return binding

    def resign(self,value):
        value['binding_sha256']=m.sha(m.canonical({k:v for k,v in value.items() if k!='binding_sha256'}))
        return value

    def test_real_reviewed_template_bytes_exact_removal_not_newly_guessed_tcl(self):
        for name,original in (('common',self.common),('incremental',self.incremental)):
            row=self.sources[name]
            self.assertEqual(original.count(m.REMOVED),1)
            self.assertEqual(row['tcl_bytes'],original.replace(m.REMOVED,b'',1))
            self.assertNotIn(b'add_processors',row['tcl_bytes'])
            self.assertEqual(row['tcl_bytes'].count(b'create_patterns '),1)
            self.assertEqual(m.sha(row['tcl_bytes']),m.SOURCE_PINS[name][2])

    def test_all_48_fixed_requests_relocate_without_mutating_intent(self):
        before=copy.deepcopy(self.plan);count=0
        with patch('subprocess.Popen') as spawn:
            for phase in self.plan['phases']:
                freeze,binder=self.binder(phase['circuit'])
                for node in phase['tasks']:
                    binding=self.advance(binder,node);original=copy.deepcopy(binding)
                    if node['kind']=='TRANSLATION':continue
                    envelope=m.compile_execution(freeze,binding,self.sources);count+=1
                    self.assertEqual(binding,original)
                    self.assertEqual(envelope['argv'][0],m.identities.LAUNCHER)
                    self.assertTrue(envelope['argv'][5].startswith(m.ROOT+'/'))
                    self.assertTrue(envelope['argv'][7].startswith(m.ROOT+'/code/'))
                    self.assertNotIn(m.stage.ROOT,m.canonical(envelope).decode('ascii').replace(envelope['base_recipe_sha256'],''))
                    env=envelope['env']
                    self.assertEqual(envelope['result_dir'],env['CIRCUIT_ROOT']+'/'+env['PHASE']+'/'+env['MODE']+'_'+env['RUN_ID'])
                    if node['stage']!='F':self.assertEqual(env['PATTERN_LIMIT'],str(node['control']['value']))
                    else:self.assertEqual(env['TEST_COVERAGE_LIMIT'],'95')
                    self.assertNotEqual(envelope['effective_tcl_sha256'],envelope['base_tcl_sha256'])
                    self.assertEqual(envelope['lineage_claims'],{key:binding[key] for key in m.LINEAGE_KEYS})
                    self.assertFalse(envelope['lineage_claims_authenticated'])
                    self.assertFalse(envelope['translation_reference_is_native_mtfi_hash'])
                    self.assertFalse(envelope['execution_ready']);self.assertFalse(envelope['execution_authorized'])
                    self.assertIsNone(envelope['resource_budget'])
                    if node['stage']=='H':
                        self.assertIsNone(envelope['pre_statistics_path']);self.assertEqual(envelope['required_tasks'],[])
                    else:
                        self.assertEqual(len(envelope['required_tasks']),1)
                        self.assertEqual(envelope['required_tasks'][0]['output_status_file'],env['STATUS_FILE'])
            spawn.assert_not_called()
        self.assertEqual(count,48);self.assertEqual(before,self.plan)

    def test_unknown_template_or_derived_changes_rejected(self):
        with self.assertRaises(ValueError):m.freeze_sources(self.common+b'\n',self.incremental)
        freeze,binder=self.binder();binding=binder.bind_next(self.plan['phases'][0]['tasks'][0]['task_uid'])
        sources=copy.deepcopy(self.sources);sources['common']['tcl_bytes']+=b'exec attacker\n'
        sources['common']['tcl_sha256']=m.sha(sources['common']['tcl_bytes'])
        with self.assertRaises(ValueError):m.compile_execution(freeze,binding,sources)

    def test_binding_tamper_and_resigned_wrong_task_rejected(self):
        freeze,binder=self.binder();binding=binder.bind_next(self.plan['phases'][0]['tasks'][0]['task_uid'])
        bad=copy.deepcopy(binding);bad['recipe']['argv'][0]='other'
        with self.assertRaises(ValueError):m.compile_execution(freeze,bad,self.sources)
        with self.assertRaises(ValueError):m.compile_execution(freeze,self.resign(bad),self.sources)
        bad=copy.deepcopy(binding);bad['slot']=True
        with self.assertRaises(ValueError):m.compile_execution(freeze,self.resign(bad),self.sources)
        bad=copy.deepcopy(binding);bad['request']['action_uid']=next(r['action_uid'] for r in freeze['requested_roster']
            if r['scheme']=='HMF' and r['h_request']==binding['request']['control']['value'])
        bad['recipe']=m.stage.compile_stage(freeze,bad['request'])
        with self.assertRaises(ValueError):m.compile_execution(freeze,self.resign(bad),self.sources)

    def test_translation_slot_is_not_a_tessent_launch(self):
        freeze,binder=self.binder();tasks=self.plan['phases'][0]['tasks']
        self.advance(binder,tasks[0]);translation=binder.bind_next(tasks[1]['task_uid'])
        with self.assertRaises(ValueError):m.compile_execution(freeze,translation,self.sources)

    def test_incremental_parent_and_translation_identity_not_substituted(self):
        freeze,binder=self.binder();tasks=self.plan['phases'][0]['tasks']
        self.advance(binder,tasks[0]);self.advance(binder,tasks[1])
        binding=binder.bind_next(tasks[2]['task_uid'])
        bad=copy.deepcopy(binding);bad['translation_task_uid']='wrong-translation'
        with self.assertRaises(ValueError):m.compile_execution(freeze,self.resign(bad),self.sources)
        bad=copy.deepcopy(binding);bad['parent_task_uid']='wrong-parent';bad['request']['parent_attempt_uid']='wrong-parent'
        bad['recipe']=m.stage.compile_stage(freeze,bad['request'])
        with self.assertRaises(ValueError):m.compile_execution(freeze,self.resign(bad),self.sources)

    def test_resigned_absent_malformed_or_inappropriate_lineage_sha_claims_rejected(self):
        freeze,binder=self.binder();tasks=self.plan['phases'][0]['tasks']
        h=binder.bind_next(tasks[0]['task_uid'])
        bad=copy.deepcopy(h);bad['translation_result_sha256']='a'*64
        with self.assertRaises(ValueError):m.compile_execution(freeze,self.resign(bad),self.sources)
        self.advance(binder,tasks[0]);self.advance(binder,tasks[1])
        binding=binder.bind_next(tasks[2]['task_uid'])
        for field in ('previous_receipt_sha256','parent_result_sha256','parent_receipt_sha256',
                      'translation_result_sha256','translation_receipt_sha256'):
            for value in (None,False,'not-a-sha'):
                bad=copy.deepcopy(binding);bad[field]=value
                with self.assertRaises(ValueError):m.compile_execution(freeze,self.resign(bad),self.sources)

    def test_binding_control_types_flags_and_unknown_fields_are_not_e86_schema(self):
        freeze,binder=self.binder()
        node=self.plan['phases'][0]['tasks'][0]
        # Find a literal h=1 slot, independent of roster sorting.
        for task in self.plan['phases'][0]['tasks']:
            if task['kind']=='TESSENT' and task['stage']=='H' and task['control']['value']==1:
                node=task;break
            self.advance(binder,task)
        binding=binder.bind_next(node['task_uid'])
        bad=copy.deepcopy(binding);bad['control']['value']=True
        with self.assertRaises(ValueError):m.compile_execution(freeze,self.resign(bad),self.sources)
        for field in ('compilation_ready','caller_claims_not_os_proof','execution_ready','training_release'):
            bad=copy.deepcopy(binding);bad[field]=int(bad[field])
            with self.assertRaises(ValueError):m.compile_execution(freeze,self.resign(bad),self.sources)
        bad=copy.deepcopy(binding);bad['quality']=95
        with self.assertRaises(ValueError):m.compile_execution(freeze,self.resign(bad),self.sources)
