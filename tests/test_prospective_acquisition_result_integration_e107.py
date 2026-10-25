"""End-to-end local synthetic E105/E106/E93 wiring, never physical ATPG."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.data import prospective_acquisition_protocol_e105 as protocol
from src.data import prospective_result_union_e106 as results
from tests.test_prospective_acquisition_protocol_e105 import Clock
from tests.test_prospective_task_lifecycle_bridge_v1 import Backend
from tests.test_prospective_tessent_stage_v1 import markers


class Outputs:
    """Fixture producer only, not a real artifact reader or process adapter."""
    def __init__(self,freezes):
        self.freezes=freezes;self.saved={};self.rows={};self.checked={}
        self.translation_count=0;self.bad_translation=False
        lines=['stuck_value\tcanonical_core_path\tH_native_path\tM_native_path\tF_native_path']
        for i in range(20):
            core='/U%d/p'%(10+i)
            lines.append('\t'.join(('0',core,core,core,'/U%d/p'%(9+i))))
        self.mapping=('\n'.join(lines)+'\n').encode('ascii')

    def mtfi(self,mode,count):
        body=list(results.faults.HEADER)
        for i in range(20):
            cls=('DI.CLK' if i==0 else 'DS') if i<count else 'RE'
            body.append('   0, %s, "/U%d/p";\n'%(cls,(9 if mode=='F' else 10)+i))
        return ''.join(body+list(results.faults.FOOTER)).encode('ascii')

    def __call__(self,binding,attempt):
        uid=binding['task_uid'];mode=binding['target_mode'];action=binding['action_uid']
        parent=(None if binding['parent_task_uid'] is None else self.saved[binding['parent_task_uid']])
        if parent is not None:
            assert binding['parent_result_sha256']==results.sha(parent['reference'])
        if binding['kind']=='TRANSLATION':
            basic=''.join('0 FU "/U%d/p"\n'%((9 if mode=='F' else 10)+i) for i in range(20)).encode('ascii')
            source=parent['mtfi']
            if self.bad_translation:source=source.replace(b'/U10/p',b'/U999/p')
            translated=results.faults.translate(self.mapping,source,basic,parent['mode'],mode,20,1,
                dict(mapping=results.sha(self.mapping),source_mtfi=results.sha(source),target_basic=results.sha(basic)))
            reference=results.canonical(dict(schema='e107-synthetic-translation-reference-v1',
                task_uid=uid,action_uid=action,binding_sha256=binding['binding_sha256'],
                parent_reference_sha256=binding['parent_result_sha256'],
                translated_mtfi_sha256=translated['output_mtfi_sha256'],
                translator_manifest_sha256=translated['manifest_sha256']))+b'\n'
            self.saved[uid]=dict(reference=reference,translated=translated)
            self.translation_count+=1
        else:
            request=binding['request'];recipe=binding['recipe']
            detected={'H':10,'M':15,'F':19}[mode]
            before=None
            if mode!='H':
                translation=self.saved[binding['translation_task_uid']]
                assert binding['translation_result_sha256']==results.sha(translation['reference'])
                minimum=translation['translated']['expected_minimum_pre_detected']
                assert minimum==parent['detected']
                before=('FU 20\nDS %d\nDI 0\n'%minimum).encode('ascii')
            generated=(min(request['control']['value'],2) if mode!='F' else 2)
            artifacts=dict(statistics=('#test_patterns %d\nFU 20\nDS %d\nDI 1\n'%(generated,detected-1)).encode('ascii'),
                stil=b'TesterCycle:10\n',driver_log=markers(recipe).encode('ascii'),
                pre_statistics=before,mtfi=self.mtfi(mode,detected))
            freeze=self.freezes[binding['circuit']]
            stage=results.build_stage_reference(freeze,request,self.mapping,1,artifacts)
            reference=stage['output_reference_bytes']
            self.saved[uid]=dict(reference=reference,mtfi=artifacts['mtfi'],detected=detected,mode=mode)
            self.rows.setdefault(action,[]).append(dict(request=copy.deepcopy(request),artifacts=artifacts))
            if mode=='F':
                checked=results.inspect_action(freeze,self.mapping,1,self.rows[action])
                assert checked['stages'][-1]['output_reference_sha256']==results.sha(reference)
                self.checked[action]=checked
        receipt=dict(task_uid=uid,binding_sha256=binding['binding_sha256'],
            output_sha256=results.sha(reference),status='SUCCESS',
            live_acknowledged_claim=True,output_authenticated_claim=True)
        return receipt,reference


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'package';self.plan=protocol.pilot.build_plan()
        self.freezes={c:protocol.requests.freeze_acquisition(self.plan,c,20,'a'*64) for c in protocol.pilot.CIRCUITS}
        self.profiles={p['circuit']:{n['task_uid']:'success' for n in p['tasks']} for p in self.plan['phases']}

    def package(self):
        value=protocol.Package.create(self.root,'test-e107',self.plan,self.freezes,
            dict(timeout_ns=100,cleanup_ns=20,phase_reservation_ns=4680,setup_timeout_ns=100),
            self.profiles,'e105-clock',Clock())
        self.addCleanup(value.close)
        return value

    def test_full_78_task_artifacts_translation_lifecycle_and_reference_join(self):
        outputs=Outputs(self.freezes);number=0;identities=set()
        with patch('subprocess.Popen') as spawn,self.package() as package:
            for phase in self.plan['phases']:
                circuit=phase['circuit'];package.begin_setup(circuit);package.end_setup(circuit,'SUCCESS',True)
                for slot,node in enumerate(phase['tasks']):
                    number+=1
                    record=package.run(circuit,node['task_uid'],Backend(number),outputs)
                    saved=outputs.saved[node['task_uid']]
                    self.assertEqual(record['output_reference_sha256'],results.sha(saved['reference']))
                    raw_intent=json.loads((self.root/('%s_%02d_intent.json'%(circuit,slot))).read_bytes())
                    self.assertEqual(raw_intent['binding']['binding_sha256'],record['binding_sha256'])
                    raw_result=json.loads((self.root/('%s_%02d_result.json'%(circuit,slot))).read_bytes())
                    self.assertEqual(raw_result,record)
                    self.assertEqual(record['output_claim_receipt']['output_sha256'],results.sha(saved['reference']))
                    observed=protocol.paired.load(self.root/circuit)
                    manifest=protocol.paired._binding(protocol.paired._read(self.root/circuit/'binding.json',65536))
                    aid=manifest['attempts'][slot]['attempt_id']
                    if node['kind']=='TESSENT':
                        self.assertEqual(raw_intent['binding']['recipe']['request_sha256'],
                                         results.reports.digest(raw_intent['binding']['request']))
                        self.assertNotEqual(manifest['attempts'][slot]['request_sha256'],
                                            raw_intent['binding']['recipe']['request_sha256'])
                    self.assertEqual(observed['lifecycle']['attempts'][aid],record['attempt'])
                    identity=record['attempt']['identity']
                    identities.add(tuple(identity[k] for k in ('host','boot_id','pid','start_ticks')))
                    self.assertEqual(record['observed_interval_ns'],10)
            snapshot=package.finish()
            spawn.assert_not_called()
        self.assertEqual(number,78);self.assertEqual(len(identities),78)
        self.assertEqual(outputs.translation_count,30);self.assertEqual(len(outputs.checked),18)
        self.assertEqual(set(snapshot['task_status'].values()),{'SUCCESS'})
        self.assertEqual(set(snapshot['action_status'].values()),{'SUCCESS_SYNTHETIC_ONLY'})
        for counts in snapshot['consumed_counts'].values():
            self.assertEqual(counts,{'TESSENT_STAGE':24,'STATUS_TRANSLATION':15})
        self.assertEqual(snapshot['observed_task_intervals_ns_sum'],780)
        self.assertGreater(snapshot['recorded_synthetic_session_ns'],780)
        self.assertEqual(sum(c['TESSENT_STAGE'] for c in snapshot['consumed_counts'].values()),48)
        self.assertEqual(sum(c['STATUS_TRANSLATION'] for c in snapshot['consumed_counts'].values()),30)
        for checked in outputs.checked.values():
            self.assertEqual(checked['explicit_ds_di_union_count'],19)
            self.assertTrue(checked['meets_declared_d95_math'])
            self.assertFalse(checked['d95_verified']);self.assertFalse(checked['training_release'])
            self.assertIsNone(checked['actual_atpg_wall_time_ns'])
            for stage in checked['stages']:
                self.assertEqual(stage['output_reference_sha256'],results.sha(outputs.saved[stage['attempt_uid']]['reference']))

    def test_translation_namespace_failure_retains_both_debits_and_known_cost(self):
        outputs=Outputs(self.freezes);outputs.bad_translation=True
        with self.package() as package:
            package.begin_setup('aes_core');package.end_setup('aes_core','SUCCESS',True)
            tasks=self.plan['phases'][0]['tasks']
            package.run('aes_core',tasks[0]['task_uid'],Backend(1),outputs)
            with self.assertRaisesRegex(ValueError,'SOURCE_EXTRA_OR_WRONG_MODE'):
                package.run('aes_core',tasks[1]['task_uid'],Backend(2),outputs)
            snapshot=package.snapshot()
            self.assertTrue(snapshot['poisoned'])
            self.assertEqual(snapshot['observed_task_intervals_ns_sum'],20)
            self.assertEqual(snapshot['consumed_counts']['aes_core'],{'TESSENT_STAGE':1,'STATUS_TRANSLATION':1})
            self.assertEqual(snapshot['task_status'][tasks[1]['task_uid']],'UNRESOLVED')
            self.assertEqual(package._binders['aes_core'].snapshot()['next_slot'],1)
            self.assertEqual(outputs.checked,{})
            self.assertIsNone(snapshot['actual_atpg_runtime_ns'])
            with self.assertRaises(ValueError):package.begin_setup('spi')
