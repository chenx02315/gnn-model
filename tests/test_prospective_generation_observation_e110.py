"""Mock observations and tiny temporary publications only; no real processes."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
from src.data import prospective_generation_observation_e110 as m
from tests import test_prospective_generation_supervision_e109 as fixtures


class Tests(unittest.TestCase):
    def setUp(self):
        self.base=fixtures.Tests();self.base.setUp()
        self.launch=self.base.launch
        self.envelope=m.supervisor.recipe.compile_execution(self.base.freeze,self.base.binding,self.base.fixture.sources)
        self.observed=self.base.observe()[0]
        self.saved={};self.events=[]

    def publish(self,kind,name,raw):
        self.events.append((kind,name))
        if name in self.saved:raise FileExistsError(name)
        self.saved[name]=raw

    def seal(self,observed=None,envelope=None,launch=None,receipt=None,log=None,sample=None):
        return m.seal_observation(self.observed if observed is None else observed,
            self.envelope if envelope is None else envelope,self.launch if launch is None else launch,
            receipt or (lambda name,raw:self.publish('receipt',name,raw)),
            log or (lambda name,raw:self.publish('log',name,raw)),
            sample or (lambda:self.events.append(('sample',None))))

    def test_success_is_observed_not_accepted_and_immutable_publication_order(self):
        original=copy.deepcopy(self.observed);result=self.seal()
        self.assertEqual(self.observed,original)
        self.assertEqual([kind for kind,name in self.events],['receipt','log','sample','receipt'])
        self.assertEqual(result['receipt']['disposition'],'OBSERVED_RETURNED_NOT_ACCEPTED')
        self.assertFalse(result['ack']['allows_next_launch'])
        self.assertFalse(result['receipt']['report_acceptance_evaluated'])
        self.assertFalse(result['ack']['callback_returns_are_fsync_or_os_proof'])
        self.assertIsNone(result['receipt']['actual_atpg_runtime_ns'])
        self.assertNotIn('synthetic-license-host',repr(result))
        for name,raw in self.saved.items():self.assertTrue(name.endswith(('.json','.log')))

    def test_all_h_m_f_roles_match_their_actual_prepared_mock_context(self):
        source=self.base.fixture;seen=set();count=0
        for phase in source.plan['phases']:
            freeze,binder=source.binder(phase['circuit'])
            for node in phase['tasks']:
                binding=source.advance(binder,node)
                if node['kind']!='TESSENT':continue
                envelope=m.supervisor.recipe.compile_execution(freeze,binding,source.sources)
                cwd=m.supervisor.recipe.ROOT+'/'+phase['circuit']+'/scratch/'+node['task_uid']
                launch=m.supervisor.prepare_launch(freeze,binding,source.sources,self.base.runtime,cwd)
                self.base.launch=launch;observed=self.base.observe()[0]
                result=self.seal(observed,envelope,launch);count+=1
                seen.add(result['receipt']['stage'])
                self.assertEqual(result['receipt']['request_sha256'],envelope['request_sha256'])
                self.assertEqual(result['receipt']['effective_tcl_sha256'],envelope['effective_tcl_sha256'])
        self.assertEqual(seen,{'H','M','F'});self.assertEqual(count,48)
        self.assertEqual(len(self.saved),144)

    def test_uncertain_cleanup_keeps_false_flag_and_measured_prefix(self):
        observed=copy.deepcopy(self.observed);observed['cleaned']=False;observed['failure']='CLEANUP_UNCONFIRMED'
        result=self.seal(observed)
        self.assertFalse(result['receipt']['observation']['cleaned'])
        self.assertEqual(result['receipt']['disposition'],'UNRESOLVED')
        self.assertTrue(result['ack']['observation_requires_failure_stop'])
        self.assertEqual(result['receipt']['observation']['observed_wrapper_interval_seconds'],0)
        self.assertIsNone(result['ack']['actual_atpg_runtime_ns'])

    def test_failed_spawn_and_unattempted_rows_do_not_become_zero_runtime_labels(self):
        observed=self.base.observe(spawn_error=OSError('private detail'))[0]
        result=self.seal(observed)
        self.assertEqual(result['receipt']['disposition'],'UNRESOLVED')
        self.saved={};self.events=[]
        observed=self.base.observe(budget=[0])[0];result=self.seal(observed)
        self.assertEqual(result['receipt']['disposition'],'NOT_ATTEMPTED')
        self.assertIsNone(result['receipt']['observation']['observed_wrapper_interval_seconds'])
        self.assertEqual(result['receipt']['log_bytes'],0)
        self.assertIsNone(result['ack']['actual_atpg_runtime_ns'])

    def test_log_write_failure_preserves_first_observation_and_does_not_retry(self):
        sample=Mock();writer=Mock(side_effect=OSError('disk failure'))
        with self.assertRaises(OSError):self.seal(log=writer,sample=sample)
        self.assertEqual(len(self.saved),1);writer.assert_called_once();sample.assert_not_called()
        first=json.loads(next(iter(self.saved.values())))
        self.assertEqual(first['log_sha256'],m.sha(b'OK'))
        self.assertFalse(first['final_sample_evaluated'])

    def test_final_sampling_failure_leaves_observation_and_log_without_seal_ack(self):
        sample=Mock(side_effect=ValueError('FINAL_SAMPLE_STOP'))
        with self.assertRaises(ValueError):self.seal(sample=sample)
        self.assertEqual(len(self.saved),2)
        self.assertFalse(any(name.startswith('seal_') for name in self.saved))
        self.assertEqual(next(raw for name,raw in self.saved.items() if name.endswith('.log')),b'OK')

    def test_first_publication_failure_does_not_call_later_callbacks_or_mutate_input(self):
        writer=Mock(side_effect=OSError('fsync unknown'));log=Mock();sample=Mock()
        original=copy.deepcopy(self.observed)
        with self.assertRaises(OSError):self.seal(receipt=writer,log=log,sample=sample)
        writer.assert_called_once();log.assert_not_called();sample.assert_not_called()
        self.assertEqual(self.observed,original)

    def test_cross_attempt_wrong_environment_and_proxy_runtime_rejected_before_writes(self):
        for field,value in (('launch_spec_sha256','b'*64),('environment_keys',['PATH']),
                            ('actual_atpg_runtime_ns',0),('returncode',True),
                            ('observed_wrapper_interval_seconds',float('nan'))):
            observed=copy.deepcopy(self.observed);observed[field]=value
            with self.assertRaises(ValueError):self.seal(observed)
        self.assertEqual(self.saved,{})

    def test_tampered_effective_context_or_launch_source_rejected_before_writes(self):
        envelope=copy.deepcopy(self.envelope);envelope['stage']='F'
        with self.assertRaises(ValueError):self.seal(envelope=envelope)
        launch=copy.deepcopy(self.launch);launch['argv'][0]='/other'
        launch['launch_spec_sha256']=m.sha(m.canonical({k:v for k,v in launch.items() if k!='launch_spec_sha256'}))
        with self.assertRaises(ValueError):self.seal(launch=launch)
        self.assertEqual(self.saved,{})

    def test_oversized_failure_text_is_explicitly_hashed_not_dropped_or_made_success(self):
        observed=copy.deepcopy(self.observed);observed['failure']='x'*2048
        result=self.seal(observed)
        self.assertEqual(result['receipt']['observation']['failure'],'OMITTED_OVERSIZED_TEXT')
        self.assertEqual(result['receipt']['omitted_text']['failure'],{'bytes':2048,'sha256':m.sha(b'x'*2048)})
        self.assertEqual(result['receipt']['disposition'],'OBSERVED_FAILED')
        self.assertTrue(result['ack']['observation_requires_failure_stop'])

    def test_returncode_zero_with_fatal_log_is_not_quality_acceptance(self):
        observed=copy.deepcopy(self.observed);observed['output']=b'FATAL later report qualification must reject\n'
        result=self.seal(observed)
        self.assertFalse(result['receipt']['report_acceptance_evaluated'])
        self.assertFalse(result['ack']['allows_next_launch'])
        self.assertFalse(result['ack']['training_release'])

    def test_exclusive_local_publication_cannot_reopen_or_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            def publish(name,raw):
                with (root/name).open('xb') as stream:
                    stream.write(raw);stream.flush();os.fsync(stream.fileno())
            result=self.seal(receipt=publish,log=publish)
            before={p.name:p.read_bytes() for p in root.iterdir()}
            self.assertEqual(len(before),3)
            with self.assertRaises(FileExistsError):self.seal(receipt=publish,log=publish)
            self.assertEqual(before,{p.name:p.read_bytes() for p in root.iterdir()})
            receipt_raw=before[result['observation_name']]
            self.assertEqual(result['ack']['observation_sha256'],m.sha(receipt_raw))
