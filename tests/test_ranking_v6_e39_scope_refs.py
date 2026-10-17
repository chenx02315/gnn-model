"""Fabricated four-target reference fixtures only; no actual metadata reads."""
import copy
import json
import unittest
from unittest.mock import patch

from scripts import diagnose_ranking_v6_e39_scope_refs as refs


def fixture():
    targets=[]
    for circuit in ('s35932','s38417'):
        for candidate in ('1','2'):
            targets.append(dict(source_candidate_uid=circuit+':hf_coarse:H64-F4:'+candidate,
                                circuit=circuit,candidate_scope_roots=sorted(refs.ROOTS[circuit])))
    return targets,[],[]


def append_ref(inputs,index=0,root_index=0,attempt_id='SESSION_SECRET_1',mode='H',path=None):
    target=inputs[0][index]
    if path is None: path=target['candidate_scope_roots'][root_index].rsplit('/',1)[-1]+'/02_hf_coarse/logfile'
    inputs[1].append(dict(source_candidate_uid=target['source_candidate_uid'],circuit=target['circuit'],
                          mode=mode,attempt_id=attempt_id))
    inputs[2].append(dict(circuit=target['circuit'],mode=mode,attempt_id=attempt_id,
                          stage='02_hf_coarse',source_log_path=path))


class ScopeReferenceTests(unittest.TestCase):
    def setUp(self): self.inputs=fixture()
    def diagnose(self): return refs.diagnose(*self.inputs)

    def test_four_targets_one_scope_and_no_origin_assignment(self):
        for index in range(4): append_ref(self.inputs,index,0,'SESSION_SECRET_'+str(index))
        result=self.diagnose()
        self.assertEqual(result['status'],'PARTIAL_SCOPE_OWNERSHIP_NOT_CERTIFIED')
        self.assertEqual(result['target_count'],4)
        self.assertTrue(all(t['reference_classification']=='ALL_PROVIDED_REFERENCES_ONE_SCOPE_NOT_ORIGIN_CERT'
                            for t in result['targets']))
        self.assertNotIn('SESSION_SECRET',json.dumps(result))
        self.assertNotIn('logfile',json.dumps(result))
        for flag in ('source_origin_assigned','reference_universe_authenticated','provenance_authenticated',
                     'invocation_identity_certified','version_selected','majority_scope_choice_applied',
                     'source_log_paths_followed','physical_files_read','costs_computed','quality_accessed',
                     'training_release','pre_outcome_certified'):
            self.assertIs(result[flag],False)

    def test_both_roots_outside_and_zero_refs_retained(self):
        append_ref(self.inputs,0,0,'first')
        append_ref(self.inputs,0,1,'second',mode='F')
        append_ref(self.inputs,1,0,'outside',path='unknown_coverage/04_integer_refine/logfile')
        result=self.diagnose()
        self.assertEqual(result['targets'][0]['reference_classification'],'PROVIDED_MULTI_SCOPE_REFERENCES')
        self.assertEqual(result['targets'][0]['provided_unique_session_reference_count'],2)
        self.assertEqual(result['targets'][1]['outside_candidate_scopes_reference_count'],1)
        self.assertEqual(result['targets'][1]['reference_classification'],'OUTSIDE_CANDIDATE_SCOPES')
        self.assertEqual(result['targets'][2]['reference_classification'],'NO_PROVIDED_REFERENCES')

    def test_unsafe_log_paths_no_prefix_search_and_no_opens(self):
        invalid=('/absolute/log','../log','leaf/../log','./leaf/log','leaf//log','C:/log',
                 'leaf\\log','leaf/\x00log','leaf/\nlog','leaf/./log')
        for path in invalid:
            self.inputs=fixture()
            append_ref(self.inputs,path=path)
            with self.subTest(path=path),self.assertRaises(refs.ScopeReferenceError): self.diagnose()
        self.inputs=fixture()
        prefix=self.inputs[0][0]['candidate_scope_roots'][0].rsplit('/',1)[-1]
        append_ref(self.inputs,path='unrecognized/'+prefix+'/log')
        self.assertEqual(self.diagnose()['targets'][0]['outside_candidate_scopes_reference_count'],1)

    def test_duplicate_orphan_mode_mixed_circuit_and_source_join_rejected(self):
        for kind in ('edge_duplicate','attempt_duplicate','orphan','mode','mixed_circuit','unknown_source'):
            self.inputs=fixture()
            append_ref(self.inputs)
            if kind=='edge_duplicate': self.inputs[1].append(dict(self.inputs[1][0]))
            elif kind=='attempt_duplicate': self.inputs[2].append(dict(self.inputs[2][0]))
            elif kind=='orphan': self.inputs[1][0]['attempt_id']='missing'
            elif kind=='mode': self.inputs[1][0]['mode']='F'
            elif kind=='mixed_circuit': self.inputs[2][0]['circuit']='s38417'
            else: self.inputs[1][0]['source_candidate_uid']='s35932:hf_coarse:H64-F4:9'
            with self.subTest(kind=kind),self.assertRaises(refs.ScopeReferenceError): self.diagnose()

    def test_exact_two_phase2_roots_and_no_validation_blind_or_quality(self):
        for kind in ('one_root','duplicate_root','wrong_circuit_root','blind','phase4','quality'):
            self.inputs=fixture()
            if kind=='one_root': self.inputs[0][0]['candidate_scope_roots'].pop()
            elif kind=='duplicate_root': self.inputs[0][0]['candidate_scope_roots'][1]=self.inputs[0][0]['candidate_scope_roots'][0]
            elif kind=='wrong_circuit_root': self.inputs[0][0]['candidate_scope_roots']=sorted(refs.ROOTS['s38417'])
            elif kind=='blind': self.inputs[0][0]['circuit']='s9234'
            elif kind=='phase4': self.inputs[0][0]['circuit']='spi'
            else: self.inputs[0][0]['total_cycles']='forbidden'
            with self.subTest(kind=kind),self.assertRaises(refs.ScopeReferenceError): self.diagnose()
        for position in (1,2):
            self.inputs=fixture()
            append_ref(self.inputs)
            self.inputs[position][0]['result_status']='forbidden'
            with self.assertRaises(refs.ScopeReferenceError): self.diagnose()

    def test_no_io_no_mutation_and_order_stability(self):
        append_ref(self.inputs,0,0,'secret1')
        append_ref(self.inputs,0,1,'secret2',mode='F')
        before=copy.deepcopy(self.inputs)
        with patch('builtins.open',side_effect=AssertionError('CONTENT')),patch('os.open',side_effect=AssertionError('FD')), \
                patch('socket.socket',side_effect=AssertionError('NETWORK')):
            result=self.diagnose()
        self.assertEqual(before,self.inputs)
        for values in self.inputs: values.reverse()
        for target in self.inputs[0]: target['candidate_scope_roots'].reverse()
        self.assertEqual(result,self.diagnose())


if __name__=='__main__': unittest.main()
