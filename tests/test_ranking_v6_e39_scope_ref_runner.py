"""Synthetic orchestration only; no staged tables, real CLI or remote calls."""
import copy
import csv
import io
import json
import os
import unittest
from unittest.mock import patch

from scripts import run_ranking_v6_e39_scope_refs as runner


def tsv(fields,rows):
    stream=io.StringIO(newline='')
    writer=csv.DictWriter(stream,fields,delimiter='\t',lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode('utf-8')


def fixtures():
    projection={'files':[]}
    edges=[]
    manifests={c:[] for c in ('s35932','s38417')}
    for circuit in manifests:
        for alias in ('hf_coarse','hmf_coarse'):
            scheme='HMF' if alias.startswith('hmf') else 'HF'
            modes='H64-M16-F4' if scheme=='HMF' else 'H64-F4'
            uid=circuit+':'+alias+':'+modes+':1'
            action=circuit+':'+scheme+':h64'+(':m16' if scheme=='HMF' else '')
            stage='03_hmf_coarse' if scheme=='HMF' else '02_hf_coarse'
            attempt='SYNTH_SECRET_'+circuit+'_'+alias
            for root in sorted(runner.diagnostic.ROOTS[circuit]):
                projection['files'].append(dict(circuit=circuit,coverage_root=root,stage_alias=alias,
                    rows=[[2,'1','64','16' if scheme=='HMF' else '0','explicit_candidate']]))
            edges.append(dict(action_uid=action,source_candidate_uid=uid,circuit=circuit,stage=stage,
                action_scheme=scheme,h_patterns='64',m_patterns='16' if scheme=='HMF' else '',
                mode='F',retry_group_id='SYNTH_GROUP_'+attempt,retry_order='1',attempt_id=attempt,
                mapping_rule='DIRECT_RESULT_BASENAME'))
            row={field:'' for field in runner.stable.reader.MANIFEST_FIELDS}
            row.update(circuit=circuit,family='iscas89_'+circuit,role='TRAIN',mode='F',attempt_id=attempt,
                       stage=stage,source_log_path='10_coverage95_v1/'+stage+'/synthetic.log',
                       wall_s='NOT_A_TIME_DO_NOT_ANALYZE',attempt_outcome_class='NOT_A_CLASS_DO_NOT_ANALYZE')
            manifests[circuit].append(row)
    for i in range(1776):
        edges.append(dict(action_uid='spi:HF:h64',source_candidate_uid='spi:hf_coarse:H64-F4:'+str(1000+i),
            circuit='spi',stage='02_hf_coarse',action_scheme='HF',h_patterns='64',m_patterns='',mode='F',
            retry_group_id='SYNTH_SPI_GROUP_'+str(i),retry_order='1',attempt_id='SYNTH_SPI_REF_'+str(i),
            mapping_rule='F_SEARCH_RUN_ID'))
    return projection,edges,manifests


class FocusedScopeRunnerTests(unittest.TestCase):
    def setUp(self):
        self.projection,self.edges,self.manifests=fixtures()
        self.classes=dict(UID_ABSENT=0,UID_PRESENT_NO_CONFIG_MATCH=0,
                          ONE_SCOPED_CONFIG_MATCH=1776,MULTIPLE_SCOPED_CONFIG_MATCH=4)
        self.result=dict(status='PARTIAL_SCOPE_OWNERSHIP_NOT_CERTIFIED',physical_files_read=False,
                         source_origin_assigned=False,training_release=False)

    def buffers(self,edge_fields=None,manifest_fields=None):
        return [json.dumps(self.projection,separators=(',',':')).encode('ascii'),
                tsv(runner.previous.FIELDS if edge_fields is None else edge_fields,self.edges)] + [
                tsv(runner.stable.reader.MANIFEST_FIELDS if manifest_fields is None else manifest_fields,
                    self.manifests[circuit]) for circuit,digest in runner.MANIFESTS]

    def invoke(self,buffers=None,classes=None,helper_result=None,helper_error=None):
        payloads=self.buffers() if buffers is None else buffers
        with patch.object(runner.sys,'argv',['synthetic_unit_invocation']), \
                patch.object(runner.stable,'_stable_bytes',side_effect=payloads) as read, \
                patch.object(runner.join,'summarize',return_value={'edge_class_counts':self.classes if classes is None else classes}) as join, \
                patch.object(runner.diagnostic,'diagnose',return_value=copy.deepcopy(self.result if helper_result is None else helper_result),
                             side_effect=helper_error) as diagnose, \
                patch('builtins.open',side_effect=AssertionError('REAL_CONTENT_OPEN')), \
                patch('os.open',side_effect=AssertionError('REAL_FD_OPEN')), \
                patch('subprocess.Popen',side_effect=AssertionError('REMOTE_OR_PROCESS')), \
                io.StringIO() as output, patch('sys.stdout',output):
            code=runner.main()
            text=output.getvalue()
        return code,json.loads(text),read,join,diagnose,text

    def test_exact_four_fixed_pinned_reads_and_selected_metadata_only(self):
        code,result,read,join,diagnose,text=self.invoke()
        self.assertEqual(code,0)
        self.assertEqual(read.call_count,4)
        expected=list(runner.previous.SPECS)+[(os.path.join(runner.previous.BASE,
            'runtime_attempt_remediation_v2_r1_remote','outputs_v2',circuit+'_attempt_manifest_v2_remediated.tsv'),digest)
            for circuit,digest in runner.MANIFESTS]
        self.assertEqual([call.args[:2] for call in read.call_args_list],expected)
        self.assertEqual([digest for path,digest in expected],[
            'a742707477aa39553fab8f3ee14c808494cccfaad3ef9a05a661a309ad8b52ed',
            'd5b25fdd934a18a352c286f572172ad8ba79fa064cf70dbe3f68e8e44e0fdfea',
            'af7236dc484e2a5e3a489787f98ec1ae5963ec34fe625585cd59820c48b4db36',
            '30aea1c23bc6751c3b17e1e2e32ae36fc3cbd7934f03df22fb78df1f7c962300'])
        remaining=20*1024*1024
        for call,raw in zip(read.call_args_list,self.buffers()):
            self.assertEqual(call.args[2],remaining)
            remaining-=len(raw)
        join.assert_called_once()
        self.assertEqual(len(join.call_args.args[1]),1780)
        targets,selected,attempts=diagnose.call_args.args
        self.assertEqual(len(targets),4)
        self.assertEqual(len(selected),4)
        self.assertEqual(len(attempts),4)
        self.assertEqual({row['source_candidate_uid'] for row in selected},{row['source_candidate_uid'] for row in targets})
        for target in targets:
            self.assertEqual(set(target['candidate_scope_roots']),runner.diagnostic.ROOTS[target['circuit']])
        self.assertTrue(all(set(row)=={'circuit','mode','attempt_id','stage','source_log_path'} for row in attempts))
        self.assertNotIn('NOT_A_TIME',json.dumps(attempts))
        self.assertNotIn('NOT_A_CLASS',json.dumps(attempts))
        self.assertIs(result['pure_diagnostic_function_performed_io'],False)
        self.assertNotIn('physical_files_read',result)
        self.assertEqual(result['local_metadata_files_read'],4)
        self.assertFalse(result['fixed_local_input_audit']['source_measurements_or_logs_opened'])
        self.assertFalse(result['fixed_local_input_audit']['status_or_wall_analyzed'])
        self.assertEqual(result['fixed_local_input_audit']['remote_calls'],0)
        self.assertNotIn('SYNTH_SECRET',text)

    def assert_fixed_failure(self,output):
        code,result,read,join,diagnose,text=output
        self.assertEqual(code,2)
        self.assertEqual(result,dict(status='FAIL_CLOSED_SCOPE_REFERENCE_DIAGNOSTIC',code='INPUT_OR_DIAGNOSTIC_REJECTED'))
        self.assertNotIn('SYNTH_SECRET',text)
        return read,join,diagnose

    def test_unknown_edge_and_manifest_headers_fail_without_quality_output(self):
        payloads=self.buffers()
        payloads[1]=payloads[1].replace(b'action_uid\t',b'total_cycles\t',1)
        self.assert_fixed_failure(self.invoke(buffers=payloads))
        payloads=self.buffers()
        payloads[2]=payloads[2].replace(b'attempt_id\t',b'total_cycles\t',1)
        self.assert_fixed_failure(self.invoke(buffers=payloads))

    def test_bad_role_or_family_rejected_before_selected_projection(self):
        for field,value in (('role','BLIND_TEST'),('family','wrong_family')):
            self.projection,self.edges,self.manifests=fixtures()
            self.manifests['s35932'][0][field]=value
            _,_,diagnose=self.assert_fixed_failure(self.invoke())
            diagnose.assert_not_called()

    def test_expected_unit_counts_and_prior_diagnostic_must_match(self):
        self.edges.pop()
        _,join,diagnose=self.assert_fixed_failure(self.invoke())
        join.assert_not_called()
        diagnose.assert_not_called()
        self.projection,self.edges,self.manifests=fixtures()
        _,_,diagnose=self.assert_fixed_failure(self.invoke(classes=dict(self.classes,ONE_SCOPED_CONFIG_MATCH=1775)))
        diagnose.assert_not_called()

    def test_missing_fourth_target_fails_before_helper(self):
        self.projection['files'][0]['rows']=[]
        _,_,diagnose=self.assert_fixed_failure(self.invoke())
        diagnose.assert_not_called()

    def test_helper_exception_or_oversized_output_fixed_no_leak(self):
        self.assert_fixed_failure(self.invoke(helper_error=ValueError('SYNTH_SECRET_HELPER_ERROR')))
        large=dict(self.result,large='SYNTH_SECRET'*7000)
        self.assert_fixed_failure(self.invoke(helper_result=large))

    def test_no_dynamic_path_or_cli_arguments_before_any_read(self):
        with patch.object(runner.sys,'argv',['unit','/arbitrary']), \
                patch.object(runner.stable,'_stable_bytes',side_effect=AssertionError('REAL_READ')) as read, \
                io.StringIO() as output,patch('sys.stdout',output):
            self.assertEqual(runner.main(),2)
            self.assertIn('INPUT_OR_DIAGNOSTIC_REJECTED',output.getvalue())
        read.assert_not_called()


if __name__=='__main__': unittest.main()
