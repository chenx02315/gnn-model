"""Synthetic strings and in-memory recipes only; no Tessent or file access."""
import copy
import unittest

from src.data import prospective_request_features_v1 as features
from src.data import prospective_tessent_stage_v1 as m


ROWS=[dict(action_uid='hf',scheme='HF',h_request=3,m_request=None),
      dict(action_uid='hmf',scheme='HMF',h_request=4,m_request=2)]
GRAPH='a'*64
PARENT_SHA='b'*64
STATS='#test_patterns 2\nFU (full) 100\nDS (full) 30\nDI 15\nPT 55\n'
PRE='FU (full) 100\nDS (full) 25\nDI 15\n'
STIL='Header TesterCycle:17 Other TesterCycle:99\n'


def freeze():
    return features.freeze_requests('aes_core',ROWS,100,GRAPH)


def request(stage='H',action='hmf',control=None,index=1,uid=None,parent=None):
    if control is None:
        control={'kind':'PATTERN_LIMIT','value':4 if stage=='H' else 2}
    uid=uid or ('attempt-'+stage.lower())
    return dict(run_uid='run-1',action_uid=action,attempt_uid=uid,stage=stage,
                stage_index=index,freeze_sha256=freeze()['freeze_sha256'],
                control=control,parent_attempt_uid=(parent if parent is not None else
                (None if stage=='H' else 'attempt-h')),
                parent_result_sha256=(None if stage=='H' else PARENT_SHA))


def markers(recipe):
    mode=recipe['stage'];uid=recipe['attempt_uid']
    control=recipe['control']
    if control['kind']=='COVERAGE_PERCENT':
        marker='ATPG_TEST_COVERAGE_LIMIT='+control['value']+'\n'
    else:
        marker='ATPG_PATTERN_LIMIT='+(
            str(control['value']) if control['kind']=='PATTERN_LIMIT' else 'FULL')+'\n'
    if mode=='H':
        return marker+'MAPPED_COMMON_ATPG_STATUS=PASS\nMAPPED_COMMON_ATPG_MODE=H\nMAPPED_COMMON_ATPG_RUN_ID='+uid+'\n'
    env=recipe['env']
    return (marker+'MAPPED_INCREMENTAL_ATPG_STATUS=PASS\nMAPPED_INCREMENTAL_MODE='+mode+'\n'
            'MAPPED_INCREMENTAL_RUN_ID='+uid+'\n'
            'MAPPED_INCREMENTAL_TRANSLATED_STATUS_FILE='+env['STATUS_FILE']+'\n'
            'MAPPED_INCREMENTAL_TRANSLATION_MANIFEST='+env['STATUS_TRANSLATION_MANIFEST']+'\n')


class TessentStageTests(unittest.TestCase):
    def test_h_exact_argv_env_paths_and_no_execution(self):
        recipe=m.compile_stage(freeze(),request())
        root=m.ROOT+'/aes_core'
        run_root=root+'/runs/run-1'
        self.assertEqual(recipe['argv'],['tessent','-shell','-license_wait','5','-log',
                         run_root+'/logs/H_attempt-h.log','-dofile',m.ROOT+'/code/common.tcl'])
        self.assertEqual(recipe['result_dir'],run_root+'/attempts/H_attempt-h')
        self.assertEqual(recipe['env'],dict(CIRCUIT_ROOT=root,CIRCUIT='aes_core',
                         TOP_MODULE='aes_cipher_top',CELL_LIBRARY=root+'/inputs/aes_core/cells.lib',
                         COMMON_FAULT_DIR='common_frozen',MODE='H',RUN_ID='attempt-h',
                         TSDB_INPUT_DIR=run_root+'/tsdb/attempt-h',PHASE='runs/run-1/attempts',
                         PATTERN_LIMIT='4'))
        self.assertEqual(recipe['required_tasks'],[])
        for flag in ('source_and_input_authenticated','translated_status_verified',
                     'lineage_verified','memory_timeout_enforced','process_monitor_implemented',
                     'execution_ready','training_release','result_dir_exists_checked'):
            self.assertFalse(recipe[flag])

    def test_m_and_f_have_unimplemented_target_native_translation(self):
        for stage,control in [('M',{'kind':'PATTERN_LIMIT','value':2}),
                              ('F',{'kind':'PATTERN_LIMIT','value':7}),
                              ('F',{'kind':'FULL','value':None}),
                              ('F',{'kind':'COVERAGE_PERCENT','value':'95.000000'})]:
            recipe=m.compile_stage(freeze(),request(stage,control=control))
            self.assertEqual(recipe['argv'][-1],m.ROOT+'/code/incremental.tcl')
            self.assertEqual(recipe['required_tasks'][0]['kind'],'translate_status')
            self.assertEqual(recipe['required_tasks'][0]['parent_result_sha256'],PARENT_SHA)
            self.assertFalse(recipe['required_tasks'][0]['implemented'])
            self.assertFalse(recipe['required_tasks'][0]['charged_as_free'])
            self.assertTrue(recipe['env']['STATUS_FILE'].startswith(
                m.ROOT+'/aes_core/runs/run-1/attempts/_prereq/'))
            self.assertEqual(recipe['env']['STATUS_TRANSLATION_MANIFEST'],
                             recipe['required_tasks'][0]['output_manifest'])
            self.assertNotIn('SHELL',recipe['env'])
            if control['kind']=='FULL':
                self.assertNotIn('PATTERN_LIMIT',recipe['env'])
                self.assertNotIn('TEST_COVERAGE_LIMIT',recipe['env'])
            elif control['kind']=='COVERAGE_PERCENT':
                self.assertNotIn('PATTERN_LIMIT',recipe['env'])
                self.assertEqual(recipe['env']['TEST_COVERAGE_LIMIT'],'95.000000')
            else:
                self.assertNotIn('TEST_COVERAGE_LIMIT',recipe['env'])

    def test_same_attempt_uid_in_distinct_runs_has_distinct_writable_paths(self):
        first=m.compile_stage(freeze(),request('M'))
        second_request=request('M');second_request['run_uid']='run-2'
        second=m.compile_stage(freeze(),second_request)
        self.assertNotEqual(first['result_dir'],second['result_dir'])
        for key in ('TSDB_INPUT_DIR','STATUS_FILE','STATUS_TRANSLATION_MANIFEST','PHASE'):
            self.assertNotEqual(first['env'][key],second['env'][key])
        self.assertNotEqual(first['argv'][5],second['argv'][5])

    def test_bad_requests_and_path_injection_rejected(self):
        bad=[]
        for field,value in [('attempt_uid','../escape'),('attempt_uid','x/y'),
                            ('attempt_uid','.'),('attempt_uid','..'),('run_uid','..'),
                            ('stage_index',True),('stage_index',0),
                            ('freeze_sha256','0'*64),('action_uid','absent'),
                            ('parent_result_sha256','not-a-sha')]:
            row=request();row[field]=value;bad.append(row)
        row=request();row['user_root']='/other';bad.append(row)
        row=request();row['parent_attempt_uid']='parent';bad.append(row)
        row=request(stage='M',action='hf');bad.append(row)
        row=request(stage='F');row['parent_attempt_uid']=None;bad.append(row)
        row=request(stage='F',control={'kind':'PATTERN_LIMIT','value':True});bad.append(row)
        for row in bad:
            with self.assertRaises(ValueError):
                m.compile_stage(freeze(),row)

    def test_reports_keep_requested_and_generated_separate(self):
        recipe=m.compile_stage(freeze(),request())
        parsed=m.parse_reports(STATS,STIL,markers(recipe),recipe)
        self.assertEqual(parsed['requested_pattern_limit'],4)
        self.assertEqual(parsed['generated_patterns'],2)
        self.assertEqual(parsed['detected_common_faults'],45)
        self.assertEqual(parsed['ate_cycles'],99)
        self.assertTrue(parsed['ate_cycles_not_wall_time'])
        self.assertFalse(parsed['requested_vs_realized_equivalence_verified'])
        self.assertFalse(parsed['d95_verified'])
        self.assertFalse(parsed['report_bytes_authenticated'])
        self.assertFalse(parsed['execution_ready'])

    def test_incremental_full_fu_and_parent_minimum_are_mandatory(self):
        recipe=m.compile_stage(freeze(),request('M'))
        with self.assertRaisesRegex(ValueError,'INCREMENTAL_PRE_ATPG_REQUIRED'):
            m.parse_reports(STATS,STIL,markers(recipe),recipe)
        parsed=m.parse_reports(STATS,STIL,markers(recipe),recipe,PRE,40)
        self.assertEqual(parsed['pre_atpg_classes']['FU'],100)
        self.assertEqual(parsed['parent_detected_min'],40)
        self.assertFalse(parsed['parent_min_authenticated'])
        for pre,minimum in [('FU 99\nDS 25\nDI 15\n',40),
                            ('FU 100\nDS 25\nDI 15\n',41),
                            ('FU 100\nDS 25\nDI 15\n',True)]:
            with self.assertRaises(ValueError):
                m.parse_reports(STATS,STIL,markers(recipe),recipe,pre,minimum)
        with self.assertRaisesRegex(ValueError,'H_HAS_NO_PRE_ATPG_PARENT'):
            h=m.compile_stage(freeze(),request())
            m.parse_reports(STATS,STIL,markers(h),h,PRE,40)

    def test_parser_rejects_wrong_or_duplicate_marker_and_failure(self):
        recipe=m.compile_stage(freeze(),request())
        good=markers(recipe)
        for log in (good.replace('STATUS=PASS','STATUS=FAIL'),
                    good.replace('MODE=H','MODE=M'),
                    good.replace('RUN_ID=attempt-h','RUN_ID=other'),
                    good+good,'ERROR: failed\n'+good,
                    good.replace('ATPG_PATTERN_LIMIT=4','ATPG_PATTERN_LIMIT=999'),
                    good.replace('ATPG_PATTERN_LIMIT=4','ATPG_PATTERN_LIMIT=FULL'),
                    good.replace('ATPG_PATTERN_LIMIT=4\n',''),
                    good+'ATPG_TEST_COVERAGE_LIMIT=95\n',
                    'invalid pin_pathname\n'+good,
                    'Invalid Pin_Pathname\n'+good,
                    ' '+good,
                    good+'MAPPED_INCREMENTAL_ATPG_STATUS=PASS\n'):
            with self.assertRaises(ValueError):
                m.parse_reports(STATS,STIL,log,recipe)
        incremental=m.compile_stage(freeze(),request('M'))
        with self.assertRaises(ValueError):
            m.parse_reports(STATS,STIL,markers(incremental).replace(
                'MAPPED_INCREMENTAL_ATPG_STATUS','MAPPED_INCREMENTAL_STATUS'),
                incremental,PRE,40)

    def test_parser_rejects_duplicate_malformed_or_missing_counts_and_stil(self):
        recipe=m.compile_stage(freeze(),request())
        log=markers(recipe)
        for stats in (STATS+'#test_patterns 3\n',STATS+'DS 1\n',
                      STATS.replace('FU (full) 100','FU (full) 99'),
                      STATS.replace('FU (full) 100',''),
                      STATS.replace('#test_patterns 2','#test_patterns NaN'),
                      STATS.replace('DI 15','DI 100'),
                      STATS.replace('DI 15',''),
                      STATS.replace('DS (full) 30','DS xx')):
            with self.assertRaises(ValueError):
                m.parse_reports(stats,STIL,log,recipe)
        for stil in ('no cycle', 'TesterCycle:NaN','TesterCycle:12 TesterCycle:bad',
                     'TesterCycle:123.5','TesterCycle:123e2','TesterCycle:123abc',
                     'TesterCycle:'+str(2**63)):
            with self.assertRaises(ValueError):
                m.parse_reports(STATS,stil,log,recipe)
        with self.assertRaises(ValueError):
            m.parse_reports(STATS+'x'*65536,STIL,log,recipe)
        altered=copy.deepcopy(recipe);altered['stage']='F'
        with self.assertRaisesRegex(ValueError,'RECIPE_CHANGED'):
            m.parse_reports(STATS,STIL,log,altered)


if __name__=='__main__':
    unittest.main()
