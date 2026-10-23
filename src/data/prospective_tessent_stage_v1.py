"""Pure E81 Tessent-stage recipe and bounded text parser, never a runner.

Paths name a *future*, uncreated dedicated root. This module does not inspect
those paths, authenticate Tcl/input bytes, translate fault status, launch a
process, enforce memory/timeouts, or authorize any ATPG work.
"""
import hashlib
import json
import re

from src.data import prospective_request_features_v1 as features
from src.data import prospective_acquisition_request_v1 as acquisition
from src.data import prospective_stage_observation_v1 as observations

ROOT = '/temp/jiangchuanc/multimode_ate_prospective_e81_20261022_r1'
TOP = {'aes_core':'aes_cipher_top','spi':'spi_top'}
UID = re.compile(r'[A-Za-z0-9_:.-]{1,128}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')
CLASS = re.compile(r'^\s*(FU|DS|DI|PT|UU|TI|AU|UC|UO)\s+(?:\(full\)\s+)?([0-9]+)\s*$')
PATTERNS = re.compile(r'^#test_patterns\s+([0-9]+)\s*$')
CYCLE = re.compile(r'TesterCycle:([0-9]+)(?=$|\s)')
MAX_COUNT = 2**63-1
TCL_SOURCE_SHA256 = {'H':'dd26a13d1542052ca6664b4b1f8ef23afb76a9d0dfc8c6ea23b40a98d057ae8a',
                     'M':'4f95afb6d693f43f4747dfa06db2e3735ecca8506391ac0a00a24d3d23f1aaa3',
                     'F':'4f95afb6d693f43f4747dfa06db2e3735ecca8506391ac0a00a24d3d23f1aaa3'}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),
                                   ensure_ascii=True,allow_nan=False).encode('ascii')).hexdigest()


def safe_uid(value):
    return type(value) is str and UID.fullmatch(value) is not None and value not in ('.','..')


def compile_stage(freeze, request):
    """Describe one exact fixed stage; lineage and prereqs remain unverified.

    H uses the fixed common Tcl. M/F require a future, separately charged
    target-native status translation of the declared parent's result; this
    recipe neither creates nor checks that artifact. Every path is derived,
    never caller supplied. No shell, inherited environment, or launch API.
    """
    if type(freeze) is dict and freeze.get('schema') == acquisition.SCHEMA:
        acquisition.validate_freeze(freeze)
    else:
        features.build_features(freeze)  # Keep the E80 path unchanged.
    require(type(request) is dict and set(request)==observations.REQUEST_KEYS,
            'REQUEST_KEYS')
    run_uid=request['run_uid'];uid=request['attempt_uid'];action=request['action_uid']
    stage=request['stage'];index=request['stage_index']
    require(safe_uid(run_uid) and safe_uid(uid) and safe_uid(action), 'REQUEST_UID')
    require(type(stage) is str and stage in ('H','M','F') and
            type(index) is int and 1<=index<=64, 'STAGE_INDEX')
    require(request['freeze_sha256']==freeze['freeze_sha256'] and
            request['run_uid']==run_uid, 'FREEZE_BINDING')
    roster={row['action_uid']:row for row in freeze['requested_roster']}
    require(action in roster and (stage!='M' or roster[action]['scheme']=='HMF'),
            'ACTION_STAGE')
    observations.control_valid(request['control'],stage,roster[action])
    parent_uid=request['parent_attempt_uid']
    parent_sha=request['parent_result_sha256']
    if stage=='H':
        require(parent_uid is None and parent_sha is None,'H_PARENT')
    else:
        require(safe_uid(parent_uid) and
                parent_uid!=uid and type(parent_sha) is str and SHA.fullmatch(parent_sha),
                'INCREMENTAL_PARENT')
    circuit=freeze['circuit'];root=ROOT+'/'+circuit
    run_root=root+'/runs/'+run_uid
    phase='runs/'+run_uid+'/attempts'
    result_dir=run_root+'/attempts/'+stage+'_'+uid
    log=run_root+'/logs/'+stage+'_'+uid+'.log'
    env={'CIRCUIT_ROOT':root,'CIRCUIT':circuit,'TOP_MODULE':TOP[circuit],
         'CELL_LIBRARY':root+'/inputs/'+circuit+'/cells.lib',
         'COMMON_FAULT_DIR':'common_frozen','MODE':stage,'RUN_ID':uid,
         'TSDB_INPUT_DIR':run_root+'/tsdb/'+uid,'PHASE':phase}
    required=[]
    if stage in ('H','M'):
        env['PATTERN_LIMIT']=str(request['control']['value'])
    elif request['control']['kind']=='PATTERN_LIMIT':
        env['PATTERN_LIMIT']=str(request['control']['value'])
    elif request['control']['kind']=='COVERAGE_PERCENT':
        env['TEST_COVERAGE_LIMIT']=request['control']['value']
    if stage!='H':
        prereq=run_root+'/attempts/_prereq/'+uid
        status=prereq+'/translated_status.mtfi'
        manifest=prereq+'/translation_manifest.json'
        env['STATUS_FILE']=status
        env['STATUS_TRANSLATION_MANIFEST']=manifest
        required.append(dict(kind='translate_status',parent_attempt_uid=parent_uid,
                             parent_result_sha256=parent_sha,target_mode=stage,
                             target_native_common_faults=root+'/03_fault_universe/common_frozen/'+
                             stage+'_common_initial_faults.basic',
                             output_status_file=status,output_manifest=manifest,
                             implemented=False,charged_as_free=False))
    tcl=ROOT+'/code/'+('common.tcl' if stage=='H' else 'incremental.tcl')
    body=dict(schema='prospective-tessent-stage-recipe-v1',
              freeze_sha256=freeze['freeze_sha256'],request_sha256=digest(request),
              run_uid=run_uid,action_uid=action,attempt_uid=uid,stage=stage,
              stage_index=index,control=dict(request['control']),
              common_fault_count=freeze['common_fault_count'],
              argv=['tessent','-shell','-license_wait','5','-log',log,'-dofile',tcl],
              intended_tcl_source_sha256=TCL_SOURCE_SHA256[stage],
              env=env,result_dir=result_dir,required_tasks=required,
              requires_exclusive_result_dir=True,result_dir_exists_checked=False,
              source_and_input_authenticated=False,translated_status_verified=False,
              lineage_verified=False,memory_timeout_enforced=False,
              process_monitor_implemented=False,execution_ready=False,
              training_release=False)
    return dict(body,recipe_sha256=digest(body))


def _counts(text, patterns_required):
    classes={};patterns=None
    for line in text.splitlines():
        stripped=line.strip()
        if stripped.startswith('#test_patterns'):
            match=PATTERNS.fullmatch(stripped)
            require(match is not None and patterns is None,'PATTERN_RECORD')
            patterns=int(match.group(1))
            require(patterns<=MAX_COUNT,'PATTERN_BOUND')
        else:
            token=stripped.split(None,1)[0] if stripped else ''
            if token in ('FU','DS','DI','PT','UU','TI','AU','UC','UO'):
                match=CLASS.fullmatch(line)
                require(match is not None and token not in classes,'CLASS_RECORD')
                count=int(match.group(2))
                require(count<=MAX_COUNT,'CLASS_BOUND')
                classes[token]=count
    require((not patterns_required or patterns is not None) and
            'DS' in classes and 'DI' in classes,'REQUIRED_REPORT_COUNTS')
    return patterns,classes


def parse_reports(statistics_text, stil_text, driver_log_text, recipe,
                  pre_statistics_text=None, parent_detected_min=None):
    """Parse supplied synthetic/small text only; no report file is opened.

    TesterCycle is an ATE-cycle count, never process wall time. A parsed PASS
    marker is not report authentication, D95 proof, or safe execution release.
    """
    require(type(recipe) is dict and type(recipe.get('recipe_sha256')) is str and
            digest({k:v for k,v in recipe.items() if k!='recipe_sha256'})==
            recipe['recipe_sha256'] and recipe.get('schema')=='prospective-tessent-stage-recipe-v1',
            'RECIPE_CHANGED')
    for value,cap,label in ((statistics_text,65536,'STATISTICS'),
                            (stil_text,131072,'STIL'),
                            (driver_log_text,65536,'DRIVER_LOG')):
        require(type(value) is str and len(value.encode('utf-8'))<=cap,
                label+'_TEXT_BOUND')
    patterns,classes=_counts(statistics_text,True)
    detected=classes['DS']+classes['DI']
    common=recipe['common_fault_count']
    require(type(common) is int and 1<=common<=2**31-1 and
            classes.get('FU')==common and detected<=common,
            'DECLARED_COMMON_FAULT_BOUND')
    if recipe['stage']=='H':
        require(pre_statistics_text is None and parent_detected_min is None,
                'H_HAS_NO_PRE_ATPG_PARENT')
        pre_classes=None
    else:
        require(type(pre_statistics_text) is str and
                len(pre_statistics_text.encode('utf-8'))<=65536 and
                type(parent_detected_min) is int and 0<=parent_detected_min<=common,
                'INCREMENTAL_PRE_ATPG_REQUIRED')
        _,pre_classes=_counts(pre_statistics_text,False)
        require(pre_classes.get('FU')==common and
                parent_detected_min<=pre_classes['DS']+pre_classes['DI']<=common,
                'INCREMENTAL_FULL_UNIVERSE_AND_INHERITED_MINIMUM')
    cycles=[int(item) for item in CYCLE.findall(stil_text)]
    require(cycles and len(cycles)==stil_text.count('TesterCycle:') and
            all(0<=item<=MAX_COUNT for item in cycles),'TESTER_CYCLE_RECORD')
    kind='MAPPED_COMMON_ATPG' if recipe['stage']=='H' else 'MAPPED_INCREMENTAL'
    expected={(kind+'_STATUS' if recipe['stage']=='H' else
               'MAPPED_INCREMENTAL_ATPG_STATUS'):'PASS',
              kind+'_MODE':recipe['stage'],kind+'_RUN_ID':recipe['attempt_uid']}
    if recipe['stage']!='H':
        expected[kind+'_TRANSLATED_STATUS_FILE']=recipe['env']['STATUS_FILE']
        expected[kind+'_TRANSLATION_MANIFEST']=recipe['env']['STATUS_TRANSLATION_MANIFEST']
    control=recipe['control']
    if control['kind']=='COVERAGE_PERCENT':
        expected['ATPG_TEST_COVERAGE_LIMIT']=control['value']
    else:
        expected['ATPG_PATTERN_LIMIT']=(str(control['value']) if
                                        control['kind']=='PATTERN_LIMIT' else 'FULL')
    require(re.search(r'\b(?:ERROR|FATAL)\b',driver_log_text,re.IGNORECASE) is None and
            'invalid pin_pathname' not in driver_log_text.lower(),
            'DRIVER_FAILURE_MARKER')
    found={}
    for line in driver_log_text.splitlines():
        require(not (line.lstrip().startswith(('MAPPED_','ATPG_')) and
                     not line.startswith(('MAPPED_','ATPG_'))),
                'DRIVER_MARKER')
        if line.startswith(('MAPPED_','ATPG_')):
            require('=' in line,'DRIVER_MARKER')
            key,value=line.split('=',1)
            require(key in expected and key not in found and value==expected[key],
                    'DRIVER_MARKER')
            found[key]=value
    require(set(found)==set(expected),'MISSING_DRIVER_MARKER')
    requested_limit=control['value'] if control['kind']=='PATTERN_LIMIT' else None
    return dict(schema='prospective-tessent-text-observation-v1',
                status='PARSED_TEXT_ONLY_NOT_AUTHENTICATED',
                recipe_sha256=recipe['recipe_sha256'],stage=recipe['stage'],
                attempt_uid=recipe['attempt_uid'],
                requested_control=dict(control),requested_pattern_limit=requested_limit,
                generated_patterns=patterns,detected_common_faults=detected,
                pre_atpg_classes=pre_classes,parent_detected_min=parent_detected_min,
                classes=classes,ate_cycles=max(cycles),
                ate_cycles_not_wall_time=True,
                requested_vs_realized_equivalence_verified=False,
                d95_verified=False,report_bytes_authenticated=False,
                parent_min_authenticated=False,translated_status_verified=False,
                process_monitor_implemented=False,
                execution_ready=False,training_release=False)
