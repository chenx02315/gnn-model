"""Pure offline effective-execution recipe, never a runner or a release.

E86/E81 intent remains immutable. This separately binds a new output root,
reviewed Tcl derivation and explicit launcher to that intent. Input materializing,
resource admission and observed process/output identities are still required.
"""
import copy
from . import prospective_acquisition_binding_v1 as bindings
from . import prospective_acquisition_request_v1 as requests
from . import prospective_acquisition_pilot_v1 as pilot
from . import prospective_tessent_stage_v1 as stage
from . import prospective_tessent_acceptance_v1 as identities

ROOT='/temp/jiangchuanc/multimode_ate_prospective_e108_20261025_r1'
SCHEMA='prospective-generation-execution-intent-e108-v1'
REMOVED=b'add_processors localhost:1\n'
BINDING_KEYS=frozenset(('schema','plan_sha256','freeze_sha256','circuit','slot',
    'previous_receipt_sha256','task_uid','action_uid','kind','target_mode',
    'parent_task_uid','parent_result_sha256','parent_receipt_sha256',
    'translation_task_uid','translation_result_sha256','translation_receipt_sha256',
    'control','request','recipe','compilation_ready','caller_claims_not_os_proof',
    'execution_ready','training_release','binding_sha256'))
LINEAGE_KEYS=('previous_receipt_sha256','parent_task_uid','parent_result_sha256',
    'parent_receipt_sha256','translation_task_uid','translation_result_sha256','translation_receipt_sha256')
SOURCE_PINS={
    'common':(3096,'dd26a13d1542052ca6664b4b1f8ef23afb76a9d0dfc8c6ea23b40a98d057ae8a',
              '9b78e5c874fd2d4eb8987ac534d9c5414606184f8aea0012971130891ad1d92f'),
    'incremental':(4134,'4f95afb6d693f43f4747dfa06db2e3735ecca8506391ac0a00a24d3d23f1aaa3',
                   '1a9d4435551919b34c5beb4a142120df0322fcf209ebd493cfe2e70d92e42967')}
require=bindings.require
sha=bindings.sha
canonical=bindings.canonical


def freeze_sources(common_bytes,incremental_bytes):
    """Only the two exact reviewed originals; one exact command removal."""
    rows={}
    for name,raw in (('common',common_bytes),('incremental',incremental_bytes)):
        count,base_pin,derived_pin=SOURCE_PINS[name]
        require(type(raw) is bytes and len(raw)==count and sha(raw)==base_pin,'EXACT_BASE_SOURCE_'+name)
        require(raw.count(REMOVED)==1,'EXACT_SINGLE_PROCESSOR_COMMAND')
        derived=raw.replace(REMOVED,b'',1)
        require(sha(derived)==derived_pin and b'add_processors' not in derived.lower(),'EXACT_DERIVED_SOURCE')
        rows[name]=dict(base_sha256=base_pin,tcl_sha256=derived_pin,tcl_bytes=derived)
    return rows


def _sources(value):
    require(type(value) is dict and set(value)==set(SOURCE_PINS),'EXACT_SOURCE_ROSTER')
    for name,row in value.items():
        count,base_pin,derived_pin=SOURCE_PINS[name]
        require(type(row) is dict and set(row)=={'base_sha256','tcl_sha256','tcl_bytes'} and
                row['base_sha256']==base_pin and row['tcl_sha256']==derived_pin and
                type(row['tcl_bytes']) is bytes and len(row['tcl_bytes'])==count-len(REMOVED) and
                sha(row['tcl_bytes'])==derived_pin,'DERIVED_SOURCE_CHANGED')


def _relocate(path):
    require(type(path) is str and path.startswith(stage.ROOT+'/'),'BASE_PATH_PREFIX')
    return ROOT+path[len(stage.ROOT):]


def compile_execution(freeze,binding,sources):
    """Compile exact E84 task claims; no ancestor/live ACK or OS proof.

    binding_sha256 checks caller object consistency only, not authenticity.
    Required translation and resource receipts are not created here.
    """
    freeze=copy.deepcopy(freeze);binding=copy.deepcopy(binding);sources=copy.deepcopy(sources)
    requests.validate_freeze(freeze);_sources(sources)
    require(type(binding) is dict and set(binding)==BINDING_KEYS and binding.get('kind')=='TESSENT' and
            binding.get('schema')==bindings.SCHEMA and
            binding.get('compilation_ready') is True and binding.get('caller_claims_not_os_proof') is True and
            binding.get('execution_ready') is False and binding.get('training_release') is False and
            sha(canonical({k:v for k,v in binding.items() if k!='binding_sha256'}))==binding.get('binding_sha256'),
            'SEMANTIC_BINDING_CHANGED')
    phase=next(p for p in pilot.build_plan()['phases'] if p['circuit']==freeze['circuit'])
    require(type(binding.get('slot')) is int and 0<=binding['slot']<len(phase['tasks']),'EXACT_TASK_SLOT')
    node=phase['tasks'][binding['slot']]
    request=binding.get('request')
    require(type(request) is dict and binding.get('plan_sha256')==freeze['plan_sha256'] and
            binding.get('freeze_sha256')==freeze['freeze_sha256'] and binding.get('circuit')==freeze['circuit'] and
            node['kind']=='TESSENT' and binding.get('task_uid')==node['task_uid'] and
            binding.get('action_uid')==node['action_uid'] and binding.get('target_mode')==node['stage'] and
            canonical(binding.get('control'))==canonical(node['control']) and request.get('action_uid')==node['action_uid'] and
            request.get('attempt_uid')==node['task_uid'] and
            request.get('stage')==node['stage'] and type(request.get('stage_index')) is int and
            request['stage_index']==node['stage_index'] and request.get('control')==node['control'],
            'EXACT_FROZEN_TASK')
    expected=stage.compile_stage(freeze,request)
    for field in ('previous_receipt_sha256','parent_result_sha256','parent_receipt_sha256',
                  'translation_result_sha256','translation_receipt_sha256'):
        required=(binding['slot']>0 if field=='previous_receipt_sha256' else node['stage']!='H')
        value=binding[field]
        require((type(value) is str and stage.SHA.fullmatch(value) is not None) if required else value is None,
                'LINEAGE_SHA_CLAIM_'+field)
    require(canonical(binding.get('recipe'))==canonical(expected) and binding.get('parent_task_uid')==request['parent_attempt_uid'] and
            binding.get('parent_task_uid')==node['parent_result_task_uid'] and
            binding.get('parent_result_sha256')==request['parent_result_sha256'] and
            binding.get('translation_task_uid')==(None if node['stage']=='H' else node['depends_on'][1]),
            'BASE_RECIPE_OR_PARENT_CHANGED')
    name='common' if node['stage']=='H' else 'incremental'
    source=sources[name]
    require(expected['intended_tcl_source_sha256']==source['base_sha256'],'BASE_SOURCE_BINDING')
    argv=copy.deepcopy(expected['argv']);argv[0]=identities.LAUNCHER
    argv[5]=_relocate(argv[5]);argv[7]=_relocate(argv[7])
    env=copy.deepcopy(expected['env'])
    for key in ('CIRCUIT_ROOT','CELL_LIBRARY','TSDB_INPUT_DIR','STATUS_FILE','STATUS_TRANSLATION_MANIFEST'):
        if key in env:env[key]=_relocate(env[key])
    required=copy.deepcopy(expected['required_tasks'])
    for task in required:
        for key in ('target_native_common_faults','output_status_file','output_manifest'):
            task[key]=_relocate(task[key])
    result_dir=_relocate(expected['result_dir'])
    body=dict(schema=SCHEMA,root=ROOT,semantic_binding_sha256=binding['binding_sha256'],
        base_recipe_sha256=expected['recipe_sha256'],request_sha256=expected['request_sha256'],
        circuit=freeze['circuit'],task_uid=node['task_uid'],stage=node['stage'],
        lineage_claims={key:binding[key] for key in LINEAGE_KEYS},
        lineage_claims_authenticated=False,translation_reference_is_native_mtfi_hash=False,
        argv=argv,env=env,result_dir=result_dir,required_tasks=required,
        launcher_expected_sha256=identities.LAUNCHER_SHA256,
        base_tcl_sha256=source['base_sha256'],effective_tcl_sha256=source['tcl_sha256'],
        transformation='EXACT_SINGLE_ADD_PROCESSORS_COMMAND_REMOVAL',
        output_paths={role:result_dir+'/'+filename for role,filename in (
            ('statistics','statistics.rpt'),('patterns','patterns.rpt'),('scan_volume','scan_volume.rpt'),
            ('faults_report','faults.rpt'),('procedures','procedures.rpt'),
            ('mtfi','faults.mtfi'),('stil','tester.stil'))},
        pre_statistics_path=(None if node['stage']=='H' else result_dir+'/pre_atpg_statistics.rpt'),
        resource_budget=None,root_created_or_admitted=False,environment_clear_required=True,
        caller_binding_authenticated=False,inputs_deployed_and_authenticated=False,
        actual_tcl_deployed_and_accepted=False,real_process_monitor_connected=False,
        low_memory_generation_verified=False,lsf_used=False,execution_authorized=False,
        execution_ready=False,training_release=False)
    return dict(body,envelope_sha256=sha(canonical(body)))
