"""Reviewed E137 capture/batch packets, original clock and one-use local ledger.

Only execute() can connect, after exact independent whole-package review.
Raw records precede validation; runtime instance hashes are consistency only.
"""
import ast
import base64
import datetime
import math
import os
from pathlib import Path
import platform
import re
import shlex
import time

from src.data import physical_replay_capture_e137 as capture
from src.data import physical_f_replay_execution_e137 as execution
from src.data import physical_e137_batch_execution as batch
from src.data import physical_runtime_bootstrap_e137 as bootstrap

require,sha,canonical,decode = capture.require,capture.sha,capture.canonical,capture.decode
AUTH = 'contracts/physical_f_clean_replay_authorization_e137.json'
AUTH_SHA = '49f000fe45de6cfc029ad8a9c1ead5e09edd24321de6062039d638436cce4969'
PROPOSAL = 'contracts/physical_f_clean_replay_proposal_e137_v1.json'
PHASE = 'v6_e137_clean_F_replay_r1'
RUNTIME_BINDER_SOURCE_SHA256 = DEPENDENCY_VALIDATOR_SHA256 = None
ENGINE_PATH_ALLOWLIST = None
ROLES = ('capture','execution','readback')
REVIEW_KEYS = ('payload_sha256','controller_sha256','worker_sha256','source_sha256','input_sha256',
    'authorization_sha256','proposal_sha256','protocol_sha256','policy_sha256','invocation_sha256','package_source_sha256')
SOURCES = (
    'direct_runtime_compatibility_e102','direct_diagnostic_policy_e102','prospective_tessent_acceptance_v1',
    'direct_low_memory_recipe_e104','direct_memory_sample_e101','direct_memory_sample_e103',
    'direct_observation_journal_e102','prospective_fault_translation_v2','prospective_lsf_memory_preflight_v1',
    'prospective_acceptance_materializer_v1','direct_scratch_monitor_e102','prospective_acceptance_scratch_v1',
    'direct_tessent_acceptance_e100','direct_tessent_acceptance_e104','prospective_fault_translation_e129',
    'prospective_report_dialect_e115','prospective_report_dialect_e126','eq_group_coverage_e133_r2',
    'prospective_input_binding_v1','prospective_acquisition_pilot_v1','prospective_acquisition_request_v1',
    'prospective_request_features_v1','prospective_stage_observation_v1','prospective_tessent_stage_v1',
    'prospective_acquisition_binding_v1','prospective_generation_recipe_e108','prospective_generation_supervision_e109',
    'prospective_generation_process_e113','prospective_generation_storage_e118','physical_f_replay_execution_e135',
    'physical_f_replay_recipe_e135_r2','physical_replay_source_reader_e135','physical_replay_source_inventory_e135',
    'physical_replay_capture_e137','physical_f_replay_execution_e137')
ROOT = execution.ROOT
JOURNAL = ('recipe_artifacts.json','dependency_validation.json','launch_intent.json','spawn_identity.json',
    'observation.json','stdout.log','stdout_ack.json','observation_exception.json')+tuple(
    case+'_'+suffix for case in ('success','timeout','setsid_child') for suffix in
    ('intent.json','observation.json','output.log','receipt.json'))
OUTPUTS = (ROOT+'.initial_intent.json',ROOT+'/code/replay.tcl',ROOT+'/code/expected_baseline.tcl',ROOT+'/tool.log')+tuple(
    ROOT+'/journal/'+name for name in JOURNAL)+tuple(ROOT+'/snapshots/'+stage+'.'+suffix
    for stage in ('baseline','imported','simulated') for suffix in ('statistics.rpt','faults.rpt','faults.mtfi'))+(
    ROOT+'/snapshots/loaded.patterns.rpt',ROOT+'/snapshots/simulated.patterns.rpt')


def readiness():
    return dict(ready=False,implementation_available=True,mode='BATCH_IMPLEMENTED_PACKET_REVIEW_PENDING',
        independent_packet_review_required=True,new_connections=0,execution_ready=False)


def transport_timeout(first,seconds):
    require(type(seconds) is int and seconds in (60,2400),'FIXED_ROLE_TIMEOUT')
    active=min(seconds-10,int(remaining(first))-10)
    require(active>=1,'INSUFFICIENT_ORIGINAL_CLEANUP_RESERVE')
    return active


def _authority(raw,proposal):
    require(sha(raw) == AUTH_SHA and sha(proposal) == capture.PROPOSAL_SHA,'ACTUAL_E137_GRANT')
    # Call identical pure check bytecode with a private auth namespace; never patch capture globals.
    import types
    namespace = dict(vars(capture),AUTH_SHA=AUTH_SHA)
    check = types.FunctionType(capture.check_authority.__code__,namespace)
    check(raw,proposal)


BOOTSTRAP = ('import time\n__connection_start__=time.monotonic()\n'
    'import sys,base64,hashlib,json\n'
    'raw=sys.stdin.buffer.read(4194305)\n'
    'if len(raw)>4194304 or len(sys.argv)!=2:raise ValueError("PACKET_BOUND")\n'
    '__payload_sha256__=hashlib.sha256(raw).hexdigest()\n'
    'arg=base64.b64decode(sys.argv[1],validate=True)\n'
    '__role_intent__=json.loads(arg.decode("ascii"))\n'
    'if (json.dumps(__role_intent__,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False)).encode("ascii")!=arg:raise ValueError("CANONICAL_INTENT")\n'
    'exec(compile(raw,"<e137-reviewed-payload>","exec"),globals())\n')


def intent_value(role,payload_sha):
    return dict(role=role,attempt_consumed=True,role_index=ROLES.index(role)+1,connections_max=3,
        automatic_retries=0,payload_sha256=payload_sha)


def remote_command(role,payload_sha):
    argument=base64.b64encode(canonical(intent_value(role,payload_sha))).decode('ascii')
    return '/usr/bin/python3 -I -S -B -c '+shlex.quote(BOOTSTRAP)+' '+shlex.quote(argument)


def _execution_inputs(repo,ledger):
    from scripts import acceptance_transport_e98 as control
    first=ledger.phase/'capture/stdout.json'
    raw=(control.STAGING/'v6_e128_failure_readback_20261027_r1/stdout.json').read_bytes()
    require(sha(raw)=='d70818980f52ad17e9a1d7eb917d9618d1bf203d4ec29b7e780430529528189e','E128_FIXED_LOCAL_PROOF')
    tcl=base64.b64decode(next(r['body_base64'] for r in decode(raw)['files'] if r.get('sha256')==execution.legacy.BASE_TCL_SHA256),validate=True)
    require(sha(tcl)==execution.legacy.BASE_TCL_SHA256,'EXACT_FROZEN_INCREMENTAL_TCL')
    supplement=control.STAGING/'v6_e137_engine_source_supplement_r1/files'
    inputs=dict(original_clock=(ledger.phase/'package_clock.json').read_bytes(),role1_response=first.read_bytes(),
        policy=canonical(batch.POLICY),functions=(supplement/batch.selector.FUNCTIONS_SHA).read_bytes(),
        shell=(supplement/batch.selector.SHELL_SHA).read_bytes(),
        e112=(control.STAGING/'v6_e112_preparation_20261026_r1/stdout.json').read_bytes(),
        parent_worker_source=(repo/'scripts/worker_pt_label_generation_e127.py').read_bytes(),
        profile_source=(repo/'src/data/prospective_runtime_profile_e112.py').read_bytes(),incremental=tcl,
        parent_helper=execution.legacy.EXPECTED_INIT.encode('ascii'))
    for name,key in (('physical_f_replay_execution_e135','runtime_source'),('physical_f_replay_execution_e137','worker_source'),
            ('physical_runtime_bootstrap_e137','bootstrap_source'),('physical_engine_evidence_e137','collector_source'),
            ('physical_e137_root_receipt','root_receipt_source')):
        inputs[key]=(repo/'src/data'/(name+'.py')).read_bytes()
    require(sha(inputs['functions'])==batch.selector.FUNCTIONS_SHA and sha(inputs['shell'])==batch.selector.SHELL_SHA and
        sha(inputs['e112'])==bootstrap.E112_SHA256 and sha(inputs['parent_worker_source'])==bootstrap.WORKER_SHA256 and
        sha(inputs['profile_source'])==bootstrap.PROFILE_SHA256,'LOCAL_FROZEN_HELPER_PROFILE_BYTES')
    return inputs


def prepare(role='capture',staging=None):
    require(role in ('capture','execution'),'ROLE3_USE_REVIEWED_DEDICATED_WRAPPER')
    from scripts.run_direct_tessent_e104 import PINS
    repo = Path(__file__).resolve().parents[1]
    authority,proposal = (repo/AUTH).read_bytes(),(repo/PROPOSAL).read_bytes()
    _authority(authority,proposal)
    pins = dict(PINS)
    pins.update(execution.SOURCE_PINS)
    pins.update(capture.DEPENDENCY_SHA256)
    rows = []
    names=SOURCES+('prospective_runtime_profile_e112','prospective_runtime_adapter_e114',
        'physical_engine_selector_e137','physical_stil_dependencies_e137','physical_runtime_bootstrap_e137',
        'physical_engine_evidence_e137','physical_e137_root_receipt','physical_e137_batch_execution')
    pins.update(bootstrap.SOURCE_PINS)
    for name in names:
        raw = (repo/'src/data'/(name+'.py')).read_bytes()
        require(name not in pins or sha(raw) == pins[name],'FROZEN_SOURCE_DRIFT')
        ast.parse(raw.decode('utf-8'),feature_version=(3,6))
        rows.append(dict(name=name,sha256=sha(raw),body=base64.b64encode(raw).decode('ascii')))
    inputs=dict(authority=authority,proposal=proposal)
    if role=='execution':
        from scripts import acceptance_transport_e98 as control
        ledger=RoleLedger(control.STAGING if staging is None else staging)
        ledger.validate_cached('capture')
        inputs.update(_execution_inputs(repo,ledger))
    worker=(repo/'scripts/worker_e137_batch.py').read_bytes()
    packet=dict(role=role,sources=rows,source_sha256={r['name']:r['sha256'] for r in rows},
        authorization_sha256=AUTH_SHA,input_sha256={k:sha(v) for k,v in inputs.items()},
        inputs={k:base64.b64encode(v).decode('ascii') for k,v in inputs.items()})
    wire=canonical(packet).decode('ascii')
    payload=('import base64,json\nworker=base64.b64decode('+repr(base64.b64encode(worker).decode('ascii'))+',validate=True)\n'
        'if __import__("hashlib").sha256(worker).hexdigest()!='+repr(sha(worker))+':raise ValueError("WORKER_SHA")\n'
        'ns={};exec(compile(worker,"<e137-worker>","exec"),ns)\n'
        'packet=json.loads('+repr(wire)+')\n'
        'result=ns["dispatch"](packet,__role_intent__,__payload_sha256__,__connection_start__)\n'
        'print(json.dumps(result,sort_keys=True,allow_nan=False),flush=True)\n').encode('ascii')
    ast.parse(payload.decode('ascii'),feature_version=(3,6))
    command=remote_command(role,sha(payload))
    whole={name:sha((repo/name).read_bytes()) for name in ('src/data/physical_e137_role3_binding.py',
        'src/data/physical_e137_role3_export.py','scripts/run_e137_role3_readback.py')}
    protocol = dict(role=role,outputs=list(OUTPUTS),roles=ROLES,seconds=3600,first_failure_stops=True,
        policy=batch.POLICY,command=command,source_order=[r['name'] for r in rows])
    return dict(payload=payload,payload_sha256=sha(payload),controller_sha256=sha(Path(__file__).read_bytes()),
        worker_sha256=sha(worker),input_sha256=packet['input_sha256'],policy_sha256=sha(canonical(batch.POLICY)),
        invocation_sha256=sha(canonical(dict(remote_command=command,payload_sha256=sha(payload)))),
        package_source_sha256=whole,
        source_sha256={r['name']:r['sha256'] for r in rows},authorization_sha256=AUTH_SHA,
        proposal_sha256=capture.PROPOSAL_SHA,protocol_sha256=sha(canonical(protocol)),readiness=readiness())


def remaining(first):
    require(type(first) is dict and set(first) == {'authorization_sha256','start','end','utc_start','utc_end','domain'} and
        all(type(first[k]) in (int,float) and math.isfinite(first[k]) and first[k] >= 0 for k in ('start','end')) and
        all(type(first[k]) is str for k in ('authorization_sha256','utc_start','utc_end')),'EXACT_ORIGINAL_CLOCK_FIELDS')
    require(first['authorization_sha256'] == AUTH_SHA and first['domain'] ==
        dict(host=platform.node(),clock=time.get_clock_info('monotonic').implementation),'ORIGINAL_LOCAL_CLOCK_DOMAIN')
    now = time.monotonic()
    require(first['end'] == first['start']+3600 and first['start'] <= now < first['end'],'ORIGINAL_MONOTONIC_DEADLINE')
    utc = datetime.datetime.now(datetime.timezone.utc)
    began = datetime.datetime.strptime(first['utc_start'],'%Y-%m-%dT%H:%M:%S.%f%z')
    end = datetime.datetime.strptime(first['utc_end'],'%Y-%m-%dT%H:%M:%S.%f%z')
    require((end-began).total_seconds() == 3600 and abs((utc-began).total_seconds()-(now-first['start'])) <= 5,'CLOCK_DIVERGENCE')
    seconds = min(first['end']-now,(end-utc).total_seconds())
    require(seconds > 10,'ORIGINAL_PACKAGE_EXPIRED')
    return seconds


def validate_intent(value,role,payload_sha=None):
    require(role in ROLES and type(value) is dict and set(value) == {'role','attempt_consumed','role_index',
        'connections_max','automatic_retries','payload_sha256'} and value['role'] == role and
        value['attempt_consumed'] is True and all(type(value[k]) is int for k in ('role_index','connections_max','automatic_retries')) and
        value['role_index'] == ROLES.index(role)+1 and value['connections_max'] == 3 and value['automatic_retries'] == 0 and
        type(value['payload_sha256']) is str and re.fullmatch('[0-9a-f]{64}',value['payload_sha256']) is not None and
        (payload_sha is None or value['payload_sha256'] == payload_sha),'EXACT_ROLE_DEBIT_AND_PAYLOAD')
    return value


def validate_owned_root(receipt,clock_raw,role2_intent):
    """No caller-owned bool is accepted as an ownership attestation."""
    require(OWNED_ROOT_EMITTER_SHA256 is not None,'ROLE2_OWNED_ROOT_EMITTER_NOT_FROZEN')
    require(type(clock_raw) is bytes and decode(clock_raw)['authorization_sha256'] == AUTH_SHA,'ROOT_PROOF_ORIGINAL_GRANT')
    remaining(decode(clock_raw))
    require(type(receipt) is dict and receipt.get('root') == ROOT and receipt.get('authorization_sha256') == AUTH_SHA and
        receipt.get('clock_sha256') == sha(clock_raw) and receipt.get('payload_sha256') == role2_intent.get('payload_sha256') and
        role2_intent.get('role') == 'execution' and role2_intent.get('attempt_consumed') is True,'ROOT_PROOF_EXACT_INSTANCE')
    # A future emitter needs a reviewed authenticity contract, not a boolean.
    raise ValueError('ROLE2_ROOT_ATTESTATION_PROTOCOL_UNIMPLEMENTED')


def validate_cached_role(record,role,clock_raw,intent,stdout,stderr,transport):
    """Authenticate cache joins; role-specific scientific validation stays separate."""
    expected = dict(schema='e137-local-role-validation-v1',role=role,authorization_sha256=AUTH_SHA,
        clock_sha256=sha(clock_raw),payload_sha256=intent.get('payload_sha256'),stdout_sha256=sha(stdout),
        stderr_sha256=sha(stderr),transport_sha256=sha(canonical(transport)))
    require(type(record) is dict and record == expected,'ROLE_VALIDATED_CONTENT_BINDING')
    validate_intent(intent,role)
    require(transport.get('stdout_sha256') == sha(stdout) and transport.get('stderr_sha256') == sha(stderr) and
        type(transport.get('exit_code')) is int and transport['exit_code'] == 0 and all(transport.get(k) is False for k in
        ('timeout','overflow','write_failed','threads_incomplete')),'ROLE_RAW_TRANSPORT_BINDING')
    remaining(decode(clock_raw))
    value = decode(stdout)
    require(type(value) is dict and value.get('role') == role and value.get('execution_ready') is False,'ROLE_RAW_SCHEMA')
    if role == 'capture':
        import types
        namespace = dict(vars(capture),AUTH_SHA=AUTH_SHA)
        types.FunctionType(capture.validate_receipt.__code__,namespace)(canonical(value['capture']))
    elif role == 'execution':
        validate_owned_root(value.get('owned_root'),clock_raw,intent)
    return value


def open_output_parent(path,expected_root):
    """Missing owned subdirectories are absent, but missing/replaced root is fatal."""
    require(path in OUTPUTS,'FIXED_OUTPUT_ONLY')
    root = execution.io._directory(ROOT)
    child = None
    try:
        require(capture.source.identity(os.fstat(root)) == expected_root,'OWNED_EXPORT_ROOT_CHANGED')
        parent = path.rsplit('/',1)[0]
        try:
            child = execution.io._directory(parent)
        except FileNotFoundError:
            pass
        fresh = execution.io._directory(ROOT)
        try:
            require(capture.source.identity(os.fstat(fresh)) == expected_root == capture.source.identity(os.fstat(root)),
                'OWNED_EXPORT_ROOT_CHANGED')
        finally:
            os.close(fresh)
        return child
    except BaseException:
        if child is not None:
            os.close(child)
        raise
    finally:
        os.close(root)


def execute(role,review_path,payload_sha,staging=None):
    """Parent-only actual one-use entry, conditional on exact independent review."""
    from scripts import acceptance_transport_e98 as control
    plan = prepare(role,staging)
    review_raw=Path(review_path).read_bytes();review = decode(review_raw)
    require(review.get('status') == 'PASS' and review.get('reviewed') == {k:plan[k] for k in REVIEW_KEYS} and
        payload_sha == plan['payload_sha256'],'EXACT_ROLE_PACKET_REVIEW')
    require(plan['readiness']['implementation_available'] is True,'PACKAGE_NOT_IMPLEMENTED')
    helper=control.load_transport()
    fingerprint=helper.verify_cached_host('A')
    require(fingerprint=='SHA256:9+c0w59UN6NMPA6MnG45jtRW63JT9gKLTBxtnnSpJqM','EXACT_KNOWN_A_HOST_KEY')
    ledger=RoleLedger(control.STAGING if staging is None else staging)
    directory=ledger.reserve(role,payload_sha)
    try:
        control.write_new(directory/'packet_review.json',review_raw)
        control.write_new(directory/'packet.json',control.encode({k:plan[k] for k in REVIEW_KEYS}))
        def validate(raw):
            value=validate_response(role,raw,plan,ledger)
            if role=='capture':
                control.write_new(ledger.phase/'package_clock.json',control.encode(package_clock(value,
                    (ledger.phase/'start.json').read_bytes(),payload_sha)))
            else:
                policy=source_policy(value,plan,ledger)
                validate_execution(value,policy,(ledger.phase/'package_clock.json').read_bytes(),
                    (directory/'intent.json').read_bytes())
                control.write_new(directory/'source_policy.json',control.encode(policy))
                control.write_new(directory/'owned_root_receipt.json',control.encode(value['owned_root']))
            remaining(decode((ledger.phase/'start.json').read_bytes()))
            record=validation_record(role,ledger)
            control.write_new(directory/'validated.json',control.encode(record))
            return value
        result=ledger.capture_transport(role,helper,plan['payload'],6291456,validate,
            command=remote_command(role,payload_sha),fingerprint=fingerprint,seconds=60 if role=='capture' else 2400)
        if role=='execution' and result['worker_response']['status']=='STOPPED_FIRST_FAILURE':
            ledger.close_failure(role,'SCIENTIFIC_FAILURE_OWNED_CLEAN_EVIDENCE_RECOVERABLE')
        return dict(phase=str(directory),response=result,execution_ready=False)
    except BaseException:
        if not (ledger.phase/'closed.json').exists():ledger.close_failure(role,'ROLE_FAILED_NO_RETRY')
        raise


def package_clock(value,start_raw,payload_sha):
    first=decode(start_raw);remaining(first)
    remote=value['remote_start_monotonic'];sample=value['remote_sample_monotonic']
    require(type(remote) in (int,float) and type(sample) in (int,float) and math.isfinite(remote) and math.isfinite(sample) and
        0<=remote<=sample<remote+60 and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value['boot_id']),
        'ACTUAL_FIRST_CALL_BOOT_CLOCK')
    utc=datetime.datetime.strptime(value['remote_utc_sample'],'%Y-%m-%dT%H:%M:%S.%f%z')
    began=datetime.datetime.strptime(first['utc_start'],'%Y-%m-%dT%H:%M:%S.%f%z')
    now=datetime.datetime.now(datetime.timezone.utc)
    require(began-datetime.timedelta(seconds=5)<=utc<=now+datetime.timedelta(seconds=5),'REMOTE_UTC_SAMPLE_SKEW')
    clock=dict(schema=execution.CLOCK_SCHEMA,authorization_sha256=AUTH_SHA,proposal_sha256=capture.PROPOSAL_SHA,
        reader_payload_sha256=payload_sha,initial_response_sha256=sha(canonical(value['capture'])),start_file_sha256=sha(start_raw),
        boot_id=value['boot_id'],remote_start_monotonic=remote,remote_deadline_monotonic=remote+3600,
        remote_utc_sample=value['remote_utc_sample'],remote_clock_sample_monotonic=sample,
        local_utc_start=first['utc_start'],local_utc_deadline=first['utc_end'],local_monotonic_start=first['start'],
        local_monotonic_deadline=first['end'],local_clock_domain=first['domain'])
    import types
    types.FunctionType(execution.package_clock.__code__,dict(vars(execution),AUTH_SHA=AUTH_SHA,
        INITIAL_CLOCK_SHA256=sha(canonical(clock))))(canonical(clock))
    return clock


def validate_response(role,raw,plan,ledger):
    require(type(raw) is bytes and len(raw)<=6291456,'ROLE_RESPONSE_CAP')
    value=decode(raw)
    if role=='capture':
        require(type(value) is dict and set(value)=={'role','capture','boot_id','remote_start_monotonic',
            'remote_sample_monotonic','remote_utc_sample','execution_ready'} and value['role']==role and
            value['execution_ready'] is False and type(value['boot_id']) is str,'CAPTURE_CLOSED_RESPONSE')
        import types
        types.FunctionType(capture.validate_receipt.__code__,dict(vars(capture),AUTH_SHA=AUTH_SHA))(canonical(value['capture']))
    else:
        require(type(value) is dict and set(value)=={'role','worker_response','owned_root','cleanup_observation','execution_ready'} and
            value['role']==role and value['execution_ready'] is False and type(value['owned_root']) is dict,
            'UNQUALIFIED_OR_FAILED_BATCH_RESPONSE')
    return value


def source_policy(value,plan,ledger):
    directory=ledger.phase/'execution';response=value['worker_response'];sources=plan['source_sha256']
    return dict(schema='e137-batch-source-policy-redacted-v1',authorization_sha256=AUTH_SHA,proposal_sha256=capture.PROPOSAL_SHA,
        original_clock_sha256=sha((ledger.phase/'package_clock.json').read_bytes()),role2_payload_sha256=plan['payload_sha256'],
        role2_intent_sha256=sha((directory/'intent.json').read_bytes()),role2_stdout_sha256=sha((directory/'stdout.json').read_bytes()),
        role2_stderr_sha256=sha((directory/'stderr.log').read_bytes()),role2_transport_sha256=sha((directory/'transport.json').read_bytes()),
        instance_sha256=response['instance_sha256'],policy_sha256=plan['policy_sha256'],source_manifest_sha256=sha(canonical(sources)),
        source_sha256=sources,emitter_source_sha256=sources['physical_e137_root_receipt'],
        runtime_source_sha256=sources['physical_f_replay_execution_e135'],worker_source_sha256=sources['physical_f_replay_execution_e137'])


def validate_execution(value,policy,clock_raw,intent_raw):
    """Reported-data joins inside the reviewed one-use transport creator chain."""
    from src.data import physical_e137_role3_binding as binding
    response,receipt,cleanup=value['worker_response'],value['owned_root'],value['cleanup_observation']
    keys={'schema','status','launch_debit','selfchecks','instance_sha256','policy_sha256','payload_sha256',
        'source_manifest_sha256','engine_metadata','bootstrap','ldd_policy','final_environment_observed',
        'physical_d95_verified','execution_ready','training_release'}
    require(type(response) is dict and set(response)==keys and response['schema']==execution.SCHEMA and
        response['status'] in ('OBSERVED_PENDING_SCIENTIFIC_AUDIT','STOPPED_FIRST_FAILURE') and
        type(response['launch_debit']) is int and response['launch_debit']==1 and type(response['selfchecks']) is int and response['selfchecks']==3 and
        all(response[k] is False for k in ('final_environment_observed','physical_d95_verified','execution_ready','training_release')) and
        all(response[k]==policy[p] for k,p in (('instance_sha256','instance_sha256'),('policy_sha256','policy_sha256'),
        ('payload_sha256','role2_payload_sha256'),('source_manifest_sha256','source_manifest_sha256'))),'BATCH_RESPONSE_EXACT_BINDINGS')
    require(type(receipt) is dict and set(receipt)==binding.RECEIPT_KEYS and
        receipt['schema']=='e137-final-registered-root-receipt-v1' and receipt['root']==ROOT and
        receipt['worker_response_sha256']==sha(canonical(response)) and receipt['cleanup_evidence_sha256']==sha(canonical(cleanup)) and
        receipt['cleanup_observer_source_sha256']==policy['source_sha256']['physical_e137_batch_execution'] and
        receipt['launch_debit']==1 and type(receipt['launch_debit']) is int,'ACTUAL_EMITTER_RESPONSE_JOIN')
    require(type(cleanup) is dict and cleanup.get('cleaned') is True and cleanup.get('cleanup_error') is None and
        type(cleanup.get('returncode')) is int and cleanup.get('launch_attempted') is True,'ACTUAL_FINAL_CLEANUP')
    bindings=dict(authorization_sha256=AUTH_SHA,clock_sha256=sha(clock_raw),role2_intent_sha256=sha(intent_raw),
        role2_payload_sha256=policy['role2_payload_sha256'],worker_spec_sha256=policy['instance_sha256'],
        runtime_source_sha256=policy['runtime_source_sha256'],worker_source_sha256=policy['worker_source_sha256'],
        emitter_source_sha256=policy['emitter_source_sha256'])
    require(receipt['input_bindings']==bindings,'ACTUAL_EMITTER_INSTANCE_BINDINGS')
    import types
    clock=types.FunctionType(execution.package_clock.__code__,dict(vars(execution),AUTH_SHA=AUTH_SHA,
        INITIAL_CLOCK_SHA256=sha(clock_raw)))(clock_raw)
    require(receipt['boot_id']==clock['boot_id'] and receipt['original_remote_deadline']==clock['monotonic_end'] and
        type(receipt['final_snapshot_monotonic']) in (int,float) and math.isfinite(receipt['final_snapshot_monotonic']) and
        clock['remote_start_monotonic']<=receipt['final_snapshot_monotonic']<clock['monotonic_end'],'EMITTER_ORIGINAL_CLOCK')
    binding.core._file_identity(receipt['identity'],0,directory=True)
    require(receipt['birth_continuity']=={k:receipt['identity'][k] for k in ('st_dev','st_ino','st_uid','st_mode')},'ROOT_BIRTH_CONTINUITY')


def validation_record(role,ledger):
    directory=ledger.phase/role;intent=decode((directory/'intent.json').read_bytes())
    return dict(schema='e137-local-role-validation-v1',role=role,authorization_sha256=AUTH_SHA,
        clock_sha256=sha((ledger.phase/'start.json').read_bytes()),payload_sha256=intent['payload_sha256'],
        stdout_sha256=sha((directory/'stdout.json').read_bytes()),stderr_sha256=sha((directory/'stderr.log').read_bytes()),
        transport_sha256=sha(canonical(decode((directory/'transport.json').read_bytes()))))


class RoleLedger(object):
    """Create-once local debit mechanism; tests never use the real phase."""
    def __init__(self,staging):
        self.phase = Path(staging)/PHASE

    def reserve(self,role,payload_sha):
        from scripts import acceptance_transport_e98 as control
        require(role in ROLES,'FIXED_ROLE')
        if role == 'capture':
            self.phase.mkdir(exist_ok=False)
            utc,start = datetime.datetime.now(datetime.timezone.utc),time.monotonic()
            first = dict(authorization_sha256=AUTH_SHA,start=start,end=start+3600,
                utc_start=utc.strftime('%Y-%m-%dT%H:%M:%S.%f%z'),
                utc_end=(utc+datetime.timedelta(seconds=3600)).strftime('%Y-%m-%dT%H:%M:%S.%f%z'),
                domain=dict(host=platform.node(),clock=time.get_clock_info('monotonic').implementation))
            control.write_new(self.phase/'start.json',control.encode(first))
        else:
            if (self.phase/'closed.json').exists():
                require(role == 'readback','FIRST_FAILURE_CLOSED_SCIENTIFIC_EXECUTION')
                closed = decode((self.phase/'closed.json').read_bytes())
                require(closed.get('role') == 'execution' and
                    (self.phase/'execution/intent.json').is_file(),'FAILURE_EVIDENCE_REQUIRES_ROLE2_DEBIT')
                first = decode((self.phase/'start.json').read_bytes())
                remaining(first)
                require(not (self.phase/'readback').exists(),'FAILURE_EVIDENCE_ALREADY_CONSUMED')
                require((self.phase/'execution/owned_root_receipt.json').is_file(),'FAILURE_EVIDENCE_ROOT_OWNERSHIP_UNPROVEN')
                # Proposal permits this exception, but no role2 response/ownership
                # authenticator exists yet. Presence of JSON is never proof.
                raise ValueError('FAILURE_EVIDENCE_ROOT_RECEIPT_AUTHENTICATOR_UNAVAILABLE')
            previous = ROLES[ROLES.index(role)-1]
            require((self.phase/previous/'validated.json').is_file(),'PREVIOUS_ROLE_NOT_VALIDATED')
            self.validate_cached(previous)
            first = decode((self.phase/'start.json').read_bytes())
        remaining(first)
        directory = self.phase/role
        directory.mkdir(exist_ok=False)
        control.write_new(directory/'intent.json',control.encode(dict(role=role,attempt_consumed=True,
            role_index=ROLES.index(role)+1,connections_max=3,automatic_retries=0,payload_sha256=payload_sha)))
        return directory

    def validate_cached(self,role):
        directory = self.phase/role
        return validate_cached_role(decode((directory/'validated.json').read_bytes()),role,
            (self.phase/'start.json').read_bytes(),decode((directory/'intent.json').read_bytes()),
            (directory/'stdout.json').read_bytes(),(directory/'stderr.log').read_bytes(),
            decode((directory/'transport.json').read_bytes()))

    def capture_transport(self,role,helper,payload,cap,validator,command=None,fingerprint=None,seconds=60):
        """Actual one-use transport primitive, not a release for execute()."""
        require(role in ROLES and type(payload) is bytes and callable(validator),'ROLE_TRANSPORT_ARGUMENTS')
        require(not (self.phase/'closed.json').exists(),'FIRST_FAILURE_CLOSED_PACKAGE')
        directory = self.phase/role
        require((directory/'intent.json').is_file(),'DEBIT_BEFORE_TRANSPORT')
        validate_intent(decode((directory/'intent.json').read_bytes()),role,sha(payload))
        from scripts import acceptance_transport_e98 as control
        if fingerprint is None:fingerprint=helper.verify_cached_host('A')
        require(type(fingerprint) is str and fingerprint=='SHA256:9+c0w59UN6NMPA6MnG45jtRW63JT9gKLTBxtnnSpJqM','EXACT_KNOWN_A_HOST_KEY')
        control.write_new(directory/'transport_consumed.json',control.encode(dict(attempt_consumed=True,automatic_retries=0,
            payload_sha256=sha(payload),host_fingerprint=fingerprint)))
        first = decode((self.phase/'start.json').read_bytes())
        helper.TIMEOUT = transport_timeout(first,seconds)
        try:
            argv=helper.command('A')
            if command is not None:
                require(command==remote_command(role,sha(payload)),'EXACT_REVIEWED_REMOTE_COMMAND')
                argv=list(argv);argv[-1]=command
            observed = helper.transport(argv,payload,cap)
            self.save_raw(role,observed['stdout'],observed['stderr'],{k:v for k,v in observed.items() if k not in ('stdout','stderr')})
            remaining(first)
            require(type(observed['exit_code']) is int and observed['exit_code'] == 0 and all(observed[k] is False for k in
                ('timeout','overflow','write_failed','threads_incomplete')) and observed['stderr']==b'','ROLE_TRANSPORT_FAILED')
            return validator(observed['stdout'])
        except BaseException:
            self.close_failure(role,'ROLE_FAILED_RAW_MAY_BE_PARTIAL_NO_RETRY')
            raise

    def save_raw(self,role,stdout,stderr,transport):
        from scripts import acceptance_transport_e98 as control
        directory = self.phase/role
        require((directory/'intent.json').is_file(),'DEBIT_BEFORE_TRANSPORT')
        control.write_new(directory/'stdout.json',stdout)
        control.write_new(directory/'stderr.log',stderr)
        control.write_new(directory/'transport.json',control.encode(dict(transport,
            stdout_sha256=sha(stdout),stdout_bytes=len(stdout),stderr_sha256=sha(stderr),stderr_bytes=len(stderr),remote_termination_verified=False)))

    def close_failure(self,role,code):
        from scripts import acceptance_transport_e98 as control
        control.write_new(self.phase/'closed.json',control.encode(dict(role=role,code=code,
            stop_new_scientific_execution=True,conditional_role3_evidence_permitted_by_proposal=True,
            evidence_recovery_implemented=False,automatic_retries=0)))


def remote(spec,started):
    """Physical capture/export primitives only; no tool or role2 fallback."""
    import stat
    from src.data import direct_tessent_acceptance_e104 as direct
    authority = base64.b64decode(spec['authority'],validate=True)
    proposal = base64.b64decode(spec['proposal'],validate=True)
    _authority(authority,proposal)
    require(spec['role'] in ('capture','readback'),'NO_UNREVIEWED_EXECUTION_ROLE')
    if spec['role'] == 'readback':
        validate_owned_root(spec.get('owned_root'),
            base64.b64decode(spec.get('clock_base64',''),validate=True),spec.get('role2_intent',{}))
    require(platform.node() == 'bupt-vncs2' and os.getuid() == 1047 and os.sys.platform.startswith('linux'),'FIXED_A')
    require(type(started) in (int,float) and math.isfinite(started) and started >= 0,'BOOTSTRAP_CLOCK')
    boot = execution.process._boot_id()
    domain = direct.Descendants()
    def tick():
        require(started <= time.monotonic() < started+60,'ROLE_DEADLINE')
        require(not domain.sample() and domain.peak <= 536870912,'ROLE_MEMORY_OR_CHILD')
    if spec['role'] == 'capture':
        import types
        namespace = dict(vars(capture),AUTH_SHA=AUTH_SHA)
        for name in ('check_authority','validate_receipt','capture'):
            function = getattr(capture,name)
            namespace[name] = types.FunctionType(function.__code__,namespace,name,function.__defaults__,function.__closure__)
        value = namespace['capture'](authority,proposal,started+60,tick,time.monotonic)
        return dict(role='capture',capture=value,boot_id=boot,remote_start_monotonic=started,
            remote_sample_monotonic=time.monotonic(),remote_utc_sample=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f%z'),
            execution_ready=False)
    rows,budget = [],[0]
    # No readback IO until the original clock and actual role2 root attestation join.
    for path in OUTPUTS:
        tick()
        parent,name = path.rsplit('/',1)
        fd = open_output_parent(path,spec['owned_root']['identity'])
        if fd is None:
            rows.append(dict(path=path,missing=True,reason='FIXED_PARENT_ABSENT'))
            continue
        try:
            parent_id = capture.source.identity(os.fstat(fd))
            try:
                info = os.stat(name,dir_fd=fd,follow_symlinks=False)
            except FileNotFoundError:
                rows.append(dict(path=path,missing=True))
                continue
            cap = 8388608 if name.endswith(('faults.rpt','faults.mtfi')) else 2097152 if name in ('tool.log','stdout.log') else 65536
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 1047 and
                0 <= info.st_size <= cap and budget[0]+info.st_size <= 16777216,'OWNED_OUTPUT_BOUND')
            raw,size,digest = execution.legacy._stream_io(tick)['_read_at'](fd,name,[0],expected_bytes=info.st_size,max_bytes=cap)
            require(capture.source.identity(info) == capture.source.identity(os.stat(name,dir_fd=fd,follow_symlinks=False)) and
                capture.source.identity(os.fstat(fd)) == parent_id,'OUTPUT_CHANGED')
            fresh = execution.io._directory(parent)
            try:
                require(capture.source.identity(os.fstat(fresh)) == parent_id,'OUTPUT_PARENT_CHANGED')
            finally:
                os.close(fresh)
            budget[0] += size
            rows.append(dict(path=path,bytes=size,sha256=digest,identity=capture.source.identity(info),body_base64=base64.b64encode(raw).decode('ascii')))
        finally:
            os.close(fd)
    value = dict(role='readback',files=rows,boot_id=boot,execution_ready=False)
    require(len(canonical(value)) <= 25165824,'READBACK_RESPONSE_CAP')
    return value
