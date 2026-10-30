"""Source-reviewed deterministic batch integration, disabled until packet freeze.

Dynamic instance hashes are consistency commitments, not independent approval.
Vendor ldd transformation is admitted by explicit policy, not called verified.
No external instance ACK, network transport, or controller is implemented here.
"""
import base64
import copy
import math
import os
import platform
import re
import sys
import time
import types
from . import physical_f_replay_execution_e137 as execution
from . import physical_replay_capture_e137 as capture
from . import physical_runtime_bootstrap_e137 as bootstrap
from . import physical_engine_evidence_e137 as evidence
from . import physical_engine_selector_e137 as selector
from . import physical_stil_dependencies_e137 as dependencies
from . import physical_e137_root_receipt as roots

require,sha,canonical,decode=capture.require,capture.sha,capture.canonical,capture.decode
AUTH_SHA256 = POLICY_SHA256 = PAYLOAD_SHA256 = None
FROZEN_INPUT_SHA256 = FROZEN_SOURCE_SHA256 = None
_USED=False
ROOT=execution.ROOT
POLICY=dict(schema='e137-deterministic-vendor-batch-policy-v1',external_ack_required=False,
    vendor_ldd='UNCHANGED_LAUNCHER_SOURCE_BOUNDED_TRANSFORMS_NO_EXTRA_PROBE',
    source_paths=list(evidence.PATHS),bootstrap_max=1,selfchecks=3,tool_launches_max=1,
    package_seconds=3600,connection_seconds=2400,session_seconds=1800,
    sampled_memory_max=536870912,sampled_storage_max=8589934592,automatic_retries=0)
INPUT_KEYS={'authority','proposal','original_clock','role1_response','role2_intent','policy','runtime_source',
    'worker_source','bootstrap_source','collector_source','root_receipt_source','functions','shell','e112',
    'parent_worker_source','profile_source','incremental','parent_helper'}


def _hex(value):return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None


def _private(raw,name):
    module=types.ModuleType('src.data._batch_'+name);module.__package__='src.data'
    exec(compile(raw,'<e137-frozen-'+name+'>','exec'),module.__dict__)
    module.__source_sha256__=sha(raw)
    return module


def _publish_evidence(files,tick,name,raw):
    # TrackedFiles.directory checks the package clock, not the shorter role2
    # deadline. Guard both sides even when legacy publish(check=False) is used.
    tick()
    result=files.publish(name,raw,check=False)
    tick()
    return result


def admission(package):
    """Pure admission; no filesystem, proc, callback or wall-clock access."""
    require(AUTH_SHA256 == roots.APPROVED_AUTH_SHA and _hex(POLICY_SHA256) and _hex(PAYLOAD_SHA256) and
        type(FROZEN_INPUT_SHA256) is dict and type(FROZEN_SOURCE_SHA256) is dict,'BATCH_PACKET_NOT_FROZEN')
    require(type(package) is dict and set(package) == INPUT_KEYS == set(FROZEN_INPUT_SHA256) and
        all(type(v) is bytes for v in package.values()) and sum(map(len,package.values())) <= 10485760 and
        all(_hex(pin) and sha(package[k]) == pin for k,pin in FROZEN_INPUT_SHA256.items()),'BATCH_EXACT_INPUT_BYTES')
    require(sha(package['authority']) == AUTH_SHA256 and sha(package['policy']) == POLICY_SHA256 and
        decode(package['policy']) == POLICY,'BATCH_EXACT_APPROVED_POLICY')
    required={'physical_e137_batch_execution','physical_f_replay_execution_e137','physical_replay_capture_e137',
        'physical_runtime_bootstrap_e137','physical_engine_evidence_e137','physical_engine_selector_e137',
        'physical_stil_dependencies_e137','physical_e137_root_receipt'}|set(execution.SOURCE_PINS)|set(bootstrap.SOURCE_PINS)|set(capture.DEPENDENCY_SHA256)
    require(required <= set(FROZEN_SOURCE_SHA256),'BATCH_COMPLETE_SOURCE_BINDINGS')
    namespace=dict(vars(capture),AUTH_SHA=AUTH_SHA256)
    types.FunctionType(capture.check_authority.__code__,namespace)(package['authority'],package['proposal'])
    for name,pin in FROZEN_SOURCE_SHA256.items():
        module=sys.modules.get('src.data.'+name)
        require(_hex(pin) and module is not None and getattr(module,'__source_sha256__',None) == pin,'BATCH_VERIFIED_SOURCE_LOADER')
    for name,key in (('physical_f_replay_execution_e137','worker_source'),('physical_runtime_bootstrap_e137','bootstrap_source'),
            ('physical_engine_evidence_e137','collector_source'),('physical_e137_root_receipt','root_receipt_source')):
        require(FROZEN_SOURCE_SHA256.get(name) == sha(package[key]),'BATCH_PRIVATE_SOURCE_JOIN')
    require(FROZEN_SOURCE_SHA256.get('physical_e137_batch_execution') == globals().get('__source_sha256__') and
        sha(package['runtime_source']) == execution.SOURCE_PINS['physical_f_replay_execution_e135'],'BATCH_FACTORY_SOURCE_JOIN')
    role1=decode(package['role1_response'])
    require(role1.get('role') == 'capture' and role1.get('execution_ready') is False,'BATCH_ROLE1_SCHEMA')
    observed=types.FunctionType(capture.validate_receipt.__code__,namespace)(canonical(role1['capture']))
    namespace=dict(vars(execution),AUTH_SHA=AUTH_SHA256,INITIAL_CLOCK_SHA256=sha(package['original_clock']))
    clock=types.FunctionType(execution.package_clock.__code__,namespace)(package['original_clock'])
    require(role1['boot_id'] == clock['boot_id'] and role1['remote_start_monotonic'] == clock['remote_start_monotonic'] and
        sha(canonical(observed)) == clock['initial_response_sha256'],'BATCH_ORIGINAL_ROLE1_CLOCK_JOIN')
    intent=decode(package['role2_intent'])
    require(intent == dict(role='execution',attempt_consumed=True,role_index=2,connections_max=3,automatic_retries=0,
        payload_sha256=PAYLOAD_SHA256) and all(type(intent[k]) is int for k in ('role_index','connections_max','automatic_retries')),
        'BATCH_CONSUMED_ROLE2_DEBIT')
    recipe=execution.recipe.build_candidate(package['incremental'],package['parent_helper'])
    require(ROOT == execution.recipe.ROOT,'BATCH_REVIEWED_ROOT')
    return clock,observed,recipe


def _launch(environment):
    env=dict(environment,HOME=ROOT+'/work',TMPDIR=ROOT+'/work',LANG='C',LC_ALL='C')
    body=dict(schema=execution.legacy.launch_base.SCHEMA,
        argv=[selector.LAUNCHER,'-shell','-license_wait','5','-log',ROOT+'/tool.log','-dofile',ROOT+'/code/replay.tcl'],
        cwd=ROOT+'/work',env=env,effective_envelope_sha256=sha(canonical(dict(policy=POLICY_SHA256,root=ROOT))),
        environment_sha256=sha(canonical(env)),environment_profile_authenticated=False,execution_authorized=False,execution_ready=False)
    body['launch_spec_sha256']=sha(canonical(body));execution.validate_launch(body)
    return body


def _ldd_policy(plan,measured,environment):
    """Model both unchanged vendor outcomes; never claim actual final LD seen."""
    chosen=measured['classification']['selected'];ld=environment.get('LD_LIBRARY_PATH','')
    for role in ('mgls','engine'):
        if role in chosen:
            lib=selector.ROOT+'/lnx-x86/lib'+chosen[role]['width']
            if not ld:ld=lib
            elif lib not in ld:ld=lib+':'+ld
    require(sha(ld.encode('utf-8')) == measured['classification']['pre_ldd_library_path_sha256'],'BATCH_VENDOR_LD_ORDER')
    fallback=selector.ROOT+'/lnx-x86/lib'+chosen['engine']['width']
    return dict(policy=POLICY['vendor_ldd'],pre_ldd_sha256=sha(ld.encode('utf-8')),
        replacement_sha256=sha(fallback.encode('utf-8')),final_environment_observed=False,
        ldd_behavior_verified=False,full_os_library_authentication=False,unresolved_startup_diagnostics_reject_scientific_acceptance=True)


def _verify_dependencies(pattern,allowed,tick):
    # verify refers to its own global name: bind both references privately,
    # without mutating the imported function or another worker's namespace.
    namespace=dict(vars(dependencies))
    fn=types.FunctionType(dependencies.verify.__code__,namespace,
        dependencies.verify.__name__,dependencies.verify.__defaults__,dependencies.verify.__closure__)
    fn.__source_sha256__=FROZEN_SOURCE_SHA256['physical_stil_dependencies_e137']
    namespace['verify']=fn
    return fn(pattern,allowed,tick)


def execute(package,connection_start):
    """Actual composition. Caller must debit role2 before sending this packet."""
    global _USED
    prepared=admission(package)
    require(not _USED,'BATCH_ONE_ATTEMPT_NO_RETRY');_USED=True
    try:
        return _execute(package,connection_start,prepared)
    except BaseException as exc:
        return dict(schema='e137-batch-execution-failure-v1',role='execution',status='STOPPED_FIRST_FAILURE',
            error_type=type(exc).__name__,launch_debit=0,instance_sha256=None,owned_root=None,execution_ready=False)


def _execute(package,connection_start,prepared):
    clock,observed,recipe=prepared
    require(type(connection_start) in (int,float) and math.isfinite(connection_start) and
        platform.node() == 'bupt-vncs2' and os.getuid() == 1047 and os.sys.platform.startswith('linux') and
        platform.machine() == 'x86_64','BATCH_FIXED_HOST_PLATFORM')
    require(execution.process._boot_id() == clock['boot_id'],'BATCH_ORIGINAL_BOOT')
    end=min(clock['monotonic_end'],connection_start+2400)
    domain=execution.direct.Descendants()
    phase=['ACTIVE']
    def guard():
        limit=end if phase[0] == 'EVIDENCE' else end-10
        require(clock['remote_start_monotonic'] <= connection_start <= time.monotonic() < limit and
            time.time() < clock['utc_end'],'BATCH_ORIGINAL_DEADLINE')
        domain.sample();require(domain.peak <= 536870912,'BATCH_SAMPLED_MEMORY')
    guard()
    context=canonical(dict(role='execution',authorization_sha256=AUTH_SHA256,boot_id=clock['boot_id'],
        package_start=clock['remote_start_monotonic'],package_end=clock['monotonic_end'],connection_start=connection_start,utc_end=clock['utc_end']))
    private_bootstrap=_private(package['bootstrap_source'],'bootstrap')
    private_bootstrap.AUTH_SHA256=AUTH_SHA256;private_bootstrap.CONTEXT_SHA256=sha(context);private_bootstrap.EXPECTED_BOOT_ID=clock['boot_id']
    boot_evidence={}
    runtime=private_bootstrap.bootstrap(dict(authority=package['authority'],context=context,e112=package['e112'],
        worker_source=package['parent_worker_source'],profile_source=package['profile_source']),domain,guard,boot_evidence)
    environment=runtime.environment();launch=_launch(environment)
    plan=selector.build_plan(package['functions'],package['shell'],launch['env'],launch['argv'],
        system=platform.system(),machine=platform.machine())
    sampler=_private(package['collector_source'],'collector')
    sampler.AUTH_SHA256=AUTH_SHA256;sampler.CONTEXT_SHA256=sha(context)
    sample_packet=canonical(dict(role='execution',authorization_sha256=AUTH_SHA256,context_sha256=sha(context),selector_sha256=sampler.SELECTOR_SHA256))
    sampler.PACKET_SHA256=sha(sample_packet)
    measured=sampler.collect(package['authority'],sample_packet,context,clock['boot_id'],plan,guard,time.monotonic,time.time)
    ld_policy=_ldd_policy(plan,measured,launch['env'])
    closure=[dict(path=path,bytes=row['identity']['st_size'],sha256=row['sha256'],identity=row['identity'])
        for path,row in measured['files'].items() if row['state'] == 'PRESENT' and row['whole_file_hashed']]
    spec=dict(schema=execution.SCHEMA,launch=launch,inputs=observed,execution_closure=closure,
        policy_sha256=POLICY_SHA256,payload_sha256=PAYLOAD_SHA256,source_manifest_sha256=sha(canonical(FROZEN_SOURCE_SHA256)),
        original_clock_sha256=sha(package['original_clock']),code_sha256=dict(replay=recipe['sha256'],helper=recipe['baseline_expectations_sha256']))
    # This is a consistency digest of actual RAM state, NOT a new permission.
    spec_raw=canonical(spec);instance_sha=sha(spec_raw)
    root_module=_private(package['root_receipt_source'],'root_receipt')
    state=dict(stage='WRITING',debit=0,observation=None)
    source_pin=globals().get('__source_sha256__')
    def tagged(fn):fn.__source_sha256__=source_pin;return fn
    @tagged
    def boot_reader():return execution.process._boot_id()
    @tagged
    def mono_reader():return time.monotonic()
    @tagged
    def utc_reader():return time.time()
    @tagged
    def cleanup_observer(files,cleanup_raw,response_raw,bindings):
        require(state['stage'] == 'FINAL' and state['observation'] is not None and
            decode(cleanup_raw) == state['observation'] and state['observation'].get('cleaned') is True and
            state['observation'].get('launch_attempted') is True,'BATCH_REAL_FINAL_OBSERVATION')
        execution.process._check_worker(domain)
        require(not domain.snapshot(),'BATCH_ACTIVE_DESCENDANTS_AFTER_CLEANUP')
        return dict(schema='e137-supervisor-final-cleanup-observation-v1',root=ROOT,boot_id=boot_reader(),
            cleanup_observation_sha256=sha(cleanup_raw),worker_response_sha256=sha(response_raw),
            clock_sha256=sha(package['original_clock']),role2_intent_sha256=sha(package['role2_intent']),
            owner_identity=dict(pid=domain.pid,startticks=domain.identity[1],uid=os.getuid()),active_descendant_pids=[],
            pending_root_writes=0,launch_debit=state['debit'])
    for key,value in dict(AUTH_SHA256=AUTH_SHA256,CLOCK_SHA256=sha(package['original_clock']),ROLE2_INTENT_SHA256=sha(package['role2_intent']),
        ROLE2_PAYLOAD_SHA256=PAYLOAD_SHA256,WORKER_SPEC_SHA256=instance_sha,RUNTIME_SOURCE_SHA256=sha(package['runtime_source']),
        WORKER_SOURCE_SHA256=sha(package['worker_source']),TRUSTED_SELF_SOURCE_SHA256=sha(package['root_receipt_source']),
        CAPABILITY_PINS={k:source_pin for k in ('cleanup','boot','monotonic','utc')},CLEANUP_OBSERVER=cleanup_observer,
        BOOT_READER=boot_reader,MONOTONIC_READER=mono_reader,UTC_READER=utc_reader).items():setattr(root_module,key,value)
    root_session=root_module.tracked_services(dict(authority=package['authority'],proposal=package['proposal'],
        original_clock=package['original_clock'],role2_intent=package['role2_intent'],worker_spec=spec_raw,
        runtime_source=package['runtime_source'],worker_source=package['worker_source']))
    services=root_session.services
    persist_initial,monitor=services._storage(end)
    active=[False]
    def tick():
        guard()
        if active[0]:require(monitor.sample()['sampled_named_bytes'] <= 8589934592,'BATCH_SAMPLED_STORAGE')
        guard()
    def recheck_installed():
        # Reobserve absent alternatives and Tcl directories as well as full
        # file hashes, so a different fallback cannot appear before launch.
        budget=[0]
        fresh={path:sampler.sample_path(path,tick,budget) for path in evidence.PATHS}
        require(fresh == measured['files'],'BATCH_INSTALLED_SOURCE_OR_SELECTION_DRIFT')
    guard()
    persist_initial(canonical(dict(schema=execution.SCHEMA,instance_sha256=instance_sha,launch_debit=0,
        original_package_deadline=clock['monotonic_end'],connection_deadline=end)))
    guard()
    files=services.Files(tick)
    try:
        os.close(files.directory(ROOT,True))
        for name in ('journal','code','work','inputs','snapshots'):os.close(files.directory(ROOT+'/'+name,True))
        active[0]=True
        execution._source_recheck(observed,tick)
        targets=dict(pattern='tester.stil',library='cells.lib',F_basic='F.basic')
        for row in [observed['pattern']]+observed['inputs']:
            files.copy(row['path'],ROOT+'/inputs/'+targets[row['role']],row['bytes'],row['sha256'],row['identity'])
        services._tree_copy(files,capture.TREE_PIN['path'],dict(observed['tree'],files=19,directories=9))
        execution._source_recheck(observed,tick)
        for name,raw in (('replay.tcl',recipe['body']),('expected_baseline.tcl',recipe['baseline_expectations_body'])):
            fd=files.directory(ROOT+'/code')
            try:execution.io._publish(fd,name,raw)
            finally:os.close(fd)
        files.publish('recipe_artifacts.json',canonical(dict(replay_sha256=recipe['sha256'],helper_sha256=recipe['baseline_expectations_sha256'])))
        allowed=[dict(path=ROOT+'/inputs/'+targets[r['role']],bytes=r['bytes'],sha256=r['sha256']) for r in [observed['pattern']]+observed['inputs']]
        allowed += [dict(path=ROOT+'/tsdb/'+r['relative'],bytes=r['bytes'],sha256=r['sha256']) for r in observed['tree']['rows'] if r['kind']=='file']
        dep=_verify_dependencies(ROOT+'/inputs/tester.stil',allowed,tick)
        files.publish('dependency_validation.json',canonical(dep))
        receipts=services.run_selftests(dict(root=ROOT,end=end,sample=tick,persist=lambda n,r:files.publish(n,r,
            check=not n.endswith(('_observation.json','_output.log')))),domain)
        require(len(receipts)==3 and tuple(r['case'] for r in receipts)==execution.legacy.SELFTEST_CASES and
            all(r['passed'] is True and r['cleaned'] is True for r in receipts),'BATCH_THREE_SELFCHECKS')
        execution._closure_recheck(closure,services,tick)
        recheck_installed()
        tick();state['debit']=1
        files.publish('launch_intent.json',canonical(dict(instance_sha256=instance_sha,launch_debit=1,automatic_retries=0)))
        def on_spawn(value):files.publish('spawn_identity.json',canonical(value));return True
        session_end=min(end-10,time.monotonic()+1800,time.monotonic()+max(0,clock['utc_end']-time.time()-10))
        observed_tool=services._observer(launch,session_end,domain,[16777216],on_spawn,services.SimpleMonitor(tick))
        # Stop scientific work. Only bounded raw evidence/ownership publication
        # may use the final reserve; the original hard deadline is unchanged.
        phase[0]='EVIDENCE'
        output=observed_tool['output'];metadata={k:v for k,v in observed_tool.items() if k!='output'}
        _publish_evidence(files,tick,'observation.json',canonical(dict(metadata,output_bytes=len(output),output_sha256=sha(output))))
        _publish_evidence(files,tick,'stdout.log',output)
        _publish_evidence(files,tick,'stdout_ack.json',canonical(dict(bytes=len(output),sha256=sha(output))))
        state['observation']=metadata
        status='OBSERVED_PENDING_SCIENTIFIC_AUDIT' if (metadata.get('failure') is None and metadata.get('cleaned') is True and
            type(metadata.get('returncode')) is int and metadata['returncode']==0) else 'STOPPED_FIRST_FAILURE'
        response=dict(schema=execution.SCHEMA,status=status,launch_debit=1,selfchecks=3,instance_sha256=instance_sha,
            policy_sha256=POLICY_SHA256,payload_sha256=PAYLOAD_SHA256,source_manifest_sha256=sha(canonical(FROZEN_SOURCE_SHA256)),
            engine_metadata=measured,bootstrap=boot_evidence,ldd_policy=ld_policy,
            final_environment_observed=False,physical_d95_verified=False,execution_ready=False,training_release=False)
        tick();state['stage']='FINAL'
        receipt=root_session.emit(files,canonical(response),canonical(metadata))
        return dict(role='execution',worker_response=response,owned_root=receipt,cleanup_observation=metadata,execution_ready=False)
    except BaseException as exc:
        # Never export exception text, raw environment, locals or an invented cleanup.
        return dict(schema='e137-batch-execution-failure-v1',role='execution',status='STOPPED_FIRST_FAILURE',error_type=type(exc).__name__,launch_debit=state['debit'],
            instance_sha256=instance_sha,owned_root=None,execution_ready=False)
