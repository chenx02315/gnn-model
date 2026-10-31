"""Default-disabled native E138 assembler; local composition, not a release.

Only independently frozen exact sources/configuration may be loaded. Source
attributes remain consistency claims, not an authenticity boundary against
trusted-code mutation. No transport/controller or real grant is supplied here.
"""
import math
import os
import platform
import time
import types
from . import physical_e138_contract as contract
from . import physical_batch_diagnostics_e138 as diagnostics
from . import direct_tessent_acceptance_e104 as direct
from . import prospective_generation_process_e113 as process
from .physical_runtime_bootstrap_e138 import STAGES as _BOOTSTRAP_STAGES,LITERAL_CODES as _BOOTSTRAP_LITERALS
from .physical_e138_root_receipt import PUBLIC_CODES as _ROOT_PUBLIC_CODES

_ENGINE_PUBLIC_CODES=frozenset(('E138_ENGINE_FREEZE_REQUIRED','E138_ENGINE_ONE_COLLECTION_NO_RETRY',
    'E138_ENGINE_PACKAGE','E138_ENGINE_CONTEXT_PIN','E138_ENGINE_ORIGINAL_CONTEXT',
    'E138_ENGINE_SOURCE_PIN','E138_ENGINE_GUARDS','E138_ENGINE_CLOCK','E138_ENGINE_DEADLINE',
    'E138_ENGINE_RESPONSE_BOUND','ENGINE_VENDOR_CHAIN_MISSING','ENGINE_OBSERVED_BRANCH_NOT_VIABLE'))

require,sha,canonical,decode=contract.require,contract.sha,contract.canonical,contract.decode
ROOT=contract.ROOT
AUTH_SHA256=PROPOSAL_SHA256=POLICY_SHA256=PAYLOAD_SHA256=None
FROZEN_INPUT_SHA256=FROZEN_SOURCE_SHA256=None
_USED=False
COMPONENTS=dict(capture='physical_replay_capture_e138',runtime='physical_e138_runtime_primitives',
    bootstrap='physical_runtime_bootstrap_e138',collector='physical_engine_evidence_e138',
    binding='physical_e138_dependency_binding',roots='physical_e138_root_receipt',
    recipe='physical_f_replay_recipe_e138')
ORIGINS=dict(storage='prospective_generation_storage_e118',sampler='physical_engine_evidence_e137',
    selector='physical_engine_selector_e137',stil='physical_stil_dependencies_e137')
INPUT_SOURCES=dict(runtime_source='physical_f_replay_execution_e135',
    worker_source='physical_e138_runtime_primitives',bootstrap_source='physical_runtime_bootstrap_e138',
    collector_source='physical_engine_evidence_e138',root_receipt_source='physical_e138_root_receipt')


def admission(package,source_bodies):
    f=contract.FROZEN
    require(not _USED and all(contract._hex(v) for v in (AUTH_SHA256,PROPOSAL_SHA256,POLICY_SHA256,PAYLOAD_SHA256)) and
        AUTH_SHA256!=contract.OLD_AUTH_SHA256 and type(FROZEN_INPUT_SHA256) is dict and
        type(FROZEN_SOURCE_SHA256) is dict and type(f) is dict and
        f.get('authorization_sha256')==AUTH_SHA256 and f.get('proposal_sha256')==PROPOSAL_SHA256 and
        f.get('policy_sha256')==POLICY_SHA256 and f.get('payload_sha256')==PAYLOAD_SHA256 and
        f.get('input_sha256')==FROZEN_INPUT_SHA256 and f.get('source_sha256')==FROZEN_SOURCE_SHA256,
        'E138_ASSEMBLER_FROZEN_MANIFEST_REQUIRED')
    admitted=contract.admit(package)
    needed=set(COMPONENTS.values())|set(ORIGINS.values())|set(INPUT_SOURCES.values())|{
        'physical_e138_batch_assembler','physical_e138_contract'}
    require(needed<=set(FROZEN_SOURCE_SHA256) and
        globals().get('__source_sha256__')==FROZEN_SOURCE_SHA256['physical_e138_batch_assembler'],
        'E138_ASSEMBLER_COMPLETE_SOURCE_ROSTER')
    require(type(source_bodies) is dict and set(source_bodies)==set(FROZEN_SOURCE_SHA256) and
        all(type(raw) is bytes and 0<len(raw)<=262144 and sha(raw)==FROZEN_SOURCE_SHA256[name]
            for name,raw in source_bodies.items()) and sum(map(len,source_bodies.values()))<=8388608,
        'E138_ASSEMBLER_EXACT_SOURCE_BYTES')
    require(all(package[key]==source_bodies[name] for key,name in INPUT_SOURCES.items()),
        'E138_ASSEMBLER_INPUT_SOURCE_CROSSJOIN')
    return admitted


def _private(raw,name):
    module=types.ModuleType('src.data._e138_assembled_'+name);module.__package__='src.data'
    exec(compile(raw,'<e138-frozen-'+name+'>','exec'),module.__dict__)
    module.__source_sha256__=sha(raw)
    return module


def _components(source_bodies):
    modules={key:_private(source_bodies[name],key) for key,name in COMPONENTS.items()}
    # Explicitly bind the private graph, never change imported module globals.
    modules['roots'].worker=modules['runtime']
    modules['collector'].binding=modules['binding']
    needed=set(modules['bootstrap'].SOURCE_PINS)|set(modules['capture'].DEPENDENCY_SHA256)|{
        getattr(modules['runtime'].legacy,name).__name__.rsplit('.',1)[1]
        for name in modules['runtime'].HELPER_PINS}
    needed.add('physical_f_replay_recipe_e135_r2')
    require(needed<=set(FROZEN_SOURCE_SHA256),'E138_ASSEMBLER_HELPER_SOURCE_ROSTER')
    require(all(FROZEN_SOURCE_SHA256[name]==pin for name,pin in modules['capture'].DEPENDENCY_SHA256.items()),
        'E138_ASSEMBLER_CAPTURE_DEPENDENCY_PIN_DRIFT')
    return modules


def _publish_evidence(files,tick,name,raw):
    tick();result=files.publish(name,raw,check=False);tick()
    return result


def _launch(environment,runtime,selector):
    env=dict(environment,HOME=ROOT+'/work',TMPDIR=ROOT+'/work',LANG='C',LC_ALL='C')
    body=dict(schema=runtime.legacy.launch_base.SCHEMA,
        argv=[selector.LAUNCHER,'-shell','-license_wait','5','-log',ROOT+'/tool.log','-dofile',ROOT+'/code/replay.tcl'],
        cwd=ROOT+'/work',env=env,effective_envelope_sha256=sha(canonical(dict(policy=POLICY_SHA256,root=ROOT))),
        environment_sha256=sha(canonical(env)),environment_profile_authenticated=False,execution_authorized=False,execution_ready=False)
    body['launch_spec_sha256']=sha(canonical(body));runtime.validate_launch(body)
    return body


def _ldd_policy(measured,environment,selector):
    chosen=measured['classification']['selected'];ld=environment.get('LD_LIBRARY_PATH','')
    for role in ('mgls','engine'):
        if role in chosen:
            lib=selector.ROOT+'/lnx-x86/lib'+chosen[role]['width']
            if not ld:ld=lib
            elif lib not in ld:ld=lib+':'+ld
    require(sha(ld.encode('utf-8'))==measured['classification']['pre_ldd_library_path_sha256'],'BATCH_VENDOR_LD_ORDER')
    fallback=selector.ROOT+'/lnx-x86/lib'+chosen['engine']['width']
    return dict(policy='UNCHANGED_LAUNCHER_SOURCE_BOUNDED_TRANSFORMS_NO_EXTRA_PROBE',
        pre_ldd_sha256=sha(ld.encode('utf-8')),replacement_sha256=sha(fallback.encode('utf-8')),
        final_environment_observed=False,ldd_behavior_verified=False,full_os_library_authentication=False)


def _bootstrap_failure(metadata):
    """Closed public FAILED receipt only; never copy arbitrary evidence data."""
    keys=('schema','status','stage_attempted','error_code','reviewed_literal_code',
        'values_disclosed','bootstrap_children','output_bytes','output_sha256',
        'output_metadata_measured','execution_ready')
    try:
        if type(metadata) is not dict or set(metadata)!=set(keys):return None
        if not all(type(metadata[key]) is str for key in
                ('schema','status','stage_attempted','error_code','output_sha256')):return None
        stage=metadata['stage_attempted'];literal=metadata['reviewed_literal_code']
        if not (metadata['schema']=='e138-private-runtime-bootstrap-v1' and metadata['status']=='FAILED' and
                stage in _BOOTSTRAP_STAGES and metadata['error_code']=='E138_BOOTSTRAP_'+stage+'_FAILED' and
                (literal is None or type(literal) is str and literal in _BOOTSTRAP_LITERALS) and
                metadata['values_disclosed'] is False and metadata['execution_ready'] is False and
                type(metadata['bootstrap_children']) is int and 0<=metadata['bootstrap_children']<=1 and
                type(metadata['output_bytes']) is int and 0<=metadata['output_bytes']<=65536 and
                contract._hex(metadata['output_sha256']) and type(metadata['output_metadata_measured']) is bool):return None
        if not metadata['output_metadata_measured'] and (metadata['output_bytes']!=0 or
                metadata['output_sha256']!=sha(b'')):return None
        return {key:metadata[key] for key in keys}
    except BaseException:
        # A hostile malformed object cannot add new public diagnostics.
        return None


def _failure(diagnostic,exc,failure_context=None):
    value=diagnostic.failure(exc)
    bootstrap_failure=None
    if value['stage_attempted']=='BOOTSTRAP' and type(failure_context) is dict:
        bootstrap_failure=_bootstrap_failure(failure_context.get('bootstrap'))
    component_failure=None
    if type(failure_context) is dict:
        candidate=failure_context.get('component_failure')
        if (type(candidate) is dict and set(candidate)=={'component','code'} and
                type(candidate['component']) is str and type(candidate['code']) is str and len(candidate['code'])<=96):
            allowed=(_ENGINE_PUBLIC_CODES if candidate['component']=='ENGINE_COLLECTION' else
                _ROOT_PUBLIC_CODES|{'ROOT_RECEIPT_CAPABILITY_OR_IO_FAILED'} if candidate['component']=='ROOT_RECEIPT' else ())
            if candidate['component']==value['stage_attempted'] and candidate['code'] in allowed:
                component_failure=dict(candidate)
    response=dict(schema='physical-f-clean-replay-execution-e138-v1',status='STOPPED_FIRST_FAILURE',
        launch_debit=value['launch_debit'],instance_sha256=value['instance_sha256'],diagnostic=value,
        bootstrap_failure=bootstrap_failure,
        component_failure=component_failure,
        attempt_consumed=_USED,physical_d95_verified=False,execution_ready=False,training_release=False)
    return dict(role='execution',worker_response=response,owned_root=None,cleanup_observation=None,execution_ready=False)


def execute(package,source_bodies,connection_start):
    global _USED
    diagnostic=diagnostics.DiagnosticState()
    failure_context={'bootstrap':None}
    try:
        admission(package,source_bodies)
        _USED=True
        modules=_components(source_bodies)
        return _execute(package,source_bodies,connection_start,modules,diagnostic,failure_context)
    except BaseException as exc:
        return _failure(diagnostic,exc,failure_context)
def _execute(package,source_bodies,connection_start,modules,diagnostic,failure_context):
    capture,runtime,private_bootstrap,collector,binding,root_module,recipe_module=(
        modules[key] for key in ('capture','runtime','bootstrap','collector','binding','roots','recipe'))
    clock=runtime.package_clock(package['original_clock'],AUTH_SHA256,PROPOSAL_SHA256,sha(package['original_clock']))
    capture.AUTH_SHA,capture.PROPOSAL_SHA=AUTH_SHA256,PROPOSAL_SHA256
    capture.check_authority(package['authority'],package['proposal'])
    role1=decode(package['role1_response'])
    require(type(role1) is dict and role1.get('role')=='capture' and role1.get('execution_ready') is False,
        'E138_ASSEMBLER_ROLE1_SCHEMA')
    observed=capture.validate_receipt(canonical(role1['capture']))
    require(role1['boot_id']==clock['boot_id'] and role1['remote_start_monotonic']==clock['remote_start_monotonic'] and
        sha(canonical(observed))==clock['initial_response_sha256'],'E138_ASSEMBLER_ROLE1_CLOCK_JOIN')
    intent=decode(package['role2_intent'])
    require(type(intent) is dict and intent==dict(role='execution',attempt_consumed=True,role_index=2,
        connections_max=3,automatic_retries=0,payload_sha256=PAYLOAD_SHA256) and
        all(type(intent[k]) is int for k in ('role_index','connections_max','automatic_retries')),
        'E138_ASSEMBLER_CONSUMED_ROLE2')
    recipe=recipe_module.build_candidate(package['incremental'],package['parent_helper'])
    binding.FREEZE=dict(authorization_sha256=AUTH_SHA256,proposal_sha256=PROPOSAL_SHA256,
        adapter_source_sha256=FROZEN_SOURCE_SHA256[COMPONENTS['binding']])
    derived=binding.bind(source_bodies[ORIGINS['selector']],source_bodies[ORIGINS['stil']],
        package['authority'],package['proposal'])
    selector,dependencies=derived['selector'],derived['stil']
    diagnostic.checkpoint('HOST_CLOCK')
    require(type(connection_start) in (int,float) and math.isfinite(connection_start) and
        clock['remote_start_monotonic']<=connection_start<clock['monotonic_end'] and
        platform.node() == 'bupt-vncs2' and os.getuid() == 1047 and os.sys.platform.startswith('linux') and
        platform.machine() == 'x86_64','BATCH_FIXED_HOST_PLATFORM')
    require(process._boot_id() == clock['boot_id'],'BATCH_ORIGINAL_BOOT')
    end=min(clock['monotonic_end'],connection_start+2400)
    domain=direct.Descendants()
    phase=['ACTIVE']
    last=[None,None]
    import datetime
    epoch=datetime.datetime.strptime(clock['remote_utc_sample'],'%Y-%m-%dT%H:%M:%S.%f%z').timestamp()
    utc_end=min(clock['utc_end'],epoch+end-clock['remote_clock_sample_monotonic'])
    def guard():
        limit=end if phase[0] == 'EVIDENCE' else end-10
        utc_limit=utc_end if phase[0] == 'EVIDENCE' else utc_end-10
        now,utc=time.monotonic(),time.time()
        require(runtime._number(now) and runtime._number(utc) and process._boot_id()==clock['boot_id'] and
            clock['remote_start_monotonic'] <= connection_start <= now < limit and utc < utc_limit and
            (last[0] is None or last[0]<=now) and (last[1] is None or last[1]<=utc) and
            abs((utc-epoch)-(now-clock['remote_clock_sample_monotonic']))<=5,'BATCH_ORIGINAL_DEADLINE')
        last[:]=[now,utc]
        domain.sample();require(type(domain.peak) is int and 0<=domain.peak <= 536870912,'BATCH_SAMPLED_MEMORY')
        require(time.monotonic()<limit and time.time()<utc_limit,'BATCH_ORIGINAL_DEADLINE')
    guard()
    context=canonical(dict(role='execution',authorization_sha256=AUTH_SHA256,boot_id=clock['boot_id'],
        package_start=clock['remote_start_monotonic'],package_end=clock['monotonic_end'],connection_start=connection_start,utc_end=clock['utc_end'],root=ROOT,phase=contract.PHASE))
    diagnostic.checkpoint('BOOTSTRAP')
    private_bootstrap.AUTH_SHA256=AUTH_SHA256;private_bootstrap.PROPOSAL_SHA256=PROPOSAL_SHA256;private_bootstrap.CONTEXT_SHA256=sha(context);private_bootstrap.EXPECTED_BOOT_ID=clock['boot_id']
    require(private_bootstrap.E112_SHA256==sha(package['e112']),'E138_ASSEMBLER_E112_ORIGIN_PIN')
    boot_evidence={}
    failure_context['bootstrap']=boot_evidence
    private_environment=private_bootstrap.bootstrap(dict(authority=package['authority'],proposal=package['proposal'],context=context,e112=package['e112'],
        worker_source=package['parent_worker_source'],profile_source=package['profile_source']),domain,guard,dict(authorization_sha256=AUTH_SHA256,proposal_sha256=PROPOSAL_SHA256,
        context_sha256=sha(context),expected_boot_id=clock['boot_id'],root=ROOT,phase=contract.PHASE),boot_evidence)
    diagnostic.checkpoint('LAUNCH_SPEC')
    environment=private_environment.environment();launch=_launch(environment,runtime,selector)
    diagnostic.checkpoint('ENGINE_COLLECTION')
    plan=selector.build_plan(package['functions'],package['shell'],launch['env'],launch['argv'],
        system=platform.system(),machine=platform.machine())
    collector.FREEZE=dict(authorization_sha256=AUTH_SHA256,proposal_sha256=PROPOSAL_SHA256,
        context_sha256=sha(context),adapter_source_sha256=FROZEN_SOURCE_SHA256[COMPONENTS['collector']])
    try:
        measured=collector.collect(dict(authority=package['authority'],proposal=package['proposal'],context=context),
            source_bodies[ORIGINS['sampler']],source_bodies[ORIGINS['selector']],clock['boot_id'],
            plan,guard,time.monotonic,time.time)
    except BaseException as exc:
        if type(exc) is ValueError and len(exc.args)==1 and type(exc.args[0]) is str and exc.args[0] in _ENGINE_PUBLIC_CODES:
            failure_context['component_failure']=dict(component='ENGINE_COLLECTION',code=exc.args[0])
        raise
    sampler=_private(source_bodies[ORIGINS['sampler']],'finite_sampler')
    sampler.selector=selector;sampler.collect=None
    ld_policy=_ldd_policy(measured,launch['env'],selector)
    closure=[dict(path=path,bytes=row['identity']['st_size'],sha256=row['sha256'],identity=row['identity'])
        for path,row in measured['files'].items() if row['state'] == 'PRESENT' and row['whole_file_hashed']]
    diagnostic.checkpoint('INSTANCE_BUILD')
    spec=dict(schema=runtime.SCHEMA,connection_start_monotonic=connection_start,launch=launch,inputs=observed,execution_closure=closure,
        policy_sha256=POLICY_SHA256,payload_sha256=PAYLOAD_SHA256,source_manifest_sha256=sha(canonical(FROZEN_SOURCE_SHA256)),
        original_clock_sha256=sha(package['original_clock']),code_sha256=dict(replay=recipe['sha256'],helper=recipe['baseline_expectations_sha256']))
    # This is a consistency digest of actual RAM state, NOT a new permission.
    spec_raw=canonical(spec);instance_sha=sha(spec_raw)
    diagnostic.instance_constructed(instance_sha)
    diagnostic.checkpoint('ROOT_SERVICES')
    state=dict(stage='WRITING',debit=0,observation=None)
    source_pin=globals().get('__source_sha256__')
    def tagged(fn):fn.__source_sha256__=source_pin;return fn
    @tagged
    def boot_reader():return process._boot_id()
    @tagged
    def mono_reader():return time.monotonic()
    @tagged
    def utc_reader():return time.time()
    @tagged
    def cleanup_observer(files,cleanup_raw,response_raw,bindings):
        require(state['stage'] == 'FINAL' and state['observation'] is not None and
            decode(cleanup_raw) == state['observation'] and state['observation'].get('cleaned') is True and
            state['observation'].get('launch_attempted') is True,'BATCH_REAL_FINAL_OBSERVATION')
        process._check_worker(domain)
        require(not domain.snapshot(),'BATCH_ACTIVE_DESCENDANTS_AFTER_CLEANUP')
        return dict(schema='e138-supervisor-final-cleanup-observation-v1',root=ROOT,boot_id=boot_reader(),
            cleanup_observation_sha256=sha(cleanup_raw),worker_response_sha256=sha(response_raw),
            clock_sha256=sha(package['original_clock']),role2_intent_sha256=sha(package['role2_intent']),
            owner_identity=dict(pid=domain.pid,startticks=domain.identity[1],uid=os.getuid()),active_descendant_pids=[],
            pending_root_writes=0,launch_debit=state['debit'])
    for key,value in dict(AUTH_SHA256=AUTH_SHA256,PROPOSAL_SHA=PROPOSAL_SHA256,
        STORAGE_SOURCE_SHA256=sha(source_bodies[ORIGINS['storage']]),CLOCK_SHA256=sha(package['original_clock']),ROLE2_INTENT_SHA256=sha(package['role2_intent']),
        ROLE2_PAYLOAD_SHA256=PAYLOAD_SHA256,WORKER_SPEC_SHA256=instance_sha,RUNTIME_SOURCE_SHA256=sha(package['runtime_source']),
        WORKER_SOURCE_SHA256=sha(package['worker_source']),TRUSTED_SELF_SOURCE_SHA256=sha(package['root_receipt_source']),
        CAPABILITY_PINS={k:source_pin for k in ('cleanup','boot','monotonic','utc')},CLEANUP_OBSERVER=cleanup_observer,
        BOOT_READER=boot_reader,MONOTONIC_READER=mono_reader,UTC_READER=utc_reader).items():setattr(root_module,key,value)
    runtime.FACTORY_FREEZE=dict(authorization_sha256=AUTH_SHA256,proposal_sha256=PROPOSAL_SHA256,
        origin_source_sha256=sha(package['runtime_source']),adapter_source_sha256=sha(package['worker_source']),
        effective_root=ROOT)
    root_session=root_module.tracked_services(dict(authority=package['authority'],proposal=package['proposal'],
        original_clock=package['original_clock'],role2_intent=package['role2_intent'],worker_spec=spec_raw,
        runtime_source=package['runtime_source'],worker_source=package['worker_source'],
        storage_source=source_bodies[ORIGINS['storage']]))
    services=root_session.services
    persist_initial,monitor=services._storage(end)
    active=[False]
    def tick():
        guard()
        if active[0]:
            sample=monitor.sample()['sampled_named_bytes']
            require(type(sample) is int and 0<=sample<=8589934592,'BATCH_SAMPLED_STORAGE')
        guard()
    def recheck_installed():
        # Reobserve absent alternatives and Tcl directories as well as full
        # file hashes, so a different fallback cannot appear before launch.
        budget=[0]
        fresh={path:sampler.sample_path(path,tick,budget) for path in sampler.PATHS}
        require(fresh == measured['files'],'BATCH_INSTALLED_SOURCE_OR_SELECTION_DRIFT')
    # Rehash fixed sources before the first sidecar/ROOT write.
    def source_recheck():
        # This is role2 revalidation, not a new role1 read connection. Reuse
        # the unchanged role2 guard, never invent another 60-second deadline.
        tick()
        pattern=capture.source.read_file(capture.source.FILES[0],tick)
        inputs=[capture.inventory.read_input(pin,tick) for pin in capture.INPUT_PINS]
        tree=capture.inventory.inventory(tick)
        fresh=dict(observed,pattern=pattern,inputs=inputs,tree=tree)
        capture.validate_receipt(canonical(fresh))
        require(fresh==observed,'E138_ASSEMBLER_FRESH_SOURCE_DRIFT')
        tick()
    source_recheck()
    diagnostic.checkpoint('INITIAL_INTENT')
    guard()
    parent,name=ROOT.rsplit('/',1)
    parent_fd=services.io._directory(parent)
    try:
        try:
            os.stat(name,dir_fd=parent_fd,follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError('E138_ASSEMBLER_ROOT_MUST_NOT_EXIST')
    finally:
        os.close(parent_fd)
    persist_initial(canonical(dict(schema=runtime.SCHEMA,instance_sha256=instance_sha,launch_debit=0,
        original_package_deadline=clock['monotonic_end'],connection_deadline=end)))
    guard()
    files=services.Files(tick)
    try:
        diagnostic.checkpoint('ROOT_CREATE')
        os.close(files.directory(ROOT,True))
        for name in ('journal','code','work','inputs','snapshots'):os.close(files.directory(ROOT+'/'+name,True))
        active[0]=True
        diagnostic.checkpoint('SOURCE_COPY')
        source_recheck()
        targets=dict(pattern='tester.stil',library='cells.lib',F_basic='F.basic')
        for row in [observed['pattern']]+observed['inputs']:
            files.copy(row['path'],ROOT+'/inputs/'+targets[row['role']],row['bytes'],row['sha256'],row['identity'])
        services._tree_copy(files,capture.TREE_PIN['path'],dict(observed['tree'],files=capture.TREE_PIN['files'],directories=capture.TREE_PIN['directories']))
        source_recheck()
        diagnostic.checkpoint('RECIPE_WRITE')
        for name,raw in (('replay.tcl',recipe['body']),('expected_baseline.tcl',recipe['baseline_expectations_body'])):
            fd=files.directory(ROOT+'/code')
            try:services.io._publish(fd,name,raw)
            finally:os.close(fd)
        files.publish('recipe_artifacts.json',canonical(dict(replay_sha256=recipe['sha256'],helper_sha256=recipe['baseline_expectations_sha256'])))
        allowed=[dict(path=ROOT+'/inputs/'+targets[r['role']],bytes=r['bytes'],sha256=r['sha256']) for r in [observed['pattern']]+observed['inputs']]
        allowed += [dict(path=ROOT+'/tsdb/'+r['relative'],bytes=r['bytes'],sha256=r['sha256']) for r in observed['tree']['rows'] if r['kind']=='file']
        allowed.sort(key=lambda row:row['path'])
        diagnostic.checkpoint('DEPENDENCIES')
        dep=dependencies.verify(ROOT+'/inputs/tester.stil',allowed,tick)
        files.publish('dependency_validation.json',canonical(dep))
        diagnostic.checkpoint('SELFCHECKS')
        receipts=services.run_selftests(dict(root=ROOT,end=end,sample=tick,persist=lambda n,r:files.publish(n,r,
            check=not n.endswith(('_observation.json','_output.log')))),domain)
        require(len(receipts)==3 and tuple(r['case'] for r in receipts)==services.SELFTEST_CASES and
            all(r['passed'] is True and r['cleaned'] is True for r in receipts),'BATCH_THREE_SELFCHECKS')
        diagnostic.checkpoint('PRELAUNCH_RECHECK')
        source_recheck()
        require(dependencies.verify(ROOT+'/inputs/tester.stil',allowed,tick)==dep,'E138_ASSEMBLER_STIL_DRIFT')
        recheck_installed()
        diagnostic.checkpoint('LAUNCH_DEBIT')
        tick();state['debit']=1
        diagnostic.consume_launch()
        files.publish('launch_intent.json',canonical(dict(instance_sha256=instance_sha,launch_debit=1,automatic_retries=0)))
        def on_spawn(value):files.publish('spawn_identity.json',canonical(value));return True
        session_end=min(end-10,time.monotonic()+1800,time.monotonic()+max(0,clock['utc_end']-time.time()-10))
        diagnostic.checkpoint('TOOL_OBSERVATION')
        observed_tool=services._observer(launch,session_end,domain,[16777216],on_spawn,services.SimpleMonitor(tick))
        # Stop scientific work. Only bounded raw evidence/ownership publication
        # may use the final reserve; the original hard deadline is unchanged.
        phase[0]='EVIDENCE'
        diagnostic.checkpoint('RAW_PUBLICATION')
        output=observed_tool['output'];require(type(output) is bytes and len(output)<=16777216,'E138_ASSEMBLER_TOOL_OUTPUT_BOUND')
        metadata={k:v for k,v in observed_tool.items() if k!='output'}
        _publish_evidence(files,tick,'observation.json',canonical(dict(metadata,output_bytes=len(output),output_sha256=sha(output))))
        _publish_evidence(files,tick,'stdout.log',output)
        _publish_evidence(files,tick,'stdout_ack.json',canonical(dict(bytes=len(output),sha256=sha(output))))
        state['observation']=metadata
        status='OBSERVED_PENDING_SCIENTIFIC_AUDIT' if (metadata.get('failure') is None and metadata.get('cleaned') is True and
            type(metadata.get('returncode')) is int and metadata['returncode']==0) else 'STOPPED_FIRST_FAILURE'
        response=dict(schema=runtime.SCHEMA,status=status,launch_debit=1,selfchecks=3,instance_sha256=instance_sha,
            policy_sha256=POLICY_SHA256,payload_sha256=PAYLOAD_SHA256,source_manifest_sha256=sha(canonical(FROZEN_SOURCE_SHA256)),
            engine_metadata=measured,bootstrap=boot_evidence,ldd_policy=ld_policy,
            final_environment_observed=False,physical_d95_verified=False,execution_ready=False,training_release=False)
        tick();state['stage']='FINAL'
        diagnostic.checkpoint('ROOT_RECEIPT')
        try:
            receipt=root_session.emit(files,canonical(response),canonical(metadata))
        except BaseException as exc:
            if type(exc) is root_module.RootReceiptFailure and len(exc.args)==1 and type(exc.args[0]) is str and exc.args[0] in (_ROOT_PUBLIC_CODES|{'ROOT_RECEIPT_CAPABILITY_OR_IO_FAILED'}):
                failure_context['component_failure']=dict(component='ROOT_RECEIPT',code=exc.args[0])
            raise
        return dict(role='execution',worker_response=response,owned_root=receipt,cleanup_observation=metadata,execution_ready=False)
    except BaseException as exc:
        return _failure(diagnostic,exc,failure_context)
