"""Default-disabled E137 worker integration, not a controller or runtime grant.

The source-bundle deployer and actual executable/environment closure are not
provided here. Independent future freezes must fill every None gate first.
"""
import base64
import copy
import datetime
import math
import os
import platform
import re
import stat
import time
import types

from . import physical_replay_capture_e137 as capture
from . import physical_f_replay_recipe_e135_r2 as recipe

legacy = recipe.legacy
io,process,direct = legacy.io,legacy.process,legacy.direct
require,sha,canonical,decode = capture.require,capture.sha,capture.canonical,capture.decode
SCHEMA = 'physical-f-clean-replay-execution-e137-v1'
CLOCK_SCHEMA = 'physical-f-clean-replay-package-clock-e137-v1'
ROOT = '/temp/jiangchuanc/multimode_ate_physical_f_replay_e135_recipe_r2'
AUTH_SHA = REVIEWED_SPEC_SHA256 = INITIAL_CLOCK_SHA256 = EXECUTION_CLOSURE_SHA256 = None
DEPENDENCY_VALIDATOR = DEPENDENCY_VALIDATOR_SHA256 = None  # Actual reviewed STIL verifier is missing.
_USED = False
SOURCE_PINS = {
    'physical_f_replay_execution_e135':'83fa927774b59d43ad838d09333f6ad787edfed27cd52043f9fcda4dc4b9f85f',
    'physical_f_replay_recipe_e135_r2':'63ab7aba869d9d755488cb8aaa4e5629b595d9e1672b1db35458e565771a62d2',
    'physical_replay_capture_e137':'5d911a9df834b1e155f1bd200261ffb078be98bd0420b31b39d71140ef500e76',
    'prospective_generation_storage_e118':'0045cb1c6ba4b81cf4f1d2d6c8723c44d69bb48d3b357c8c95e8a217c14597bb',
    'prospective_generation_process_e113':'6b1922de253550b3d4091f11186d9447867662c445e46fdc47801f3c340411f6',
    'prospective_acceptance_materializer_v1':'a04127c07227814e331ede4268c6f8d5df4def4d7041c0c69ec048378216cab9',
    'direct_tessent_acceptance_e104':'6b7961e8238b2676a9c90a69a1c554be7238daa789de2e41a1e820044e17b190',
}
SPEC_KEYS = {'schema','authority_base64','proposal_base64','package_clock_base64','capture_base64',
    'legacy_runtime_source_base64','incremental_base64','parent_helper_base64','code_base64','launch','execution_closure'}


def _b64(value,cap):
    require(type(value) is str and len(value) <= 4*((cap+2)//3),'E137_BASE64_BOUND')
    raw = base64.b64decode(value,validate=True)
    require(len(raw) <= cap,'E137_DECODED_BOUND')
    return raw


def package_clock(raw):
    """Pure first-call clock parsing; actual host/boot comparison is later."""
    require(INITIAL_CLOCK_SHA256 is not None and type(raw) is bytes and len(raw) <= 4096 and
        sha(raw) == INITIAL_CLOCK_SHA256,'E137_FIRST_CALL_CLOCK_PIN')
    value = decode(raw)
    keys = {'schema','authorization_sha256','proposal_sha256','reader_payload_sha256','initial_response_sha256',
        'start_file_sha256','boot_id','remote_start_monotonic','remote_deadline_monotonic','remote_utc_sample',
        'remote_clock_sample_monotonic','local_utc_start','local_utc_deadline','local_monotonic_start',
        'local_monotonic_deadline','local_clock_domain'}
    require(type(value) is dict and set(value) == keys and value['schema'] == CLOCK_SCHEMA and
        value['authorization_sha256'] == AUTH_SHA and value['proposal_sha256'] == capture.PROPOSAL_SHA,
        'E137_NEW_PACKAGE_CLOCK_SCHEMA')
    for key in ('reader_payload_sha256','initial_response_sha256','start_file_sha256'):
        require(type(value[key]) is str and re.fullmatch('[0-9a-f]{64}',value[key]) is not None,'E137_CLOCK_HASH')
    require(type(value['boot_id']) is str and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value['boot_id']) is not None,'E137_CLOCK_BOOT')
    for key in ('remote_start_monotonic','remote_deadline_monotonic','remote_clock_sample_monotonic',
            'local_monotonic_start','local_monotonic_deadline'):
        require(type(value[key]) in (int,float) and math.isfinite(value[key]) and value[key] >= 0,'E137_CLOCK_NUMBER')
    utc = lambda key:datetime.datetime.strptime(value[key],'%Y-%m-%dT%H:%M:%S.%f%z').timestamp()
    require(value['remote_deadline_monotonic'] == value['remote_start_monotonic']+3600 and
        value['local_monotonic_deadline'] == value['local_monotonic_start']+3600 and
        utc('local_utc_deadline')-utc('local_utc_start') == 3600 and
        value['remote_start_monotonic'] <= value['remote_clock_sample_monotonic'] < value['remote_start_monotonic']+60,
        'E137_ORIGINAL_3600_CLOCK')
    domain = value['local_clock_domain']
    require(type(domain) is dict and set(domain) == {'host','clock'} and
        all(type(v) is str and 0 < len(v) <= 512 for v in domain.values()),'E137_LOCAL_CLOCK_DOMAIN')
    remote_utc_end = utc('remote_utc_sample')+value['remote_deadline_monotonic']-value['remote_clock_sample_monotonic']
    return dict(value,monotonic_end=value['remote_deadline_monotonic'],utc_end=min(remote_utc_end,utc('local_utc_deadline')))


def validate_launch(launch):
    base = legacy.launch_base
    require(type(launch) is dict and set(launch) == base.LAUNCH_KEYS and launch['schema'] == base.SCHEMA and
        all(launch[k] is False for k in ('environment_profile_authenticated','execution_authorized','execution_ready')),
        'E137_LAUNCH_NOT_AUTHORITY')
    require(launch['argv'] == [base.recipe.identities.LAUNCHER,'-shell','-license_wait','5','-log',ROOT+'/tool.log',
        '-dofile',ROOT+'/code/replay.tcl'] and launch['cwd'] == ROOT+'/work','E137_FIXED_LAUNCH')
    base._environment(launch['env'],launch['cwd'])
    require(sha(canonical(launch['env'])) == launch['environment_sha256'] and
        sha(canonical({k:v for k,v in launch.items() if k != 'launch_spec_sha256'})) == launch['launch_spec_sha256'],
        'E137_LAUNCH_HASH')


def check_spec(spec):
    """No filesystem/proc/clock IO; all gates are exact future freezes, not bools."""
    require(all(type(pin) is str and re.fullmatch('[0-9a-f]{64}',pin) is not None for pin in
        (AUTH_SHA,REVIEWED_SPEC_SHA256,INITIAL_CLOCK_SHA256,EXECUTION_CLOSURE_SHA256,DEPENDENCY_VALIDATOR_SHA256)),
        'E137_UNFROZEN_AUTH_SPEC_CLOCK_CLOSURE_DEPENDENCIES')
    require(callable(DEPENDENCY_VALIDATOR) and getattr(DEPENDENCY_VALIDATOR,'__source_sha256__',None) ==
        DEPENDENCY_VALIDATOR_SHA256,'E137_REVIEWED_DEPENDENCY_VERIFIER_MISSING')
    require(type(spec) is dict and set(spec) == SPEC_KEYS and spec['schema'] == SCHEMA and
        len(canonical(spec)) <= 8388608 and sha(canonical(spec)) == REVIEWED_SPEC_SHA256,'E137_EXACT_REVIEWED_SPEC')
    require(capture.AUTH_SHA == AUTH_SHA,'E137_CAPTURE_AUTH_SOURCE_NOT_FROZEN')
    authority,proposal = _b64(spec['authority_base64'],65536),_b64(spec['proposal_base64'],65536)
    require(sha(authority) == AUTH_SHA,'E137_AUTHORITY_BYTES')
    capture.check_authority(authority,proposal)
    require(decode(proposal)['scope_if_granted']['new_remote_root'] == ROOT == recipe.ROOT,'E137_REVIEWED_ROOT')
    raw_capture = _b64(spec['capture_base64'],capture.BOUNDS['response_bytes'])
    observed = capture.validate_receipt(raw_capture)
    clock = package_clock(_b64(spec['package_clock_base64'],4096))
    require(sha(raw_capture) == clock['initial_response_sha256'],'E137_FIRST_CALL_CAPTURE_JOIN')
    runtime_source = _b64(spec['legacy_runtime_source_base64'],131072)
    require(sha(runtime_source) == SOURCE_PINS['physical_f_replay_execution_e135'],'E137_FROZEN_RUNTIME_BYTECODE')
    candidate = recipe.build_candidate(_b64(spec['incremental_base64'],65536),_b64(spec['parent_helper_base64'],65536))
    require(type(spec['code_base64']) is dict and set(spec['code_base64']) == {'replay.tcl','expected_baseline.tcl'},'E137_TWO_ACTUAL_TCL_ARTIFACTS')
    code = {name:_b64(raw,65536) for name,raw in spec['code_base64'].items()}
    require(code['replay.tcl'] == candidate['body'] and sha(code['replay.tcl']) == candidate['sha256'] and
        code['expected_baseline.tcl'] == candidate['baseline_expectations_body'] and
        sha(code['expected_baseline.tcl']) == candidate['baseline_expectations_sha256'],'E137_ACTUAL_REBASED_RECIPE_HELPER_HASH')
    validate_launch(spec['launch'])
    closure = spec['execution_closure']
    require(type(closure) is list and 2 <= len(closure) <= 64 and sha(canonical(closure)) == EXECUTION_CLOSURE_SHA256,
        'E137_FULL_EXECUTION_CLOSURE_NOT_FROZEN')
    paths = set()
    for item in closure:
        require(type(item) is dict and set(item) == {'path','bytes','sha256','identity'} and
            legacy.launch_base._absolute(item['path']) and item['path'].startswith('/cad/mentor/tessent2021_2/') and
            item['path'] not in paths and type(item['bytes']) is int and 0 < item['bytes'] <= 2147483648 and
            type(item['sha256']) is str and re.fullmatch('[0-9a-f]{64}',item['sha256']) is not None,'E137_FIXED_ENGINE_CLOSURE_RECORD')
        paths.add(item['path'])
        info = item['identity']
        require(type(info) is dict and set(info) == set(capture.source.FIELDS) and
            all(type(n) is int and n >= 0 for n in info.values()) and info['st_size'] == item['bytes'] and
            stat.S_ISREG(info['st_mode']) and info['st_nlink'] == 1,
            'E137_ENGINE_INITIAL_IDENTITY')
    require(spec['launch']['argv'][0] in paths,'E137_LAUNCHER_IN_FROZEN_CLOSURE')
    require(sum(item['bytes'] for item in closure) <= 4294967296,'E137_EXECUTION_CLOSURE_TOTAL_BYTES')
    modules = (legacy,recipe,capture,legacy.storage,process,io,direct)
    require(all(getattr(module,'__source_sha256__',None) == SOURCE_PINS[module.__name__.rsplit('.',1)[1]]
        for module in modules),'E137_VERIFIED_SOURCE_LOADER_REQUIRED')
    return dict(clock=clock,capture=observed,code=code,runtime_source=runtime_source,launch=copy.deepcopy(spec['launch']),
        closure=copy.deepcopy(closure))


def private_services(raw):
    """Inert-load fixed bytecode: classes AND functions share private new globals."""
    require(type(raw) is bytes and sha(raw) == SOURCE_PINS['physical_f_replay_execution_e135'],'E137_PRIVATE_SOURCE_PIN')
    module = types.ModuleType('src.data._e137_private_runtime')
    module.__package__ = 'src.data'
    exec(compile(raw,'<e137-private-frozen-runtime>','exec'),module.__dict__)
    module.ROOT,module.AUTH_SHA256 = ROOT,AUTH_SHA
    module.REVIEWED_SPEC_SHA256 = module.INITIAL_CLOCK_SHA256 = None
    module.COMMANDS_VERIFIED,module._USED = False,True
    module.worker = module.package_clock = None  # Never reopen either old entry.
    # The observer's existing strict launch validator reads the private ROOT.
    return module


def _source_recheck(observed,tick):
    rows = [capture.source.read_file(capture.source.FILES[0],tick)]
    rows += [capture.inventory.read_input(pin,tick) for pin in capture.INPUT_PINS]
    require(rows == [observed['pattern']]+observed['inputs'],'E137_CURRENT_SOURCE_IDENTITY_HASH_CHANGED')


def _closure_recheck(items,services,tick):
    for item in items:
        tick()
        parent,name = item['path'].rsplit('/',1)
        fd = io._directory(parent)
        sink = None
        try:
            parent_identity = capture.source.identity(os.fstat(fd))
            named = os.stat(name,dir_fd=fd,follow_symlinks=False)
            require(capture.source.identity(named) == item['identity'] and stat.S_ISREG(named.st_mode) and
                named.st_nlink == 1,'E137_ENGINE_BEFORE_IDENTITY')
            sink = os.open('/dev/null',os.O_WRONLY)
            stream = services._stream_io(tick)
            stream['MAX_FILE'] = 2147483648  # Private helper namespace; streaming sink, not RAM body.
            result = stream['_read_at'](fd,name,[0],sink,expected_bytes=item['bytes'],max_bytes=2147483648)
            require(result[2] == item['sha256'] and capture.source.identity(os.stat(name,dir_fd=fd,follow_symlinks=False)) ==
                item['identity'],'E137_ENGINE_FRESH_HASH_IDENTITY')
            os.close(sink)
            sink = None
            require(capture.source.identity(os.fstat(fd)) == parent_identity,'E137_ENGINE_HELD_PARENT_CHANGED')
            fresh = io._directory(parent)
            try:
                require(capture.source.identity(os.fstat(fresh)) == parent_identity and
                    capture.source.identity(os.fstat(fd)) == parent_identity,'E137_ENGINE_PARENT_REPLACED')
            finally:
                os.close(fresh)
        finally:
            if sink is not None:
                os.close(sink)
            os.close(fd)
        tick()


def _dependencies(observed,tick):
    """Interface only: no actual STIL verifier or completeness proof is provided."""
    require(callable(DEPENDENCY_VALIDATOR) and DEPENDENCY_VALIDATOR_SHA256 is not None and
        getattr(DEPENDENCY_VALIDATOR,'__source_sha256__',None) == DEPENDENCY_VALIDATOR_SHA256,
        'E137_REVIEWED_DEPENDENCY_VERIFIER_MISSING')
    names = dict(pattern='tester.stil',library='cells.lib',F_basic='F.basic')
    allowed = [dict(path=ROOT+'/inputs/'+names[r['role']],bytes=r['bytes'],sha256=r['sha256'])
        for r in [observed['pattern']]+observed['inputs']]
    allowed += [dict(path=ROOT+'/tsdb/'+r['relative'],bytes=r['bytes'],sha256=r['sha256'])
        for r in observed['tree']['rows'] if r['kind'] == 'file']
    allowed.sort(key=lambda row:row['path'])
    tick()
    receipt = DEPENDENCY_VALIDATOR(ROOT+'/inputs/tester.stil',copy.deepcopy(allowed),tick)
    require(type(receipt) is dict and len(canonical(receipt)) <= 65536 and receipt.get('status') == 'PASS' and
        receipt.get('validator_source_sha256') == DEPENDENCY_VALIDATOR_SHA256 and
        receipt.get('pattern_sha256') == observed['pattern']['sha256'] and
        receipt.get('exact_allowlist_sha256') == sha(canonical(allowed)),
        'E137_STIL_DEPENDENCIES_NOT_VERIFIED')
    tick()
    return receipt


def worker(spec):
    global _USED
    prepared = check_spec(spec)  # Default rejection before all FS/proc/time IO.
    require(not _USED,'E137_ONE_WORKER_ZERO_RETRY')
    _USED = True
    require(platform.node() == 'bupt-vncs2' and os.getuid() == 1047 and os.sys.platform.startswith('linux'),'E137_HOST_UID')
    clock = prepared['clock']
    require(process._boot_id() == clock['boot_id'],'E137_ORIGINAL_BOOT')
    now = time.monotonic()
    package_end = clock['monotonic_end']
    require(clock['remote_start_monotonic'] <= now < package_end-10 and time.time() < clock['utc_end'],'E137_ORIGINAL_PACKAGE_EXPIRED')
    connection_end = min(package_end,now+2400)
    services = private_services(prepared['runtime_source'])
    domain = direct.Descendants()
    # Storage receipt END is the original package end, never the shorter connection.
    persist_initial,monitor = services._storage(package_end)
    active = [False]
    def tick():
        require(time.monotonic() < connection_end-10 and time.time() < clock['utc_end'],'E137_CONNECTION_PACKAGE_DEADLINE')
        domain.sample()
        require(domain.peak <= 536870912,'E137_SAMPLED_MEMORY_STOP')
        if active[0]:
            require(monitor.sample()['sampled_named_bytes'] <= 8589934592,'E137_SAMPLED_STORAGE_STOP')
        require(time.monotonic() < connection_end-10 and time.time() < clock['utc_end'],'E137_CONNECTION_PACKAGE_DEADLINE')
    tick()
    persist_initial(canonical(dict(schema=SCHEMA,spec_sha256=REVIEWED_SPEC_SHA256,launch_debit=0,
        original_package_deadline=package_end,connection_deadline=connection_end)))
    files = services.Files(tick)
    os.close(files.directory(ROOT,True))
    for name in ('journal','code','work','inputs','snapshots'):
        os.close(files.directory(ROOT+'/'+name,True))
    active[0] = True
    _source_recheck(prepared['capture'],tick)
    targets = dict(pattern='tester.stil',library='cells.lib',F_basic='F.basic')
    for row in [prepared['capture']['pattern']]+prepared['capture']['inputs']:
        files.copy(row['path'],ROOT+'/inputs/'+targets[row['role']],row['bytes'],row['sha256'],row['identity'])
    tree = dict(prepared['capture']['tree'],files=capture.TREE_PIN['files'],directories=capture.TREE_PIN['directories'])
    services._tree_copy(files,capture.TREE_PIN['path'],tree)
    _source_recheck(prepared['capture'],tick)
    for name,raw in sorted(prepared['code'].items()):
        tick()
        fd = files.directory(ROOT+'/code')
        try:
            io._publish(fd,name,raw)
        finally:
            os.close(fd)
    files.publish('recipe_artifacts.json',canonical({name:dict(bytes=len(raw),sha256=sha(raw)) for name,raw in prepared['code'].items()}))
    files.publish('dependency_validation.json',canonical(_dependencies(prepared['capture'],tick)))
    def persist_case(name,raw):
        return files.publish(name,raw,check=not name.endswith(('_observation.json','_output.log')))
    receipts = services.run_selftests(dict(root=ROOT,end=connection_end,sample=tick,persist=persist_case),domain)
    require(type(receipts) is list and len(receipts) == 3 and tuple(r['case'] for r in receipts) == legacy.SELFTEST_CASES and
        all(r['passed'] is True and r['cleaned'] is True and r['authenticated_claim'] is True for r in receipts),'E137_THREE_PROCESS_SELFCHECKS')
    _closure_recheck(prepared['closure'],services,tick)
    tick()
    launch = prepared['launch']
    validate_launch(launch)
    files.publish('launch_intent.json',canonical(dict(schema=SCHEMA,launch_debit=1,automatic_retries=0,
        spec_sha256=REVIEWED_SPEC_SHA256,launch_spec_sha256=launch['launch_spec_sha256'])))
    def on_spawn(identity):
        files.publish('spawn_identity.json',canonical(identity))
        return True
    session_end = min(connection_end,package_end,time.monotonic()+1800,
        time.monotonic()+max(0,clock['utc_end']-time.time()))
    try:
        observed = services._observer(launch,session_end,domain,[16777216],on_spawn,services.SimpleMonitor(tick))
    except BaseException as exc:
        files.publish('observation_exception.json',canonical(dict(error_type=type(exc).__name__,launch_debit=1,
            status='NO_RETRY_NO_FABRICATED_OBSERVATION')),check=False)
        raise
    raw = observed['output']
    metadata = {k:v for k,v in observed.items() if k != 'output'}
    files.publish('observation.json',canonical(dict(metadata,output_bytes=len(raw),output_sha256=sha(raw))),check=False)
    files.publish('stdout.log',raw,check=False)
    files.publish('stdout_ack.json',canonical(dict(bytes=len(raw),sha256=sha(raw))),check=False)
    tick()
    require(observed['failure'] is None and observed['cleaned'] is True and observed['returncode'] == 0,'E137_TOOL_OBSERVATION_REJECTED')
    return dict(schema=SCHEMA,status='OBSERVED_PENDING_FIXED_ARTIFACT_EXPORT_AND_SCIENTIFIC_AUDIT',launch_debit=1,
        selfchecks=3,original_package_deadline=package_end,connection_deadline=connection_end,session_deadline=session_end,
        engine_identity_verified=False,environment_profile_authenticated=False,internal_pattern_count_required_positive=False,
        external_pattern_application_verified=False,physical_d95_verified=False,execution_ready=False,training_release=False)
