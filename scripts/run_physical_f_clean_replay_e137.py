"""Offline E137 role packets and one-use ledger. Engine closure still unresolved.

No connection may start until the complete binder/validator protocol is frozen.
This module does not guess installed engine paths or reopen earlier packages.
"""
import ast
import base64
import datetime
import math
import os
from pathlib import Path
import platform
import re
import time

from src.data import physical_replay_capture_e137 as capture
from src.data import physical_f_replay_execution_e137 as execution

require,sha,canonical,decode = capture.require,capture.sha,capture.canonical,capture.decode
AUTH = 'contracts/physical_f_clean_replay_authorization_e137.json'
AUTH_SHA = '49f000fe45de6cfc029ad8a9c1ead5e09edd24321de6062039d638436cce4969'
PROPOSAL = 'contracts/physical_f_clean_replay_proposal_e137_v1.json'
PHASE = 'v6_e137_clean_F_replay_r1'
RUNTIME_BINDER_SOURCE_SHA256 = DEPENDENCY_VALIDATOR_SHA256 = None
ENGINE_PATH_ALLOWLIST = None
OWNED_ROOT_EMITTER_SHA256 = None  # No reviewed role2 receipt emitter exists yet.
ROLES = ('capture','execution','readback')
REVIEW_KEYS = ('payload_sha256','controller_sha256','source_sha256','authorization_sha256','proposal_sha256','protocol_sha256')
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
    return dict(ready=False,blockers=[
        'EXACT_INSTALLED_ENGINE_PATH_SELECTION_CHAIN_UNKNOWN',
        'SAME_CONNECTION_RUNTIME_BINDER_NOT_IMPLEMENTED_OR_FROZEN',
        'STIL_DEPENDENCY_VALIDATOR_NOT_BOUND'],new_connections=0,execution_ready=False)


def _authority(raw,proposal):
    require(sha(raw) == AUTH_SHA and sha(proposal) == capture.PROPOSAL_SHA,'ACTUAL_E137_GRANT')
    # Call identical pure check bytecode with a private auth namespace; never patch capture globals.
    import types
    namespace = dict(vars(capture),AUTH_SHA=AUTH_SHA)
    check = types.FunctionType(capture.check_authority.__code__,namespace)
    check(raw,proposal)


def prepare(role='capture'):
    require(role in ROLES,'FIXED_ROLE')
    require(role != 'execution','ENGINE_SELECTION_AND_ACK_PROTOCOL_UNRESOLVED')
    from scripts.run_direct_tessent_e104 import PINS
    repo = Path(__file__).resolve().parents[1]
    authority,proposal = (repo/AUTH).read_bytes(),(repo/PROPOSAL).read_bytes()
    _authority(authority,proposal)
    pins = dict(PINS)
    pins.update(execution.SOURCE_PINS)
    pins.update(capture.DEPENDENCY_SHA256)
    rows = []
    for name in SOURCES+('_e137_controller',):
        raw = (Path(__file__) if name == '_e137_controller' else repo/'src/data'/(name+'.py')).read_bytes()
        require(name not in pins or sha(raw) == pins[name],'FROZEN_SOURCE_DRIFT')
        ast.parse(raw.decode('utf-8'),feature_version=(3,6))
        rows.append(dict(name=name,sha256=sha(raw),body=base64.b64encode(raw).decode('ascii')))
    spec = dict(role=role,authority=base64.b64encode(authority).decode('ascii'),proposal=base64.b64encode(proposal).decode('ascii'))
    wire = canonical(dict(sources=rows,spec=spec)).decode('ascii')
    payload = ('import time\nstarted=time.monotonic()\nimport base64,hashlib,json,types,sys\np=json.loads('+repr(wire)+')\n'
        'for name in ("src","src.data"):\n'
        ' m=types.ModuleType(name);m.__path__=[];sys.modules[name]=m\n'
        ' if name=="src.data":sys.modules["src"].data=m\n'
        'for row in p["sources"]:\n'
        ' raw=base64.b64decode(row["body"],validate=True)\n'
        ' if hashlib.sha256(raw).hexdigest()!=row["sha256"]:raise ValueError("SOURCE_SHA")\n'
        ' name="src.data."+row["name"];m=types.ModuleType(name);m.__package__="src.data";sys.modules[name]=m\n'
        ' setattr(sys.modules["src.data"],row["name"],m);exec(compile(raw,"<e137-"+row["name"]+">","exec"),m.__dict__)\n'
        ' m.__source_sha256__=row["sha256"]\n'
        'result=sys.modules["src.data._e137_controller"].remote(p["spec"],started)\n'
        'print(json.dumps(result,sort_keys=True,allow_nan=False),flush=True)\n').encode('ascii')
    ast.parse(payload.decode('ascii'),feature_version=(3,6))
    protocol = dict(role=role,outputs=list(OUTPUTS),roles=ROLES,seconds=3600,first_failure_stops=True,
        runtime_binder=RUNTIME_BINDER_SOURCE_SHA256,validator=DEPENDENCY_VALIDATOR_SHA256,engine_paths=ENGINE_PATH_ALLOWLIST)
    return dict(payload=payload,payload_sha256=sha(payload),controller_sha256=sha(Path(__file__).read_bytes()),
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


def execute(role,review_path,payload_sha):
    """Intentionally denies first connection until the missing full closure exists."""
    plan = prepare(role)
    review = decode(Path(review_path).read_bytes())
    require(review.get('status') == 'PASS' and review.get('reviewed') == {k:plan[k] for k in REVIEW_KEYS} and
        payload_sha == plan['payload_sha256'],'EXACT_ROLE_PACKET_REVIEW')
    require(plan['readiness']['ready'] is True,'WHOLE_PACKAGE_ENGINE_BINDER_VALIDATOR_UNRESOLVED')
    # No reachable transport until a future reviewed implementation closes this gate.
    raise ValueError('ROLE_TRANSPORT_NOT_RELEASED')


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
                utc_start=utc.isoformat(timespec='microseconds'),
                utc_end=(utc+datetime.timedelta(seconds=3600)).isoformat(timespec='microseconds'),
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

    def capture_transport(self,role,helper,payload,cap,validator):
        """Actual one-use transport primitive, not a release for execute()."""
        require(role in ROLES and type(payload) is bytes and callable(validator),'ROLE_TRANSPORT_ARGUMENTS')
        require(not (self.phase/'closed.json').exists(),'FIRST_FAILURE_CLOSED_PACKAGE')
        directory = self.phase/role
        require((directory/'intent.json').is_file(),'DEBIT_BEFORE_TRANSPORT')
        validate_intent(decode((directory/'intent.json').read_bytes()),role,sha(payload))
        from scripts import acceptance_transport_e98 as control
        control.write_new(directory/'transport_consumed.json',control.encode(dict(attempt_consumed=True)))
        first = decode((self.phase/'start.json').read_bytes())
        helper.TIMEOUT = min(50,int(remaining(first)))
        try:
            observed = helper.transport(helper.command('A'),payload,cap)
            self.save_raw(role,observed['stdout'],observed['stderr'],{k:v for k,v in observed.items() if k not in ('stdout','stderr')})
            remaining(first)
            require(type(observed['exit_code']) is int and observed['exit_code'] == 0 and all(observed[k] is False for k in
                ('timeout','overflow','write_failed','threads_incomplete')),'ROLE_TRANSPORT_FAILED')
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
            stdout_sha256=sha(stdout),stderr_sha256=sha(stderr),remote_termination_verified=False)))

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
            remote_sample_monotonic=time.monotonic(),remote_utc_sample=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds'),
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
