"""Real role3 source-bound adapter for the reviewed local-phase trust model.

No receipt self-hash, status boolean or JSON file existence authenticates origin.
The local controller must obtain these exact raw records from its reviewed,
host-key-pinned one-use transport phase, then obtain independent review of the
complete role3 code/data/invocation projection. That is the trust boundary, not
a new vendor signature, complete OS proof or per-instance approval ritual.
Import and authenticate() are pure. run() is callable only by a source-verified
bootstrap with an exact config pin; no remote transport is implemented here.
"""
import base64
import copy
import math
import re
import sys
import time

from . import physical_e137_role3_export as core
from . import prospective_generation_process_e113 as process
from . import direct_tessent_acceptance_e104 as direct

sha,canonical,decode = core.sha,core.canonical,core.decode
TRUSTED_CONFIG_SHA256 = None
HOST_PIN = 'SHA256:9+c0w59UN6NMPA6MnG45jtRW63JT9gKLTBxtnnSpJqM'
ARG_MAX = 8192
REQUIRED_LOADED = frozenset(('physical_e137_role3_binding','physical_e137_role3_export',
    'prospective_generation_process_e113','direct_tessent_acceptance_e104','direct_tessent_acceptance_e100',
    'direct_memory_sample_e101','direct_memory_sample_e103','prospective_acceptance_materializer_v1',
    'physical_replay_source_reader_e135'))
PACKAGE_KEYS = {'authority','proposal','original_clock','role2_stdout','role2_stderr','role2_transport','role2_intent'}
POLICY_KEYS = {'schema','authorization_sha256','proposal_sha256','original_clock_sha256','role2_payload_sha256',
    'role2_intent_sha256','role2_stdout_sha256','role2_stderr_sha256','role2_transport_sha256','instance_sha256',
    'policy_sha256','source_manifest_sha256','source_sha256','emitter_source_sha256','runtime_source_sha256','worker_source_sha256'}
RECEIPT_KEYS = {'schema','root','identity','birth_continuity','boot_id','input_bindings','worker_response_sha256',
    'worker_response_scope','worker_source_scope','cleanup_evidence_sha256','cleanup_observer_source_sha256',
    'supervisor_identity','launch_debit','final_snapshot_monotonic','original_remote_deadline','no_future_mutations_proven',
    'wrapper_must_not_write_root_after_snapshot','outer_raw_response_and_transport_join_required','full_role2_transport_authenticated',
    'executor_source_policy_join_required','physical_D95_verified','execution_ready','training_release'}


def require(ok,code):
    if not ok:
        raise ValueError(code)


def _hex(v):
    return type(v) is str and re.fullmatch('[0-9a-f]{64}',v) is not None


def _json(raw,cap):
    require(type(raw) is bytes and 0 < len(raw) <= cap,'ROLE3_BINDING_RAW_BOUND')
    value = decode(raw)
    require(type(value) is dict,'ROLE3_BINDING_JSON_OBJECT')
    return value


def decode_intent_argument(arguments):
    require(type(arguments) is list and len(arguments) == 1 and type(arguments[0]) is str and
        0 < len(arguments[0]) <= ARG_MAX and re.fullmatch('[A-Za-z0-9+/]+={0,2}',arguments[0]),
        'ROLE3_ONE_STRICT_BASE64_ARGUMENT')
    raw = base64.b64decode(arguments[0],validate=True)
    require(base64.b64encode(raw).decode('ascii') == arguments[0] and len(raw) <= 4096,'ROLE3_CANONICAL_INTENT_ARGUMENT')
    return raw


def authenticate(config,intent_raw,reviewed_payload_sha256):
    """Pure exact byte/provenance joins; requires trusted origin outside JSON."""
    require(type(config) is dict and set(config) == {'schema','package','source_policy','role2_packet_review','loaded_source_sha256'} and
        config['schema'] == 'e137-role3-reviewed-phase-inputs-v1' and type(config['package']) is dict and
        set(config['package']) == PACKAGE_KEYS,'ROLE3_EXACT_PHASE_CONFIG')
    package = {}
    for name,encoded in config['package'].items():
        require(type(encoded) is str and len(encoded) <= 4*((6291456+2)//3),'ROLE3_PHASE_ENCODING_BOUND')
        package[name] = base64.b64decode(encoded,validate=True)
    require(sha(package['authority']) == core.APPROVED_AUTH_SHA and sha(package['proposal']) == core.PROPOSAL_SHA,
        'ROLE3_ACTUAL_EXISTING_GRANT')
    authority,proposal = _json(package['authority'],65536),_json(package['proposal'],65536)
    require(authority.get('user_authorization_received') is True and authority.get('approval_source') == 'explicit_user_reply' and
        authority.get('proposal_sha256') == core.PROPOSAL_SHA and authority.get('approved_scope') == proposal.get('scope_if_granted'),
        'ROLE3_EXISTING_SCOPE_JOIN')
    policy_raw = base64.b64decode(config['source_policy'],validate=True)
    review_raw = base64.b64decode(config['role2_packet_review'],validate=True)
    policy,review = _json(policy_raw,65536),_json(review_raw,131072)
    require(set(policy) == POLICY_KEYS and policy['schema'] == 'e137-batch-source-policy-redacted-v1' and
        type(policy['source_sha256']) is dict and 1 <= len(policy['source_sha256']) <= 96 and
        all(type(k) is str and re.fullmatch('[A-Za-z0-9_]+',k) and _hex(v) for k,v in policy['source_sha256'].items()),
        'ROLE3_REDACTED_SOURCE_POLICY_ONLY')
    expected = dict(authorization_sha256=core.APPROVED_AUTH_SHA,proposal_sha256=core.PROPOSAL_SHA,
        original_clock_sha256=sha(package['original_clock']),role2_intent_sha256=sha(package['role2_intent']),
        role2_stdout_sha256=sha(package['role2_stdout']),role2_stderr_sha256=sha(package['role2_stderr']),
        role2_transport_sha256=sha(package['role2_transport']))
    require(all(policy[k] == v for k,v in expected.items()) and
        all(_hex(policy[k]) for k in POLICY_KEYS-{'schema','source_sha256'}),'ROLE3_SOURCE_POLICY_RAW_BINDINGS')
    reviewed = review.get('reviewed')
    require(review.get('status') == 'PASS' and type(reviewed) is dict and
        reviewed.get('payload_sha256') == policy['role2_payload_sha256'] and
        reviewed.get('authorization_sha256') == core.APPROVED_AUTH_SHA and reviewed.get('proposal_sha256') == core.PROPOSAL_SHA and
        reviewed.get('policy_sha256') == policy['policy_sha256'] and reviewed.get('source_sha256') == policy['source_sha256'],
        'ROLE3_EXACT_REVIEWED_ROLE2_PACKET_JOIN')
    require(policy['source_manifest_sha256'] == sha(canonical(policy['source_sha256'])) and
        policy['source_sha256'].get('physical_e137_root_receipt') == policy['emitter_source_sha256'] and
        policy['source_sha256'].get('physical_f_replay_execution_e135') == policy['runtime_source_sha256'] and
        policy['source_sha256'].get('physical_f_replay_execution_e137') == policy['worker_source_sha256'] and
        'physical_e137_batch_execution' in policy['source_sha256'],'ROLE3_SOURCE_MANIFEST_JOIN')
    transport = _json(package['role2_transport'],65536)
    require(type(transport.get('exit_code')) is int and transport['exit_code'] in (0,1) and
        all(transport.get(k) is False for k in ('timeout','overflow','write_failed','threads_incomplete')) and
        transport.get('remote_termination_verified') is False and package['role2_stderr'] == b'' and
        type(transport.get('stdout_bytes')) is int and transport['stdout_bytes'] == len(package['role2_stdout']) and
        transport.get('stdout_sha256') == sha(package['role2_stdout']) and type(transport.get('stderr_bytes')) is int and
        transport['stderr_bytes'] == 0 and transport.get('stderr_sha256') == sha(b''),'ROLE3_GENUINE_PHASE_RAW_TRANSPORT_JOIN')
    intent = _json(package['role2_intent'],4096)
    core._intent(package['role2_intent'],'execution',policy['role2_payload_sha256'])
    third = _json(intent_raw,4096)
    require(_hex(reviewed_payload_sha256) and third.get('payload_sha256') == reviewed_payload_sha256,
        'ROLE3_REVIEWED_CODE_PAYLOAD_HASH_REQUIRED')
    core._intent(intent_raw,'readback',third['payload_sha256'])
    raw = _json(package['role2_stdout'],6291456)
    require(set(raw) == {'role','worker_response','owned_root','cleanup_observation','execution_ready'} and
        raw['role'] == 'execution' and raw['execution_ready'] is False and type(raw['owned_root']) is dict,
        'ROLE3_QUALIFIED_BATCH_FINAL_RESPONSE_REQUIRED')
    response,receipt,cleanup = raw['worker_response'],raw['owned_root'],raw['cleanup_observation']
    require(type(response) is dict and response.get('schema') == 'physical-f-clean-replay-execution-e137-v1' and
        response.get('status') in ('OBSERVED_PENDING_SCIENTIFIC_AUDIT','STOPPED_FIRST_FAILURE') and
        type(response.get('launch_debit')) is int and response['launch_debit'] in (0,1) and
        response.get('instance_sha256') == policy['instance_sha256'] and response.get('policy_sha256') == policy['policy_sha256'] and
        response.get('payload_sha256') == policy['role2_payload_sha256'] and
        response.get('source_manifest_sha256') == policy['source_manifest_sha256'] and
        all(response.get(k) is False for k in ('physical_d95_verified','execution_ready','training_release')),
        'ROLE3_EXACT_SOURCE_DERIVED_WORKER_RESPONSE')
    require(type(cleanup) is dict and cleanup.get('cleaned') is True and type(cleanup.get('returncode')) is int and
        'cleanup_error' in cleanup and cleanup['cleanup_error'] is None,'ROLE3_ACTUAL_VERIFIED_CLEANUP_REQUIRED')
    require(set(receipt) == RECEIPT_KEYS and receipt['schema'] == 'e137-final-registered-root-receipt-v1' and
        receipt['root'] == core.ROOT and receipt['worker_response_sha256'] == sha(canonical(response)) and
        receipt['cleanup_evidence_sha256'] == sha(canonical(cleanup)) and
        receipt['worker_response_scope'] == 'EXACT_WORKER_RESULT_BEFORE_RECEIPT_EMBEDDING' and
        receipt['worker_source_scope'] == 'PINNED_PRIVATE_SERVICES_PROVIDER_NOT_ENTIRE_EXECUTOR_CLOSURE' and
        receipt['cleanup_observer_source_sha256'] == policy['source_sha256']['physical_e137_batch_execution'] and
        type(receipt['launch_debit']) is int and receipt['launch_debit'] == response['launch_debit'] and
        all(receipt[k] is False for k in ('no_future_mutations_proven','full_role2_transport_authenticated',
            'physical_D95_verified','execution_ready','training_release')) and
        all(receipt[k] is True for k in ('wrapper_must_not_write_root_after_snapshot',
            'outer_raw_response_and_transport_join_required','executor_source_policy_join_required')),
        'ROLE3_SOURCE_REVIEWED_FINAL_ROOT_RECEIPT')
    core._file_identity(receipt['identity'],0,directory=True)
    require(receipt['birth_continuity'] == {k:receipt['identity'][k] for k in ('st_dev','st_ino','st_uid','st_mode')},
        'ROLE3_REGISTERED_BIRTH_CONTINUITY_JOIN')
    bindings = dict(authorization_sha256=core.APPROVED_AUTH_SHA,clock_sha256=sha(package['original_clock']),
        role2_intent_sha256=sha(package['role2_intent']),role2_payload_sha256=policy['role2_payload_sha256'],
        worker_spec_sha256=policy['instance_sha256'],runtime_source_sha256=policy['runtime_source_sha256'],
        worker_source_sha256=policy['worker_source_sha256'],emitter_source_sha256=policy['emitter_source_sha256'])
    require(receipt['input_bindings'] == bindings,'ROLE3_EXACT_REGISTERED_INSTANCE_BINDINGS')
    clock_namespace = dict(vars(core),AUTH_SHA256=core.APPROVED_AUTH_SHA)
    import types
    clock = types.FunctionType(core._clock.__code__,clock_namespace)(package['original_clock'])
    require(receipt['boot_id'] == clock['boot_id'] and receipt['original_remote_deadline'] == clock['end'] and
        type(receipt['final_snapshot_monotonic']) in (int,float) and math.isfinite(receipt['final_snapshot_monotonic']) and
        clock['start'] <= receipt['final_snapshot_monotonic'] < clock['end'],'ROLE3_ORIGINAL_REMOTE_INSTANCE_CLOCK')
    owner = receipt['supervisor_identity']
    require(type(owner) is dict and set(owner) == {'pid','startticks','uid'} and all(type(v) is int for v in owner.values()) and
        owner['pid'] > 1 and owner['startticks'] > 0 and owner['uid'] == 1047,'ROLE3_REAL_SUPERVISOR_IDENTITY_JOIN')
    package['role3_intent'] = intent_raw
    return dict(package=package,policy=policy,root_identity=copy.deepcopy(receipt['identity']),boot_id=clock['boot_id'],
        role3_payload_sha256=third['payload_sha256'],clock=clock,
        trust_scope='REVIEWED_PHASE_PRODUCER_PLUS_PINNED_SSH_CHANNEL_NOT_JSON_SELF_AUTHENTICATION')


def run(config_raw,intent_raw,bootstrap_started,reviewed_payload_sha256):
    """Install real source-reviewed callbacks only after exact bootstrap admission."""
    source_pin = globals().get('__source_sha256__')
    require(_hex(source_pin) and _hex(TRUSTED_CONFIG_SHA256) and type(config_raw) is bytes and
        len(config_raw) <= 10*1048576 and sha(config_raw) == TRUSTED_CONFIG_SHA256,'ROLE3_VERIFIED_BOOTSTRAP_CONFIG_REQUIRED')
    config = decode(config_raw)
    loaded = config.get('loaded_source_sha256')
    require(type(loaded) is dict and REQUIRED_LOADED <= set(loaded) and len(loaded) <= 96 and
        loaded.get('physical_e137_role3_binding') == source_pin and
        all(type(name) is str and re.fullmatch('[A-Za-z0-9_]+',name) and _hex(pin) and
            getattr(sys.modules.get('src.data.'+name),'__source_sha256__',None) == pin
            for name,pin in loaded.items()),'ROLE3_COMPLETE_VERIFIED_SOURCE_LOADER')
    admitted = authenticate(config,intent_raw,reviewed_payload_sha256)  # No FS/proc/clock before this proof.
    package,policy = admitted['package'],admitted['policy']
    require(core._USED is False,'ROLE3_SINGLE_FRESH_CORE')
    require(type(bootstrap_started) in (int,float) and math.isfinite(bootstrap_started) and bootstrap_started >= 0 and
        bootstrap_started <= time.monotonic() < bootstrap_started+60,'ROLE3_BOOTSTRAP_READ_DEADLINE')
    # Construct monitor only after source/raw/owned-root proof; no child launch.
    domain = direct.Descendants()
    def auth(raw_package):
        require(raw_package == package,'ROLE3_EXACT_EMBEDDED_RAW_PACKAGE')
        return dict(schema='e137-authenticated-role2-owned-root-context-v1',root=core.ROOT,
            identity=admitted['root_identity'],boot_id=admitted['boot_id'],authorization_sha256=core.APPROVED_AUTH_SHA,
            original_clock_sha256=sha(package['original_clock']),role2_stdout_sha256=sha(package['role2_stdout']),
            role2_stderr_sha256=sha(package['role2_stderr']),role2_transport_sha256=sha(package['role2_transport']),
            role2_intent_sha256=sha(package['role2_intent']),role2_payload_sha256=policy['role2_payload_sha256'],
            role3_intent_sha256=sha(intent_raw),role3_payload_sha256=admitted['role3_payload_sha256'])
    def boot():return process._boot_id()
    def monotonic():
        now = time.monotonic()
        require(bootstrap_started <= now < bootstrap_started+60,'ROLE3_BOOTSTRAP_READ_DEADLINE')
        return now
    def utc():return time.time()
    def sample():
        children = domain.sample()
        return dict(rss_swap_bytes=domain.peak,children=len(children))
    callbacks = dict(authenticate=auth,boot=boot,monotonic=monotonic,utc=utc,sample=sample)
    for fn in callbacks.values():fn.__source_sha256__ = source_pin
    core.AUTH_SHA256 = core.APPROVED_AUTH_SHA
    core.ORIGINAL_CLOCK_SHA256 = sha(package['original_clock'])
    core.ROLE2_STDOUT_SHA256,core.ROLE2_STDERR_SHA256 = sha(package['role2_stdout']),sha(package['role2_stderr'])
    core.ROLE2_TRANSPORT_SHA256,core.ROLE2_INTENT_SHA256 = sha(package['role2_transport']),sha(package['role2_intent'])
    core.ROLE2_PAYLOAD_SHA256 = policy['role2_payload_sha256']
    core.ROLE3_INTENT_SHA256,core.ROLE3_PAYLOAD_SHA256 = sha(intent_raw),admitted['role3_payload_sha256']
    core.CAPABILITY_PINS = {name:source_pin for name in callbacks}
    core.ROLE2_AUTHENTICATOR,core.BOOT_READER,core.MONOTONIC_READER,core.UTC_READER,core.RESOURCE_GUARD = auth,boot,monotonic,utc,sample
    return core.collect(package)


def execute_payload(config_raw,arguments,output,bootstrap_started,reviewed_payload_sha256):
    """One final JSON only; failure prefix is never passed off as complete."""
    try:
        result = run(config_raw,decode_intent_argument(arguments),bootstrap_started,reviewed_payload_sha256)
        raw = canonical(result)
        core.validate_result(result,complete=True)
        exit_code = 0
    except BaseException as exc:
        partial = exc.partial_result if isinstance(exc,core.ExportFailure) else None
        if partial is not None:
            core.validate_result(partial,complete=False)
        code = exc.code if isinstance(exc,core.ExportFailure) else 'ROLE3_BINDING_OR_BOOTSTRAP_REJECTED'
        raw = canonical(dict(schema='e137-role3-partial-error-v1',role='readback',error_code=code,
            partial_result=partial,execution_ready=False))
        require(len(raw) <= core.MAX_RESPONSE,'ROLE3_ERROR_FRAME_BOUND')
        exit_code = 1
    # One frame attempt only. A broken/short stdout write must not trigger a
    # second error frame after a partially written normal/partial result.
    require(output.write(raw+b'\n') == len(raw)+1,'ROLE3_OUTPUT_SHORT_WRITE')
    output.flush()
    return exit_code
