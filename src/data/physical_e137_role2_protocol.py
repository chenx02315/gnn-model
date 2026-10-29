"""Bounded role2 protocol coordinator; missing release capabilities deny by default.

Authenticated first-call/role1 loading, source-bundle loading, private runtime
bootstrap and physical instance assembly must be supplied by reviewed code.
This module cannot authenticate a reviewer, a transport or an engine by itself.
"""
import math
import struct
import base64
import types
import sys
from contextlib import contextmanager
from . import physical_engine_ack_e137 as ack
from . import physical_engine_selector_e137 as selector

require,sha,canonical,decode = ack.require,ack.sha,ack.canonical,ack.decode
CAP = 65536
AUTH_SHA256 = None
INSTANCE_ASSEMBLER_SHA256 = None
INSTANCE_ASSEMBLER = None
FIRST_CALL_VERIFIER_SHA256 = None
FIRST_CALL_VERIFIER = None
SELECTOR_SHA256 = 'efcf80e98b4a26051d057320e4dc75882929545fbd42be41be4336a2586d5d73'
ACK_SHA256 = '5132a0f5a611d21507d3cc7df0173bb7fbb46ef3e9d4a69d6c77bc2e29ecabb6'
TRUSTED_BUNDLE_SHA256 = None
TRUSTED_FIRST_CALL_CONTEXT_SHA256 = None
BUNDLE_NAMES = frozenset((
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
    'physical_replay_capture_e137','physical_f_replay_execution_e137','physical_engine_ack_e137',
    'physical_engine_selector_e137','physical_stil_dependencies_e137','physical_e137_role2_protocol'))


@contextmanager
def inert_source_bundle(rows,trusted_manifest_sha256=None):
    """Keep private src modules active for the whole use, restore on any failure.

    Expected manifest SHA must come from the authenticated packet review, not
    from the submitted rows themselves. No authentication of that channel here.
    """
    trusted = TRUSTED_BUNDLE_SHA256 if trusted_manifest_sha256 is None else trusted_manifest_sha256
    require(_hash(trusted),'ROLE2_TRUSTED_BUNDLE_REVIEW_REQUIRED')
    require(type(rows) is list and len(rows) == len(BUNDLE_NAMES),'ROLE2_EXACT_SOURCE_ROSTER')
    names,manifest,decoded,total = set(),[],[],0
    for row in rows:
        require(type(row) is dict and set(row) == {'name','sha256','body'} and row['name'] in BUNDLE_NAMES and
            row['name'] not in names and _hash(row['sha256']) and type(row['body']) is str and len(row['body']) <= 1048576,
            'ROLE2_SOURCE_ROW')
        names.add(row['name'])
        raw = base64.b64decode(row['body'],validate=True)
        total += len(raw)
        require(total <= 4194304 and sha(raw) == row['sha256'],'ROLE2_SOURCE_BYTES')
        decoded.append((row['name'],raw,row['sha256']))
        manifest.append(dict(name=row['name'],sha256=row['sha256']))
    require(names == BUNDLE_NAMES and sha(canonical(manifest)) == trusted,'ROLE2_EXACT_REVIEWED_MANIFEST')
    saved = {k:v for k,v in sys.modules.items() if k == 'src' or k.startswith('src.')}
    try:
        # Do not let forward imports accidentally resolve an old cached child.
        for name in saved:
            del sys.modules[name]
        for name in ('src','src.data'):
            module = types.ModuleType(name);module.__path__=[];sys.modules[name]=module
            if name == 'src.data':sys.modules['src'].data=module
        result = {}
        for name,raw,digest in decoded:
            full = 'src.data.'+name
            module = types.ModuleType(full);module.__package__='src.data'
            sys.modules[full]=module;setattr(sys.modules['src.data'],name,module)
            exec(compile(raw,'<e137-reviewed-'+name+'>','exec'),module.__dict__)
            module.__source_sha256__=digest
            result[name]=module
        yield result
    finally:
        for name in list(sys.modules):
            if name == 'src' or name.startswith('src.'):del sys.modules[name]
        sys.modules.update(saved)


def verify_first_call(package,trusted_context,trusted_context_sha256=None):
    """Pure join to externally frozen role1 raw bytes and original E137 clock.

    Does not reread A or authenticate supplied hashes without external trust.
    """
    from . import physical_replay_capture_e137 as capture
    from . import physical_f_replay_execution_e137 as execution
    trusted = TRUSTED_FIRST_CALL_CONTEXT_SHA256 if trusted_context_sha256 is None else trusted_context_sha256
    require(_hash(trusted) and type(trusted_context) is dict and sha(canonical(trusted_context)) == trusted,
        'ROLE2_TRUSTED_FIRST_CALL_REVIEW_REQUIRED')
    keys = {'authorization_sha256','proposal_sha256','role1_stdout_sha256','clock_sha256','role2_payload_sha256','nonce'}
    require(set(trusted_context) == keys and all(_hash(trusted_context[k]) for k in keys) and
        trusted_context['authorization_sha256'] == '49f000fe45de6cfc029ad8a9c1ead5e09edd24321de6062039d638436cce4969' and
        trusted_context['proposal_sha256'] == capture.PROPOSAL_SHA,'ROLE2_EXACT_FIRST_CALL_CONTEXT')
    require(type(package) is dict and set(package) == {'role1_stdout','package_clock'} and
        type(package['role1_stdout']) is bytes and len(package['role1_stdout']) <= 6291456 and
        type(package['package_clock']) is bytes and len(package['package_clock']) <= 4096 and
        sha(package['role1_stdout']) == trusted_context['role1_stdout_sha256'] and
        sha(package['package_clock']) == trusted_context['clock_sha256'],'ROLE2_FIRST_CALL_RAW_HASHES')
    raw = decode(package['role1_stdout'])
    require(type(raw) is dict and raw.get('role') == 'capture' and raw.get('execution_ready') is False,'ROLE2_ROLE1_SCHEMA')
    namespace = dict(vars(capture),AUTH_SHA=trusted_context['authorization_sha256'])
    types.FunctionType(capture.validate_receipt.__code__,namespace)(canonical(raw['capture']))
    namespace = dict(vars(execution),AUTH_SHA=trusted_context['authorization_sha256'],
        INITIAL_CLOCK_SHA256=trusted_context['clock_sha256'])
    clock = types.FunctionType(execution.package_clock.__code__,namespace)(package['package_clock'])
    require(clock['boot_id'] == raw['boot_id'] and clock['remote_start_monotonic'] == raw['remote_start_monotonic'] and
        clock['initial_response_sha256'] == sha(canonical(raw['capture'])),'ROLE2_ORIGINAL_CAPTURE_CLOCK_JOIN')
    return dict(authorization_sha256=trusted_context['authorization_sha256'],clock_sha256=trusted_context['clock_sha256'],
        role2_payload_sha256=trusted_context['role2_payload_sha256'],nonce=trusted_context['nonce'],
        remote_start=clock['remote_start_monotonic'],remote_end=clock['monotonic_end'],utc_end=clock['utc_end'])


def _hash(value):
    return type(value) is str and ack._hex(value)


def write_frame(stream,raw,tick):
    require(type(raw) is bytes and 0 < len(raw) <= CAP,'ROLE2_FRAME_BOUND')
    view = memoryview(struct.pack('!I',len(raw))+raw)
    while view:
        tick()
        count = stream.write(view[:65536])
        require(type(count) is int and 0 < count <= min(len(view),65536),'ROLE2_FRAME_WRITE')
        view = view[count:]
    stream.flush()


def read_frame(stream,tick,save_raw):
    """save_raw receives complete wire bytes BEFORE JSON or semantic parsing."""
    captured = bytearray()
    def take(count):
        chunks = []
        while count:
            tick()
            raw = stream.read(min(count,65536))
            require(type(raw) is bytes and 0 < len(raw) <= min(count,65536),'ROLE2_SHORT_FRAME')
            captured.extend(raw)
            chunks.append(raw);count -= len(raw)
        return b''.join(chunks)
    try:
        prefix = take(4)
        size = struct.unpack('!I',prefix)[0]
        require(0 < size <= CAP,'ROLE2_FRAME_BOUND')
        raw = take(size)
    except BaseException:
        save_raw(bytes(captured))
        raise
    save_raw(bytes(captured))
    return raw


def _capability(function,pin,code):
    require(_hash(pin) and callable(function) and getattr(function,'__source_sha256__',None) == pin,code)


def decode_frame_bytes(wire):
    """Standalone bounded frame including exact EOF; not a live pipe EOF probe."""
    require(type(wire) is bytes and 4 < len(wire) <= CAP+4,'ROLE2_FRAME_BOUND')
    count = struct.unpack('!I',wire[:4])[0]
    require(0 < count <= CAP and len(wire) == count+4,'ROLE2_FRAME_LENGTH_OR_TRAILING_BYTES')
    return wire[4:]


class Session(object):
    """One in-process attempt. Cross-process debit and authenticated callbacks external."""
    def __init__(self):
        self.used = False

    def run(self,package,now,utc_now,bootstrap,snapshot,emit,receive_review,persist,worker):
        # Never invoke a callback, clock, FS or process before default release gates.
        require(_hash(AUTH_SHA256),'ROLE2_ACTUAL_AUTHORITY_NOT_FROZEN')
        _capability(FIRST_CALL_VERIFIER,FIRST_CALL_VERIFIER_SHA256,'ROLE2_FIRST_CALL_VERIFIER_MISSING')
        _capability(INSTANCE_ASSEMBLER,INSTANCE_ASSEMBLER_SHA256,'ROLE2_INSTANCE_ASSEMBLER_MISSING')
        require(not self.used,'ROLE2_ONE_ATTEMPT_NO_RETRY')
        self.used = True
        clock = FIRST_CALL_VERIFIER(package)
        require(type(clock) is dict and set(clock) == {'authorization_sha256','clock_sha256','role2_payload_sha256',
            'remote_start','remote_end','utc_end','nonce'} and clock['authorization_sha256'] == AUTH_SHA256 and
            all(_hash(clock[k]) for k in ('clock_sha256','role2_payload_sha256','nonce')) and
            all(type(clock[k]) in (int,float) and math.isfinite(clock[k]) for k in ('remote_start','remote_end','utc_end')) and
            clock['remote_end'] == clock['remote_start']+3600,'ROLE2_ORIGINAL_CLOCK')
        start = now()
        connection_end = min(clock['remote_end'],start+2400)
        def tick():
            current,utc = now(),utc_now()
            require(type(current) in (int,float) and math.isfinite(current) and
                clock['remote_start'] <= current < connection_end-10 and
                type(utc) in (int,float) and math.isfinite(utc) and utc < clock['utc_end'],'ROLE2_ORIGINAL_DEADLINE')
        tick()
        persist('role2_intent.json',canonical(dict(clock,connection_end=connection_end,bootstrap_max=1,selfchecks_max=3,
            tool_launches_max=1,automatic_retries=0)))
        # bootstrap must supervise exactly one <=30s/64KiB fixed module child;
        # raw environment values remain ONLY in this RAM mapping.
        environment,bootstrap_metadata = bootstrap(tick)
        require(type(environment) is dict and type(bootstrap_metadata) is dict,'ROLE2_BOOTSTRAP_RESULT')
        require(set(bootstrap_metadata) == {'output_bytes','output_sha256','values_disclosed','bootstrap_children'} and
            type(bootstrap_metadata['output_bytes']) is int and 0 <= bootstrap_metadata['output_bytes'] <= 65536 and
            _hash(bootstrap_metadata['output_sha256']) and bootstrap_metadata['values_disclosed'] is False and
            type(bootstrap_metadata['bootstrap_children']) is int and bootstrap_metadata['bootstrap_children'] == 1,
            'ROLE2_PRIVATE_BOOTSTRAP_METADATA')
        persist('bootstrap_metadata.json',canonical(bootstrap_metadata))
        tick()
        observed = snapshot(tuple(selector.CANDIDATES),tick)
        # Actual IO, UID/type/anchor/hash enforcement belongs to the frozen sampler.
        require(type(observed) is dict and set(observed) <= set(selector.CANDIDATES),'ROLE2_FINITE_SNAPSHOT')
        private_spec,redacted = INSTANCE_ASSEMBLER(package,clock,environment,observed,tick)
        require(type(private_spec) is dict and type(redacted) is bytes and len(redacted) <= CAP,'ROLE2_INSTANCE_BOUND')
        bindings = dict(authorization_sha256=AUTH_SHA256,original_clock_sha256=clock['clock_sha256'],
            role2_payload_sha256=clock['role2_payload_sha256'],instance_sha256=sha(canonical(private_spec)),
            metadata_sha256=sha(redacted),nonce=clock['nonce'],role='execution')
        evidence = ack.make_evidence(bindings)
        persist('redacted_metadata.json',redacted)
        persist('evidence.json',evidence)
        emit(evidence,redacted,tick)
        tick()
        # trusted SHA must originate in authenticated parent review handling,
        # NEVER be calculated here from a self-declared PASS receipt.
        ack_raw,review_raw,trusted_sha = receive_review(tick)
        persist('ack.raw',ack_raw);persist('review.raw',review_raw)
        result = ack.validate_ack(ack_raw,evidence,review_raw,trusted_sha)
        tick()
        persist('ack_binding.json',canonical(result))
        # Controller's persist MUST create these exclusively and durably before release.
        persist('instance_consumed.json',canonical(dict(instance_sha256=bindings['instance_sha256'],
            evidence_sha256=sha(evidence),nonce=clock['nonce'],automatic_retries=0)))
        tick()
        # worker adapter must inert-load frozen source privately, recheck actual
        # instance/source hashes, then use existing 3-selfcheck/one-tool worker.
        return worker(private_spec,clock,connection_end,tick)
