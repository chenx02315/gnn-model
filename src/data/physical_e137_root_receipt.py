"""Default-disabled tracked Files factory and final read-only root snapshot.

Only the private source-verified legacy services namespace is subclassed; old
modules are untouched. A successful exclusive create registers the actual
Files instance, not a copied owned dict. Python closure/registry isolation is
not an unforgeable boundary against a caller allowed to mutate trusted code.

Real supervisor/cleanup observation capability and reviewed bootstrap remain
mandatory and absent by default. The receipt binds pre-embedding worker bytes;
it cannot circularly authenticate the final SSH stream containing itself.
Later independent raw stdout/stderr/transport joins are still required.
No filesystem writes occur during emission. The wrapper must not write ROOT
after the final snapshot, and must serialize only outside that namespace.
"""
import copy
import datetime
import math
import os
import re
import stat
import types
import weakref

from . import physical_f_replay_execution_e137 as worker
from . import prospective_acceptance_materializer_v1 as anchored
from .physical_replay_source_reader_e135 import canonical,decode,identity,sha,FIELDS

ROOT = '/temp/jiangchuanc/multimode_ate_physical_f_replay_e135_recipe_r2'
APPROVED_AUTH_SHA = '49f000fe45de6cfc029ad8a9c1ead5e09edd24321de6062039d638436cce4969'
PROPOSAL_SHA = 'f9b7da390b21c5c3280a7d4688494a3c3315b45091c7657db197b633cfcc4cd9'
LEGACY_RUNTIME_SHA = '83fa927774b59d43ad838d09333f6ad787edfed27cd52043f9fcda4dc4b9f85f'
ANCHOR_SOURCE_SHA = 'a04127c07227814e331ede4268c6f8d5df4def4d7041c0c69ec048378216cab9'
AUTH_SHA256 = CLOCK_SHA256 = ROLE2_INTENT_SHA256 = ROLE2_PAYLOAD_SHA256 = None
WORKER_SPEC_SHA256 = RUNTIME_SOURCE_SHA256 = WORKER_SOURCE_SHA256 = TRUSTED_SELF_SOURCE_SHA256 = None
CAPABILITY_PINS = None
CLEANUP_OBSERVER = BOOT_READER = MONOTONIC_READER = UTC_READER = None
_FACTORY_USED = False
CORE_FIELDS = ('st_dev','st_ino','st_uid','st_mode')


class _Stop(ValueError):
    pass


def _require(ok,code):
    if not ok:
        raise _Stop(code)


def _hex(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None


def _number(value):
    return type(value) in (int,float) and math.isfinite(value) and value >= 0


def _directory_identity(value):
    _require(type(value) is dict and set(value) == set(FIELDS) and
        all(type(n) is int and 0 <= n < 2**64 for n in value.values()) and
        value['st_uid'] == 1047 and stat.S_ISDIR(value['st_mode']) and value['st_nlink'] >= 1,
        'ROOT_RECEIPT_OWNED_DIRECTORY_IDENTITY')
    return value


class RootReceiptFailure(ValueError):
    def __init__(self,code,partial_receipt=None):
        super(RootReceiptFailure,self).__init__(code)
        self.code = code
        self.partial_receipt = partial_receipt


def _gates(package):
    global _FACTORY_USED
    pins = (AUTH_SHA256,CLOCK_SHA256,ROLE2_INTENT_SHA256,ROLE2_PAYLOAD_SHA256,
        WORKER_SPEC_SHA256,RUNTIME_SOURCE_SHA256,WORKER_SOURCE_SHA256,TRUSTED_SELF_SOURCE_SHA256)
    callbacks = dict(cleanup=CLEANUP_OBSERVER,boot=BOOT_READER,monotonic=MONOTONIC_READER,utc=UTC_READER)
    _require(not _FACTORY_USED and all(_hex(v) for v in pins) and AUTH_SHA256 == APPROVED_AUTH_SHA and
        RUNTIME_SOURCE_SHA256 == LEGACY_RUNTIME_SHA and
        globals().get('__source_sha256__') == TRUSTED_SELF_SOURCE_SHA256 and
        getattr(worker,'__source_sha256__',None) == WORKER_SOURCE_SHA256 and
        getattr(anchored,'__source_sha256__',None) == ANCHOR_SOURCE_SHA and
        worker.private_services.__module__ == worker.__name__ and worker.package_clock.__module__ == worker.__name__ and
        type(CAPABILITY_PINS) is dict and set(CAPABILITY_PINS) == set(callbacks) and
        all(_hex(CAPABILITY_PINS[k]) and callable(fn) and getattr(fn,'__source_sha256__',None) == CAPABILITY_PINS[k]
            for k,fn in callbacks.items()),'ROOT_RECEIPT_FROZEN_SOURCE_AUTH_AND_CAPABILITIES_REQUIRED')
    _FACTORY_USED = True
    expected = dict(authority=(AUTH_SHA256,65536),proposal=(PROPOSAL_SHA,65536),original_clock=(CLOCK_SHA256,4096),
        role2_intent=(ROLE2_INTENT_SHA256,4096),worker_spec=(WORKER_SPEC_SHA256,8*1048576),
        runtime_source=(RUNTIME_SOURCE_SHA256,131072),worker_source=(WORKER_SOURCE_SHA256,65536))
    _require(type(package) is dict and set(package) == set(expected),'ROOT_RECEIPT_EXACT_INPUT_BYTES')
    for name,(pin,cap) in expected.items():
        _require(type(package[name]) is bytes and 0 < len(package[name]) <= cap and sha(package[name]) == pin,
            'ROOT_RECEIPT_PINNED_'+name.upper())
    authority,proposal,intent = (decode(package[k]) for k in ('authority','proposal','role2_intent'))
    _require(authority.get('approval_source') == 'explicit_user_reply' and authority.get('user_authorization_received') is True and
        authority.get('proposal_sha256') == PROPOSAL_SHA and authority.get('approved_scope') == proposal.get('scope_if_granted'),
        'ROOT_RECEIPT_EXACT_EXISTING_GRANT')
    _require(type(intent) is dict and set(intent) == {'role','attempt_consumed','role_index','connections_max','automatic_retries','payload_sha256'} and
        intent['role'] == 'execution' and intent['attempt_consumed'] is True and
        type(intent['role_index']) is int and intent['role_index'] == 2 and type(intent['connections_max']) is int and intent['connections_max'] == 3 and
        type(intent['automatic_retries']) is int and intent['automatic_retries'] == 0 and intent['payload_sha256'] == ROLE2_PAYLOAD_SHA256,
        'ROOT_RECEIPT_ACTUAL_CONSUMED_ROLE2_INTENT')
    namespace = dict(vars(worker),AUTH_SHA=AUTH_SHA256,INITIAL_CLOCK_SHA256=CLOCK_SHA256,
        capture=types.SimpleNamespace(PROPOSAL_SHA=PROPOSAL_SHA))
    parse_clock = types.FunctionType(worker.package_clock.__code__,namespace)
    return parse_clock(package['original_clock'])


def tracked_services(package):
    """One private services module plus emit method; genuine registration path.

    Adapter must use session.services.Files in the actual worker, retain that
    actual instance, and call session.emit only after all writes and cleanup.
    Merely copying legacy Files.owned into another instance cannot register it.
    """
    clock = _gates(package)  # Default denial precedes callbacks, FS or clock.
    services = worker.private_services(package['runtime_source'])
    base_class = services.Files
    registry = weakref.WeakKeyDictionary()
    creating = [None]
    # Legacy directory() closes _mkdir's child then reopens by path. Capture
    # that actual child identity before close, otherwise a replacement in the
    # gap could be mistaken for the exclusively created directory.
    original_io = services.io
    private_io = types.ModuleType(original_io.__name__)
    private_io.__dict__.update(vars(original_io))
    private_io.__derived_from_sha256__ = getattr(original_io,'__source_sha256__',None)
    private_io.__source_sha256__ = None  # Not identical raw module bytes.
    original_mkdir = original_io._mkdir
    def registered_mkdir(parent,name):
        fd = original_mkdir(parent,name)
        try:
            if creating[0] is not None:
                _require(name == ROOT.rsplit('/',1)[1] and creating[0]['born'] is None,
                    'ROOT_RECEIPT_EXACT_CREATION_OPERATION')
                creating[0]['born'] = _directory_identity(identity(os.fstat(fd)))
            return fd
        except BaseException:
            os.close(fd)
            raise
    private_io._mkdir = registered_mkdir
    services.io = private_io  # Never mutate the imported anchored module.
    last = [None,None]
    emitted = [False]
    binding = dict(authorization_sha256=AUTH_SHA256,clock_sha256=CLOCK_SHA256,
        role2_intent_sha256=ROLE2_INTENT_SHA256,role2_payload_sha256=ROLE2_PAYLOAD_SHA256,
        worker_spec_sha256=WORKER_SPEC_SHA256,runtime_source_sha256=RUNTIME_SOURCE_SHA256,
        worker_source_sha256=WORKER_SOURCE_SHA256,emitter_source_sha256=TRUSTED_SELF_SOURCE_SHA256)
    def tick(deadline=None):
        now,utc,boot = MONOTONIC_READER(),UTC_READER(),BOOT_READER()
        _require(_number(now) and _number(utc) and boot == clock['boot_id'] and
            clock['remote_start_monotonic'] <= now < clock['monotonic_end'] and utc < clock['utc_end'] and
            (deadline is None or now < deadline) and
            (last[0] is None or last[0] <= now) and (last[1] is None or last[1] <= utc),
            'ROOT_RECEIPT_ORIGINAL_BOOT_CLOCK_OR_EXPIRY')
        epoch = datetime.datetime.strptime(clock['remote_utc_sample'],'%Y-%m-%dT%H:%M:%S.%f%z').timestamp()
        _require(abs((utc-epoch)-(now-clock['remote_clock_sample_monotonic'])) <= 5,
            'ROOT_RECEIPT_CLOCK_DOMAIN_MISMATCH')
        last[:] = [now,utc]
        return now
    class TrackedFiles(base_class):
        def directory(self,path,create=False):
            _require(not emitted[0],'ROOT_RECEIPT_WRITES_AFTER_FINAL_EMISSION_FORBIDDEN')
            tick()
            if path == ROOT and create:
                _require(self not in registry and not registry,'ROOT_RECEIPT_ONE_EXCLUSIVE_CREATION')
                _require(creating[0] is None,'ROOT_RECEIPT_NONREENTRANT_CREATION')
                creating[0] = dict(instance=self,born=None)
            active_creation = creating[0] if path == ROOT and create else None
            try:
                fd = super(TrackedFiles,self).directory(path,create)
            except BaseException:
                if active_creation is not None:
                    creating[0] = None
                raise
            try:
                if path == ROOT and create:
                    born = _directory_identity(identity(os.fstat(fd)))
                    _require(active_creation is not None and active_creation['instance'] is self and
                        active_creation['born'] == born,'ROOT_RECEIPT_CREATION_REOPEN_IDENTITY_CHANGED')
                    _require(type(self.owned) is dict and self.owned.get(ROOT) == (born['st_dev'],born['st_ino']),
                        'ROOT_RECEIPT_ACTUAL_FILES_OWNED_JOIN')
                    registry[self] = dict(birth=born,core={k:born[k] for k in CORE_FIELDS})
                tick()
                return fd
            except BaseException:
                os.close(fd)
                raise
            finally:
                if active_creation is not None:
                    creating[0] = None
    services.Files = TrackedFiles  # Only this private source-derived module.
    class Session(object):
        def __init__(self):
            self.services = services

        def emit(self,files,worker_response_bytes,cleanup_evidence_bytes):
            partial = None
            fd = fresh = None
            try:
                _require(not emitted[0],'ROOT_RECEIPT_SINGLE_FINAL_EMISSION')
                emitted[0] = True
                # Same actual registered object, not an owned/status boolean.
                _require(isinstance(files,TrackedFiles) and files in registry,'ROOT_RECEIPT_GENUINE_REGISTERED_FILES_REQUIRED')
                born = registry[files]
                _require(type(files.owned) is dict and files.owned.get(ROOT) ==
                    (born['core']['st_dev'],born['core']['st_ino']),'ROOT_RECEIPT_BIRTH_OWNED_CONTINUITY')
                partial = dict(schema='e137-unqualified-root-receipt-diagnostic-v1',root=ROOT,
                    input_bindings=dict(binding),qualified_final_root_receipt=False,
                    final_root_identity=None,outer_transport_authenticated=False)
                _require(type(worker_response_bytes) is bytes and 0 < len(worker_response_bytes) <= 1048576 and
                    type(cleanup_evidence_bytes) is bytes and 0 < len(cleanup_evidence_bytes) <= 65536,
                    'ROOT_RECEIPT_BOUNDED_RESULT_AND_CLEANUP_BYTES')
                response,observation = decode(worker_response_bytes),decode(cleanup_evidence_bytes)
                _require(type(response) is dict and response.get('schema') == worker.SCHEMA and
                    type(response.get('launch_debit')) is int and response['launch_debit'] in (0,1),
                    'ROOT_RECEIPT_EXACT_WORKER_RESULT_AND_DEBIT')
                _require(type(observation) is dict and observation.get('cleaned') is True and
                    'cleanup_error' in observation and observation['cleanup_error'] is None and
                    type(observation.get('returncode')) is int and type(observation.get('launch_attempted')) is bool and
                    (response['launch_debit'] == 0 or observation['launch_attempted'] is True),
                    'ROOT_RECEIPT_RAW_CLEANUP_OBSERVATION_REQUIRED')
                started = tick()
                deadline = min(clock['monotonic_end'],started+5)
                proof = CLEANUP_OBSERVER(files,cleanup_evidence_bytes,worker_response_bytes,dict(binding))
                proof_keys = {'schema','root','boot_id','cleanup_observation_sha256','worker_response_sha256',
                    'clock_sha256','role2_intent_sha256','owner_identity','active_descendant_pids','pending_root_writes','launch_debit'}
                _require(type(proof) is dict and set(proof) == proof_keys and proof['schema'] == 'e137-supervisor-final-cleanup-observation-v1' and
                    proof['root'] == ROOT and proof['boot_id'] == clock['boot_id'] and
                    proof['cleanup_observation_sha256'] == sha(cleanup_evidence_bytes) and
                    proof['worker_response_sha256'] == sha(worker_response_bytes) and
                    proof['clock_sha256'] == CLOCK_SHA256 and proof['role2_intent_sha256'] == ROLE2_INTENT_SHA256 and
                    type(proof['active_descendant_pids']) is list and proof['active_descendant_pids'] == [] and
                    type(proof['pending_root_writes']) is int and proof['pending_root_writes'] == 0 and
                    type(proof['launch_debit']) is int and proof['launch_debit'] == response['launch_debit'],
                    'ROOT_RECEIPT_SOURCE_BOUND_FINAL_CLEANUP_REQUIRED')
                owner = proof['owner_identity']
                _require(type(owner) is dict and set(owner) == {'pid','startticks','uid'} and
                    all(type(v) is int for v in owner.values()) and owner['pid'] > 1 and owner['startticks'] > 0 and owner['uid'] == 1047,
                    'ROOT_RECEIPT_SUPERVISOR_IDENTITY_REQUIRED')
                tick(deadline)
                fd = anchored._directory(ROOT)
                before = _directory_identity(identity(os.fstat(fd)))
                _require({k:before[k] for k in CORE_FIELDS} == born['core'],'ROOT_RECEIPT_BIRTH_IDENTITY_CHANGED')
                fresh = anchored._directory(ROOT)
                after = _directory_identity(identity(os.fstat(fresh)))
                _require(before == after == identity(os.fstat(fd)),'ROOT_RECEIPT_FINAL_SNAPSHOT_UNSTABLE')
                tick(deadline)
                _require(before == identity(os.fstat(fd)) == identity(os.fstat(fresh)),
                    'ROOT_RECEIPT_FINAL_SNAPSHOT_CHANGED_DURING_GUARD')
                result = dict(schema='e137-final-registered-root-receipt-v1',root=ROOT,identity=before,
                    birth_continuity={k:born['core'][k] for k in CORE_FIELDS},boot_id=clock['boot_id'],
                    input_bindings=dict(binding),worker_response_sha256=sha(worker_response_bytes),
                    worker_response_scope='EXACT_WORKER_RESULT_BEFORE_RECEIPT_EMBEDDING',
                    worker_source_scope='PINNED_PRIVATE_SERVICES_PROVIDER_NOT_ENTIRE_EXECUTOR_CLOSURE',
                    cleanup_evidence_sha256=sha(cleanup_evidence_bytes),cleanup_observer_source_sha256=CAPABILITY_PINS['cleanup'],
                    supervisor_identity=dict(owner),launch_debit=response['launch_debit'],
                    final_snapshot_monotonic=last[0],original_remote_deadline=clock['monotonic_end'],
                    no_future_mutations_proven=False,wrapper_must_not_write_root_after_snapshot=True,
                    outer_raw_response_and_transport_join_required=True,full_role2_transport_authenticated=False,
                    executor_source_policy_join_required=True,
                    physical_D95_verified=False,execution_ready=False,training_release=False)
                _require(len(canonical(result)) <= 8192,'ROOT_RECEIPT_OUTPUT_BOUND')
                return result
            except BaseException as exc:
                code = str(exc) if type(exc) is _Stop else 'ROOT_RECEIPT_CAPABILITY_OR_IO_FAILED'
                raise RootReceiptFailure(code,partial) from None
            finally:
                if fresh is not None:
                    os.close(fresh)
                if fd is not None:
                    os.close(fd)
    return Session()
