"""Pure E138 raw-frame/receipt consistency join, never a trust origin.

FREEZE must originate in the future reviewed phase creator and pinned host
transport, not from the bytes being checked. The returned context alone does
not authenticate a remote execution or authorize a read. No IO/callbacks.
"""
import math
import stat
from . import physical_e138_contract as contract
from . import physical_e138_runtime_primitives as runtime

FREEZE=None
require,sha,canonical,decode=contract.require,contract.sha,contract.canonical,contract.decode
PACKAGE_KEYS=frozenset(('authority','proposal','original_clock','role2_stdout','role2_stderr',
    'role2_transport','role2_intent','role3_intent'))
BINDING_KEYS=frozenset(('authorization_sha256','proposal_sha256','clock_sha256','role2_intent_sha256',
    'role2_payload_sha256','worker_spec_sha256','runtime_source_sha256','worker_source_sha256',
    'storage_source_sha256','emitter_source_sha256'))
RECEIPT_KEYS=frozenset(('schema','root','identity','birth_continuity','boot_id','input_bindings',
    'worker_response_sha256','worker_response_scope','worker_source_scope','cleanup_evidence_sha256',
    'cleanup_observer_source_sha256','supervisor_identity','launch_debit','final_snapshot_monotonic',
    'original_remote_deadline','no_future_mutations_proven','wrapper_must_not_write_root_after_snapshot',
    'outer_raw_response_and_transport_join_required','full_role2_transport_authenticated',
    'executor_source_policy_join_required','physical_D95_verified','execution_ready','training_release'))
IDENTITY_KEYS=frozenset(('st_dev','st_ino','st_mode','st_nlink','st_uid','st_size','st_mtime_ns','st_ctime_ns'))


def _intent(raw,role,payload):
    value=decode(raw)
    require(type(value) is dict and set(value)=={'role','attempt_consumed','role_index','connections_max','automatic_retries','payload_sha256'} and
        value['role']==role and value['attempt_consumed'] is True and value['payload_sha256']==payload and
        type(value['role_index']) is int and value['role_index']==(2 if role=='execution' else 3) and
        type(value['connections_max']) is int and value['connections_max']==3 and
        type(value['automatic_retries']) is int and value['automatic_retries']==0,'E138_JOIN_CONSUMED_INTENT')


def join(package):
    f=FREEZE
    require(type(f) is dict and set(f)=={'raw_sha256','role2_payload_sha256','role3_payload_sha256',
        'input_bindings','cleanup_observer_source_sha256'} and
        type(f['raw_sha256']) is dict and set(f['raw_sha256'])==PACKAGE_KEYS and
        all(contract._hex(v) for v in f['raw_sha256'].values()) and
        type(f['input_bindings']) is dict and set(f['input_bindings'])==BINDING_KEYS and
        all(contract._hex(v) for v in f['input_bindings'].values()) and
        all(contract._hex(f[k]) for k in ('role2_payload_sha256','role3_payload_sha256','cleanup_observer_source_sha256')),
        'E138_JOIN_FREEZE_REQUIRED')
    require(type(package) is dict and set(package)==PACKAGE_KEYS and
        all(type(raw) is bytes and len(raw)<=6291456 for raw in package.values()) and
        sum(map(len,package.values()))<=8388608,'E138_JOIN_EXACT_RAW_PACKAGE')
    require(all(sha(raw)==f['raw_sha256'][key] for key,raw in package.items()),'E138_JOIN_RAW_PIN')
    b=f['input_bindings'];pins=f['raw_sha256']
    require(all(b[key]==pins[rawkey] for key,rawkey in (('authorization_sha256','authority'),
        ('proposal_sha256','proposal'),('clock_sha256','original_clock'),('role2_intent_sha256','role2_intent'))) and
        b['role2_payload_sha256']==f['role2_payload_sha256'],'E138_JOIN_CROSS_BINDINGS')
    contract.check_authority(package['authority'],package['proposal'],pins['authority'],pins['proposal'])
    clock=runtime.package_clock(package['original_clock'],pins['authority'],pins['proposal'],pins['original_clock'])
    _intent(package['role2_intent'],'execution',f['role2_payload_sha256'])
    _intent(package['role3_intent'],'readback',f['role3_payload_sha256'])
    transport=decode(package['role2_transport'])
    require(type(transport) is dict and type(transport.get('exit_code')) is int and transport['exit_code']==0 and
        package['role2_stderr']==b'' and all(transport.get(key) is False for key in
        ('timeout','overflow','write_failed','threads_incomplete')) and
        all(type(transport.get(key)) is int for key in ('stdout_bytes','stderr_bytes')) and
        transport['stdout_bytes']==len(package['role2_stdout']) and transport['stderr_bytes']==0 and
        transport.get('stdout_sha256')==pins['role2_stdout'] and transport.get('stderr_sha256')==pins['role2_stderr'],
        'E138_JOIN_COMPLETE_TRANSPORT_REQUIRED')
    outer=decode(package['role2_stdout'])
    require(type(outer) is dict and set(outer)=={'role','worker_response','owned_root','cleanup_observation','execution_ready'} and
        outer['role']=='execution' and outer['execution_ready'] is False,'E138_JOIN_WORKER_FRAME')
    response,receipt,cleanup=outer['worker_response'],outer['owned_root'],outer['cleanup_observation']
    require(type(response) is dict and response.get('schema')==runtime.SCHEMA and
        response.get('status') in ('OBSERVED_PENDING_SCIENTIFIC_AUDIT','STOPPED_FIRST_FAILURE') and
        type(response.get('launch_debit')) is int and response['launch_debit'] in (0,1), 'E138_JOIN_WORKER_RESPONSE')
    require(type(cleanup) is dict and cleanup.get('cleaned') is True and 'cleanup_error' in cleanup and
        cleanup['cleanup_error'] is None and type(cleanup.get('returncode')) is int and
        type(cleanup.get('launch_attempted')) is bool and
        (response['launch_debit']==0 or cleanup['launch_attempted'] is True),'E138_JOIN_QUALIFIED_CLEANUP')
    require(type(receipt) is dict and set(receipt)==RECEIPT_KEYS and
        receipt['schema']=='e138-final-registered-root-receipt-v1' and receipt['root']==contract.ROOT and
        receipt['input_bindings']==b and receipt['worker_response_sha256']==sha(canonical(response)) and
        receipt['cleanup_evidence_sha256']==sha(canonical(cleanup)) and
        receipt['cleanup_observer_source_sha256']==f['cleanup_observer_source_sha256'] and
        type(receipt['launch_debit']) is int and receipt['launch_debit']==response['launch_debit'] and
        receipt['boot_id']==clock['boot_id'],'E138_JOIN_NATIVE_RECEIPT')
    identity=receipt['identity'];core=('st_dev','st_ino','st_uid','st_mode')
    require(type(identity) is dict and set(identity)==IDENTITY_KEYS and
        all(type(value) is int and 0<=value<2**64 for value in identity.values()) and
        identity['st_uid']==1047 and identity['st_nlink']>=1 and stat.S_ISDIR(identity['st_mode']) and
        type(receipt['birth_continuity']) is dict and set(receipt['birth_continuity'])==set(core) and
        all(type(value) is int for value in receipt['birth_continuity'].values()) and
        receipt['birth_continuity']=={key:identity[key] for key in core},'E138_JOIN_DIRECTORY_IDENTITY')
    owner=receipt['supervisor_identity']
    require(type(owner) is dict and set(owner)=={'pid','startticks','uid'} and
        all(type(value) is int for value in owner.values()) and owner['uid']==1047 and
        owner['pid']>1 and owner['startticks']>0,'E138_JOIN_SUPERVISOR')
    stamp=receipt['final_snapshot_monotonic']
    require(type(stamp) in (int,float) and math.isfinite(stamp) and
        clock['remote_start_monotonic']<=stamp<clock['monotonic_end'] and
        receipt['original_remote_deadline']==clock['monotonic_end'] and
        all(receipt[key] is True for key in ('wrapper_must_not_write_root_after_snapshot',
            'outer_raw_response_and_transport_join_required','executor_source_policy_join_required')) and
        all(receipt[key] is False for key in ('no_future_mutations_proven','full_role2_transport_authenticated',
            'physical_D95_verified','execution_ready','training_release')) and
        receipt['worker_response_scope']=='EXACT_WORKER_RESULT_BEFORE_RECEIPT_EMBEDDING' and
        receipt['worker_source_scope']=='PINNED_PRIVATE_SERVICES_PROVIDER_NOT_ENTIRE_EXECUTOR_CLOSURE',
        'E138_JOIN_RECEIPT_SCOPE')
    return dict(schema='e138-authenticated-role2-owned-root-context-v1',root=contract.ROOT,identity=dict(identity),
        boot_id=clock['boot_id'],authorization_sha256=pins['authority'],proposal_sha256=pins['proposal'],
        original_clock_sha256=pins['original_clock'],role2_stdout_sha256=pins['role2_stdout'],
        role2_stderr_sha256=pins['role2_stderr'],role2_transport_sha256=pins['role2_transport'],
        role2_intent_sha256=pins['role2_intent'],role2_payload_sha256=f['role2_payload_sha256'],
        role3_intent_sha256=pins['role3_intent'],role3_payload_sha256=f['role3_payload_sha256'])
