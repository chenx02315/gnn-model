"""Pure E138 grant/root/source consistency checks, NOT an execution release.

Freeze values must be supplied by a separately reviewed complete entrypoint.
They must never be learned from the untrusted package being admitted. Module
tags and loader-order claims are consistency data, not an authenticity root.
No real E138 grant or complete source adapter currently exists.
"""
import hashlib
import json
import math
import sys
import types

ROOT='/temp/jiangchuanc/multimode_ate_physical_f_replay_e138_r1'
PHASE='v6_e138_clean_F_replay_r1'
OLD_AUTH_SHA256='49f000fe45de6cfc029ad8a9c1ead5e09edd24321de6062039d638436cce4969'
FROZEN=None
LOADED_SOURCE_ORDER=None

POLICY=dict(schema='e138-fixed-f-replay-policy-v1',package='E138',
    new_remote_root=ROOT,new_local_phase=PHASE,root_must_not_exist_at_deployment=True,
    circuit='aes_core',input_scope='E127_AES_CURRENT_PINNED_F4_ONLY',
    connections_max=3,read_seconds_max=60,execution_seconds_max=2400,
    tessent_session_seconds_max=1800,whole_package_seconds_max=3600,
    clock_starts_at_first_connection=True,clock_includes_review_and_transfer=True,
    worker_count=1,bootstrap_children_max=1,bootstrap_seconds_max=30,
    bootstrap_output_bytes_max=65536,process_selfchecks_max=3,tessent_launches_max=1,
    sampled_worker_and_descendant_rss_swap_bytes_max=536870912,
    sampled_new_directory_bytes_max=8589934592,source_pattern_bytes_max=67108864,
    source_tree_bytes_max=2147483648,source_tree_entries_max=4000,source_tree_depth_max=32,
    installed_file_hash_bytes_max=2147483648,installed_total_hash_bytes_max=4294967296,
    initial_response_bytes_max=6291456,result_body_bytes_max=16777216,
    result_response_bytes_max=25165824,automatic_retries=0,
    first_failure_stops=True,ambiguous_launch_consumes_attempt=True,
    readback_requires_owned_clean_root=True,readback_cannot_launch_or_resume=True,
    history_or_source_writes=False,ATPG_generation_commands=0,
    foreign_detection_status_merges=0,help_only_tessent_launches=0,
    LSF_jobs=0,B_access=False,BLIND_access=False,training=False)

INPUT_KEYS=frozenset(('authority','proposal','original_clock','role1_response','role2_intent',
    'policy','runtime_source','worker_source','bootstrap_source','collector_source',
    'root_receipt_source','functions','shell','e112','parent_worker_source',
    'profile_source','incremental','parent_helper'))
FREEZE_KEYS=frozenset(('authorization_sha256','proposal_sha256','payload_sha256',
    'policy_sha256','input_sha256','source_sha256','source_order'))
REQUIRED_SOURCES=frozenset(('physical_e138_contract','physical_e138_batch_candidate',
    'physical_batch_diagnostics_e138'))


def require(ok,code):
    if not ok:raise ValueError(code)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def _hex(value):
    return type(value) is str and len(value)==64 and all(c in '0123456789abcdef' for c in value)


def _pairs(rows):
    result={}
    for key,value in rows:
        require(key not in result,'E138_CONTRACT_DUPLICATE_JSON_KEY')
        result[key]=value
    return result


def decode(raw):
    require(type(raw) is bytes and len(raw)<=1048576,'E138_CONTRACT_JSON_BOUND')
    try:
        return json.loads(raw.decode('utf-8'),object_pairs_hook=_pairs,
            parse_constant=_nonfinite,parse_float=_finite_float)
    except (ValueError,UnicodeError,RecursionError):
        raise ValueError('E138_CONTRACT_JSON_REJECTED') from None


def _nonfinite(value):
    raise ValueError('E138_NONFINITE_JSON_NUMBER')


def _finite_float(value):
    result=float(value)
    require(math.isfinite(result),'E138_NONFINITE_JSON_NUMBER')
    return result


def _policy(value):
    # JSON byte comparison deliberately distinguishes true from 1.
    require(type(value) is dict and canonical(value)==canonical(POLICY),'E138_EXACT_FROZEN_POLICY')


def _freeze():
    f=FROZEN
    require(type(f) is dict and set(f)==FREEZE_KEYS and
        all(_hex(f[k]) for k in ('authorization_sha256','proposal_sha256','payload_sha256','policy_sha256')) and
        f['authorization_sha256']!=OLD_AUTH_SHA256,'E138_FREEZE_NOT_CONFIGURED')
    require(type(f['input_sha256']) is dict and set(f['input_sha256'])==INPUT_KEYS and
        all(_hex(pin) for pin in f['input_sha256'].values()),'E138_INPUT_FREEZE_ROSTER')
    sources,order=f['source_sha256'],f['source_order']
    require(type(sources) is dict and REQUIRED_SOURCES<=set(sources) and 3<=len(sources)<=96 and
        all(type(name) is str and 0<len(name)<=128 and
            all(c in 'abcdefghijklmnopqrstuvwxyz0123456789_' for c in name) and _hex(pin)
            for name,pin in sources.items()) and
        type(order) is tuple and len(order)==len(sources) and
        all(type(name) is str for name in order) and len(set(order))==len(order) and set(order)==set(sources),
        'E138_SOURCE_FREEZE_ROSTER_AND_ORDER')
    return f


def admit(package):
    """Consistency only; no clock, process, FS, ledger or callback access."""
    f=_freeze()
    require(type(package) is dict and set(package)==INPUT_KEYS and
        all(type(raw) is bytes for raw in package.values()) and
        sum(map(len,package.values()))<=10485760,'E138_EXACT_PACKAGE_BYTES')
    require(all(sha(raw)==f['input_sha256'][key] for key,raw in package.items()),'E138_FROZEN_INPUT_DRIFT')
    require(sha(package['authority'])==f['authorization_sha256'] and
        sha(package['proposal'])==f['proposal_sha256'] and
        sha(package['policy'])==f['policy_sha256'],'E138_GRANT_PROPOSAL_POLICY_PIN')
    proposal,authority,policy=(decode(package[k]) for k in ('proposal','authority','policy'))
    require(type(proposal) is dict and set(proposal)=={'schema','package','status','scope_if_granted'} and
        proposal['schema']=='e138-fixed-f-replay-proposal-v1' and proposal['package']=='E138' and
        proposal['status']=='PENDING_EXPLICIT_WHOLE_PACKAGE_AUTHORIZATION','E138_NEW_PROPOSAL_REQUIRED')
    _policy(proposal['scope_if_granted']);_policy(policy)
    require(type(authority) is dict and set(authority)=={'schema','approved_package','approval_source',
        'user_reply','user_authorization_received','proposal_sha256','approved_scope','execution_ready'} and
        authority['schema']=='e138-explicit-whole-package-authorization-v1' and
        authority['approved_package']=='E138' and authority['approval_source']=='explicit_user_reply' and
        authority['user_authorization_received'] is True and authority['execution_ready'] is False and
        type(authority['user_reply']) is str and 0<len(authority['user_reply'])<=4096 and
        authority['proposal_sha256']==f['proposal_sha256'],'E138_NEW_EXPLICIT_GRANT_REQUIRED')
    _policy(authority['approved_scope'])
    require(type(LOADED_SOURCE_ORDER) is tuple and LOADED_SOURCE_ORDER==f['source_order'],
        'E138_LOADER_ORDER_CONSISTENCY')
    for name,pin in f['source_sha256'].items():
        module=sys.modules.get('src.data.'+name)
        require(type(module) is types.ModuleType and
            vars(module).get('__source_sha256__')==pin,'E138_LOADED_SOURCE_TAG_CONSISTENCY')
    require(globals().get('__source_sha256__')==f['source_sha256']['physical_e138_contract'],
        'E138_CONTRACT_SELF_SOURCE_CONSISTENCY')
    return dict(schema='e138-contract-consistency-only-v1',package='E138',root=ROOT,phase=PHASE,
        authorization_sha256=f['authorization_sha256'],proposal_sha256=f['proposal_sha256'],
        payload_sha256=f['payload_sha256'],policy_sha256=f['policy_sha256'],
        source_manifest_sha256=sha(canonical(f['source_sha256'])),
        source_order_sha256=sha(canonical(f['source_order'])),
        input_manifest_sha256=sha(canonical(f['input_sha256'])),
        loaded_tags_are_authentication=False,independent_review_verified=False,
        remote_authorization_proven=False,components_rebound=False,
        ledger_consumed=False,execution_ready=False)
