"""E138 native clock/launch checks and isolated source-derived services.

No execution entrypoint. A services object is not a runtime permission or an
ownership receipt. The factory requires separately frozen new grant/source
inputs and leaves historical worker entries disabled. Raw source identity and
effective configuration are deliberately recorded as different commitments.
"""
import datetime
import math
import re
import types
from . import physical_e138_contract as contract
from . import physical_f_replay_execution_e135 as legacy

ROOT,PHASE=contract.ROOT,contract.PHASE
SCHEMA='physical-f-clean-replay-execution-e138-v1'
CLOCK_SCHEMA='physical-f-clean-replay-package-clock-e138-v1'
ORIGIN_RUNTIME_SHA256='83fa927774b59d43ad838d09333f6ad787edfed27cd52043f9fcda4dc4b9f85f'
ORIGIN_STORAGE_SHA256='0045cb1c6ba4b81cf4f1d2d6c8723c44d69bb48d3b357c8c95e8a217c14597bb'
FACTORY_FREEZE=None
HELPER_PINS={
    'io':'a04127c07227814e331ede4268c6f8d5df4def4d7041c0c69ec048378216cab9',
    'process':'6b1922de253550b3d4091f11186d9447867662c445e46fdc47801f3c340411f6',
    'launch_base':'6bc12ff0843316e4fdd96cb99016af1f271459547869537133f68e060e245f17',
    'faults':'f659ca52bc6c48645736162223d1f6a931c343d4dd6cafac690aaeff90a2c681',
    'evidence':'879b0d244e4d649c4a6be5a673bb1b566000cce69194d555634ad3d8037fc37e',
    'direct':'6b7961e8238b2676a9c90a69a1c554be7238daa789de2e41a1e820044e17b190'}
require,sha,canonical,decode=contract.require,contract.sha,contract.canonical,contract.decode


def _number(value):
    return type(value) in (int,float) and math.isfinite(value) and value>=0


def _hex(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None


def package_clock(raw,authorization_sha256=None,proposal_sha256=None,initial_clock_sha256=None):
    """Pure clock consistency; caller still checks real host, boot and now."""
    require(all(_hex(pin) for pin in (authorization_sha256,proposal_sha256,initial_clock_sha256)) and
        authorization_sha256!=contract.OLD_AUTH_SHA256,'E138_CLOCK_FREEZE_REQUIRED')
    require(type(raw) is bytes and 0<len(raw)<=4096 and sha(raw)==initial_clock_sha256,'E138_EXACT_CLOCK_BYTES')
    value=decode(raw)
    keys={'schema','authorization_sha256','proposal_sha256','reader_payload_sha256','initial_response_sha256',
        'start_file_sha256','boot_id','remote_start_monotonic','remote_deadline_monotonic','remote_utc_sample',
        'remote_clock_sample_monotonic','local_utc_start','local_utc_deadline','local_monotonic_start',
        'local_monotonic_deadline','local_clock_domain','root','phase'}
    require(type(value) is dict and set(value)==keys and value['schema']==CLOCK_SCHEMA and
        value['authorization_sha256']==authorization_sha256 and value['proposal_sha256']==proposal_sha256 and
        value['root']==ROOT and value['phase']==PHASE,'E138_CLOCK_IDENTITY')
    require(all(_hex(value[key]) for key in ('reader_payload_sha256','initial_response_sha256','start_file_sha256')) and
        type(value['boot_id']) is str and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value['boot_id']) and
        all(_number(value[key]) for key in ('remote_start_monotonic','remote_deadline_monotonic',
            'remote_clock_sample_monotonic','local_monotonic_start','local_monotonic_deadline')),
        'E138_CLOCK_FIELDS')
    stamps={}
    for key in ('remote_utc_sample','local_utc_start','local_utc_deadline'):
        stamp=value[key]
        require(type(stamp) is str and re.fullmatch('[0-9]{4}(?:-[0-9]{2}){2}T[0-9]{2}(?::[0-9]{2}){2}\\.[0-9]{6}\\+0000',stamp),
            'E138_CLOCK_PY36_UTC_FORMAT')
        stamps[key]=datetime.datetime.strptime(stamp,'%Y-%m-%dT%H:%M:%S.%f%z').timestamp()
    require(value['remote_deadline_monotonic']==value['remote_start_monotonic']+3600 and
        value['local_monotonic_deadline']==value['local_monotonic_start']+3600 and
        stamps['local_utc_deadline']-stamps['local_utc_start']==3600 and
        value['remote_start_monotonic']<=value['remote_clock_sample_monotonic']<value['remote_start_monotonic']+60,
        'E138_ORIGINAL_UNRESET_CLOCK')
    domain=value['local_clock_domain']
    require(type(domain) is dict and set(domain)=={'host','clock'} and
        all(type(item) is str and 0<len(item)<=512 for item in domain.values()),'E138_LOCAL_CLOCK_DOMAIN')
    remote_utc_end=stamps['remote_utc_sample']+value['remote_deadline_monotonic']-value['remote_clock_sample_monotonic']
    return dict(value,monotonic_end=value['remote_deadline_monotonic'],
        utc_end=min(remote_utc_end,stamps['local_utc_deadline']))


def validate_launch(launch):
    base=legacy.launch_base
    require(type(launch) is dict and set(launch)==base.LAUNCH_KEYS and launch['schema']==base.SCHEMA and
        all(launch[key] is False for key in ('environment_profile_authenticated','execution_authorized','execution_ready')),
        'E138_LAUNCH_NOT_AUTHORITY')
    require(launch['argv']==[base.recipe.identities.LAUNCHER,'-shell','-license_wait','5',
        '-log',ROOT+'/tool.log','-dofile',ROOT+'/code/replay.tcl'] and launch['cwd']==ROOT+'/work',
        'E138_FIXED_LAUNCH_ROOT')
    base._environment(launch['env'],launch['cwd'])
    require(sha(canonical(launch['env']))==launch['environment_sha256'] and
        sha(canonical({key:value for key,value in launch.items() if key!='launch_spec_sha256'}))==launch['launch_spec_sha256'],
        'E138_LAUNCH_HASH')


def private_services(raw,authority,proposal,storage_raw=None):
    """Inert factory only; all filesystem/process methods remain uncalled."""
    frozen=FACTORY_FREEZE
    require(type(frozen) is dict and set(frozen)=={'authorization_sha256','proposal_sha256',
        'origin_source_sha256','adapter_source_sha256','effective_root'} and
        all(_hex(frozen[key]) for key in ('authorization_sha256','proposal_sha256',
            'origin_source_sha256','adapter_source_sha256')) and
        frozen['effective_root']==ROOT and frozen['origin_source_sha256']==ORIGIN_RUNTIME_SHA256 and
        globals().get('__source_sha256__')==frozen['adapter_source_sha256'],'E138_FACTORY_FROZEN_BINDING_REQUIRED')
    contract.check_authority(authority,proposal,frozen['authorization_sha256'],frozen['proposal_sha256'])
    require(type(raw) is bytes and 0<len(raw)<=131072 and sha(raw)==ORIGIN_RUNTIME_SHA256,'E138_FACTORY_ORIGIN_PIN')
    require(type(storage_raw) is bytes and 0<len(storage_raw)<=131072 and sha(storage_raw)==ORIGIN_STORAGE_SHA256,
        'E138_FACTORY_STORAGE_ORIGIN_PIN')
    # Claims supplied by a trusted source loader, not a proof against mutation
    # of Python objects by a caller already allowed to change trusted code.
    require(all(getattr(getattr(legacy,name),'__source_sha256__',None)==pin for name,pin in HELPER_PINS.items()),
        'E138_FACTORY_HELPER_TAG_CONSISTENCY')
    module=types.ModuleType('src.data._e138_private_services');module.__package__='src.data'
    exec(compile(raw,'<e138-frozen-origin-services>','exec'),module.__dict__)
    storage_module=types.ModuleType('src.data._e138_private_storage');storage_module.__package__='src.data'
    exec(compile(storage_raw,'<e138-frozen-origin-storage>','exec'),storage_module.__dict__)
    storage_module.__source_sha256__=None
    storage_module.__origin_source_sha256__=ORIGIN_STORAGE_SHA256
    module.storage=storage_module
    module.ROOT=ROOT;module.AUTH_SHA256=None
    module.REVIEWED_SPEC_SHA256=module.INITIAL_CLOCK_SHA256=None
    module.COMMANDS_VERIFIED=False;module._USED=True
    module.worker=module.package_clock=None
    config=dict(root=ROOT,sidecar=ROOT+'.initial_intent.json',worker_entry_disabled=True,
        original_clock_entry_disabled=True,historical_execution_authority_reused=False)
    evidence=dict(schema='e138-derived-services-binding-v1',origin_source_sha256=ORIGIN_RUNTIME_SHA256,
        adapter_source_sha256=frozen['adapter_source_sha256'],effective_config_sha256=sha(canonical(config)),
        helper_tag_manifest_sha256=sha(canonical(HELPER_PINS)),
        helper_tags_are_authentication=False,raw_module_identity_claimed=False,execution_ready=False)
    module.__source_sha256__=None
    module.__origin_source_sha256__=ORIGIN_RUNTIME_SHA256
    module.__e138_binding__=dict(evidence)
    original_storage=module._storage
    def storage(end):
        require(_number(end) and module.ROOT==ROOT,'E138_STORAGE_DEADLINE_REQUIRED')
        persist,monitor=original_storage(end)
        namespace=persist.__globals__
        namespace['__source_sha256__']=None
        namespace['__origin_source_sha256__']=ORIGIN_STORAGE_SHA256
        namespace['__e138_binding__']=dict(evidence,origin_source_sha256=ORIGIN_STORAGE_SHA256,
            effective_config_sha256=sha(canonical(dict(root=ROOT,sidecar=ROOT+'.initial_intent.json',end=end))))
        return persist,monitor
    module._storage=storage
    return module
