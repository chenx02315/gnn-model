"""Finite E137 engine binding; candidates are NOT authenticated observations.

Private environment/selector plan never enter public evidence. Physical sampler,
original-clock authentication and actual ldd behavior verifier remain missing;
bind() therefore defaults to denial. No IO or process entry is provided.
"""
import copy
import math
import re
import stat
from . import physical_engine_selector_e137 as selector
from . import prospective_runtime_adapter_e114 as adapter
from .physical_replay_source_reader_e135 import require,sha,canonical,FIELDS

AUTH_SHA256 = '49f000fe45de6cfc029ad8a9c1ead5e09edd24321de6062039d638436cce4969'
LAUNCHER_SHA256 = 'd92e81eaacf0727fd18d4cafa67d7c9a066069c6d8f7fc05caaf1252c3e44905'
PROFILE_NORMALIZED_SHA256 = 'b9b54844adcc9b753af0108c96a2292e938fec525fa8f87a3c91ab2593015256'
SOURCE_PINS = dict(physical_engine_selector_e137='efcf80e98b4a26051d057320e4dc75882929545fbd42be41be4336a2586d5d73',
    prospective_runtime_adapter_e114='57ad390828e2ce33e2bebd0830c787473e98a7ba1c31843e12b03759ef6a77f1',
    prospective_runtime_profile_e112='b7f096782faefe9abcd9e3e748176ffcf3c2944c72cb1d39b32b0d196d1a2e3a')
EVIDENCE_VERIFIER = EVIDENCE_VERIFIER_SHA256 = None
LDD_VERIFIER = LDD_VERIFIER_SHA256 = None
CHAIN_PATHS = (selector.LAUNCHER,selector.ROOT+'/lib/scripts/tessent_functions',selector.ROOT+'/lib/scripts/tessent_shell')


def _hex(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None


def _clock(clock,now,utc_now):
    fields = {'authorization_sha256','original_clock_sha256','boot_id','nonce','package_start','package_end','connection_start','utc_end'}
    require(type(clock) is dict and set(clock) == fields and clock['authorization_sha256'] == AUTH_SHA256 and
        _hex(clock['original_clock_sha256']) and _hex(clock['nonce']) and type(clock['boot_id']) is str and
        re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',clock['boot_id']) is not None,'ENGINE_ORIGINAL_CONTEXT')
    values=[clock[k] for k in ('package_start','package_end','connection_start','utc_end')]+[now,utc_now]
    require(all(type(n) in (int,float) and math.isfinite(n) and n >= 0 for n in values) and
        clock['package_end'] == clock['package_start']+3600 and
        clock['package_start'] <= clock['connection_start'] <= now < min(clock['package_end'],clock['connection_start']+2400)-10 and
        utc_now < clock['utc_end'],'ENGINE_ORIGINAL_DEADLINE')


def _record(row,directory=False):
    require(type(row) is dict and set(row) == {'identity','sha256'} and type(row['identity']) is dict and
        set(row['identity']) == set(FIELDS) and all(type(n) is int and n >= 0 for n in row['identity'].values()),'ENGINE_RECORD_FIELDS')
    info=row['identity']
    require(info['st_uid'] == 0 and not info['st_mode'] & 0o022 and
        (stat.S_ISDIR(info['st_mode']) and info['st_nlink'] >= 1 and row['sha256'] is None if directory else
        stat.S_ISREG(info['st_mode']) and info['st_nlink'] == 1 and info['st_size'] > 0 and _hex(row['sha256'])),
        'ENGINE_RECORD_UID_TYPE_LINKS')


class Binding(object):
    __slots__ = ('_environment','_plan','public')
    def __init__(self,environment,plan,public):
        self._environment,self._plan,self.public=copy.deepcopy(environment),copy.deepcopy(plan),copy.deepcopy(public)
    def __repr__(self):
        return '<E137Binding PRIVATE_RAM_ONLY; public_bytes() is redacted>'
    def public_bytes(self):
        return canonical(self.public)
    def private_runtime(self):
        """Intentional RAM-only accessor; caller must never log or persist this."""
        return copy.deepcopy(self._environment),copy.deepcopy(self._plan)


def build_candidate(functions_bytes,shell_bytes,launcher_bytes,raw_environment,profile_metadata,argv,metadata,chain,clock,now,utc_now):
    _clock(clock,now,utc_now)
    selector._sources(functions_bytes,shell_bytes)
    require(type(launcher_bytes) is bytes and len(launcher_bytes) == 3658 and sha(launcher_bytes) == LAUNCHER_SHA256,'ENGINE_PINNED_LAUNCHER_BYTES')
    require(type(profile_metadata) is dict and profile_metadata.get('normalized_sha256') == PROFILE_NORMALIZED_SHA256,
        'ENGINE_FIXED_RUNTIME_PROFILE')
    environment,compatibility=adapter.prepare_runtime(raw_environment,profile_metadata,LAUNCHER_SHA256)
    environment.update(HOME=selector.RUN_ROOT+'/work',TMPDIR=selector.RUN_ROOT+'/work',LANG='C',LC_ALL='C')
    plan=selector.build_plan(functions_bytes,shell_bytes,environment,argv)
    require(type(metadata) is dict and set(metadata) == set(selector.CANDIDATES),'ENGINE_EXACT_SEVEN_PATHS')
    selector_rows={}
    for path,row in metadata.items():
        require(type(row) is dict and row.get('state') in ('PRESENT','MISSING','UNOBSERVED'),'ENGINE_METADATA_STATE')
        if row['state'] == 'PRESENT':
            require(set(row) == {'state','record'},'ENGINE_METADATA_FIELDS')
            _record(row['record'],path in selector.TCL.values())
            selector_rows[path]=dict(state='PRESENT',identity=row['record']['identity'])
        else:
            require(set(row) == {'state'},'ENGINE_ABSENCE_FIELDS')
            selector_rows[path]=dict(row)
    require(type(chain) is dict and set(chain) == set(CHAIN_PATHS),'ENGINE_EXACT_VENDOR_CHAIN')
    for path,digest,size in zip(CHAIN_PATHS,(LAUNCHER_SHA256,selector.FUNCTIONS_SHA,selector.SHELL_SHA),(3658,12306,49725)):
        _record(chain[path]);require(chain[path]['sha256'] == digest and chain[path]['identity']['st_size'] == size,'ENGINE_VENDOR_CHAIN_HASH')
    classification=selector.classify(plan,selector_rows)
    require(classification['status'] == 'CONDITIONALLY_SELECTED','ENGINE_BRANCH_NOT_COMPLETE_OR_UNSAFE')
    public=dict(schema='e137-engine-binding-candidate-v1',clock=copy.deepcopy(clock),
        source_sha256=dict(SOURCE_PINS),plan=selector.redact_plan(plan),classification=classification,
        finite_metadata_sha256=sha(canonical(metadata)),vendor_chain_sha256=sha(canonical(chain)),
        compatibility=compatibility,environment_authenticated=False,engine_authenticated=False,
        physical_sampling_verified=False,ldd_behavior_verified=False,execution_ready=False)
    return Binding(environment,plan,public)


def bind(*args,**kwargs):
    """No actual sampler/ldd trust capability exists in this implementation."""
    for function,pin,code in ((EVIDENCE_VERIFIER,EVIDENCE_VERIFIER_SHA256,'ENGINE_EVIDENCE_VERIFIER_MISSING'),
            (LDD_VERIFIER,LDD_VERIFIER_SHA256,'ENGINE_LDD_VERIFIER_MISSING')):
        require(_hex(pin) and callable(function) and getattr(function,'__source_sha256__',None) == pin,code)
    # Merely setting attributes cannot supply the missing authenticated protocol.
    raise ValueError('ENGINE_PHYSICAL_BINDING_RELEASE_PROTOCOL_UNIMPLEMENTED')
