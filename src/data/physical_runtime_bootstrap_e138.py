"""Default-disabled E138 bootstrap with finite, secret-free attempted stages.

Uses the exact pinned E127 capture_runtime code object and unchanged child
command, not the old worker's main/entrypoint. No E137 grant is accepted.
Frozen arguments must come from a separately reviewed E138 entrypoint, never
be learned from an untrusted package. There is no actual new grant here.

Stage means attempted operation, not successful completion. Only explicit
literal diagnostic codes are exported. Unknown exception text, repr, cause,
traceback, child stdout and private environment values are never exported.
PrivateRuntime.environment() is intentionally private RAM; never persist it.
"""
import base64
import copy
import json
import math
import os
import platform
import re
import shlex
import time
from types import SimpleNamespace,CodeType,FunctionType

from . import direct_tessent_acceptance_e104 as direct
from . import prospective_generation_process_e113 as process
from . import prospective_runtime_profile_e112 as profile
from . import prospective_runtime_adapter_e114 as adapter
from . import prospective_tessent_acceptance_v1 as pins
from .physical_replay_source_reader_e135 import sha,canonical,decode

ROOT='/temp/jiangchuanc/multimode_ate_physical_f_replay_e138_r1'
PHASE='v6_e138_clean_F_replay_r1'
AUTH_SHA256=PROPOSAL_SHA256=CONTEXT_SHA256=EXPECTED_BOOT_ID=None
OLD_E137_AUTH_SHA256='49f000fe45de6cfc029ad8a9c1ead5e09edd24321de6062039d638436cce4969'
ORIGIN_E137_SOURCE_SHA256='d59531d92a2f3cd7080497d7a77eb51c61e543aecbeeb6304d21aae6ef07990d'
WORKER_SHA256='360dd42f9c0a950858dad085d9c0a3ebda551991cd9ab525ea71fa97216abe10'
E112_SHA256='fd09999da5355c8b66fb0bbae0e6f495544bbf578df8894b01ac5fc8685864ae'
PROFILE_SHA256='b7f096782faefe9abcd9e3e748176ffcf3c2944c72cb1d39b32b0d196d1a2e3a'
LAUNCHER_SHA256='d92e81eaacf0727fd18d4cafa67d7c9a066069c6d8f7fc05caaf1252c3e44905'
SOURCE_PINS={
    'direct_tessent_acceptance_e104':'6b7961e8238b2676a9c90a69a1c554be7238daa789de2e41a1e820044e17b190',
    'direct_tessent_acceptance_e100':'92f9915bc431483ba73cc38829356ca315a16ae39713b021b2025d0ce744fb58',
    'prospective_generation_process_e113':'6b1922de253550b3d4091f11186d9447867662c445e46fdc47801f3c340411f6',
    'prospective_runtime_profile_e112':PROFILE_SHA256,
    'prospective_runtime_adapter_e114':'57ad390828e2ce33e2bebd0830c787473e98a7ba1c31843e12b03759ef6a77f1',
    'prospective_tessent_acceptance_v1':'6d4b45d303a4be34f03914b8f9cb4aad2d9fe73c41c666a6c12058c43ef5aac2'}
STAGES=('ADMISSION','PACKAGE_SHAPE','PINNED_BYTES','AUTHORITY_JSON','PROPOSAL_JSON','AUTHORITY_VALIDATE',
    'CONTEXT_JSON','CONTEXT_VALIDATE','SOURCE_BINDING','ARGUMENTS','HOST_CHECK','BOOT_CHECK','WORKER_IDENTITY',
    'CLOCK_CAPTURE','INITIAL_GUARD','WORKER_COMPILE','FUNCTION_EXTRACTION','ORIGINAL_CALL','PROFILE_SOURCE_BINDING','CHILD_CODE_BUILD',
    'COMMAND_CHECK','PRE_CHILD_GUARD','SUPERVISION','OUTPUT_BOUND','OBSERVATION_CHECK','OUTPUT_JSON','OUTPUT_SCHEMA',
    'PREPARATION_JSON','PROFILE_COMPATIBILITY','PROFILE_DRIFT','POST_ORIGINAL_NORMALIZE','NORMALIZED_KEYS','FINAL_GUARD','RECEIPT')
ERROR_CODES=frozenset('E138_BOOTSTRAP_'+stage+'_FAILED' for stage in STAGES)
SUPERVISOR_LITERAL_CODES=frozenset(('PRELAUNCH_TIMEOUT','OUTPUT_STOP','CASE_TIMEOUT','CLEANUP_UNCONFIRMED','SAMPLED_MEMORY_STOP'))
LITERAL_CODES=frozenset(('DUPLICATE_JSON_KEY','NONFINITE_JSON','PROFILE_SOURCE_BINDING','BOOTSTRAP_PRIVATE_SCHEMA',
    'BOOTSTRAP_PROFILE_DRIFT','BOOTSTRAP_BOUND','BOOTSTRAP_FAILED','RUNTIME_ALLOWLIST_ONLY','RUNTIME_PROFILE_DRIFT',
    'PINNED_ABSOLUTE_LAUNCHER_REQUIRED','UNQUALIFIED_RUNTIME_PROFILE','NORMALIZATION_DIGEST_MISMATCH',
    'PROFILE_VALUE_BOUND_OR_TYPE','RUNTIME_ENV_KEYS','RUNTIME_ENV_VALUE','ABSOLUTE_SEARCH_PATHS_ONLY'))|SUPERVISOR_LITERAL_CODES
_USED=False


class _Fault(ValueError):
    pass


class PrivateRuntime(object):
    __slots__=('_values','_receipt')
    def __init__(self,values,receipt):
        self._values,self._receipt=copy.deepcopy(values),copy.deepcopy(receipt)
    def __repr__(self):
        return '<E138Runtime PRIVATE_RAM_ONLY; redacted_receipt() is exportable>'
    def __reduce_ex__(self,protocol):
        raise TypeError('E138_PRIVATE_RUNTIME_NOT_SERIALIZABLE')
    def environment(self):
        return copy.deepcopy(self._values)
    def redacted_receipt(self):
        return copy.deepcopy(self._receipt)


def _hex(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None


def _number(value):
    return type(value) in (int,float) and math.isfinite(value) and value >= 0


def bootstrap(package,domain,tick,frozen,evidence=None):
    """One fixed private profile child, 30s/64KiB/512MiB, no Tessent.

    frozen exact fields: authorization_sha256, proposal_sha256, context_sha256,
    expected_boot_id, root, phase. Module freeze pins still default to None.
    """
    global _USED
    state={'stage':'ADMISSION','literal':None}
    metadata={}
    calls=[0]
    values=normalized=namespace=original_package=None
    def stage(name):
        if name not in STAGES:
            raise _Fault('E138_BOOTSTRAP_ADMISSION_FAILED')
        state['stage']=name
    def check(ok,literal=None):
        if not ok:
            if literal in LITERAL_CODES:
                state['literal']=literal
            raise _Fault('E138_BOOTSTRAP_'+state['stage']+'_FAILED')
    def remember(exc):
        # Do not stringify an exception. Only these exact reviewed literals can
        # survive the original capture_runtime's generic wrapping exception.
        if type(exc) is ValueError and len(exc.args)==1 and type(exc.args[0]) is str and exc.args[0] in LITERAL_CODES:
            state['literal']=exc.args[0]
    try:
        check(_hex(AUTH_SHA256) and _hex(PROPOSAL_SHA256) and _hex(CONTEXT_SHA256) and
            type(EXPECTED_BOOT_ID) is str and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',EXPECTED_BOOT_ID) and
            AUTH_SHA256 != OLD_E137_AUTH_SHA256)
        check(type(frozen) is dict and set(frozen)=={'authorization_sha256','proposal_sha256','context_sha256','expected_boot_id','root','phase'} and
            frozen==dict(authorization_sha256=AUTH_SHA256,proposal_sha256=PROPOSAL_SHA256,context_sha256=CONTEXT_SHA256,
                expected_boot_id=EXPECTED_BOOT_ID,root=ROOT,phase=PHASE))
        check(not _USED)
        _USED=True
        stage('PACKAGE_SHAPE')
        check(type(package) is dict and set(package)=={'authority','proposal','context','e112','worker_source','profile_source'} and
            all(type(raw) is bytes for raw in package.values()))
        stage('PINNED_BYTES')
        expected=dict(authority=(AUTH_SHA256,65536),proposal=(PROPOSAL_SHA256,65536),context=(CONTEXT_SHA256,4096),
            e112=(E112_SHA256,262144),worker_source=(WORKER_SHA256,131072),profile_source=(PROFILE_SHA256,65536))
        check(all(0<len(package[k])<=cap and sha(package[k])==pin for k,(pin,cap) in expected.items()))
        stage('AUTHORITY_JSON');auth=decode(package['authority'])
        stage('PROPOSAL_JSON');proposal=decode(package['proposal'])
        stage('AUTHORITY_VALIDATE')
        check(type(auth) is dict and set(auth)=={'schema','approved_package','approval_source','user_reply',
            'user_authorization_received','proposal_sha256','approved_scope','execution_ready'} and
            auth['schema']=='e138-explicit-whole-package-authorization-v1' and auth['approved_package']=='E138' and
            auth['approval_source']=='explicit_user_reply' and type(auth['user_reply']) is str and
            0<len(auth['user_reply'])<=4096 and auth['user_authorization_received'] is True and auth['execution_ready'] is False and
            auth['proposal_sha256']==PROPOSAL_SHA256 and type(auth['approved_scope']) is dict and
            type(proposal) is dict and proposal.get('schema')=='e138-fixed-f-replay-proposal-v1' and
            proposal.get('package')=='E138' and proposal.get('status')=='PENDING_EXPLICIT_WHOLE_PACKAGE_AUTHORIZATION' and
            auth['approved_scope']==proposal.get('scope_if_granted') and auth['approved_scope'].get('new_remote_root')==ROOT and
            auth['approved_scope'].get('new_local_phase')==PHASE)
        stage('CONTEXT_JSON');context=decode(package['context'])
        stage('CONTEXT_VALIDATE')
        check(type(context) is dict and set(context)=={'role','authorization_sha256','boot_id','package_start','package_end',
            'connection_start','utc_end','root','phase'} and context['role']=='execution' and
            context['authorization_sha256']==AUTH_SHA256 and context['boot_id']==EXPECTED_BOOT_ID and context['root']==ROOT and
            context['phase']==PHASE and all(_number(context[k]) for k in ('package_start','package_end','connection_start','utc_end')) and
            context['package_end']==context['package_start']+3600 and
            context['package_start']<=context['connection_start']<context['package_end'])
        stage('SOURCE_BINDING')
        check(all(getattr(module,'__source_sha256__',None)==SOURCE_PINS[module.__name__.rsplit('.',1)[1]]
            for module in (direct,direct.base,process,profile,adapter,pins)))
        stage('ARGUMENTS')
        check(callable(tick) and type(domain) is direct.Descendants and (evidence is None or type(evidence) is dict))
        stage('HOST_CHECK')
        check(platform.node()=='bupt-vncs2' and os.getuid()==1047 and os.sys.platform.startswith('linux'))
        stage('BOOT_CHECK');check(process._boot_id()==EXPECTED_BOOT_ID)
        stage('WORKER_IDENTITY');process._check_worker(domain)
        stage('CLOCK_CAPTURE');started=time.monotonic()
        check(_number(started))
        outer_end=min(context['package_end'],context['connection_start']+2400)
        wall=time.time();check(_number(wall))
        end=min(outer_end,started+30,started+max(0,context['utc_end']-wall))
        last=[started]
        def guard():
            now=time.monotonic();utc=time.time()
            check(_number(now) and _number(utc) and context['package_start']<=context['connection_start']<=started<=last[0]<=now<end and
                utc<context['utc_end'])
            last[0]=now
            tick();domain.sample()
            check(type(domain.peak) is int and 0<=domain.peak<=536870912)
            after=time.monotonic();check(_number(after) and now<=after<end and time.time()<context['utc_end'])
            last[0]=after
        stage('INITIAL_GUARD');guard()
        stage('WORKER_COMPILE');compiled=compile(package['worker_source'].decode('utf-8'),'<pinned-E127-capture-only>','exec')
        stage('FUNCTION_EXTRACTION')
        functions=[v for v in compiled.co_consts if isinstance(v,CodeType) and v.co_name=='capture_runtime']
        check(len(functions)==1)
        def supervise(argv,cwd,deadline,passed_domain,budget):
            stage('COMMAND_CHECK')
            check(calls[0]==0 and passed_domain is domain and cwd=='/' and type(budget) is list and
                len(budget)==1 and type(budget[0]) is int and budget[0]==65536 and _number(deadline) and started<deadline<=end and
                type(argv) is list and len(argv)==3 and argv[:2]==['/bin/bash','-lc'] and type(argv[2]) is str and
                argv[2].startswith('module load mentor/tessent2021 >/dev/null && /usr/bin/python3 -I -S -B -c '))
            calls[0]+=1
            stage('PRE_CHILD_GUARD');guard()
            metadata['command_sha256']=sha(canonical(argv))
            stage('SUPERVISION')
            observed=direct.base.supervise(argv,cwd,min(deadline,end),domain,budget,scratch=SimpleNamespace(sample=guard))
            stage('OUTPUT_BOUND')
            check(type(observed) is dict and type(observed.get('output')) is bytes and len(observed['output'])<=65536)
            raw=observed['output']
            metadata.update(bytes=len(raw),sha256=sha(raw),cleaned=observed.get('cleaned') is True,
                returncode=observed.get('returncode') if type(observed.get('returncode')) is int else None)
            stage('OBSERVATION_CHECK')
            if type(observed.get('failure')) is str and observed['failure'] in SUPERVISOR_LITERAL_CODES:
                state['literal']=observed['failure']
            check(observed.get('launch_attempted') is True and observed.get('cleaned') is True and
                type(observed.get('returncode')) is int and observed['returncode']==0 and observed.get('failure') is None)
            return observed
        loads=[0]
        class JsonProxy(object):
            @staticmethod
            def loads(raw,**kwargs):
                stage('OUTPUT_JSON' if loads[0]==0 else 'PREPARATION_JSON')
                check(loads[0]<2);loads[0]+=1
                kwargs['object_pairs_hook']=pins._pairs
                def nonfinite(_):
                    raise ValueError('NONFINITE_JSON')
                kwargs['parse_constant']=nonfinite
                try:return json.loads(raw,**kwargs)
                except BaseException as exc:
                    remember(exc);raise
        class AdapterProxy(object):
            @staticmethod
            def prepare_runtime(*args):
                stage('PROFILE_COMPATIBILITY')
                try:return adapter.prepare_runtime(*args)
                except BaseException as exc:
                    remember(exc);raise
        reason_stages={'PROFILE_SOURCE_BINDING':'PROFILE_SOURCE_BINDING','BOOTSTRAP_PRIVATE_SCHEMA':'OUTPUT_SCHEMA',
            'BOOTSTRAP_PROFILE_DRIFT':'PROFILE_DRIFT','BOOTSTRAP_BOUND':'OUTPUT_BOUND','BOOTSTRAP_FAILED':'OBSERVATION_CHECK'}
        def original_require(ok,reason):
            stage(reason_stages.get(reason,'ORIGINAL_CALL'))
            check(ok,reason)
            if reason=='BOOTSTRAP_BOUND':stage('OUTPUT_JSON')
            elif reason=='BOOTSTRAP_PRIVATE_SCHEMA':stage('PREPARATION_JSON')
            elif reason=='PROFILE_SOURCE_BINDING':stage('CHILD_CODE_BUILD')
        namespace=dict(base64=base64,json=JsonProxy,shlex=shlex,time=time,require=original_require,sha=sha,profile=profile,
            adapter=AdapterProxy,NONCE='E127_PRIVATE_RUNTIME_V1',direct=SimpleNamespace(base=SimpleNamespace(supervise=supervise)),
            controller=SimpleNamespace(PACKAGE_END=end,material=SimpleNamespace(pins=pins)))
        namespace['capture_runtime']=FunctionType(functions[0],namespace,'capture_runtime')
        original_package=dict(runtime_profile_source=base64.b64encode(package['profile_source']).decode('ascii'),
            runtime_profile_source_sha256=PROFILE_SHA256,source_sha256={'prospective_runtime_profile_e112':PROFILE_SHA256},
            inputs={'e112':base64.b64encode(package['e112']).decode('ascii')})
        stage('ORIGINAL_CALL')
        values,_=namespace['capture_runtime'](original_package,domain,metadata)
        stage('POST_ORIGINAL_NORMALIZE')
        try:normalized,compatibility=adapter.prepare_runtime(values,decode(package['e112'])['runtime_profile'],LAUNCHER_SHA256)
        except BaseException as exc:
            remember(exc);raise
        stage('NORMALIZED_KEYS')
        check(type(normalized) is dict and set(normalized)<=set(profile.KEYS) and
            not set(normalized)&{'DEBUG','MGC_DFT_EXTRA_ARG','TESSENT_PATH'})
        stage('FINAL_GUARD');guard()
        stage('RECEIPT')
        compatibility_keys={'schema','status','compatibility_branch','raw_sha256','normalized_sha256','keys','launcher_sha256',
            'missing_mgc_root_preserved','values_disclosed_in_receipt','executable_tree_authenticated',
            'runtime_launch_success_verified','execution_ready','training_release'}
        check(type(compatibility) is dict and set(compatibility)==compatibility_keys and
            compatibility['schema']=='prospective-runtime-compatibility-e114-v1' and
            compatibility['status']=='COMPATIBLE_SHAPE_ONLY_NOT_ENVIRONMENT_AUTHENTICATION' and
            compatibility['compatibility_branch'] in ('OBSERVED_ROOTLESS_ABSOLUTE_LAUNCHER','EXPLICIT_VENDOR_ROOT') and
            _hex(compatibility['raw_sha256']) and _hex(compatibility['normalized_sha256']) and
            type(compatibility['keys']) is list and all(type(k) is str and k in profile.KEYS for k in compatibility['keys']) and
            len(compatibility['keys'])==len(set(compatibility['keys'])) and compatibility['launcher_sha256']==LAUNCHER_SHA256 and
            type(compatibility['missing_mgc_root_preserved']) is bool and
            all(compatibility[k] is False for k in ('values_disclosed_in_receipt','executable_tree_authenticated',
                'runtime_launch_success_verified','execution_ready','training_release')))
        receipt=dict(schema='e138-private-runtime-bootstrap-v1',status='COMPATIBLE_PROFILE_ONLY',stage_attempted=state['stage'],
            error_code=None,reviewed_literal_code=None,authorization_sha256=AUTH_SHA256,proposal_sha256=PROPOSAL_SHA256,
            context_sha256=CONTEXT_SHA256,root=ROOT,phase=PHASE,output_bytes=metadata['bytes'],output_sha256=metadata['sha256'],
            cleaned=metadata['cleaned'],returncode=metadata['returncode'],command_sha256=metadata['command_sha256'],
            bootstrap_children=calls[0],values_disclosed=False,compatibility=compatibility,
            environment_authenticated=False,full_executable_tree_authenticated=False,parent_shell_environment_sanitized=False,
            sampled_peak_rss_swap_bytes=domain.peak,bootstrap_counts_as_selftest=False,tessent_launches=0,execution_ready=False)
        result=PrivateRuntime(normalized,receipt)
        if type(evidence) is dict:evidence.update(receipt)
        return result
    except BaseException as exc:
        remember(exc)
        code='E138_BOOTSTRAP_'+state['stage']+'_FAILED'
        if type(evidence) is dict:
            evidence.update(dict(schema='e138-private-runtime-bootstrap-v1',status='FAILED',stage_attempted=state['stage'],
                error_code=code,reviewed_literal_code=state['literal'],values_disclosed=False,bootstrap_children=calls[0],
                output_bytes=metadata.get('bytes',0),output_sha256=metadata.get('sha256',sha(b'')),
                output_metadata_measured='bytes' in metadata,execution_ready=False))
        values=normalized=namespace=original_package=compatibility=result=None
    # Raise outside except: no secret exception context/cause is attached.
    raise ValueError(code) from None
