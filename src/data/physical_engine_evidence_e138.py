"""Native E138 admission around frozen finite-path sampling primitives.

No transport, search or tool launch. Source/context pins must be independently
frozen by the future complete entrypoint. The injected tick owns resource
sampling. Boot and module attributes are not independently authenticated here.
"""
import math
import re
import types
from . import physical_e138_contract as contract
from . import physical_e138_dependency_binding as binding

FREEZE=None
_USED=False
SAMPLER_SHA='b1ed9394047575d4066459b091d2b7bcb542342711152530c1a22506db0f3df2'
require,sha,canonical,decode=contract.require,contract.sha,contract.canonical,contract.decode


def _number(value):return type(value) in (int,float) and math.isfinite(value) and value>=0


def _load(raw,name):
    module=types.ModuleType('src.data._e138_engine_'+name);module.__package__='src.data'
    exec(compile(raw,'<e138-frozen-'+name+'>','exec'),module.__dict__)
    module.__source_sha256__=None;module.__origin_source_sha256__=sha(raw)
    return module


def collect(package,sampler_raw,selector_raw,runtime_boot_id,plan,tick,monotonic,utc_now):
    global _USED
    f=FREEZE
    require(type(f) is dict and set(f)=={'authorization_sha256','proposal_sha256','context_sha256','adapter_source_sha256'} and
        all(contract._hex(pin) for pin in f.values()) and globals().get('__source_sha256__')==f['adapter_source_sha256'],
        'E138_ENGINE_FREEZE_REQUIRED')
    require(not _USED,'E138_ENGINE_ONE_COLLECTION_NO_RETRY')
    require(type(package) is dict and set(package)=={'authority','proposal','context'} and
        all(type(raw) is bytes and 0<len(raw)<=65536 for raw in package.values()),'E138_ENGINE_PACKAGE')
    contract.check_authority(package['authority'],package['proposal'],f['authorization_sha256'],f['proposal_sha256'])
    require(len(package['context'])<=4096 and sha(package['context'])==f['context_sha256'],'E138_ENGINE_CONTEXT_PIN')
    c=decode(package['context'])
    require(type(c) is dict and set(c)=={'role','authorization_sha256','boot_id','root','phase','package_start',
        'package_end','connection_start','utc_end'} and c['role']=='execution' and
        c['authorization_sha256']==f['authorization_sha256'] and c['root']==contract.ROOT and c['phase']==contract.PHASE and
        type(runtime_boot_id) is str and runtime_boot_id==c['boot_id'] and
        re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',runtime_boot_id) and
        all(_number(c[k]) for k in ('package_start','package_end','connection_start','utc_end')) and
        c['package_end']==c['package_start']+3600 and c['package_start']<=c['connection_start']<c['package_end'],
        'E138_ENGINE_ORIGINAL_CONTEXT')
    require(all(type(raw) is bytes and 0<len(raw)<=131072 and sha(raw)==pin
        for raw,pin in ((sampler_raw,SAMPLER_SHA),(selector_raw,binding.SELECTOR_SHA))), 'E138_ENGINE_SOURCE_PIN')
    require(all(callable(fn) for fn in (tick,monotonic,utc_now)),'E138_ENGINE_GUARDS')
    _USED=True
    start=monotonic();require(_number(start),'E138_ENGINE_CLOCK')
    end=min(c['package_end'],c['connection_start']+2400);last=[start]
    def guard():
        now,utc=monotonic(),utc_now()
        require(_number(now) and _number(utc) and c['package_start']<=c['connection_start']<=start<=last[0]<=now<end and
            utc<c['utc_end'],'E138_ENGINE_DEADLINE')
        last[0]=now;tick()
        now,utc=monotonic(),utc_now()
        require(_number(now) and _number(utc) and last[0]<=now<end and utc<c['utc_end'],'E138_ENGINE_DEADLINE')
        last[0]=now
    guard()
    selector=_load(selector_raw,'selector');selector.RUN_ROOT=contract.ROOT
    sampler=_load(sampler_raw,'sampler');sampler.selector=selector;sampler.collect=None
    selector._validate_plan(plan)
    guard();budget=[0]
    rows={path:sampler.sample_path(path,guard,budget) for path in sampler.PATHS}
    require(all(rows[path]['state']=='PRESENT' for path in sampler.CHAIN),'ENGINE_VENDOR_CHAIN_MISSING')
    candidates={path:{k:v for k,v in rows[path].items() if k in ('state','identity')} for path in selector.CANDIDATES}
    classification=selector.classify(plan,candidates)
    require(classification['status']=='CONDITIONALLY_SELECTED','ENGINE_OBSERVED_BRANCH_NOT_VIABLE')
    effective=dict(run_root=selector.RUN_ROOT,vendor_root=selector.ROOT,paths=list(sampler.PATHS),
        chunk=sampler.CHUNK,max_file=sampler.MAX_FILE,max_total=sampler.MAX_TOTAL)
    result=dict(schema='e138-finite-engine-evidence-v1',files=rows,classification=classification,
        bytes_hashed=budget[0],plan=selector.redact_plan(plan),
        binding=dict(sampler_origin_sha256=SAMPLER_SHA,selector_origin_sha256=binding.SELECTOR_SHA,
            adapter_source_sha256=f['adapter_source_sha256'],effective_config_sha256=sha(canonical(effective))),
        context_sha256=f['context_sha256'],runtime_boot_observed_here=False,memory_enforcement_verified=False,
        engine_identity_authenticated=False,dynamic_library_closure_verified=False,ldd_behavior_verified=False,
        execution_ready=False)
    require(len(canonical(result))<=sampler.MAX_RESPONSE,'E138_ENGINE_RESPONSE_BOUND');guard()
    return result
