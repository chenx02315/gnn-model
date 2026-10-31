"""Inert, source-pinned E138 selector/STIL namespace derivation, not a release."""
import types
from . import physical_e138_contract as contract

FREEZE=None
SELECTOR_SHA='efcf80e98b4a26051d057320e4dc75882929545fbd42be41be4336a2586d5d73'
STIL_SHA='0ea8dcc1454306084d12a9f4ac439c6d19c8eed9e036aac85b0eac510caacc3d'
require,sha,canonical=contract.require,contract.sha,contract.canonical


def bind(selector_raw,stil_raw,authority,proposal):
    frozen=FREEZE
    require(type(frozen) is dict and set(frozen)=={'authorization_sha256','proposal_sha256','adapter_source_sha256'} and
        all(contract._hex(value) for value in frozen.values()) and
        globals().get('__source_sha256__')==frozen['adapter_source_sha256'],'E138_DEPENDENCY_FREEZE_REQUIRED')
    contract.check_authority(authority,proposal,frozen['authorization_sha256'],frozen['proposal_sha256'])
    for raw,pin in ((selector_raw,SELECTOR_SHA),(stil_raw,STIL_SHA)):
        require(type(raw) is bytes and 0<len(raw)<=131072 and sha(raw)==pin,'E138_DEPENDENCY_ORIGIN_PIN')
    def load(raw,name):
        module=types.ModuleType('src.data._e138_'+name);module.__package__='src.data'
        exec(compile(raw,'<e138-frozen-'+name+'>','exec'),module.__dict__)
        module.__source_sha256__=None;module.__origin_source_sha256__=sha(raw)
        return module
    selector,stil=load(selector_raw,'selector'),load(stil_raw,'stil')
    selector.RUN_ROOT=contract.ROOT  # Never relocate /cad, library or engine paths.
    old_root=stil.ROOT
    stil.ROOT=contract.ROOT;stil.PATTERN=contract.ROOT+'/inputs/tester.stil'
    stil.FIXED=tuple(dict(row,path=contract.ROOT+row['path'][len(old_root):]) for row in stil.FIXED)
    # This is the origin function's raw source identity, not an assertion that
    # its effective namespace is identical to the historical module.
    stil.verify.__source_sha256__=STIL_SHA
    config=dict(run_root=contract.ROOT,pattern=stil.PATTERN,fixed=list(stil.FIXED),
        vendor_root=selector.ROOT,candidate_paths=list(selector.CANDIDATES))
    receipt=dict(schema='e138-derived-dependency-binding-v1',
        selector_origin_sha256=SELECTOR_SHA,stil_origin_sha256=STIL_SHA,
        adapter_source_sha256=frozen['adapter_source_sha256'],effective_config_sha256=sha(canonical(config)),
        execution_ready=False,full_dependency_provenance_verified=False)
    return dict(selector=selector,stil=stil,binding=receipt)
