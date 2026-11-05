"""Read-only fixed local E138 preparation. No authority or execution release.

Private byte material stays in RAM. Only public_summary() is exportable; it
contains paths, roles, lengths, hashes and fixed check statuses, never bodies,
environment values or vendor source. No alternate cache search or writes.
"""
import ast
import base64
import hashlib
import json
from pathlib import Path
import stat

from src.data import physical_e138_contract as contract
from src.data import physical_e138_batch_assembler as assembler
from src.data import physical_e138_readback_runtime as readback
from src.data import physical_engine_selector_e137 as selector
from src.data import physical_runtime_bootstrap_e138 as bootstrap
from src.data import physical_f_replay_execution_e135 as execution

E128_SHA256='d70818980f52ad17e9a1d7eb917d9618d1bf203d4ec29b7e780430529528189e'
MODULE_CAP=262144
TOTAL_CAP=4194304
sha=lambda raw:hashlib.sha256(raw).hexdigest()


class MaterialFailure(ValueError):
    pass


def require(ok,code):
    if not ok:raise MaterialFailure(code)


def _read(path,cap,pin=None):
    """Single bounded regular-file read; no symlink/reparse leaves."""
    try:
        info=path.lstat()
        require(stat.S_ISREG(info.st_mode) and not path.is_symlink() and
            not getattr(info,'st_file_attributes',0)&1024 and 0<info.st_size<=cap,
            'REFUSED_FILE_TYPE_OR_SIZE')
        with path.open('rb') as stream:raw=stream.read(cap+1)
        require(0<len(raw)<=cap and len(raw)==info.st_size,'READ_SIZE_CHANGED')
        digest=sha(raw)
        require(pin is None or digest==pin,'PIN_MISMATCH')
        return raw
    except MaterialFailure:raise
    except (OSError,ValueError):raise MaterialFailure('MISSING_OR_REFUSED_FIXED_FILE') from None


def _static(node,values):
    if isinstance(node,ast.Name):return values[node.id]
    if isinstance(node,ast.Attribute):
        base=_static(node.value,values)
        if type(base) is str and base.startswith('@module:'):return base+'.'+node.attr
        raise ValueError('UNRESOLVED_ATTRIBUTE')
    if isinstance(node,ast.Call) and isinstance(node.func,ast.Name):
        if node.func.id=='dict' and not node.args:
            return {k.arg:_static(k.value,values) for k in node.keywords}
        if node.func.id=='frozenset' and len(node.args)==1:
            return frozenset(_static(node.args[0],values))
    if isinstance(node,(ast.Tuple,ast.List,ast.Set)):
        items=[_static(v,values) for v in node.elts]
        return tuple(items) if isinstance(node,ast.Tuple) else (set(items) if isinstance(node,ast.Set) else items)
    if isinstance(node,ast.Dict):return {_static(k,values):_static(v,values) for k,v in zip(node.keys,node.values)}
    return ast.literal_eval(node)


def _tree(raw):
    # Hash before parsing, including unpinned locally reviewed current sources.
    sha(raw)
    try:return ast.parse(raw.decode('utf-8'),feature_version=(3,6))
    except (SyntaxError,UnicodeError):raise MaterialFailure('PYTHON36_SOURCE_REQUIRED') from None


def _declarations(tree):
    values={}
    for node in tree.body:
        if isinstance(node,ast.ImportFrom) and node.level==1:
            for alias in node.names:
                target=(node.module+'.'+alias.name) if node.module else alias.name
                values[alias.asname or alias.name]='@module:'+target
    for node in tree.body:
        if isinstance(node,ast.Assign):
            try:value=_static(node.value,values)
            except (ValueError,KeyError,TypeError,AttributeError):
                declared=[target.id for target in node.targets if isinstance(target,ast.Name)]
                if set(declared)&{'DEPENDENCY_SHA256','SOURCE_PINS','PINNED_DEPENDENCIES','HELPER_PINS'}:
                    raise MaterialFailure('UNRESOLVED_NATIVE_PIN_DECLARATION') from None
                continue
            for target in node.targets:
                if isinstance(target,ast.Name):values[target.id]=value
    return values


def _closure(repo,seeds):
    """Pure source compilation order, never imports/executes candidate bodies."""
    sources={};trees={};declarations={};edges={};active=set();order=[]
    def visit(name):
        require(type(name) is str and name.replace('_','').isalnum(),'INVALID_MODULE_NAME')
        if name in active:raise MaterialFailure('SOURCE_IMPORT_CYCLE')
        if name in sources:return
        require(len(sources)<96,'SOURCE_MODULE_CAP')
        raw=_read(repo/'src/data'/(name+'.py'),MODULE_CAP)
        sources[name]=raw
        require(sum(map(len,sources.values()))<=TOTAL_CAP,'SOURCE_TOTAL_CAP')
        tree=_tree(raw);trees[name]=tree;declarations[name]=_declarations(tree)
        deps=set()
        for node in ast.walk(tree):
            if isinstance(node,ast.ImportFrom):
                if node.level==1:
                    if node.module:deps.add(node.module.split('.')[0])
                    else:deps.update(alias.name for alias in node.names)
                elif node.level==0 and node.module and node.module.startswith('src.data.'):
                    deps.add(node.module.split('.')[2])
                elif node.level==0 and node.module=='src.data':deps.update(a.name for a in node.names)
                elif node.level>1:raise MaterialFailure('UNSUPPORTED_LOCAL_IMPORT')
                elif node.module and node.module.split('.')[0] in ('src','scripts','tests'):
                    raise MaterialFailure('UNSUPPORTED_PROJECT_IMPORT')
            elif isinstance(node,ast.Import):
                for alias in node.names:
                    if alias.name.startswith('src.data.') and len(alias.name.split('.'))==3:
                        deps.add(alias.name.split('.')[2])
                    elif alias.name.split('.')[0] in ('src','scripts','tests'):
                        raise MaterialFailure('UNSUPPORTED_PROJECT_IMPORT')
        edges[name]=deps
        active.add(name)
        for dependency in sorted(deps):visit(dependency)
        active.remove(name);order.append(name)
    for name in sorted(seeds):visit(name)
    # Verify declared native dependency pins, not caller-provided replacement pins.
    checks=[]
    def module_reference(reference):
        require(type(reference) is str and reference.startswith('@module:'),'NATIVE_MODULE_ALIAS_INVALID')
        target=reference[8:]
        for _ in range(8):
            if '.' not in target:return target
            parent,alias=target.split('.',1)
            replacement=declarations.get(parent,{}).get(alias)
            require(type(replacement) is str and replacement.startswith('@module:'),
                'NATIVE_MODULE_ALIAS_INVALID')
            target=replacement[8:]
        raise MaterialFailure('NATIVE_MODULE_ALIAS_DEPTH')
    for owner,values in declarations.items():
        for field in ('DEPENDENCY_SHA256','SOURCE_PINS','PINNED_DEPENDENCIES'):
            pins=values.get(field)
            require(pins is None or type(pins) in (dict,tuple),'NATIVE_PIN_DECLARATION_TYPE_INVALID')
            if type(pins) is tuple:
                for row in pins:
                    require(type(row) is tuple and len(row)==2,'NATIVE_MODULE_ALIAS_PIN_INVALID')
                    target=module_reference(row[0]);pin=row[1]
                    require(target in sources and contract._hex(pin) and sha(sources[target])==pin,
                        'NATIVE_MODULE_ALIAS_PIN_MISMATCH')
                    checks.append((owner,target))
            if type(pins) is dict:
                if owner=='prospective_generation_recipe_e108' and field=='SOURCE_PINS':
                    # Explicit non-module Tcl artifact map, not a source alias map.
                    require(set(pins)=={'common','incremental'} and all(type(row) is tuple and
                        len(row)==3 and type(row[0]) is int and all(contract._hex(p) for p in row[1:])
                        for row in pins.values()),'NATIVE_ARTIFACT_PIN_MAP_INVALID')
                    continue
                for name,pin in pins.items():
                    target=name[9:] if type(name) is str and name.startswith('src.data.') else name
                    require(type(target) is str and target in sources and contract._hex(pin),
                        'NATIVE_DEPENDENCY_TARGET_OR_PIN_INVALID')
                    require(sha(sources[target])==pin,'NATIVE_DEPENDENCY_PIN_MISMATCH')
                    checks.append((owner,target))
    # Dynamic private compilation is deliberately included in the roster above.
    special={('physical_e138_dependency_binding','SELECTOR_SHA'):'physical_engine_selector_e137',
        ('physical_e138_dependency_binding','STIL_SHA'):'physical_stil_dependencies_e137',
        ('physical_e138_runtime_primitives','ORIGIN_RUNTIME_SHA256'):'physical_f_replay_execution_e135',
        ('physical_e138_runtime_primitives','ORIGIN_STORAGE_SHA256'):'prospective_generation_storage_e118',
        ('physical_e138_root_receipt','LEGACY_RUNTIME_SHA'):'physical_f_replay_execution_e135',
        ('physical_e138_root_receipt','ANCHOR_SOURCE_SHA'):'prospective_acceptance_materializer_v1',
        ('physical_engine_evidence_e138','SAMPLER_SHA'):'physical_engine_evidence_e137',
        ('physical_engine_selector_e137','PINNED_DEPENDENCY_SHA256'):'physical_replay_source_reader_e135',
        ('physical_f_replay_recipe_e138','EXPECTED_PARENT_SOURCE_SHA256'):'physical_f_replay_recipe_e135_r2'}
    for (owner,field),name in special.items():
        if owner in declarations:
            pin=declarations[owner].get(field)
            require(name in sources and contract._hex(pin) and sha(sources[name])==pin,
                    'NATIVE_ORIGIN_PIN_MISMATCH')
            checks.append((owner,name))
    helpers=declarations.get('physical_e138_runtime_primitives',{}).get('HELPER_PINS',{})
    helper_names=dict(io='prospective_acceptance_materializer_v1',process='prospective_generation_process_e113',
        launch_base='prospective_generation_supervision_e109',faults='prospective_fault_translation_e129',
        evidence='eq_group_coverage_e133_r2',direct='direct_tessent_acceptance_e104')
    if helpers:
        require(set(helpers)==set(helper_names),'NATIVE_HELPER_ROSTER_MISMATCH')
        for alias,name in helper_names.items():
            require(name in sources and sha(sources[name])==helpers[alias],'NATIVE_HELPER_PIN_MISMATCH')
            checks.append(('physical_e138_runtime_primitives',name))
    return dict(sources=sources,source_order=tuple(order),source_sha256={n:sha(v) for n,v in sources.items()},
                dependency_checks=len(checks))


def source_materials(repo):
    """Build actual role rosters including private assembler source origins."""
    seeds=dict(capture={'physical_e138_contract','physical_replay_capture_e138','physical_e138_runtime_primitives'},
        execution=set(assembler.COMPONENTS.values())|set(assembler.ORIGINS.values())|
            set(assembler.INPUT_SOURCES.values())|set(contract.REQUIRED_SOURCES)|{'physical_e138_batch_assembler'},
        readback=set(readback.REQUIRED))
    return {role:_closure(repo,names) for role,names in seeds.items()}


class Materials:
    __slots__=('_inputs','_roles','_summary')
    def __init__(self,inputs,roles,summary):self._inputs,self._roles,self._summary=inputs,roles,summary
    def __repr__(self):return '<E138 LOCAL MATERIALS PRIVATE_RAM_ONLY; use public_summary()>'
    def __reduce_ex__(self,protocol):raise TypeError('E138_MATERIALS_NOT_SERIALIZABLE')
    def private_bytes(self):
        require(self._summary['status']=='READY_LOCAL_MATERIALS_ONLY','FIXED_MATERIALS_NOT_READY')
        return dict(execution_inputs=dict(self._inputs),roles=self._roles)
    def public_summary(self):return json.loads(json.dumps(self._summary))


def prepare():
    """Fixed actual repo/cache only. Returns missing evidence, never substitutes."""
    repo=Path(__file__).resolve().parents[1]
    staging=repo.parent/'runtime_training_staging_20260928'
    inputs={};roles={};rows=[]
    def read(role,path,cap,pin):
        row=dict(role=role,path=str(path),bytes=None,sha256=None,check='MISSING_OR_REFUSED')
        rows.append(row)
        try:
            raw=_read(path,cap,pin)
            row.update(bytes=len(raw),sha256=sha(raw),check='PIN_VERIFIED')
            return raw
        except MaterialFailure as exc:
            row['check']=exc.args[0]
            return None
    supplement=staging/'v6_e137_engine_source_supplement_r1/files'
    requests=dict(functions=(supplement/selector.FUNCTIONS_SHA,selector.FUNCTIONS_BYTES,selector.FUNCTIONS_SHA),
        shell=(supplement/selector.SHELL_SHA,selector.SHELL_BYTES,selector.SHELL_SHA),
        e112=(staging/'v6_e112_preparation_20261026_r1/stdout.json',262144,bootstrap.E112_SHA256),
        parent_worker_source=(repo/'scripts/worker_pt_label_generation_e127.py',131072,bootstrap.WORKER_SHA256),
        profile_source=(repo/'src/data/prospective_runtime_profile_e112.py',65536,bootstrap.PROFILE_SHA256))
    for name,(path,cap,pin) in requests.items():
        raw=read(name,path,cap,pin)
        if raw is not None:inputs[name]=raw
    proof=read('incremental_proof',staging/'v6_e128_failure_readback_20261027_r1/stdout.json',262144,E128_SHA256)
    if proof is not None:
        try:
            value=json.loads(proof.decode('utf-8'),object_pairs_hook=contract._pairs,
                parse_float=contract._finite_float,parse_constant=contract._nonfinite)
            candidates=[r for r in value['files'] if r.get('sha256')==execution.BASE_TCL_SHA256]
            require(len(candidates)==1,'EXACT_INCREMENTAL_ROW_REQUIRED')
            row=candidates[0]
            require(type(row['body_base64']) is str and len(row['body_base64'])<=349528,'INCREMENTAL_BODY_CAP')
            tcl=base64.b64decode(row['body_base64'],validate=True)
            require(0<len(tcl)<=262144 and sha(tcl)==execution.BASE_TCL_SHA256,'INCREMENTAL_BODY_PIN')
            inputs['incremental']=tcl
            rows.append(dict(role='incremental',path='fixed-e128-proof:exact-base-tcl-sha256',bytes=len(tcl),sha256=sha(tcl),check='PIN_VERIFIED'))
        except (ValueError,KeyError,TypeError,AttributeError):
            rows[-1]['check']='INVALID_PINNED_INCREMENTAL_PROOF'
    try:
        roles=source_materials(repo)
        for role,bundle in roles.items():
            for name in bundle['source_order']:
                raw=bundle['sources'][name]
                rows.append(dict(role=role,path=str(repo/'src/data'/(name+'.py')),bytes=len(raw),sha256=sha(raw),check='SOURCE_CLOSURE_AND_NATIVE_PINS_VERIFIED'))
        for key,name in assembler.INPUT_SOURCES.items():inputs[key]=roles['execution']['sources'][name]
        inputs['parent_helper']=execution.EXPECTED_INIT.encode('ascii')
        inputs['policy']=contract.canonical(contract.POLICY)
        for name in ('parent_helper','policy'):
            raw=inputs[name]
            rows.append(dict(role=name,path='fixed-native-constant',bytes=len(raw),sha256=sha(raw),check='NATIVE_CONSTANT_BYTES'))
    except MaterialFailure as exc:
        rows.append(dict(role='source_closure',path=str(repo/'src/data'),bytes=None,sha256=None,check=exc.args[0]))
    needed=contract.INPUT_KEYS-{'authority','proposal','original_clock','role1_response','role2_intent'}
    ready=set(inputs)==needed and set(roles)=={'capture','execution','readback'} and all(row['check'] in
        ('PIN_VERIFIED','SOURCE_CLOSURE_AND_NATIVE_PINS_VERIFIED','NATIVE_CONSTANT_BYTES') for row in rows)
    summary=dict(status='READY_LOCAL_MATERIALS_ONLY' if ready else 'MISSING_OR_INVALID_FIXED_MATERIALS',artifacts=rows,
        execution_ready=False,authority_supplied=False,remote_execution_observed=False)
    return Materials(inputs,roles,summary)
