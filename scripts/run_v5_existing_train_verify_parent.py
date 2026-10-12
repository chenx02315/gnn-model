"""Serial resource-guarded read-only replay of 18 existing TRAIN checkpoints.

This parent imports no ML, calls no fit or optimizer, and never edits TRAIN
artifacts/once. All execution anchors and review are supplied independently.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import importlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
from types import ModuleType

ROOT='/ssd/cjc/gnn_model_ranking_v5_verify_20261012_r1'
TRAIN_ROOT='/ssd/cjc/gnn_model_ranking_v5_train_20261011_r2'
PACKAGE_ROOT='/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/train_folds'
PROGRAM='scripts/run_v5_existing_train_verify_parent.py'
CHILD='scripts/verify_ranking_v5_existing_train.py'
JIT='src/models/ranking_v5_verify_jit_admission_v1.py'
JIT_SHA='e572e7f255ff6f62903c476a22370baa7d2984f67a387e8fa76ea4dad91027b3'
AUTH_SHA='2163d176252279b850dfb8cc0004547858ba79ee894b822e7ae7a180c5c7ac20'
ARTIFACT_SHA='a81a30341c0f0e6b90435b7b4417c39b6ed23db33dbb9fcf1aad7778e1d6534c'
LEGACY_TRUST_SHA='6a6365e993caee509ef57384ad7abd1a3c1ec2c4368084bf1af39bd02e4dab0e'
FENCE='src/models/ranking_v5_frozen_import_fence.py'
FENCE_SHA='c8ba5ae9bc8f900a620b7eaf03e37e11f303d9fc8b08ccbc8c423682b0afafed'
GUARD='src/models/ranking_v4_memory_guard.py'
GUARD_SHA='3dcaf6fd545aa1c5358146567cf55a8ac6593aa14af42f31ec965f8f62c79896'
CORE_MANIFEST='data/manifests/ranking_v5_caller_source_bytes_20261008.json'
CORE_SHA='5394779faac5c77800a0a9d8ed52bf9f24ba2dd701f499a49754e51e7ddceae7'
CORE_FILES=frozenset(("requirements/runtime_v2.lock.txt",
"scripts/ranking_v4_near_optimal_pairs.py",
"src/data/ranking_v3_real_fold_package.py",
"src/models/neural_ranking_v3.py",
"src/models/preflight_runtime_v2.py",
"src/models/ranking_v3_freeze_io.py",
"src/models/ranking_v4_memory_guard.py",
"src/models/ranking_v4_training_worker.py",
"src/models/ranking_v5_approval_binding.py",
"src/models/ranking_v5_bound_input_reader.py",
"src/models/ranking_v5_caller_source_binding.py",
"src/models/ranking_v5_execution_boundary.py",
"src/models/ranking_v5_head_objective.py",
"src/models/ranking_v5_held_replay_reader.py",
"src/models/ranking_v5_package_binding.py",
"src/models/ranking_v5_parent_guard_receipt.py",
"src/models/ranking_v5_physical_worker.py",
"src/models/ranking_v5_real_artifact_store.py",
"src/models/ranking_v5_real_request_loader.py",
"src/models/ranking_v5_single_fit_worker.py",
"src/models/ranking_v5_training_kernel.py",
"src/models/ranking_v5_v3_fold_adapter.py",
"src/models/ranking_v5_worker_resource_context.py",
"src/models/run_runtime_ranking_v3.py",
"src/models/runtime_ranking_v3.py",
"src/models/runtime_training_v2.py",))
LEGACY_FILES=frozenset(("data/fixtures/ranking_v5_remote_module_non_scriptable_20261010.txt",
"requirements/runtime_v2.lock.txt",
"scripts/ranking_v4_near_optimal_pairs.py",
"scripts/run_v5_controlled_runtime_gate.py",
"scripts/run_v5_fx2trt_optimizer_gate.py",
"scripts/run_v5_train_serial_parent_v3.py",
"scripts/run_v5_train_single_fit_v3.py",
"src/data/ranking_v3_real_fold_package.py",
"src/models/neural_ranking_v3.py",
"src/models/preflight_runtime_v2.py",
"src/models/ranking_v3_freeze_io.py",
"src/models/ranking_v4_memory_guard.py",
"src/models/ranking_v4_training_worker.py",
"src/models/ranking_v5_approval_binding.py",
"src/models/ranking_v5_bound_input_reader.py",
"src/models/ranking_v5_caller_source_binding.py",
"src/models/ranking_v5_execution_boundary.py",
"src/models/ranking_v5_freeze_codec_v2.py",
"src/models/ranking_v5_freeze_supplement_v2.py",
"src/models/ranking_v5_frozen_import_fence.py",
"src/models/ranking_v5_fx2trt_probe_admission.py",
"src/models/ranking_v5_head_objective.py",
"src/models/ranking_v5_held_replay_reader.py",
"src/models/ranking_v5_independent_fit_context_v2.py",
"src/models/ranking_v5_jit_template_admission.py",
"src/models/ranking_v5_locked_runtime_imports.py",
"src/models/ranking_v5_locked_runtime_observations.py",
"src/models/ranking_v5_package_binding.py",
"src/models/ranking_v5_parent_artifact_candidate_v2.py",
"src/models/ranking_v5_parent_guard_receipt.py",
"src/models/ranking_v5_physical_worker.py",
"src/models/ranking_v5_real_artifact_store.py",
"src/models/ranking_v5_real_artifact_store_v2.py",
"src/models/ranking_v5_real_request_loader.py",
"src/models/ranking_v5_serial_matrix.py",
"src/models/ranking_v5_single_fit_worker.py",
"src/models/ranking_v5_single_fit_worker_v2.py",
"src/models/ranking_v5_train_artifact_readback_v2.py",
"src/models/ranking_v5_train_jit_admission_v3.py",
"src/models/ranking_v5_training_kernel.py",
"src/models/ranking_v5_v3_fold_adapter.py",
"src/models/ranking_v5_worker_resource_context.py",
"src/models/run_runtime_ranking_v3.py",
"src/models/runtime_ranking_v3.py",
"src/models/runtime_training_v2.py",))
NEW_FILES=frozenset((PROGRAM,CHILD,JIT))
FAMILIES=('iwls_aes_core','iscas89_s13207','iscas89_s15850','iscas89_s35932','iscas89_s38417','iwls_spi')
SEEDS=(20260824,20260825,20260826)
EXPECTED_AUTH=json.loads("{\"schema\":\"v5-existing-train-readonly-replay-authorization-v1\",\"authorization_id\":\"USER_READONLY_V5_REPLAY_20261012\",\"basis\":\"User replied 授权，继续 to the explicit proposal to read-only load the existing trained models and recompute TRAIN frozen predictions and metrics, without retraining or BLIND access and with the original memory cap.\",\"scope\":\"EXISTING_18_TRAIN_CHECKPOINTS_READONLY_PREDICTION_AND_METRIC_REPLAY\",\"artifact_root\":\"/ssd/cjc/gnn_model_ranking_v5_train_20261011_r2\",\"verification_root\":\"/ssd/cjc/gnn_model_ranking_v5_verify_20261012_r1\",\"package_root\":\"/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/train_folds\",\"artifact_receipt_sha256\":\"a81a30341c0f0e6b90435b7b4417c39b6ed23db33dbb9fcf1aad7778e1d6534c\",\"launch_receipt_sha256\":\"b549685a8d3f2e7533f8b89f0febad109936a128f73fb7aef9abce5dc6b1ba1b\",\"implementation_commit\":\"f19c04e67d1389bd06ffe36b5b8b64c3cf27d7cb\",\"families\":[\"iwls_aes_core\",\"iscas89_s13207\",\"iscas89_s15850\",\"iscas89_s35932\",\"iscas89_s38417\",\"iwls_spi\"],\"seeds\":[20260824,20260825,20260826],\"model_load_count_max\":18,\"roles\":[\"TRAIN\"],\"weights_only_required\":true,\"cpu_only\":true,\"threads\":1,\"workers\":1,\"combined_rss_cap_bytes\":1073741824,\"address_space_cap_bytes\":8589934592,\"timeout_seconds_per_child\":1800,\"automatic_retries\":0,\"stop_on_first_failure\":true,\"held_labels_after_exact_prediction_freeze_match_only\":true,\"old_artifacts_and_training_once_readonly\":true,\"temporary_jit_and_small_receipts_in_new_verification_root_only\":true,\"training_allowed\":false,\"optimizer_allowed\":false,\"blind_validation_pilot_allowed\":false,\"lsf_tessent_allowed\":false,\"protected_root_access_allowed\":false,\"gate_and_independent_review_required_before_execution\":true,\"contract_is_record_not_self_proving_user_consent\":true}")
JSON_CAP=20480
GLOBAL_LOCK='/ssd/cjc/gnn_model_ranking_v5_serial_parent.lock'
ONCE=ROOT+'/verification.once.json'
INTERPRETER='/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/venv/bin/python'
SEARCH_PATHS=('/usr/lib/python311.zip','/usr/lib/python3.11','/usr/lib/python3.11/lib-dynload',
 '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/venv/lib/python3.11/site-packages',
 '/ssd/cjc/gnn_model_runtime_v2_98efbd4f_20261002T235119/venv/lib/python3.11/site-packages')
PLAN_FIELDS={'schema','verification_root','artifact_root','package_root','authorization_sha256',
 'artifact_receipt_sha256','legacy_trust_sha256','source_sha256','families','seeds'}
REVIEW_FIELDS={'schema','status','plan_sha256','source_binding_sha256','authorization_sha256',
 'artifact_receipt_sha256','full_regression_sha256','linux_unit_sha256','fresh_gate_receipt_sha256'}
FRESH_FIELDS={'schema','status','verification_root','plan_sha256','source_binding_sha256',
 'authorization_sha256','artifact_receipt_sha256','legacy_trust_sha256','fresh_utc',
 'source_count_verified','model_deserializations','training_invocations','once_absent',
 'absent_output_count','global_lock_acquired_and_released','memory_policy','effective_total_bytes',
 'initial_available_bytes','reserve_bytes','runtime_metadata_status','runtime_distribution_count'}


def require(ok, code):
    if not ok:raise ValueError('V5_EXISTING_VERIFY_PARENT_'+code)


def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(v):return type(v) is str and re.fullmatch('[0-9a-f]{64}',v) is not None
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def equal(a,b):
    if type(a) is not type(b):return False
    if type(b) is dict:return a.keys()==b.keys() and all(equal(a[k],b[k]) for k in b)
    if type(b) is list:return len(a)==len(b) and all(equal(x,y) for x,y in zip(a,b))
    return a==b


def decode(raw, cap=JSON_CAP):
    require(type(raw) is bytes and 0<len(raw)<=cap,'JSON_BOUND')
    def unique(pairs):
        result={}
        for k,v in pairs:
            require(k not in result,'DUPLICATE');result[k]=v
        return result
    def invalid(_):raise ValueError('V5_EXISTING_VERIFY_PARENT_NONFINITE')
    try:return json.loads(raw,object_pairs_hook=unique,parse_constant=invalid)
    except (UnicodeError,RecursionError,json.JSONDecodeError) as e:
        raise ValueError('V5_EXISTING_VERIFY_PARENT_JSON') from e


def lexical(path):
    raw=str(path);text=raw.replace('\\','/')
    windows=os.name=='nt' and re.match('^[A-Za-z]:/',text) is not None
    require((text.startswith('/') or windows) and ('\\' not in raw or windows) and '//' not in text
        and all(p not in ('','.','..') for p in text.split('/')[1:]),'PATH')
    require(not (text.casefold()=='/ssd/cjc/multimode_ate_gnn_v1'
        or text.casefold().startswith('/ssd/cjc/multimode_ate_gnn_v1/')),'PROTECTED')
    return Path(path)


def ordinary(s,directory=False):
    require(not stat.S_ISLNK(s.st_mode) and not getattr(s,'st_file_attributes',0)&0x400
            and (stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode)),'ORDINARY')


def read(path,cap):
    path=lexical(path)
    for q in path.parents:ordinary(q.lstat(),True)
    before=path.lstat();ordinary(before)
    require(before.st_nlink==1 and 0<before.st_size<=cap,'FILE_BOUND')
    identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_BINARY',0))
    with os.fdopen(fd,'rb') as stream:
        opened=os.fstat(stream.fileno());ordinary(opened)
        require(identity(opened)==identity(before),'IDENTITY')
        raw=stream.read(cap+1);after=os.fstat(stream.fileno())
    final=path.lstat();ordinary(final)
    require(len(raw)==before.st_size and final.st_nlink==1
        and all(identity(s)==identity(before) for s in (after,final)),'CHANGED')
    return raw


def pinned(path,digest,cap):
    require(pin(digest),'PIN');raw=read(path,cap)
    require(sha(raw)==digest,'SHA');return raw


def external(raw,name):
    m=ModuleType(name);m.__file__='sealed-readonly-parent://'+name
    exec(compile(raw,m.__file__,'exec'),m.__dict__);return m


def tasks():
    return tuple((f,s) for f in FAMILIES for s in SEEDS)


def log_path(family,seed):
    require((family,seed) in tasks(),'TASK')
    return ROOT+'/verify_'+family+'_'+str(seed)+'.stdout.log'


def absent_paths():
    return (ONCE,ROOT+'/matrix.started.json',ROOT+'/matrix.final.json',ROOT+'/jit_tmp')+tuple(
        path for f,s in tasks() for path in (log_path(f,s),log_path(f,s)+'.memory.json'))


def absent(path):
    lexical(path);require(not os.path.lexists(path),'EXISTS')


def write_once(path,payload):
    path=lexical(path)
    require(path.as_posix().startswith(ROOT+'/'),'WRITE_ROOT')
    raw=canonical(payload)+b'\n';require(0<len(raw)<=JSON_CAP,'OUTPUT_BOUND')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    require(read(path,JSON_CAP)==raw,'OUTPUT_READBACK')


def validate_authorization(raw,trusted_sha):
    require(trusted_sha==AUTH_SHA and sha(raw)==trusted_sha,'AUTH_SHA')
    value=decode(raw)
    require(equal(value,EXPECTED_AUTH),'AUTH_SCHEMA')
    return value


def validate_plan(raw,trusted_sha):
    require(pin(trusted_sha) and sha(raw)==trusted_sha,'PLAN_SHA')
    p=decode(raw)
    fixed=dict(schema='v5-existing-train-verify-plan-v1',verification_root=ROOT,
        artifact_root=TRAIN_ROOT,package_root=PACKAGE_ROOT,authorization_sha256=AUTH_SHA,
        artifact_receipt_sha256=ARTIFACT_SHA,legacy_trust_sha256=LEGACY_TRUST_SHA,
        families=list(FAMILIES),seeds=list(SEEDS))
    require(type(p) is dict and set(p)==PLAN_FIELDS and all(equal(p[k],v) for k,v in fixed.items()),'PLAN')
    require(type(p['source_sha256']) is dict and set(p['source_sha256'])==NEW_FILES
        and all(pin(v) for v in p['source_sha256'].values()) and p['source_sha256'][JIT]==JIT_SHA,'NEW_SOURCES')
    return p


def load(root,plan_sha,review_sha,authorization_sha):
    require(type(root) is str and root==ROOT and pin(plan_sha) and pin(review_sha)
        and authorization_sha==AUTH_SHA,'ANCHORS')
    auth=validate_authorization(pinned(ROOT+'/authorization.json',authorization_sha,JSON_CAP),authorization_sha)
    plan=validate_plan(pinned(ROOT+'/plan.json',plan_sha,JSON_CAP),plan_sha)
    digest=sha(canonical(plan['source_sha256']))
    review=decode(pinned(ROOT+'/review.json',review_sha,JSON_CAP))
    fixed=dict(schema='v5-existing-train-verify-independent-review-v1',
        status='PASS_EXISTING_TRAIN_VERIFY_IMPLEMENTATION_AND_GATES',plan_sha256=plan_sha,
        source_binding_sha256=digest,authorization_sha256=AUTH_SHA,artifact_receipt_sha256=ARTIFACT_SHA)
    require(type(review) is dict and set(review)==REVIEW_FIELDS
        and all(equal(review[k],v) for k,v in fixed.items())
        and all(pin(review[k]) for k in ('full_regression_sha256','linux_unit_sha256','fresh_gate_receipt_sha256')),'REVIEW')
    fresh=decode(pinned(ROOT+'/fresh_gate.json',review['fresh_gate_receipt_sha256'],JSON_CAP))
    legacy=decode(pinned(ROOT+'/legacy_trust.json',LEGACY_TRUST_SHA,JSON_CAP))
    require(type(legacy) is dict and set(legacy)=={'source_sha256','evidence_sha256'}
        and type(legacy['source_sha256']) is dict and set(legacy['source_sha256'])==LEGACY_FILES
        and len(LEGACY_FILES)==45 and all(pin(v) for v in legacy['source_sha256'].values())
        and type(legacy['evidence_sha256']) is dict and len(legacy['evidence_sha256'])==15
        and all(type(k) is str and pin(v) for k,v in legacy['evidence_sha256'].items()),'LEGACY')
    require(legacy['source_sha256'][FENCE]==FENCE_SHA and legacy['source_sha256'][GUARD]==GUARD_SHA,'IMMUTABLE_HELPERS')
    new={p:pinned(ROOT+'/'+p,h,65536) for p,h in plan['source_sha256'].items()}
    artifact=pinned(ROOT+'/artifact_receipts.json',ARTIFACT_SHA,262144)
    old={p:pinned(TRAIN_ROOT+'/'+p,legacy['source_sha256'][p],65536)
        for p in sorted(CORE_FILES|{FENCE})}
    require(sum(map(len,old.values()))<=1048576,'CORE_TOTAL')
    core_manifest=decode(pinned(TRAIN_ROOT+'/'+CORE_MANIFEST,CORE_SHA,JSON_CAP))
    require(type(core_manifest.get('sources')) is dict and set(core_manifest['sources'])==CORE_FILES
        and all(legacy['source_sha256'][p]==h for p,h in core_manifest['sources'].items()),'CORE_MANIFEST')
    child=external(new[CHILD],'_authenticated_existing_verify_child')
    require(equal(child.validate_authorization(pinned(ROOT+'/authorization.json',AUTH_SHA,JSON_CAP),AUTH_SHA),auth)
        and equal(child.validate_plan(pinned(ROOT+'/plan.json',plan_sha,JSON_CAP),plan_sha),plan),'CHILD_API')
    expected={task:child.select_plan(artifact,*task) for task in tasks()}
    return dict(auth=auth,plan=plan,plan_sha=plan_sha,review_sha=review_sha,digest=digest,
        fresh=fresh,new=new,old=old,legacy=legacy,expected=expected)


@contextmanager
def authenticated_core(bundle):
    # load() pins every byte before either fence or core code compiles.
    old=bundle['old'];pins=bundle['legacy']['source_sha256']
    require(type(old) is dict and set(old)==CORE_FILES|{FENCE}
        and all(type(raw) is bytes and 0<len(raw)<=65536 and sha(raw)==pins[p]
            for p,raw in old.items()) and sum(map(len,old.values()))<=1048576
        and pins[FENCE]==FENCE_SHA and pins[GUARD]==GUARD_SHA,'CORE_BEFORE_COMPILE')
    fence=external(bundle['old'][FENCE],'_authenticated_existing_verify_fence')
    sources={p:bundle['old'][p] for p in CORE_FILES if p.endswith('.py')}
    with fence.sealed_imports(sources,{p:bundle['legacy']['source_sha256'][p] for p in sources}):
        guard=importlib.import_module('src.models.ranking_v4_memory_guard')
        receipt=importlib.import_module('src.models.ranking_v5_parent_guard_receipt')
        yield guard,receipt


def validate_fresh(value,bundle,guard,now=None):
    fixed=dict(schema='v5-existing-train-readonly-fresh-gate-v1',
        status='PASS_READONLY_EXISTING_TRAIN_REPLAY_FRESH_GATE',verification_root=ROOT,
        plan_sha256=bundle['plan_sha'],source_binding_sha256=bundle['digest'],authorization_sha256=AUTH_SHA,
        artifact_receipt_sha256=ARTIFACT_SHA,legacy_trust_sha256=LEGACY_TRUST_SHA,
        source_count_verified=48,model_deserializations=0,training_invocations=0,once_absent=True,
        absent_output_count=40,global_lock_acquired_and_released=True,
        runtime_metadata_status='PASS_FIXED_RUNTIME_METADATA_ONLY',runtime_distribution_count=31)
    require(type(value) is dict and set(value)==FRESH_FIELDS
        and all(equal(value[k],v) for k,v in fixed.items())
        and equal(value['memory_policy'],guard.policy()),'FRESH_SCHEMA')
    require(type(value['fresh_utc']) is str and re.fullmatch(
        '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z',value['fresh_utc']),'FRESH_TIME')
    observed=datetime.strptime(value['fresh_utc'],'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    age=((now or datetime.now(timezone.utc))-observed).total_seconds()
    require(0<=age<=600,'FRESH_EXPIRED')
    total,available,reserve=(value[k] for k in ('effective_total_bytes','initial_available_bytes','reserve_bytes'))
    require(all(type(v) is int for v in (total,available,reserve)) and total>0 and 0<=available<=total
        and guard.check_available(total,available)==reserve,'FRESH_MEMORY')


@contextmanager
def worker_lock():
    import fcntl
    path=lexical(GLOBAL_LOCK)
    for q in path.parents:ordinary(q.lstat(),True)
    before=path.lstat();ordinary(before)
    require(before.st_nlink==1 and before.st_size==0 and before.st_uid==os.getuid()
        and stat.S_IMODE(before.st_mode)==0o600,'LOCK')
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    try:
        opened=os.fstat(fd);ordinary(opened)
        require((opened.st_dev,opened.st_ino)==(before.st_dev,before.st_ino),'LOCK_IDENTITY')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        current=path.lstat();ordinary(current)
        require((current.st_dev,current.st_ino)==(before.st_dev,before.st_ino),'LOCK_IDENTITY')
        yield
    finally:
        try:fcntl.flock(fd,fcntl.LOCK_UN)
        finally:os.close(fd)


def private_jit_roots():
    base=lexical(ROOT+'/jit_tmp');base.mkdir(mode=0o700)
    require(stat.S_IMODE(base.lstat().st_mode)==0o700,'JIT_MODE')
    for f,s in tasks():
        path=base/(f+'_'+str(s));path.mkdir(mode=0o700)
        require(stat.S_IMODE(path.lstat().st_mode)==0o700,'JIT_MODE')


def environment(family,seed):
    require((family,seed) in tasks(),'TASK')
    return dict(TMPDIR=ROOT+'/jit_tmp/'+family+'_'+str(seed),PATH='/usr/bin:/bin',
        LANG='C.UTF-8',LC_ALL='C.UTF-8',OMP_NUM_THREADS='1',MKL_NUM_THREADS='1',
        OPENBLAS_NUM_THREADS='1',NUMEXPR_NUM_THREADS='1',CUDA_VISIBLE_DEVICES='',
        PYTHONNOUSERSITE='1',PYTHONDONTWRITEBYTECODE='1',SETUPTOOLS_USE_DISTUTILS='stdlib')


def child_command(family,seed,bundle):
    require((family,seed) in tasks(),'TASK')
    path=ROOT+'/'+CHILD;digest=bundle['plan']['source_sha256'][CHILD]
    code=('import sys;assert sys.flags.isolated==1 and sys.flags.no_site==1 and sys.flags.dont_write_bytecode==1;'
        'sys.path[:]='+repr(list(SEARCH_PATHS))+';import os,stat,hashlib;from pathlib import Path;'
        'p=Path('+repr(path)+');assert all(stat.S_ISDIR(q.lstat().st_mode) for q in p.parents);'
        's=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<s.st_size<=65536;'
        'fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW);f=os.fdopen(fd,"rb");raw=f.read(65537);f.close();'
        'assert len(raw)==s.st_size and hashlib.sha256(raw).hexdigest()=='+repr(digest)+';'
        'os.chdir("/ssd/cjc");__file__='+repr(path)+';exec(compile(raw,__file__,"exec"))')
    return [INTERPRETER,'-I','-S','-B','-c',code,'--verification-root',ROOT,
        '--family',family,'--seed',str(seed),'--trusted-plan-sha256',bundle['plan_sha'],
        '--trusted-authorization-sha256',AUTH_SHA]


def validate_child(value,expected,family,seed,plan_sha):
    worker=decode(expected['worker_receipt_raw'])
    boundary=worker['boundary_receipt']
    fixed=dict(schema='v5-existing-train-numerical-verification-v1',
        status='PASS_EXISTING_TRAIN_PREDICTIONS_AND_METRICS_EXACT',family=family,seed=seed,
        training_root=TRAIN_ROOT,verification_root=ROOT,artifact_receipt_sha256=ARTIFACT_SHA,
        file_sha256=expected['file_sha256'],freeze_sha256=boundary['freeze_sha256'],
        weights_only=True,state_tensor_count=6,predictions_exact=True,freeze_payload_order_digest_exact=True,
        original_metrics_exact=True,metrics=boundary['metrics'],checkpoint_loads=1,optimizer_invocations=0,
        train_fit_invocations=0,automatic_retries=0,parent_guard_enforcement_proven_by_this_child=False,
        controlled_runtime_context_completed=True,verification_jit_source_sha256=JIT_SHA,
        authorization_sha256=AUTH_SHA,plan_sha256=plan_sha,legacy_trust_sha256=LEGACY_TRUST_SHA,
        old_artifact_hashes_unchanged=True,postchecked_count=4)
    require(type(value) is dict and set(value)==set(fixed)|{'held_candidate_count'}
        and all(equal(value[k],v) for k,v in fixed.items())
        and type(value['held_candidate_count']) is int and 1<=value['held_candidate_count']<=1706,'CHILD_RESULT')
    return value


def runtime():
    require(sys.platform=='linux' and sys.executable=='/usr/bin/python3'
        and tuple(sys.version_info[:3])==(3,11,2) and sys.flags.isolated==1 and sys.flags.no_site==1
        and sys.flags.dont_write_bytecode==1 and os.getcwd()=='/ssd/cjc','RUNTIME')


def run(root,*,trusted_plan_sha256,trusted_review_sha256,trusted_authorization_sha256):
    require(type(root) is str and root==ROOT and pin(trusted_plan_sha256) and pin(trusted_review_sha256)
        and trusted_authorization_sha256==AUTH_SHA,'ANCHORS')
    runtime()
    bundle=load(root,trusted_plan_sha256,trusted_review_sha256,trusted_authorization_sha256)
    root_info=lexical(ROOT).lstat();ordinary(root_info,True)
    require(root_info.st_uid==os.getuid() and stat.S_IMODE(root_info.st_mode)==0o700,'ROOT_PRIVATE')
    with authenticated_core(bundle) as (guard,receipt),worker_lock():
        validate_fresh(bundle['fresh'],bundle,guard)
        for p,h in bundle['plan']['source_sha256'].items():
            require(pinned(ROOT+'/'+p,h,65536)==bundle['new'][p],'FRESH_SOURCE')
        for path in absent_paths():absent(path)
        total,available=guard.available_memory();guard.check_available(total,available)
        write_once(ONCE,dict(schema='v5-existing-train-verification-once-v1',verification_root=ROOT,
            authorization_sha256=AUTH_SHA,authorization_id=EXPECTED_AUTH['authorization_id'],
            plan_sha256=bundle['plan_sha'],review_sha256=bundle['review_sha'],source_binding_sha256=bundle['digest'],
            model_load_count_max=18,train_fit_invocations=0,optimizer_invocations=0,automatic_retries=0))
        write_once(ROOT+'/matrix.started.json',dict(schema='v5-existing-train-verification-started-v1',
            plan_sha256=bundle['plan_sha'],authorization_sha256=AUTH_SHA,planned_checkpoints=18,automatic_retries=0))
        old_umask=os.umask(0o077)
        completed=[];failed_index=None;failure_kind=None;attempted=0
        try:
            private_jit_roots()
            for index,(family,seed) in enumerate(tasks()):
                try:
                    log=log_path(family,seed);absent(log);absent(log+'.memory.json')
                    attempted+=1
                    returned=guard.run_bounded(child_command(family,seed,bundle),log,environment(family,seed))
                    reread=decode(read(log+'.memory.json',JSON_CAP))
                    receipt.validate_parent_guard_receipt(returned,reread)
                    child_raw=read(log,JSON_CAP)
                    value=validate_child(decode(child_raw),bundle['expected'][(family,seed)],family,seed,bundle['plan_sha'])
                    completed.append(dict(family=family,seed=seed,status=value['status'],
                        child_stdout_sha256=sha(child_raw),freeze_sha256=value['freeze_sha256'],
                        metrics=value['metrics'],held_candidate_count=value['held_candidate_count'],
                        checkpoint_loads=1,peak_combined_rss_bytes=reread['peak_combined_rss_bytes'],
                        elapsed_seconds=reread['elapsed_seconds']))
                except BaseException as error:
                    failed_index=index;failure_kind=type(error).__name__[:64];break
        except BaseException as error:
            failed_index=0;failure_kind=type(error).__name__[:64]
        finally:
            os.umask(old_umask)
        final=dict(schema='v5-existing-train-verification-matrix-v1',
            status='PASS_EXISTING_18_TRAIN_NUMERICAL_VERIFICATION' if len(completed)==18 else 'STOPPED_NO_RETRY',
            verification_root=ROOT,artifact_root=TRAIN_ROOT,plan_sha256=bundle['plan_sha'],
            authorization_sha256=AUTH_SHA,completed_count=len(completed),failed_index=failed_index,
            failure_kind=failure_kind,remaining_count=18-attempted,
            checks=completed,workers=1,automatic_retries=0,train_fit_invocations=0,optimizer_invocations=0,
            accepted_checkpoint_loads=len(completed),no_additional_train_authorized=True,
            child_invocations_attempted=attempted,
            old_training_once_modified=False,atpg_speedup_claimed=False)
        write_once(ROOT+'/matrix.final.json',final)
        return final


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('verification-root','trusted-plan-sha256','trusted-review-sha256','trusted-authorization-sha256'):
        p.add_argument('--'+name,required=True)
    a=p.parse_args(argv)
    result=run(a.verification_root,trusted_plan_sha256=a.trusted_plan_sha256,
        trusted_review_sha256=a.trusted_review_sha256,trusted_authorization_sha256=a.trusted_authorization_sha256)
    sys.stdout.buffer.write(canonical(result)+b'\n')
    return 0 if result['completed_count']==18 else 2


if __name__=='__main__':raise SystemExit(main())
