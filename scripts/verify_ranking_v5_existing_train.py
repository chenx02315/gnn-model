"""One guarded, read-only verification of existing TRAIN weights and metrics.

No fit, optimizer, checkpoint writer, scheduler, retry or TRAIN launch exists.
The external parent owns sampled RSS enforcement and serial first-failure stop.
All source/artifact joins precede weights_only checkpoint loading. TRAIN held
outcomes remain gated on exact recomputed full freeze payload/order/SHA.
"""
import argparse
from collections import OrderedDict
from contextlib import contextmanager
import base64
import hashlib
import importlib
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
from types import ModuleType

TRAIN_ROOT = '/ssd/cjc/gnn_model_ranking_v5_train_20261011_r2'
VERIFY_ROOT = '/ssd/cjc/gnn_model_ranking_v5_verify_20261012_r1'
PACKAGE_ROOT = '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/train_folds'
INTERPRETER = '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/venv/bin/python'
SEARCH_PATHS = ('/usr/lib/python311.zip','/usr/lib/python3.11','/usr/lib/python3.11/lib-dynload',
    '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/venv/lib/python3.11/site-packages',
    '/ssd/cjc/gnn_model_runtime_v2_98efbd4f_20261002T235119/venv/lib/python3.11/site-packages')
ARTIFACT_RECEIPT_SHA = 'a81a30341c0f0e6b90435b7b4417c39b6ed23db33dbb9fcf1aad7778e1d6534c'
AUTHORIZATION_SHA = '2163d176252279b850dfb8cc0004547858ba79ee894b822e7ae7a180c5c7ac20'
LEGACY_TRUST_SHA = '6a6365e993caee509ef57384ad7abd1a3c1ec2c4368084bf1af39bd02e4dab0e'
SELF_PATH = 'scripts/verify_ranking_v5_existing_train.py'
PARENT_PATH = 'scripts/run_v5_existing_train_verify_parent.py'
AUTHORIZATION_EXPECTED = json.loads('''{"schema":"v5-existing-train-readonly-replay-authorization-v1","authorization_id":"USER_READONLY_V5_REPLAY_20261012","basis":"User replied 授权，继续 to the explicit proposal to read-only load the existing trained models and recompute TRAIN frozen predictions and metrics, without retraining or BLIND access and with the original memory cap.","scope":"EXISTING_18_TRAIN_CHECKPOINTS_READONLY_PREDICTION_AND_METRIC_REPLAY","artifact_root":"/ssd/cjc/gnn_model_ranking_v5_train_20261011_r2","verification_root":"/ssd/cjc/gnn_model_ranking_v5_verify_20261012_r1","package_root":"/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/train_folds","artifact_receipt_sha256":"a81a30341c0f0e6b90435b7b4417c39b6ed23db33dbb9fcf1aad7778e1d6534c","launch_receipt_sha256":"b549685a8d3f2e7533f8b89f0febad109936a128f73fb7aef9abce5dc6b1ba1b","implementation_commit":"f19c04e67d1389bd06ffe36b5b8b64c3cf27d7cb","families":["iwls_aes_core","iscas89_s13207","iscas89_s15850","iscas89_s35932","iscas89_s38417","iwls_spi"],"seeds":[20260824,20260825,20260826],"model_load_count_max":18,"roles":["TRAIN"],"weights_only_required":true,"cpu_only":true,"threads":1,"workers":1,"combined_rss_cap_bytes":1073741824,"address_space_cap_bytes":8589934592,"timeout_seconds_per_child":1800,"automatic_retries":0,"stop_on_first_failure":true,"held_labels_after_exact_prediction_freeze_match_only":true,"old_artifacts_and_training_once_readonly":true,"temporary_jit_and_small_receipts_in_new_verification_root_only":true,"training_allowed":false,"optimizer_allowed":false,"blind_validation_pilot_allowed":false,"lsf_tessent_allowed":false,"protected_root_access_allowed":false,"gate_and_independent_review_required_before_execution":true,"contract_is_record_not_self_proving_user_consent":true}''')
CORE_MANIFEST = 'data/manifests/ranking_v5_caller_source_bytes_20261008.json'
CORE_SHA = '5394779faac5c77800a0a9d8ed52bf9f24ba2dd701f499a49754e51e7ddceae7'
VERIFY_JIT = 'src/models/ranking_v5_verify_jit_admission_v1.py'
VERIFY_JIT_SHA = 'e572e7f255ff6f62903c476a22370baa7d2984f67a387e8fa76ea4dad91027b3'
FAMILIES = ('iwls_aes_core','iscas89_s13207','iscas89_s15850','iscas89_s35932','iscas89_s38417','iwls_spi')
SEEDS = (20260824,20260825,20260826)
FENCE = 'src/models/ranking_v5_frozen_import_fence.py'
OBS = 'src/models/ranking_v5_locked_runtime_observations.py'
BASE_CONTEXT = 'src/models/ranking_v5_locked_runtime_imports.py'
PROBE = 'src/models/ranking_v5_fx2trt_probe_admission.py'
SNAPSHOT = 'data/fixtures/ranking_v5_remote_module_non_scriptable_20261010.txt'
FREEZE_LOADER = 'src/models/ranking_v5_freeze_supplement_v2.py'
FREEZE_FILES = tuple('src/models/ranking_v5_'+name+'_v2.py' for name in
    ('freeze_codec','real_artifact_store','single_fit_worker','train_artifact_readback',
     'independent_fit_context','parent_artifact_candidate'))
FIXED_PINS = {
    FENCE:'c8ba5ae9bc8f900a620b7eaf03e37e11f303d9fc8b08ccbc8c423682b0afafed',
    OBS:'0524a7b8cce7d017c3fe9fe38dcc86b29a440ed7b373c1c2361ebbb7738459c8',
    BASE_CONTEXT:'b1bddbda1ef6ea2323a1b3face282fbb21cd1a01db64d68dff8deaa28308b1da',
    PROBE:'def81c6af0454909685957edf6e3aa7c2c48b66fb09b5ad31de20def70d54f6e',
    SNAPSHOT:'8205b16956fb264841ecd8644784a0d157f87df79b17c16825dc1163433ce5d8',
    FREEZE_LOADER:'1ca99c1977d31542cd7d47dde28ee0e9bc7ef4bf2e44ff17b919960f8176b9c7',
    FREEZE_FILES[0]:'aa51f59d6556eee816479a25321f0a8a76264641954c1b0e71169910c935535a',
    FREEZE_FILES[1]:'225c0ca1566497446ae967a4f3c2e531da897078dcf76499037c67572d2925fa',
    FREEZE_FILES[2]:'ffc6e3493a24246668718524fe365cd10a78b3ac7590f926984ea579483ca544',
    FREEZE_FILES[3]:'a67388fd1b6716eb559f0f236c1069e119f0e753ef38749b335d63039db77b2a',
    FREEZE_FILES[4]:'4b235d759a5fb12d4dc604c192c38a67032d82464cf623037522413d85afd8d7',
    FREEZE_FILES[5]:'66a84d00f98d423877c7f08fc9f8c8a33319f0eae2e82edbdcdcc9753baa6be5'}
AUXILIARY = frozenset((FENCE,OBS,BASE_CONTEXT,PROBE,SNAPSHOT,FREEZE_LOADER,*FREEZE_FILES,
    'src/models/ranking_v5_train_jit_admission_v3.py','src/models/ranking_v5_serial_matrix.py',
    'src/models/ranking_v5_jit_template_admission.py','scripts/run_v5_train_single_fit_v3.py',
    'scripts/run_v5_train_serial_parent_v3.py','scripts/run_v5_fx2trt_optimizer_gate.py',
    'scripts/run_v5_controlled_runtime_gate.py'))
STATE_SHAPES = {'layers.0.weight':(32,7),'layers.0.bias':(32,),
    'layers.2.weight':(32,32),'layers.2.bias':(32,),'layers.4.weight':(1,32),'layers.4.bias':(1,)}
ARTIFACT_CAPS = {'model.pt':1048576,'freeze.json':16777216,'worker_receipt.json':20480,'fitting.jsonl':3145728}

def require(ok,code):
    if not ok: raise ValueError('V5_EXISTING_VERIFY_'+code)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def pin(value): return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None
def canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def equal(a,b):
    if type(a) is not type(b): return False
    if type(b) is dict: return a.keys()==b.keys() and all(equal(a[k],b[k]) for k in b)
    if type(b) is list: return len(a)==len(b) and all(equal(x,y) for x,y in zip(a,b))
    return a==b

def task_gate(family,seed,verification_root=VERIFY_ROOT):
    require(type(family) is str and family in FAMILIES and type(seed) is int and seed in SEEDS,'TASK')
    require(type(verification_root) is str and verification_root==VERIFY_ROOT,'VERIFICATION_ROOT')
    return TRAIN_ROOT+'_'+family+'_'+str(seed)

def validate_authorization(raw,trusted_sha256):
    require(trusted_sha256==AUTHORIZATION_SHA and type(raw) is bytes and sha(raw)==AUTHORIZATION_SHA,'AUTHORIZATION_PIN')
    value=decode(raw)
    require(equal(value,AUTHORIZATION_EXPECTED),'AUTHORIZATION_SCOPE')
    return value

def validate_plan(raw,trusted_sha256):
    require(pin(trusted_sha256) and type(raw) is bytes and sha(raw)==trusted_sha256,'PLAN_PIN')
    value=decode(raw)
    fixed=dict(schema='v5-existing-train-verify-plan-v1',verification_root=VERIFY_ROOT,
        artifact_root=TRAIN_ROOT,package_root=PACKAGE_ROOT,authorization_sha256=AUTHORIZATION_SHA,
        artifact_receipt_sha256=ARTIFACT_RECEIPT_SHA,legacy_trust_sha256=LEGACY_TRUST_SHA,
        families=list(FAMILIES),seeds=list(SEEDS))
    require(type(value) is dict and set(value)==set(fixed)|{'source_sha256'}
            and all(equal(value[k],v) for k,v in fixed.items()),'PLAN_SCOPE')
    sources=value['source_sha256']
    require(type(sources) is dict and set(sources)=={SELF_PATH,PARENT_PATH,VERIFY_JIT}
            and all(pin(v) for v in sources.values()) and sources[VERIFY_JIT]==VERIFY_JIT_SHA,'PLAN_SOURCES')
    return value

def decode(raw,cap=20480):
    require(type(raw) is bytes and 0<len(raw)<=cap,'JSON_BOUND')
    def unique(pairs):
        value={}
        for key,item in pairs:
            require(key not in value,'JSON_DUPLICATE');value[key]=item
        return value
    def invalid(_): raise ValueError('V5_EXISTING_VERIFY_JSON_NONFINITE')
    return json.loads(raw,object_pairs_hook=unique,parse_constant=invalid)

def ordinary(info,directory=False):
    require(not stat.S_ISLNK(info.st_mode) and not getattr(info,'st_file_attributes',0)&0x400,'LINK')
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode),'ORDINARY')

def read_fixed(root,relative,cap,expected_sha=None,stream_only=False):
    # Only fixed sources, the one selected task's artifacts, and two bootstrap
    # receipt names are allowed. No caller-derived arbitrary path reaches I/O.
    allowed=set(ARTIFACT_CAPS)|set(AUXILIARY)|{CORE_MANIFEST,VERIFY_JIT,'artifact_receipts.json'}
    if root==TRAIN_ROOT:
        allowed=set(AUXILIARY)|{CORE_MANIFEST}|CORE_FILES
    elif root==VERIFY_ROOT:
        allowed={VERIFY_JIT,SELF_PATH,PARENT_PATH,'artifact_receipts.json','authorization.json','plan.json','legacy_trust.json','review.json'}
    else:
        valid={TRAIN_ROOT+'_'+f+'_'+str(s) for f in FAMILIES for s in SEEDS}
        require(root in valid,'READ_ROOT');allowed=set(ARTIFACT_CAPS)
    require(type(relative) is str and relative in allowed and type(cap) is int and 0<cap<=16777216,'READ_NAME')
    require(expected_sha is None or pin(expected_sha),'READ_PIN')
    path=Path(root)/relative
    for ancestor in path.parents:ordinary(ancestor.lstat(),True)
    before=path.lstat();ordinary(before)
    require(before.st_nlink==1 and 0<before.st_size<=cap,'FILE_BOUND')
    identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    parts=[];digest=hashlib.sha256();total=0
    with os.fdopen(os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_BINARY',0)),'rb') as stream:
        opened=os.fstat(stream.fileno());ordinary(opened)
        require(identity(opened)==identity(before),'FILE_CHANGED')
        while total<=cap:
            chunk=stream.read(min(65536,cap+1-total))
            if not chunk:break
            total+=len(chunk);require(total<=cap,'STREAM_BOUND');digest.update(chunk)
            if not stream_only:parts.append(chunk)
        after=os.fstat(stream.fileno())
    final=path.lstat();ordinary(final)
    require(total==before.st_size and final.st_nlink==1
            and identity(before)==identity(after)==identity(final),'FILE_CHANGED')
    require(expected_sha is None or digest.hexdigest()==expected_sha,'FILE_SHA')
    return (total,digest.hexdigest()) if stream_only else b''.join(parts)

# Explicit immutable core25; lock is the 26th core artifact.
CORE_FILES = frozenset((
    'src/models/runtime_ranking_v3.py','src/models/runtime_training_v2.py','src/models/neural_ranking_v3.py',
    'src/models/run_runtime_ranking_v3.py','src/models/ranking_v3_freeze_io.py','src/data/ranking_v3_real_fold_package.py',
    'scripts/ranking_v4_near_optimal_pairs.py','src/models/ranking_v4_training_worker.py','src/models/ranking_v4_memory_guard.py',
    'src/models/preflight_runtime_v2.py','src/models/ranking_v5_execution_boundary.py','src/models/ranking_v5_head_objective.py',
    'src/models/ranking_v5_training_kernel.py','src/models/ranking_v5_physical_worker.py','src/models/ranking_v5_approval_binding.py',
    'src/models/ranking_v5_bound_input_reader.py','src/models/ranking_v5_package_binding.py','src/models/ranking_v5_real_request_loader.py',
    'src/models/ranking_v5_v3_fold_adapter.py','src/models/ranking_v5_held_replay_reader.py','src/models/ranking_v5_real_artifact_store.py',
    'src/models/ranking_v5_single_fit_worker.py','src/models/ranking_v5_worker_resource_context.py',
    'src/models/ranking_v5_parent_guard_receipt.py','src/models/ranking_v5_caller_source_binding.py','requirements/runtime_v2.lock.txt'))

def select_plan(raw,family,seed):
    output=task_gate(family,seed)
    require(sha(raw)==ARTIFACT_RECEIPT_SHA,'ARTIFACT_RECEIPT_PIN')
    value=decode(raw,262144)
    require(type(value) is dict and value.get('root')==TRAIN_ROOT
            and value.get('status')=='PASS_READ_ONLY_ACTUAL_MATRIX_ARTIFACT_COLLECTION_ONLY'
            and type(value.get('expected_artifact_count')) is int and value['expected_artifact_count']==110
            and type(value.get('validated_parent_completed_count')) is int and value['validated_parent_completed_count']==18,'ARTIFACT_RECEIPT')
    entries=value.get('artifacts');require(type(entries) is dict and len(entries)==110,'ARTIFACT_COUNT')
    expected_names={'matrix.final.json','authorization.once.json'}
    for f in FAMILIES:
        for s in SEEDS:
            prefix='tasks/'+f+'_'+str(s)+'/'
            expected_names.update(prefix+n for n in ('memory.json','admission.json',*ARTIFACT_CAPS))
    require(set(entries)==expected_names,'ARTIFACT_SET')
    for name,entry in entries.items():
        require(type(entry) is dict and pin(entry.get('sha256')) and type(entry.get('bytes')) is int
                and entry['bytes']>0 and type(entry.get('path')) is str,'ARTIFACT_ENTRY')
        if name.startswith('tasks/'):
            task,n=name.split('/')[1:];expected=TRAIN_ROOT+'_'+task+'/'+n
            if n=='memory.json':expected=TRAIN_ROOT+'_'+task+'.stdout.log.memory.json'
            if n=='admission.json':expected=TRAIN_ROOT+'/jit_admission_'+task+'.json'
            require(entry['path']==expected,'ARTIFACT_PATH')
        if 'raw_b64' in entry:
            receipt_raw=base64.b64decode(entry['raw_b64'],validate=True)
            require(len(receipt_raw)==entry['bytes'] and sha(receipt_raw)==entry['sha256'],'ARTIFACT_RAW_SHA')
    final_entry=entries['matrix.final.json'];final=decode(base64.b64decode(final_entry['raw_b64'],validate=True),20000)
    require(final.get('status')=='PASS_ACTUAL_SERIAL_TRAIN_ARTIFACT_BINDING'
            and final.get('completed_count')==18 and type(final.get('checks')) is list and len(final['checks'])==18,'FINAL')
    for check,(f,s) in zip(final['checks'],[(f,s) for f in FAMILIES for s in SEEDS]):
        require(check.get('family')==f and type(check.get('seed')) is int and check['seed']==s,'FINAL_ORDER')
    selected=next(c for c in final['checks'] if c['family']==family and c['seed']==seed)
    pins=selected['artifact_check']['file_sha256']
    prefix='tasks/'+family+'_'+str(seed)+'/'
    require(type(pins) is dict and set(pins)==set(ARTIFACT_CAPS)
            and all(entries[prefix+n]['sha256']==h for n,h in pins.items()),'FINAL_ARTIFACT_PIN')
    return dict(output=output,file_sha256=dict(pins),
        worker_receipt_raw=base64.b64decode(entries[prefix+'worker_receipt.json']['raw_b64'],validate=True),
        artifact_receipt_sha256=ARTIFACT_RECEIPT_SHA)

def validate_state(torch,state):
    require(type(state) in (dict,OrderedDict) and set(state)==set(STATE_SHAPES),'STATE_KEYS')
    for key,shape in STATE_SHAPES.items():
        tensor=state[key]
        require(type(tensor) is torch.Tensor and tuple(tensor.shape)==shape
                and tensor.device.type=='cpu' and tensor.dtype==torch.float32
                and bool(torch.isfinite(tensor).all().item()),'STATE_TENSOR')

def check_cpu_environment():
    # Do not query CUDA hardware/driver availability in this CPU-only replay.
    require(os.environ.get('CUDA_VISIBLE_DEVICES')=='','CPU_ENVIRONMENT')

def verify_one(torch,modules,plan,family,seed,*,read_artifact=read_fixed):
    output=task_gate(family,seed)
    require(type(plan) is dict and plan.get('output')==output and type(plan.get('file_sha256')) is dict
            and set(plan['file_sha256'])==set(ARTIFACT_CAPS) and all(pin(v) for v in plan['file_sha256'].values()),'PLAN')
    check_cpu_environment()
    modules['resource'].check_current_process()
    pins=plan['file_sha256']
    # All artifact bytes and the fitting-only snapshot are joined before load().
    worker_raw=read_artifact(output,'worker_receipt.json',20480,pins['worker_receipt.json'])
    require(worker_raw==plan['worker_receipt_raw'],'WORKER_EXACT')
    worker=decode(worker_raw);boundary=worker['boundary_receipt']
    require(worker.get('status')=='PASS_SINGLE_FIT_CALLBACK_ADAPTER_ONLY'
            and boundary.get('family')==family and type(boundary.get('seed')) is int and boundary['seed']==seed
            and boundary.get('model_ack_sha256')==boundary.get('expected_model_sha256')==pins['model.pt']
            and worker.get('fitting_log_sha256')==pins['fitting.jsonl']
            and worker.get('worker_receipt_sha256')==sha(canonical({k:v for k,v in worker.items() if k!='worker_receipt_sha256'})),'WORKER_BINDING')
    model_raw=read_artifact(output,'model.pt',1048576,pins['model.pt'])
    freeze_raw=read_artifact(output,'freeze.json',16777216,pins['freeze.json'])
    log_bytes,log_sha=read_artifact(output,'fitting.jsonl',3145728,pins['fitting.jsonl'],stream_only=True)
    require(type(log_bytes) is int and 0<log_bytes<=3145728 and log_sha==pins['fitting.jsonl'],'LOG_SHA')
    require(sha(model_raw)==pins['model.pt'] and sha(freeze_raw)==pins['freeze.json'],'ARTIFACT_SHA')
    payload,freeze_sha=modules['codec'].decode(freeze_raw,boundary['freeze_sha256'])
    snapshot=modules['inputs'].load_bound_fold_request(PACKAGE_ROOT,family,seed)
    request=snapshot['request']
    require(equal(snapshot['input_identity'],worker['input_identity'])
            and request.get('family')==family and type(request.get('seed')) is int and request['seed']==seed
            and modules['ranking'].digest(request)==boundary['canonical_request_sha256'],'FOLD_JOIN')
    fold,prepared,held_rows,recipe=modules['boundary'].prepare_request(request)
    modules['codec'].preflight(fold)
    require(modules['ranking'].digest(recipe)==boundary['head_recipe_sha256']
            and fold.family==family and tuple(prepared['fit_uids'])==fold.fitting
            and tuple(row['action_uid'] for row in held_rows)==fold.heldout
            and modules['ranking'].digest(fold.fitting)==payload['fitting_uids_sha256']
            and modules['ranking'].digest(fold.heldout)==payload['heldout_uids_sha256'],'FOLD_UID_JOIN')
    expected,expected_sha=modules['ranking'].freeze_ranking(payload['scores'],fold)
    require(equal(expected,payload) and expected_sha==freeze_sha,'STORED_FREEZE_JOIN')
    torch.set_num_threads(1)
    if torch.get_num_interop_threads()!=1:torch.set_num_interop_threads(1)
    require(torch.get_num_threads()==1 and torch.get_num_interop_threads()==1,'TORCH_THREADS')
    state=torch.load(io.BytesIO(model_raw),map_location='cpu',weights_only=True)
    validate_state(torch,state)
    model=modules['ranking'].make_candidate_ranker(torch)
    loaded=model.load_state_dict(state,strict=True)
    require(not loaded.missing_keys and not loaded.unexpected_keys,'STATE_STRICT')
    model.eval()
    features=modules['ranking'].transform(modules['ranking'].feature_matrix(held_rows),prepared['normalizer'])
    with torch.no_grad():
        values=model(torch.tensor(features,dtype=torch.float32,device='cpu')).detach().cpu().tolist()
    require(type(values) is list and len(values)==len(fold.heldout)
            and all(type(v) is float and math.isfinite(v) for v in values),'PREDICTION_SHAPE')
    recomputed,recomputed_sha=modules['ranking'].freeze_ranking(dict(zip(fold.heldout,values)),fold)
    require(equal(recomputed,payload) and recomputed_sha==freeze_sha
            and modules['codec'].payload_bytes(recomputed)==modules['codec'].payload_bytes(payload),'PREDICTIONS_EXACT')
    # Only this exact gate permits the original TRAIN held-out label reader.
    outcomes=modules['held'].load_frozen_held_outcomes(PACKAGE_ROOT,snapshot['input_identity'],fold,
        fold.heldout,freeze_sha,(payload,freeze_sha))
    metrics=modules['ranking'].replay_frozen(recomputed,recomputed_sha,fold,outcomes)
    require(equal(metrics,boundary['metrics']) and boundary.get('held_labels_replayed') is True,'METRICS_EXACT')
    # Prove the exact four original artifact byte hashes still match after replay.
    # No checkpoint/freeze/log bytes are returned by these post-run streams.
    for name,cap in ARTIFACT_CAPS.items():
        count,digest=read_artifact(output,name,cap,pins[name],stream_only=True)
        require(type(count) is int and 0<count<=cap and digest==pins[name],'POST_ARTIFACT_SHA')
    return dict(schema='v5-existing-train-numerical-verification-v1',
        status='PASS_EXISTING_TRAIN_PREDICTIONS_AND_METRICS_EXACT',family=family,seed=seed,
        training_root=TRAIN_ROOT,verification_root=VERIFY_ROOT,artifact_receipt_sha256=ARTIFACT_RECEIPT_SHA,
        file_sha256=dict(pins),freeze_sha256=freeze_sha,held_candidate_count=len(fold.heldout),
        weights_only=True,state_tensor_count=6,predictions_exact=True,freeze_payload_order_digest_exact=True,
        original_metrics_exact=True,metrics=metrics,checkpoint_loads=1,optimizer_invocations=0,
        train_fit_invocations=0,automatic_retries=0,parent_guard_enforcement_proven_by_this_child=False,
        old_artifact_hashes_unchanged=True,postchecked_count=4)

def external(raw,name):
    m=ModuleType(name);m.__file__='sealed-existing-verifier://'+name
    exec(compile(raw,m.__file__,'exec'),m.__dict__);return m

@contextmanager
def codec_context(raw):
    name='src.models.ranking_v5_freeze_codec_v2';package=importlib.import_module('src.models')
    require(type(package) is ModuleType and package.__dict__.get('__path__')==[]
            and package.__spec__.origin=='sealed://namespace/src.models'
            and name not in sys.modules and 'ranking_v5_freeze_codec_v2' not in package.__dict__,'CODEC_CONTEXT')
    m=ModuleType(name);m.__file__='sealed-existing-verifier://'+FREEZE_FILES[0];m.__package__='src.models'
    try:
        sys.modules[name]=m;package.ranking_v5_freeze_codec_v2=m
        exec(compile(raw,m.__file__,'exec'),m.__dict__)
        yield m
        require(sys.modules.get(name) is m and package.ranking_v5_freeze_codec_v2 is m,'CODEC_DRIFT')
    finally:
        if sys.modules.get(name) is m:del sys.modules[name]
        if package.__dict__.get('ranking_v5_freeze_codec_v2') is m:delattr(package,'ranking_v5_freeze_codec_v2')

def execute(family,seed,verification_root,trusted_plan_sha256,trusted_authorization_sha256):
    task_gate(family,seed,verification_root)
    require(sys.platform=='linux' and sys.executable==INTERPRETER and tuple(sys.version_info[:3])==(3,11,2)
            and sys.flags.isolated==1 and sys.flags.no_site==1 and os.getcwd()=='/ssd/cjc'
            and sys.path==list(SEARCH_PATHS),'RUNTIME')
    require(trusted_authorization_sha256==AUTHORIZATION_SHA and pin(trusted_plan_sha256),'EXTERNAL_ANCHORS')
    validate_authorization(read_fixed(VERIFY_ROOT,'authorization.json',20480,AUTHORIZATION_SHA),trusted_authorization_sha256)
    plan_record=validate_plan(read_fixed(VERIFY_ROOT,'plan.json',20480,trusted_plan_sha256),trusted_plan_sha256)
    require(__file__==VERIFY_ROOT+'/'+SELF_PATH,'SELF_LOCATION')
    read_fixed(VERIFY_ROOT,SELF_PATH,65536,plan_record['source_sha256'][SELF_PATH])
    legacy=decode(read_fixed(VERIFY_ROOT,'legacy_trust.json',20000,LEGACY_TRUST_SHA),20000)
    require(type(legacy) is dict and set(legacy)=={'source_sha256','evidence_sha256'}
            and type(legacy['evidence_sha256']) is dict and len(legacy['evidence_sha256'])==15,'LEGACY_TRUST')
    source_pins=legacy['source_sha256']
    required=CORE_FILES|AUXILIARY
    require(type(source_pins) is dict and set(source_pins)==required and len(required)==45
            and all(pin(v) for v in source_pins.values())
            and all(source_pins[p]==v for p,v in FIXED_PINS.items()),'SOURCE_PINS')
    manifest_raw=read_fixed(TRAIN_ROOT,CORE_MANIFEST,20000,CORE_SHA)
    manifest=decode(manifest_raw,20000)
    require(set(manifest['sources'])==CORE_FILES
            and all(source_pins[p]==v for p,v in manifest['sources'].items()),'CORE_IMMUTABLE')
    sources={p:read_fixed(TRAIN_ROOT,p,65536,source_pins[p]) for p in sorted(required)}
    require(sum(map(len,sources.values()))<=1048576
            and all(type(raw) is bytes and 0<len(raw)<=65536 and sha(raw)==source_pins[p]
                    for p,raw in sources.items()),'SOURCE_TOTAL_OR_SHA')
    jit_raw=read_fixed(VERIFY_ROOT,VERIFY_JIT,65536,VERIFY_JIT_SHA)
    require(sha(jit_raw)==VERIFY_JIT_SHA,'VERIFY_JIT_SHA')
    artifact_raw=read_fixed(VERIFY_ROOT,'artifact_receipts.json',262144,ARTIFACT_RECEIPT_SHA)
    plan=select_plan(artifact_raw,family,seed)
    # No helper or supplemental code compiles until all supplied bytes are pinned.
    frozen=external(sources[FENCE],'_v5_existing_fence')
    observation=external(sources[OBS],'_v5_existing_observation')
    base=external(sources[BASE_CONTEXT],'_v5_existing_runtime')
    probe=external(sources[PROBE],'_v5_existing_probe')
    jit=external(jit_raw,'_v5_existing_verification_jit')
    require(jit.SOURCE_ROOT==VERIFY_ROOT,'JIT_ROOT')
    loader=external(sources[FREEZE_LOADER],'_v5_existing_freeze_validator')
    loader.validate_sources({p:sources[p] for p in FREEZE_FILES},{p:source_pins[p] for p in FREEZE_FILES})
    core_python={p:sources[p] for p in CORE_FILES if p.endswith('.py')}
    with probe.controlled_imports(core_python,{p:source_pins[p] for p in core_python},
            frozen_helper=frozen,observation_helper=observation,lock_raw=sources['requirements/runtime_v2.lock.txt'],
            base_context=base,jit_root=VERIFY_ROOT+'/jit_tmp/'+family+'_'+str(seed),
            generated_raw=sources[SNAPSHOT],jit_admission=jit) as admission:
        modules={key:importlib.import_module('src.models.'+name) for key,name in
            (('ranking','runtime_ranking_v3'),('boundary','ranking_v5_execution_boundary'),
             ('inputs','ranking_v5_bound_input_reader'),('held','ranking_v5_held_replay_reader'),
             ('resource','ranking_v5_worker_resource_context'))}
        modules['resource'].check_current_process()
        with codec_context(sources[FREEZE_FILES[0]]) as codec:
            modules['codec']=codec
            check_cpu_environment()
            torch=importlib.import_module('torch')
            importlib.import_module('torch._dynamo')
            probe.validate_current(admission)
            result=verify_one(torch,modules,plan,family,seed)
            probe.validate_current(admission)
    result['controlled_runtime_context_completed']=True
    result['verification_jit_source_sha256']=VERIFY_JIT_SHA
    result['authorization_sha256']=AUTHORIZATION_SHA
    result['plan_sha256']=trusted_plan_sha256
    result['legacy_trust_sha256']=LEGACY_TRUST_SHA
    return result

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--family',required=True);p.add_argument('--seed',required=True,type=int)
    p.add_argument('--verification-root',required=True);p.add_argument('--trusted-plan-sha256',required=True)
    p.add_argument('--trusted-authorization-sha256',required=True)
    args=p.parse_args(argv)
    task_gate(args.family,args.seed,args.verification_root)
    result=execute(args.family,args.seed,args.verification_root,args.trusted_plan_sha256,args.trusted_authorization_sha256)
    raw=canonical(result);require(len(raw)<=20000,'RESULT_BOUND')
    sys.stdout.buffer.write(raw+b'\n')
    return 0

if __name__=='__main__':raise SystemExit(main())
