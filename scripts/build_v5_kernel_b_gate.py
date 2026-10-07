"""Pinned, in-memory synthetic CPU integration gate. No remote deployment."""
import base64
import hashlib
from pathlib import Path
import zlib

ROOT = Path(__file__).resolve().parents[1]
PINS = {
 'src/models/runtime_ranking_v3.py':'d64eb0fe17a00886d6464ae016805b1474e7324e95ad8e223aba44502709759c',
 'src/models/runtime_training_v2.py':'83a67c0a95190bc60bcb9e0af929e803dcf4cd78f88a027927540a92abbd10c5',
 'src/models/neural_ranking_v3.py':'1d3edf6c9d4605c438c1d683274ff3bc85cf0d87d1b57c53d79649aafcff69c3',
 'src/models/run_runtime_ranking_v3.py':'bb13f20e66a237f4df7a93ccc2fbaaf27df42929d889f22ee5c575241ddaf731',
 'src/models/ranking_v3_freeze_io.py':'4f904a6e4e553f39e4d9cecf4d41bad50f1fe826f60ffda4d5a3f5a9a9dcd58d',
 'src/data/ranking_v3_real_fold_package.py':'cb44a4e8f4fa0f9e2a1e88be31f948d013e96585c84c1ece603aa894d924a3cd',
 'scripts/ranking_v4_near_optimal_pairs.py':'8a4304f4befaaaf31b79dfbc7a21201e9be4b5c704a268efc184286ae92fca6e',
 'src/models/ranking_v4_training_worker.py':'808f7156c3e8a907ada332d3db7c0c16dba9c5dfcdba25b1c3b553e637a1daea',
 'src/models/ranking_v5_head_objective.py':'aa1d71fa3c6c3a10ea81b133248d334669c48cce8e2a3babe1bb1567b5af7c85',
 'src/models/ranking_v5_training_kernel.py':'e33819e259004d4bb67d8f40ede371274be7126ae1ba54fcff6870e4f0e59f44',
 'requirements/runtime_v2.lock.txt':'a9427b7cbf01048a317009dcf0f625ace51cc739b4e7e2e626a17166ed14c96f',
}
BOOTSTRAP = r'''
import base64,hashlib,importlib.metadata,json,os,platform,resource,signal,sys,time,types,zlib
if sys.platform!='linux' or os.getcwd()!='/ssd/cjc': raise ValueError('KERNEL_FIXED_CWD')
if sys.executable!='/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/venv/bin/python':
    raise ValueError('KERNEL_FIXED_INTERPRETER')
resource.setrlimit(resource.RLIMIT_AS,(8*1024**3,8*1024**3))
resource.setrlimit(resource.RLIMIT_CPU,(120,120))
def wall_expired(signum,frame): raise TimeoutError('KERNEL_WALL_TIMEOUT')
signal.signal(signal.SIGALRM,wall_expired)
signal.alarm(180)
os.environ['CUDA_VISIBLE_DEVICES']=''
os.environ['PYTHONDONTWRITEBYTECODE']='1'
sys.dont_write_bytecode=True
started=time.monotonic()
payload=PAYLOAD
decoded={}
for path,item in payload.items():
    compressed=base64.b64decode(item['zlib'],validate=True)
    if len(compressed)>30000: raise ValueError('KERNEL_COMPRESSED_BOUND')
    decoder=zlib.decompressobj()
    raw=decoder.decompress(compressed,30001)
    if len(raw)>30000 or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError('KERNEL_DECODE_BOUND')
    if hashlib.sha256(raw).hexdigest()!=item['sha256']: raise ValueError('KERNEL_SOURCE_SHA')
    decoded[path]=raw.decode('utf-8')
if sum(len(s.encode()) for s in decoded.values())>150000: raise ValueError('KERNEL_TOTAL_BOUND')
dependencies={}
for line in decoded['requirements/runtime_v2.lock.txt'].splitlines():
    if not line.strip() or line.startswith('#'): continue
    name,version=line.split('=='); actual=importlib.metadata.version(name)
    if actual!=version: raise ValueError('KERNEL_DEPENDENCY_DRIFT:'+name)
    dependencies[name]=actual
if len(dependencies)!=31: raise ValueError('KERNEL_DEPENDENCY_COUNT')
for name in ('src','src.models','src.data','scripts'):
    m=types.ModuleType(name); m.__path__=[]; sys.modules[name]=m
for path in payload:
    if not path.endswith('.py'): continue
    name=path[:-3].replace('/','.')
    module=types.ModuleType(name); sys.modules[name]=module
    exec(compile(decoded[path],path,'exec'),module.__dict__)
import numpy as np
import torch
torch.set_num_interop_threads(1)
runtime=sys.modules['src.models.runtime_ranking_v3']
kernel=sys.modules['src.models.ranking_v5_training_kernel']
rows=[]
for circuit,family in sorted(runtime.FAMILIES.items()):
    for i in range(12):
        rows.append(dict(action_uid='GENERATED:'+circuit+':'+str(i),circuit=circuit,
                         family=family,role='TRAIN',**{f:float(i)/11 for f in runtime.FEATURES}))
fold=runtime.plan_folds(rows)[0]
request=dict(scope=kernel.SCOPE,source_sha256='a'*64,family=fold.family,
             seed=20260824,model='candidate_mlp',rows=rows,
             fit_cycles={r['action_uid']:100 if r[runtime.FEATURES[0]]==0 else 110
                         for r in rows if r['family']!=fold.family})
logs=[]
def bounded_emit(record):
    if len(logs)>=122 or len(json.dumps(record,allow_nan=False).encode())>20000:
        raise ValueError('KERNEL_LOG_BOUND')
    logs.append(record)
model=kernel.fit_synthetic(torch,np,request,bounded_emit)
def weights_sha(model):
    h=hashlib.sha256()
    for name,tensor in sorted(model.state_dict().items()):
        if tensor.device.type!='cpu' or not torch.isfinite(tensor).all().item():
            raise ValueError('KERNEL_CPU_FINITE_WEIGHTS')
        h.update(name.encode()); h.update(str(tuple(tensor.shape)).encode())
        h.update(tensor.detach().numpy().tobytes())
    return h.hexdigest()
first_weights=weights_sha(model); first_logs=list(logs)
del model
logs.clear()
model=kernel.fit_synthetic(torch,np,request,bounded_emit)
if first_weights!=weights_sha(model) or first_logs!=logs: raise ValueError('KERNEL_DETERMINISM')
if len(logs)!=122 or logs[0]['phase']!='INITIAL' or logs[-1]['phase']!='FINAL':
    raise ValueError('KERNEL_LOG_STAGES')
if [r['epoch'] for r in logs[1:-1]]!=list(range(1,121)): raise ValueError('KERNEL_EPOCH_SEQUENCE')
if any(r['objective_signal_families']!=5 for r in logs): raise ValueError('KERNEL_INACTIVE_FIXTURE')
for r in logs:
    if any(uid in json.dumps(r) for uid in request['fit_cycles']): raise ValueError('KERNEL_RAW_UID_LOG')
rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024
if rss>1024**3: raise ValueError('KERNEL_RSS_OBSERVED_CAP')
result=dict(status='PASS_GENERATED_CPU_KERNEL_INTEGRATION',source_sha256={p:v['sha256'] for p,v in payload.items()},
            dependency_count_verified=31,generated_fixture_actions=72,fitting_actions=60,
            planned_synthetic_fits=2,optimizer_steps=240,real_fits=0,retries=0,
            logs_per_fit=122,deterministic_weights_and_logs=True,weight_sha256=first_weights,
            fitting_log_sha256=runtime.digest(logs),initial_macro_head_loss=logs[0]['macro_head_loss'],
            final_macro_head_loss=logs[-1]['macro_head_loss'],
            peak_process_rss_bytes=rss,address_space_cap_bytes=8*1024**3,
            observed_rss_stop_threshold_bytes=1024**3,cpu_time_cap_seconds=120,wall_timeout_seconds=180,
            wall_timeout_mechanism='SIGALRM plus required outer GNU timeout 180s',cuda_visible_devices='',
            threads=torch.get_num_threads(),interop_threads=torch.get_num_interop_threads(),
            python_version=platform.python_version(),kernel=platform.release(),elapsed_s=time.monotonic()-started,
            real_data_access=False,remote_artifact_writes=False,formal_training_release=False,
            claim_boundary='Synthetic kernel integration only; no fitting or transfer conclusion on real circuits')
raw=json.dumps(result,sort_keys=True,allow_nan=False)
if len(raw.encode())>20000: raise ValueError('KERNEL_OUTPUT_BOUND')
print(raw)
'''


def program(root=ROOT):
    payload = {}
    for path, sha in PINS.items():
        source = root / path
        if any(p.is_symlink() for p in (source, *source.parents)):
            raise ValueError('KERNEL_SYMLINK')
        raw = source.read_bytes()
        if len(raw)>30000 or hashlib.sha256(raw).hexdigest()!=sha:
            raise ValueError('KERNEL_PIN:'+path)
        payload[path] = {'sha256':sha, 'zlib':base64.b64encode(zlib.compress(raw)).decode()}
    code = BOOTSTRAP.replace('payload=PAYLOAD','payload='+repr(payload))
    if len(code.encode())>60000: raise ValueError('KERNEL_PROGRAM_BOUND')
    return code


if __name__ == '__main__': print(program())
