"""Build a bounded in-memory B synthetic gate; creates no remote files."""
import base64
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
PINS={
 'src/models/ranking_v5_head_objective.py':'aa1d71fa3c6c3a10ea81b133248d334669c48cce8e2a3babe1bb1567b5af7c85',
 'scripts/verify_v5_head_torch_fixture.py':'6bbdab0887246dc0ebb452af79332a1eca72a59b2ab10d9f04d4e016097b6150',
 'requirements/runtime_v2.lock.txt':'a9427b7cbf01048a317009dcf0f625ace51cc739b4e7e2e626a17166ed14c96f',
}

BOOTSTRAP=r'''
import base64,hashlib,importlib.metadata,json,os,platform,resource,sys,time,types
if sys.platform != 'linux' or os.getcwd() != '/ssd/cjc':
    raise ValueError('HEAD_FIXED_B_CWD')
if sys.executable != '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/venv/bin/python':
    raise ValueError('HEAD_FIXED_INTERPRETER')
resource.setrlimit(resource.RLIMIT_AS,(8*1024**3,8*1024**3))
resource.setrlimit(resource.RLIMIT_CPU,(120,120))
sys.dont_write_bytecode=True
started=time.monotonic()
payload=PAYLOAD
decoded={}
for name,item in payload.items():
    raw=base64.b64decode(item['base64'],validate=True)
    if len(raw)>30000 or hashlib.sha256(raw).hexdigest()!=item['sha256']:
        raise ValueError('HEAD_PAYLOAD_SHA_BOUND')
    decoded[name]=raw.decode('utf-8')
lock=decoded['requirements/runtime_v2.lock.txt']
installed={}
for line in lock.splitlines():
    if not line.strip() or line.startswith('#'): continue
    name,expected=line.split('==')
    actual=importlib.metadata.version(name)
    if actual!=expected: raise ValueError('HEAD_DEPENDENCY_DRIFT:'+name)
    installed[name]=actual
if len(installed)!=31: raise ValueError('HEAD_DEPENDENCY_COUNT')
for name in ('src','src.models','scripts'):
    module=types.ModuleType(name); module.__path__=[]; sys.modules[name]=module
for name,path in (('src.models.ranking_v5_head_objective','src/models/ranking_v5_head_objective.py'),
                  ('scripts.verify_v5_head_torch_fixture','scripts/verify_v5_head_torch_fixture.py')):
    module=types.ModuleType(name); sys.modules[name]=module
    exec(compile(decoded[path],path,'exec'),module.__dict__)
import torch
torch.set_num_interop_threads(1)
result=sys.modules['scripts.verify_v5_head_torch_fixture'].verify(torch)
rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024
if rss>1024**3: raise ValueError('HEAD_RSS_OBSERVED_CAP')
if result['status']!='PASS_GENERATED_TORCH_HEAD_GATE': raise ValueError('HEAD_NO_PASS')
result.update({'base_commit':'f393816b641c64bcd030ae2f5fa1345aa04e3f1d',
 'source_sha256':{name:item['sha256'] for name,item in payload.items()},
 'dependency_count_verified':len(installed),'python_version':platform.python_version(),
 'kernel':platform.release(),'peak_process_rss_bytes':rss,'elapsed_seconds':time.monotonic()-started,
 'cwd':os.getcwd(),'address_space_cap_bytes':8*1024**3,'observed_rss_stop_threshold_bytes':1024**3,
 'cpu_time_cap_seconds':120,'wall_timeout_seconds':180,'retries':0,'threads':torch.get_num_threads(),
 'interop_threads':torch.get_num_interop_threads(),'new_fits':0,'optimizer_steps':0,
 'remote_artifact_writes':False,'real_data_or_checkpoint_access':False,
 'claim_boundary':'Generated forward/gradient only, no real training release or speedup claim'})
raw=json.dumps(result,sort_keys=True,allow_nan=False)
if len(raw.encode())>20000: raise ValueError('HEAD_OUTPUT_BOUND')
print(raw)
'''


def program(root=ROOT):
    payload={}
    for name,sha in PINS.items():
        path=root/name
        if any(p.is_symlink() for p in (path,*path.parents)):
            raise ValueError('HEAD_LOCAL_SYMLINK')
        raw=path.read_bytes()
        if len(raw)>30000 or hashlib.sha256(raw).hexdigest()!=sha:
            raise ValueError('HEAD_LOCAL_SOURCE_PIN:'+name)
        payload[name]={'sha256':sha,'base64':base64.b64encode(raw).decode()}
    code=BOOTSTRAP.replace('payload=PAYLOAD','payload='+repr(payload))
    if len(code.encode())>60000: raise ValueError('HEAD_PROGRAM_BOUND')
    return code


if __name__=='__main__': print(program())
