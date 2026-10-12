"""Bounded six-file B-side deployment and synthetic gate; never actual data."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess

REPO=Path(__file__).resolve().parents[1]
ROOT='/ssd/cjc/gnn_model_ranking_v5_target_cost_20261012_r1'
FILES=('src/models/ranking_v5_target_cost_diagnostic.py','src/models/ranking_v4_memory_guard.py',
       'scripts/run_v5_target_cost.py','tests/test_ranking_v5_target_cost_diagnostic.py',
       'tests/test_run_v5_target_cost.py','src/models/ranking_v5_feature_support.py')
PINS=('4bd339617bdb982bdd8b1412b96a0d37de15a77c4c8f00c1abf81cc2ea9a8897',
      '3dcaf6fd545aa1c5358146567cf55a8ac6593aa14af42f31ec965f8f62c79896',
      'f1fa1212f166878c052a8b2511f2f9f5aa6c68d611ce1a298e11d1d7f3093fde',
      '527208031ebc8cbf4bf8a6f5c424a8be1859ef61ce82e25822f4c4a1afd54cba',
      '7acb1ecb8b1ea82db5c858eb08cdf097e0f367deb07d9d41b4b5484fdf67d5a0',
      '836040988ad6414608077455fa707f9dd5827b10e8ca932786defd499b770243')


def main():
    content={}
    for name,pin in zip(FILES,PINS):
        with (REPO/name).open('rb') as stream:
            raw=stream.read(1024*1024+1)
        if len(raw)>1024*1024:
            raise ValueError('STAGING_FILE_CAP')
        if hashlib.sha256(raw).hexdigest()!=pin:
            raise ValueError('STAGING_SOURCE_DRIFT')
        content[name]=base64.b64encode(raw).decode()
    manifest={'schema':'v5-target-cost-source-v1','files':dict(zip(FILES,PINS))}
    raw=(json.dumps(manifest,sort_keys=True)+'\n').encode()
    manifest_sha=hashlib.sha256(raw).hexdigest()
    gate='''import io,json,os,platform,sys,unittest
sys.path.insert(0,ROOT)
stream=io.StringIO()
suite=unittest.defaultTestLoader.loadTestsFromNames(['tests.test_ranking_v5_target_cost_diagnostic','tests.test_run_v5_target_cost'])
result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
receipt={'testsRun':result.testsRun,'skipped':len(result.skipped),'failures':len(result.failures),'errors':len(result.errors),'gate_pass':result.testsRun>=16 and not result.skipped and result.wasSuccessful(),'python':sys.version,'platform':platform.platform(),'kernel':platform.release(),'log':stream.getvalue()}
print(json.dumps(receipt,sort_keys=True))
sys.exit(0 if receipt['gate_pass'] else 1)
'''
    remote='''import base64,hashlib,json,os,pathlib,stat,sys
from types import ModuleType
ROOT=ROOT_VALUE
files=FILES_VALUE
pins=PINS_VALUE
manifest_raw=base64.b64decode(MANIFEST_VALUE)
root=pathlib.Path(ROOT)
for part in (root.parent,*root.parent.parents):
    info=os.lstat(part)
    if not stat.S_ISDIR(info.st_mode): raise ValueError('PARENT_NOT_ORDINARY')
if sys.version_info[:2]!=(3,11) or sys.platform!='linux': raise ValueError('LINUX_PYTHON')
root.mkdir(mode=0o700,exist_ok=False)
for name,data in sorted(files.items()):
    if name not in pins or pathlib.PurePosixPath(name).is_absolute() or '..' in pathlib.PurePosixPath(name).parts: raise ValueError('ENTRY')
    raw=base64.b64decode(data,validate=True)
    if hashlib.sha256(raw).hexdigest()!=pins[name]: raise ValueError('HASH')
    path=root/name
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as f: f.write(raw)
    if hashlib.sha256(path.read_bytes()).hexdigest()!=pins[name]: raise ValueError('READBACK')
with (root/'source_manifest.json').open('xb') as f: f.write(manifest_raw)
if (root/'source_manifest.json').read_bytes()!=manifest_raw: raise ValueError('MANIFEST_READBACK')
tmp=root/'synthetic_tmp';tmp.mkdir(mode=0o700)
code='ROOT='+repr(ROOT)+'\\n'+GATE_VALUE
env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','TMPDIR':str(tmp),'PYTHONDONTWRITEBYTECODE':'1'}
guard=ModuleType('synthetic_resource_guard');sys.modules[guard.__name__]=guard
guard_raw=base64.b64decode(files['src/models/ranking_v4_memory_guard.py'])
exec(compile(guard_raw,str(root/'src/models/ranking_v4_memory_guard.py'),'exec'),guard.__dict__)
env.update({key:'1' for key in guard.THREAD_KEYS})
log=root/'synthetic.log'
bounded=guard.run_bounded(['/usr/bin/python3','-I','-S','-B','-c',code],log,env)
if json.loads(pathlib.Path(str(log)+'.memory.json').read_bytes())!=bounded: raise ValueError('GUARD_READBACK')
with log.open('rb') as stream: output=stream.read(32769)
if len(output)>32768: raise ValueError('GATE_OUTPUT_BOUND')
payload=json.loads(output)
receipt={'status':'PASS_LINUX_SYNTHETIC_TARGET_COST_GATE' if bounded['exit_code']==0 and payload.get('gate_pass') is True else 'FAIL_LINUX_SYNTHETIC_TARGET_COST_GATE','entry_count':len(files),'source_manifest_sha256':hashlib.sha256(manifest_raw).hexdigest(),'gate':payload,'exit_code':bounded['exit_code'],'guard':bounded}
raw=(json.dumps(receipt,sort_keys=True)+'\\n').encode()
with (root/'synthetic_gate.json').open('xb') as f: f.write(raw)
print(raw.decode(),end='')
sys.exit(0 if receipt['status'].startswith('PASS_') else 1)
'''
    for key,value in [('ROOT_VALUE',repr(ROOT)),('FILES_VALUE',repr(content)),
                      ('PINS_VALUE',repr(dict(zip(FILES,PINS)))),('MANIFEST_VALUE',repr(base64.b64encode(raw).decode())),
                      ('GATE_VALUE',repr(gate))]:
        remote=remote.replace(key,value)
    if len(remote.encode())>256*1024:
        raise ValueError('STAGING_PACKAGE_BOUND')
    result=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8','-o','StrictHostKeyChecking=yes',
                           'cjc@10.161.89.11','/usr/bin/python3 -I -S -B -'],input=remote.encode(),
                          capture_output=True,timeout=1830)
    if len(result.stdout)>40000 or len(result.stderr)>8000:
        raise ValueError('STAGING_REPLY_BOUND')
    output=REPO.parent/'runtime_training_staging_20260928'/'v5_target_cost_synthetic_gate_20261012_r1.json'
    with output.open('xb') as f:
        f.write(result.stdout if result.stdout else json.dumps({'exit_code':result.returncode,'stderr':result.stderr.decode()}).encode())
    print('manifest_sha256='+manifest_sha)
    print(result.stdout.decode())
    print(result.stderr.decode())
    if result.returncode:
        raise SystemExit(result.returncode)


if __name__=='__main__':
    main()
