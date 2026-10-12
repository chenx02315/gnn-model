"""Read only seven bounded aggregate/evidence files in the new diagnostic root."""
import json
from pathlib import Path
import subprocess

REMOTE=r'''import base64,hashlib,json,os,pathlib,stat
root=pathlib.Path('/ssd/cjc/gnn_model_ranking_v5_feature_support_20261012_r1')
names=('result.json','actual.log','actual.log.memory.json','actual.once.json','child.once.json','source_manifest.json','synthetic_gate.json')
result={}
for name in names:
    path=root/name
    for ancestor in (path,*path.parents):
        if stat.S_ISLNK(os.lstat(ancestor).st_mode): raise ValueError('SYMLINK')
    before=os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>65536: raise ValueError('FILE_BOUNDARY')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        signature=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        if signature(before)!=signature(os.fstat(fd)): raise ValueError('IDENTITY')
        with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(65537)
        if len(raw)>65536 or signature(before)!=signature(os.fstat(fd)) or signature(before)!=signature(os.lstat(path)): raise ValueError('MUTATION')
    finally:os.close(fd)
    result[name]={'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'raw_base64':base64.b64encode(raw).decode()}
raw=json.dumps({'scope':'NEW_FEATURE_DIAGNOSTIC_AGGREGATES_ONLY','entry_count':7,'files':result},sort_keys=True)
if len(raw.encode())>180000:raise ValueError('OUTPUT_BOUND')
print(raw)
'''


def main():
    p=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8','-o','StrictHostKeyChecking=yes',
                      'cjc@10.161.89.11','/usr/bin/python3 -I -S -B -'],
                     input=REMOTE.encode(),capture_output=True,timeout=30)
    if p.returncode or len(p.stdout)>180000 or p.stderr:
        raise RuntimeError('RECEIPT_COLLECTION_FAILED:'+p.stderr.decode())
    value=json.loads(p.stdout)
    if value['entry_count']!=7:
        raise ValueError('ENTRY_COUNT')
    target=Path(__file__).resolve().parents[2]/'runtime_training_staging_20260928/v5_feature_support_raw_receipts_20261012_r1.json'
    with target.open('xb') as f:f.write(p.stdout)
    print(json.dumps({'entry_count':7,'bytes':len(p.stdout),'output':str(target)}))


if __name__=='__main__':main()
