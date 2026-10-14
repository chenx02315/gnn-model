"""Small SHA-checked, bounded bundle to a create-only approved B root."""
import hashlib
import io
import json
from pathlib import Path
import stat
import subprocess
import tarfile

REPO = Path(__file__).resolve().parents[1]
LOCAL = REPO.parent / 'runtime_training_staging_20260928' / 'v6_synthetic_fit_no_prior_container_20261014_r1'
REMOTE = '/ssd/cjc/gnn_model_v6_synthetic_fit_no_prior_20261014_r1'
SSH = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', '-o', 'StrictHostKeyChecking=yes', 'cjc@10.161.89.11']
MAPPING = {
    'runner.py':'scripts/run_v6_synthetic_fit_no_prior_container.py',
    '_contract.json':'contracts/ranking_v6_synthetic_fit_no_prior_gate_v1.json',
    '_protocol_tests.py':'tests/test_run_v6_synthetic_fit_no_prior_container.py',
    'src/models/ranking_v6_synthetic_fit_no_prior.py':'src/models/ranking_v6_synthetic_fit_no_prior.py',
    'src/models/runtime_ranking_v3.py':'src/models/runtime_ranking_v3.py',
    'src/models/ranking_v6_scorer_vjp_bridge.py':'src/models/ranking_v6_scorer_vjp_bridge.py',
    'src/models/ranking_v6_conditional_control_reference.py':'src/models/ranking_v6_conditional_control_reference.py',
    'src/models/ranking_v6_conditional_survival_reference.py':'src/models/ranking_v6_conditional_survival_reference.py',
    'src/models/ranking_v6_first_hit_exact_gradient.py':'src/models/ranking_v6_first_hit_exact_gradient.py',
    'src/models/ranking_v6_first_hit_reference.py':'src/models/ranking_v6_first_hit_reference.py',
}



def stage():
    sources = {}
    for name, relative in MAPPING.items():
        path = REPO / relative
        if path.is_symlink() or not path.resolve().is_relative_to(REPO.resolve()):
            raise ValueError('LOCAL_SOURCE_PATH')
        before = path.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > 131072:
            raise ValueError('LOCAL_SOURCE_BOUND')
        sources[name] = path.read_bytes()
        after = path.stat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError('LOCAL_SOURCE_CHANGED')
    pins = {name: hashlib.sha256(data).hexdigest() for name, data in sources.items()}
    manifest = (json.dumps({'sources': pins}, sort_keys=True, separators=(',', ':')) + '\n').encode()
    manifest_sha = hashlib.sha256(manifest).hexdigest()
    sources['_source_manifest.json'] = manifest
    if len(sources) != 11 or sum(map(len, sources.values())) > 393216:
        raise ValueError('BUNDLE_BOUND')
    LOCAL.mkdir(exist_ok=False)
    archive = LOCAL / 'payload.tar.gz'
    with tarfile.open(archive, 'w:gz') as bundle:
        for name, data in sorted(sources.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), 0o600, 0
            bundle.addfile(info, io.BytesIO(data))
    if archive.stat().st_size > 131072:
        raise ValueError('ARCHIVE_BOUND')
    archive_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    (LOCAL / 'source_manifest.json').write_bytes(manifest)
    # Fresh root only: collision is a stop, never overwrite or retry elsewhere.
    subprocess.run(SSH + ['mkdir -- ' + REMOTE], check=True, timeout=15)
    subprocess.run(['scp', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', '-o', 'StrictHostKeyChecking=yes',
                    str(archive), 'cjc@10.161.89.11:' + REMOTE + '/payload.tar.gz'], check=True, timeout=30)
    expected = {name: hashlib.sha256(data).hexdigest() for name, data in sources.items()}
    extraction = f'''
import hashlib,io,json,os,stat,tarfile
from pathlib import Path,PurePosixPath
root=Path({REMOTE!r})
expected={expected!r}
if root.resolve()!=root: raise ValueError('REMOTE_ROOT')
archive=root/'payload.tar.gz'
fd=os.open(archive,os.O_RDONLY|os.O_NOFOLLOW)
try:
    observed=os.fstat(fd)
    if not stat.S_ISREG(observed.st_mode) or observed.st_nlink!=1 or observed.st_size>131072: raise ValueError('ARCHIVE_BOUND')
    archive_bytes=os.read(fd,131073)
finally: os.close(fd)
if hashlib.sha256(archive_bytes).hexdigest()!={archive_sha!r}: raise ValueError('ARCHIVE_SHA')
with tarfile.open(fileobj=io.BytesIO(archive_bytes),mode='r:gz') as tar:
    members=tar.getmembers()
    if len(members)!=11 or len(set(m.name for m in members))!=11 or set(m.name for m in members)!=set(expected): raise ValueError('ENTRY_ALLOWLIST')
    if sum(m.size for m in members)>393216: raise ValueError('TOTAL_SIZE')
    for member in members:
        parts=PurePosixPath(member.name)
        if not member.isfile() or member.size>131072 or parts.is_absolute() or '..' in parts.parts: raise ValueError('ENTRY_BOUND')
    for member in members:
        data=tar.extractfile(member).read(131073)
        if len(data)!=member.size or hashlib.sha256(data).hexdigest()!=expected[member.name]: raise ValueError('ENTRY_SHA')
        parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            components=PurePosixPath(member.name).parts
            for component in components[:-1]:
                try: os.mkdir(component,mode=0o755,dir_fd=parent)
                except FileExistsError: pass
                next_parent=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                os.close(parent)
                parent=next_parent
            fd=os.open(components[-1],os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
            with os.fdopen(fd,'w+b') as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
                output.seek(0)
                if hashlib.sha256(output.read(131073)).hexdigest()!=expected[member.name]: raise ValueError('READBACK_SHA')
                fresh=os.fstat(output.fileno())
                final=os.stat(components[-1],dir_fd=parent,follow_symlinks=False)
                if fresh.st_nlink!=1 or (fresh.st_dev,fresh.st_ino)!=(final.st_dev,final.st_ino): raise ValueError('DEST_IDENTITY')
        finally: os.close(parent)
print(json.dumps({{'status':'PASS_BOUNDED_STAGING_ONLY','entries':11,'manifest_sha256':{manifest_sha!r},'archive_sha256':{archive_sha!r}}}))
'''
    staged = subprocess.run(SSH + ['/usr/bin/python3 -I -S -B -'], input=extraction,
                            text=True, capture_output=True, check=True, timeout=30)
    receipt = json.loads(staged.stdout)
    if receipt['manifest_sha256'] != manifest_sha:
        raise ValueError('STAGING_RECEIPT')
    receipt.update({'local': str(LOCAL), 'remote': REMOTE, 'archive_bytes': archive.stat().st_size,
                    'unpacked_bytes': sum(map(len, sources.values())), 'source_sha256': pins})
    (LOCAL / 'staging_receipt.json').write_text(json.dumps(receipt, sort_keys=True), encoding='utf-8')
    print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    stage()
