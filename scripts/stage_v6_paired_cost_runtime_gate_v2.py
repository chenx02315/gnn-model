"""Small SHA-checked, bounded bundle to a create-only approved B root."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import stat
import subprocess
import tarfile

REPO = Path(__file__).resolve().parents[1]
LOCAL = REPO.parent / 'runtime_training_staging_20260928' / 'v6_paired_cost_runtime_20261015_r2'
REMOTE = '/ssd/cjc/gnn_model_v6_paired_cost_runtime_20261015_r2'
SSH = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', '-o', 'StrictHostKeyChecking=yes', 'cjc@10.161.89.11']
MAPPING = {
    "runner.py": "scripts/run_v6_paired_cost_runtime_gate_v2.py",
    "_contract.json": "contracts/ranking_v6_paired_cost_runtime_gate_v2.json",
    "contracts/ranking_v6_complete_cost_fit_protocol_v1.json": "contracts/ranking_v6_complete_cost_fit_protocol_v1.json",
    "_protocol_tests.py": "tests/test_run_v6_paired_cost_runtime_gate_v2.py",
    "src/models/runtime_ranking_v3.py": "src/models/runtime_ranking_v3.py",
    "src/models/ranking_v6_scorer_vjp_bridge.py": "src/models/ranking_v6_scorer_vjp_bridge.py",
    "src/models/ranking_v6_first_hit_exact_gradient.py": "src/models/ranking_v6_first_hit_exact_gradient.py",
    "src/models/ranking_v6_first_hit_reference.py": "src/models/ranking_v6_first_hit_reference.py",
    "src/models/ranking_v6_complete_first_hit_reference.py": "src/models/ranking_v6_complete_first_hit_reference.py",
    "src/models/ranking_v6_synthetic_fit_no_prior.py": "src/models/ranking_v6_synthetic_fit_no_prior.py",
    "src/models/ranking_v6_conditional_control_reference.py": "src/models/ranking_v6_conditional_control_reference.py",
    "src/models/ranking_v6_conditional_survival_reference.py": "src/models/ranking_v6_conditional_survival_reference.py",
    "src/models/ranking_v6_complete_cost_fit_protocol.py": "src/models/ranking_v6_complete_cost_fit_protocol.py",
    "src/models/ranking_v6_complete_cost_paired_fit.py": "src/models/ranking_v6_complete_cost_paired_fit.py",
    "src/models/ranking_v6_complete_cost_paired_runtime_v2.py": "src/models/ranking_v6_complete_cost_paired_runtime_v2.py"
}
ARCHIVE_LIMIT = 131072
UNPACKED_LIMIT = 262144
FILE_LIMIT = 65536
ENTRY_COUNT = len(MAPPING) + 1


def require_authorized(contract):
    """Exact E21 one-run release; bool-as-int and widened limits are rejected."""
    fixed = {
    "status": "RELEASED_ONE_RUN_PAIRED_RUNTIME_DIAGNOSTIC_ONLY",
    "execution_authorized": True,
    "authorization": "E21 user-authorized single synthetic paired diagnostic; one run, six models, 144 optimizer steps, zero retries; no production training release.",
    "root": "/ssd/cjc/gnn_model_v6_paired_cost_runtime_20261015_r2",
    "image_id": "sha256:66ec58a325c4165749971d95dbbe1636d8423cc7328be110c5df38ed42ca57e7",
    "shared_site": "/ssd/cjc/gnn_model_runtime_v2_98efbd4f_20261002T235119/venv/lib/python3.11/site-packages",
    "python": "3.11.2",
    "torch": "2.5.1",
    "torch_runtime_version": "2.5.1+cu124",
    "numpy": "2.1.3",
    "sympy": "1.13.1",
    "memory_bytes": 1073741824,
    "swap_extra_bytes": 0,
    "address_space_bytes": 8589934592,
    "workers": 1,
    "cpus": 1,
    "pids_limit": 64,
    "timeout_seconds": 120,
    "log_limit_bytes": 524288,
    "network": "none",
    "root_filesystem": "read_only",
    "tmpfs_bytes": 67108864,
    "formal_runs": 1,
    "planned_formal_runs": 1,
    "automatic_retries": 0,
    "scope": "E21_PAIRED_COST_RUNTIME_DIAGNOSTIC_ONLY",
    "expected_child_status": "COMPLETE_PAIRED_SYNTHETIC_FIT_DIAGNOSTIC_ONLY",
    "expected_parent_status": "PASS_GUARDED_PAIRED_RUNTIME_ONLY",
    "source_count": 15,
    "bundle_entries": 16,
    "archive_limit_bytes": 131072,
    "unpacked_limit_bytes": 262144,
    "file_limit_bytes": 65536,
    "factory_sha256": "d64eb0fe17a00886d6464ae016805b1474e7324e95ad8e223aba44502709759c",
    "planned_optimizer_steps_per_arm": 72,
    "planned_optimizer_steps_total": 144,
    "dependency_integrity_limit": "Read-only bind and fresh versions/origins are verified; metadata is not a full immutable hash of every installed dependency or native library. Only the single E21 synthetic diagnostic is released; no production training release follows.",
    "authorization_id": "E21_FULL_STAGE_20261015_ONE_RUN",
    "planned_models": 6,
    "protocol_sha256": "5075785d758137c37bae3a5e352d3e9c9846cb87585ea48f94bc606a48da815c"
}
    # Human-readable annotations are not authority; every operational field is.
    annotations = {'authorization', 'dependency_integrity_limit'}
    if type(contract) is not dict or any(
            type(contract.get(key)) is not type(value) or contract.get(key) != value
            for key, value in fixed.items() if key not in annotations):
        raise ValueError('E21_EXECUTION_LOCKED')


def stage():
    return _stage_after_gate()


def _stage_after_gate():
    contract = json.loads((REPO / MAPPING['_contract.json']).read_text(encoding='utf-8'))
    require_authorized(contract)
    sources = {}
    for name, relative in MAPPING.items():
        path = REPO / relative
        if path.is_symlink() or not path.resolve().is_relative_to(REPO.resolve()):
            raise ValueError('LOCAL_SOURCE_PATH')
        before = path.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > 65536:
            raise ValueError('LOCAL_SOURCE_BOUND')
        sources[name] = path.read_bytes()
        after = path.stat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError('LOCAL_SOURCE_CHANGED')
    require_authorized(json.loads(sources['_contract.json']))
    pins = {name: hashlib.sha256(data).hexdigest() for name, data in sources.items()}
    manifest = (json.dumps({'sources': pins}, sort_keys=True, separators=(',', ':')) + '\n').encode()
    manifest_sha = hashlib.sha256(manifest).hexdigest()
    sources['_source_manifest.json'] = manifest
    if len(sources) != ENTRY_COUNT or sum(map(len, sources.values())) > UNPACKED_LIMIT:
        raise ValueError('BUNDLE_BOUND')
    LOCAL.mkdir(exist_ok=False)
    archive = LOCAL / 'payload.tar.gz'
    with tarfile.open(archive, 'w:gz') as bundle:
        for name, data in sorted(sources.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), 0o600, 0
            bundle.addfile(info, io.BytesIO(data))
    if archive.stat().st_size > ARCHIVE_LIMIT:
        raise ValueError('ARCHIVE_BOUND')
    with gzip.open(archive, 'rb') as compressed:
        if len(compressed.read(UNPACKED_LIMIT + 1)) > UNPACKED_LIMIT:
            raise ValueError('DECOMPRESSED_BOUND')
    archive_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    (LOCAL / 'source_manifest.json').write_bytes(manifest)
    # Fresh root only: collision is a stop, never overwrite or retry elsewhere.
    subprocess.run(SSH + ['mkdir -- ' + REMOTE], check=True, timeout=15)
    subprocess.run(['scp', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', '-o', 'StrictHostKeyChecking=yes',
                    str(archive), 'cjc@10.161.89.11:' + REMOTE + '/payload.tar.gz'], check=True, timeout=30)
    expected = {name: hashlib.sha256(data).hexdigest() for name, data in sources.items()}
    extraction = f'''
import gzip,hashlib,io,json,os,stat,tarfile
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
with gzip.GzipFile(fileobj=io.BytesIO(archive_bytes)) as compressed:
    raw_tar=compressed.read(262145)
if len(raw_tar)>262144: raise ValueError('DECOMPRESSED_BOUND')
with tarfile.open(fileobj=io.BytesIO(raw_tar),mode='r:') as tar:
    members=tar.getmembers()
    if len(members)!={ENTRY_COUNT} or len(set(m.name for m in members))!={ENTRY_COUNT} or set(m.name for m in members)!=set(expected): raise ValueError('ENTRY_ALLOWLIST')
    if sum(m.size for m in members)>262144: raise ValueError('TOTAL_SIZE')
    for member in members:
        parts=PurePosixPath(member.name)
        if not member.isfile() or member.size>65536 or parts.is_absolute() or '..' in parts.parts: raise ValueError('ENTRY_BOUND')
    for member in members:
        data=tar.extractfile(member).read(65537)
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
                if hashlib.sha256(output.read(65537)).hexdigest()!=expected[member.name]: raise ValueError('READBACK_SHA')
                fresh=os.fstat(output.fileno())
                final=os.stat(components[-1],dir_fd=parent,follow_symlinks=False)
                if fresh.st_nlink!=1 or (fresh.st_dev,fresh.st_ino)!=(final.st_dev,final.st_ino): raise ValueError('DEST_IDENTITY')
        finally: os.close(parent)
print(json.dumps({{'status':'PASS_BOUNDED_STAGING_ONLY','entries':{ENTRY_COUNT},'manifest_sha256':{manifest_sha!r},'archive_sha256':{archive_sha!r}}}))
'''
    staged = subprocess.run(SSH + ['/usr/bin/python3 -I -S -B -'], input=extraction,
                            text=True, capture_output=True, check=True, timeout=30)
    receipt = json.loads(staged.stdout)
    if (receipt.get('status') != 'PASS_BOUNDED_STAGING_ONLY' or receipt.get('entries') != ENTRY_COUNT
            or receipt.get('archive_sha256') != archive_sha or receipt.get('manifest_sha256') != manifest_sha):
        raise ValueError('STAGING_RECEIPT')
    receipt.update({'local': str(LOCAL), 'remote': REMOTE, 'archive_bytes': archive.stat().st_size,
                    'unpacked_bytes': sum(map(len, sources.values())), 'source_sha256': pins})
    (LOCAL / 'staging_receipt.json').write_text(json.dumps(receipt, sort_keys=True), encoding='utf-8')
    print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    stage()
