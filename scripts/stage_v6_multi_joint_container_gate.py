"""Small SHA-checked, bounded bundle to a create-only approved B root."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import stat
import subprocess
import tarfile

REPO = Path(__file__).resolve().parents[1]
LOCAL = REPO.parent / 'runtime_training_staging_20260928' / 'v6_multi_positive_joint_container_20261015_r1'
REMOTE = '/ssd/cjc/gnn_model_v6_multi_positive_joint_20261015_r1'
SSH = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', '-o', 'StrictHostKeyChecking=yes', 'cjc@10.161.89.11']
MAPPING = {
    "runner.py": "scripts/run_v6_multi_joint_container_gate.py",
    "_contract.json": "contracts/ranking_v6_multi_joint_container_gate_v1.json",
    "src/models/runtime_ranking_v3.py": "src/models/runtime_ranking_v3.py",
    "src/models/ranking_v6_scorer_vjp_bridge.py": "src/models/ranking_v6_scorer_vjp_bridge.py",
    "src/models/ranking_v6_synthetic_real_bridge_adapter.py": "src/models/ranking_v6_synthetic_real_bridge_adapter.py",
    "src/models/ranking_v6_multi_positive_joint_caller.py": "src/models/ranking_v6_multi_positive_joint_caller.py",
    "src/models/ranking_v6_multi_positive_conditional_risk.py": "src/models/ranking_v6_multi_positive_conditional_risk.py",
    "src/models/ranking_v6_multi_positive_risk_control.py": "src/models/ranking_v6_multi_positive_risk_control.py",
    "src/models/ranking_v6_multi_positive_complete_cost.py": "src/models/ranking_v6_multi_positive_complete_cost.py",
    "src/models/ranking_v6_multi_positive_joint_probe.py": "src/models/ranking_v6_multi_positive_joint_probe.py",
    "src/models/ranking_v6_synthetic_joint_freeze.py": "src/models/ranking_v6_synthetic_joint_freeze.py",
    "_protocol_tests.py": "tests/test_run_v6_multi_joint_container_gate.py"
}
ARCHIVE_LIMIT = 65536
UNPACKED_LIMIT = 196608
FILE_LIMIT = 65536
ENTRY_COUNT = len(MAPPING) + 1


def require_authorized(contract):
    expected = json.loads("{\n  \"status\": \"AUTHORIZED_ONE_E29_SYNTHETIC_MULTI_POSITIVE_JOINT_VJP_AFTER_REVIEW_AND_FRESH_GATES_NOT_TRAINING\",\n  \"authorization\": \"User approved all three proposed stages. This contract permits one new isolated synthetic forward/backward validation, no optimizer or fitting. Stage three remains protocol design only.\",\n  \"root\": \"/ssd/cjc/gnn_model_v6_multi_positive_joint_20261015_r1\",\n  \"image_id\": \"sha256:66ec58a325c4165749971d95dbbe1636d8423cc7328be110c5df38ed42ca57e7\",\n  \"shared_site\": \"/ssd/cjc/gnn_model_runtime_v2_98efbd4f_20261002T235119/venv/lib/python3.11/site-packages\",\n  \"python\": \"3.11.2\", \"torch\": \"2.5.1\", \"numpy\": \"2.1.3\", \"sympy\": \"1.13.1\",\n  \"memory_bytes\": 1073741824, \"swap_extra_bytes\": 0, \"address_space_bytes\": 8589934592,\n  \"workers\": 1, \"cpus\": 1, \"pids_limit\": 64, \"timeout_seconds\": 120,\n  \"log_limit_bytes\": 524288, \"network\": \"none\", \"root_filesystem\": \"read_only\", \"tmpfs_bytes\": 67108864,\n  \"formal_runs\": 1, \"automatic_retries\": 0,\n  \"scope\": \"SYNTHETIC_MULTI_POSITIVE_JOINT_VJP_ONLY\",\n  \"expected_child_status\": \"PASS_REAL_FACTORY_MULTI_POSITIVE_JOINT_VJP_ONLY\",\n  \"expected_parent_status\": \"PASS_GUARDED_MULTI_POSITIVE_JOINT_VJP_ONLY\",\n  \"source_count\": 12, \"bundle_entries\": 13,\n  \"factory_sha256\": \"d64eb0fe17a00886d6464ae016805b1474e7324e95ad8e223aba44502709759c\",\n  \"scorer\": \"Unchanged existing seven-feature 7->32 ReLU->32 ReLU->1 MLP, 1345 parameters, CPU float64; one newly initialized synthetic probe model, no checkpoint.\",\n  \"fixture\": {\"actions\": 6, \"positive_count\": 2, \"k\": 3, \"seed\": 11, \"pilot_samples\": 32, \"main_samples\": 480, \"risk_weight\": 0.5, \"normalized_cost_weight\": 1.0},\n  \"finite_difference\": {\"epsilon\": 0.000001, \"absolute_tolerance\": 1e-8, \"relative_tolerance\": 1e-5, \"active_coordinate_min_absolute_derivative\": 1e-7, \"relu_mask_must_match\": true},\n  \"probe_limits\": {\"mc_estimator_calls\": 1, \"optimizer_calls\": 0, \"accepted_updates\": 0, \"real_label_reads\": 0, \"checkpoint_reads\": 0, \"training_runs\": 0, \"blind_access\": false, \"lsf_tessent_calls\": 0},\n  \"dependency_integrity_limit\": \"Pinned image, read-only dependency bind, fresh versions/origins and source readback; not a full immutable digest of all shared-site dependencies or native libraries. Synthetic validation is not real TRAIN release.\",\n  \"real_training_release\": false\n}\n\r\n")
    if type(contract) is not dict or json.dumps(contract, sort_keys=True, allow_nan=False) != json.dumps(expected, sort_keys=True):
        raise ValueError('E29_EXECUTION_LOCKED')


def build():
    """Local-only fixed-source build; no transport or formal container launch."""
    return _build_bundle()


def stage(*, execute=False):
    if execute is not True:
        raise ValueError('EXPLICIT_EXECUTE_REQUIRED')
    return transfer(build())


def _build_bundle():
    contract = json.loads((REPO / MAPPING['_contract.json']).read_text(encoding='utf-8'))
    require_authorized(contract)
    sources = {}
    for name, relative in MAPPING.items():
        path = REPO / relative
        if path.is_symlink() or not path.resolve().is_relative_to(REPO.resolve()):
            raise ValueError('LOCAL_SOURCE_PATH')
        before = path.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 65536:
            raise ValueError('LOCAL_SOURCE_BOUND')
        sources[name] = path.read_bytes()
        after = path.stat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError('LOCAL_SOURCE_CHANGED')
    require_authorized(json.loads(sources['_contract.json']))
    pins = {name: hashlib.sha256(data).hexdigest() for name, data in sources.items()}
    if pins['src/models/runtime_ranking_v3.py'] != contract['factory_sha256']:
        raise ValueError('FACTORY_PIN')
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
    return {'archive': archive, 'archive_sha': archive_sha, 'manifest_sha': manifest_sha,
            'sources': sources, 'pins': pins}


def transfer(bundle):
    """Explicit transport seam; fixed remote root and fixed endpoint only."""
    archive, archive_sha = bundle['archive'], bundle['archive_sha']
    manifest_sha, sources, pins = bundle['manifest_sha'], bundle['sources'], bundle['pins']
    require_authorized(json.loads(sources['_contract.json']))
    if (archive != LOCAL / 'payload.tar.gz' or archive.is_symlink()
            or archive.stat().st_nlink != 1 or archive.stat().st_size > ARCHIVE_LIMIT
            or hashlib.sha256(archive.read_bytes()).hexdigest() != archive_sha
            or set(pins) != set(MAPPING) or set(sources) != set(MAPPING) | {'_source_manifest.json'}):
        raise ValueError('TRANSFER_BUNDLE_PIN')
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
    if not stat.S_ISREG(observed.st_mode) or observed.st_nlink!=1 or observed.st_size>65536: raise ValueError('ARCHIVE_BOUND')
    archive_bytes=os.read(fd,65537)
finally: os.close(fd)
if hashlib.sha256(archive_bytes).hexdigest()!={archive_sha!r}: raise ValueError('ARCHIVE_SHA')
with gzip.GzipFile(fileobj=io.BytesIO(archive_bytes)) as compressed:
    raw_tar=compressed.read(196609)
if len(raw_tar)>196608: raise ValueError('DECOMPRESSED_BOUND')
with tarfile.open(fileobj=io.BytesIO(raw_tar),mode='r:') as tar:
    members=tar.getmembers()
    if len(members)!={ENTRY_COUNT} or len(set(m.name for m in members))!={ENTRY_COUNT} or set(m.name for m in members)!=set(expected): raise ValueError('ENTRY_ALLOWLIST')
    if sum(m.size for m in members)>196608: raise ValueError('TOTAL_SIZE')
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args(argv)
    if not args.execute:
        parser.error('--execute is required; importing is inert')
    stage(execute=True)


if __name__ == '__main__':
    main()
