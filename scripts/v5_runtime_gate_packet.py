"""Exact four-entry small gate packet; create-once B deployment, never launch."""
import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tarfile

NAMES = frozenset(('src/models/ranking_v5_locked_runtime_observations.py',
                   'src/models/ranking_v5_locked_runtime_imports.py',
                   'scripts/run_v5_controlled_runtime_gate.py'))
MANIFEST = 'runtime_gate_packet_manifest.json'
ARCHIVE_CAP = 64*1024
TAR_CAP = 256*1024
FILE_CAP = 64*1024


def require(ok, code):
    if not ok: raise ValueError('V5_RUNTIME_PACKET_' + code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE')
        result[key] = value
    return result


def validate(packet, expected_sha):
    require(type(expected_sha) is str and re.fullmatch('[0-9a-f]{64}', expected_sha) is not None, 'SHA')
    require(type(packet) is bytes and 0 < len(packet) <= ARCHIVE_CAP
            and digest(packet) == expected_sha, 'ARCHIVE')
    with gzip.GzipFile(fileobj=io.BytesIO(packet)) as stream:
        raw = stream.read(TAR_CAP + 1)
    require(0 < len(raw) <= TAR_CAP, 'TAR_BOUND')
    payloads = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            require(len(payloads) < 4 and member.name in NAMES | {MANIFEST}
                    and member.name not in payloads and member.isfile()
                    and not member.pax_headers and 0 < member.size <= FILE_CAP, 'ENTRY')
            value = archive.extractfile(member).read(FILE_CAP + 1)
            require(len(value) == member.size, 'FILE_BOUND')
            payloads[member.name] = value
    require(set(payloads) == NAMES | {MANIFEST}, 'EXACT_SET')
    manifest = json.loads(payloads[MANIFEST], object_pairs_hook=unique,
                          parse_constant=lambda _: require(False, 'NONFINITE'))
    require(type(manifest) is dict and set(manifest) == {'schema', 'files', 'formal_training_release'}
            and manifest['schema'] == 'v5-runtime-gate-packet-v1'
            and manifest['formal_training_release'] is False
            and type(manifest['files']) is dict and set(manifest['files']) == NAMES, 'MANIFEST')
    require(all(type(pin) is str and pin == digest(payloads[name])
                for name, pin in manifest['files'].items()), 'FILE_SHA')
    return payloads, manifest, len(raw)


def receive(packet, expected_sha, root):
    # Exact lexical destination check before any filesystem operation.
    require(type(root) is str and re.fullmatch(
        '/ssd/cjc/gnn_model_ranking_v5_runtime_gate_[0-9]{8}_r[1-9][0-9]*', root) is not None, 'ROOT')
    payloads, manifest, tar_bytes = validate(packet, expected_sha)
    target = Path(root)
    require(not any(path.is_symlink() for path in (target, *target.parents)), 'SYMLINK')
    target.mkdir(mode=0o700)
    for name, raw in sorted(payloads.items()):
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        require(path.read_bytes() == raw, 'READBACK')
    receipt = dict(status='PASS_RUNTIME_GATE_SOURCE_DEPLOYMENT_ONLY', entries=4,
        root=root, archive_sha256=expected_sha, archive_bytes=len(packet), tar_bytes=tar_bytes,
        files=manifest['files'], formal_training_release=False, actual_fits=0, automatic_retries=0)
    with (target / 'deployment_receipt.json').open('x') as stream:
        json.dump(receipt, stream, sort_keys=True); stream.flush(); os.fsync(stream.fileno())
    return receipt


def build(output):
    root = Path(__file__).resolve().parents[1]
    payloads = {}
    for name in sorted(NAMES):
        path = root / name
        require(not any(item.is_symlink() for item in (path, *path.parents)), 'SYMLINK')
        with path.open('rb') as stream: raw = stream.read(FILE_CAP + 1)
        require(0 < len(raw) <= FILE_CAP, 'SOURCE_BOUND')
        payloads[name] = raw
    manifest = dict(schema='v5-runtime-gate-packet-v1',
                    files={name: digest(raw) for name, raw in payloads.items()}, formal_training_release=False)
    payloads[MANIFEST] = json.dumps(manifest, sort_keys=True).encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(payloads.items()):
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode, entry.mtime = len(raw), 0o600, 0
            archive.addfile(entry, io.BytesIO(raw))
    require(len(buffer.getvalue()) <= TAR_CAP, 'TAR_BOUND')
    packet = gzip.compress(buffer.getvalue(), mtime=0)
    pin = digest(packet)
    validate(packet, pin)
    path = Path(output)
    require(path.suffixes[-2:] == ['.tar', '.gz'], 'OUTPUT')
    require(not any(item.is_symlink() for item in (path, *path.parents)), 'SYMLINK')
    with path.open('xb') as stream: stream.write(packet)
    return dict(archive_sha256=pin, archive_bytes=len(packet), tar_bytes=len(buffer.getvalue()),
                entries=4, files=manifest['files'], formal_training_release=False)


def deploy(path, expected_sha, root):
    require(type(root) is str and re.fullmatch(
        '/ssd/cjc/gnn_model_ranking_v5_runtime_gate_[0-9]{8}_r[1-9][0-9]*', root) is not None, 'ROOT')
    path = Path(path)
    require(not any(item.is_symlink() for item in (path, *path.parents)), 'SYMLINK')
    with path.open('rb') as stream: packet = stream.read(ARCHIVE_CAP + 1)
    _, manifest, tar_bytes = validate(packet, expected_sha)
    # This exact reviewed stdlib-only source is executed remotely, not imported.
    with Path(__file__).open('rb') as stream: program = stream.read(FILE_CAP + 1)
    require(0 < len(program) <= FILE_CAP, 'PROGRAM_BOUND')
    encoded = base64.b64encode(program).decode('ascii')
    code = "import base64;exec(compile(base64.b64decode('" + encoded + "'),'<runtime-packet>','exec'))"
    command = 'python3 -I -B -c ' + shlex.quote(code) + ' receive --sha256 ' + expected_sha + ' --root ' + root
    completed = subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8',
        '-o', 'StrictHostKeyChecking=yes', 'cjc@10.161.89.11', command],
        input=base64.b64encode(packet), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=30, check=False)
    require(len(completed.stdout) <= 20000 and len(completed.stderr) <= 20000, 'REMOTE_BOUND')
    if completed.returncode != 0:
        raise RuntimeError('V5_RUNTIME_PACKET_DEPLOY_FAILED_NO_RETRY:' + completed.stderr.decode(errors='replace')[:2000])
    result = json.loads(completed.stdout, object_pairs_hook=unique)
    expected = dict(status='PASS_RUNTIME_GATE_SOURCE_DEPLOYMENT_ONLY', entries=4,
        root=root, archive_sha256=expected_sha, archive_bytes=len(packet), tar_bytes=tar_bytes,
        files=manifest['files'], formal_training_release=False, actual_fits=0, automatic_retries=0)
    require(type(result) is dict and result == expected and type(result.get('entries')) is int
            and type(result.get('actual_fits')) is int and type(result.get('automatic_retries')) is int
            and type(result.get('archive_bytes')) is int and type(result.get('tar_bytes')) is int
            and result.get('formal_training_release') is False, 'REMOTE_RECEIPT')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('build', 'deploy', 'receive'))
    parser.add_argument('--archive'); parser.add_argument('--sha256'); parser.add_argument('--root')
    args = parser.parse_args()
    if args.action == 'build': result = build(args.archive)
    elif args.action == 'deploy': result = deploy(args.archive, args.sha256, args.root)
    else:
        encoded = sys.stdin.buffer.read(100*1024 + 1)
        require(len(encoded) <= 100*1024, 'ENCODED_BOUND')
        result = receive(base64.b64decode(encoded.strip(), validate=True), args.sha256, args.root)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    import sys
    main()
