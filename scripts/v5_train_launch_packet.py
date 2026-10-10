"""Bounded, externally pinned TRAIN source transport. Deployment only; no launch.

Trust maps MUST arrive from an independent review, never the archive manifest.
The receiver is stdlib-only until executing authenticated included definitions.
No SSH, formal package, staging discovery, ML import, release creation or retry.
"""
import argparse
import gzip
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
from types import ModuleType

CLI = 'scripts/run_v5_train_single_fit.py'
PARENT = 'scripts/run_v5_train_serial_parent.py'
MANIFEST = 'launch_packet.json'
CORE_MANIFEST = 'data/manifests/ranking_v5_caller_source_bytes_20261008.json'
CORE_SHA = '5394779faac5c77800a0a9d8ed52bf9f24ba2dd701f499a49754e51e7ddceae7'
ROOT_PATTERN = r'/ssd/cjc/gnn_model_ranking_v5_train_[0-9]{8}_r[1-9][0-9]*'
ARCHIVE_CAP, TAR_CAP, SOURCE_CAP, JSON_CAP = 256*1024, 1024*1024, 65536, 20000
ENTRY_COUNT = 64


def require(ok, code):
    if not ok:
        raise ValueError('V5_TRAIN_PACKET_' + code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def encode(value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()+b'\n'
    require(0 < len(raw) <= JSON_CAP, 'JSON_BOUND')
    return raw


def decode(raw):
    require(type(raw) is bytes and 0 < len(raw) <= JSON_CAP, 'JSON_BOUND')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'JSON_DUPLICATE')
            result[key] = value
        return result
    def invalid(_):
        raise ValueError('V5_TRAIN_PACKET_JSON_NONFINITE')
    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)
    except (UnicodeError, RecursionError, json.JSONDecodeError) as error:
        raise ValueError('V5_TRAIN_PACKET_JSON_INVALID') from error
    require(type(value) is dict, 'JSON_OBJECT')
    return value


def ordinary(info, directory=False):
    require(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400,
            'LINK')
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), 'ORDINARY')


def read(path, cap):
    path = Path(path)
    for ancestor in path.parents:
        ordinary(ancestor.lstat(), True)
    before = path.lstat(); ordinary(before)
    require(0 < before.st_size <= cap, 'FILE_BOUND')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno()); ordinary(opened)
        raw = stream.read(cap+1)
        after = os.fstat(stream.fileno())
    final = path.lstat(); ordinary(final)
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
    require(0 < len(raw) == before.st_size <= cap and all(identity(item) == identity(before)
            for item in (opened, after, final)), 'FILE_CHANGED')
    return raw


def external(raw, name):
    module = ModuleType(name)
    module.__file__ = 'authenticated-transport://' + name
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


def unpack(packet, expected_sha):
    require(pin(expected_sha) and type(packet) is bytes and 0 < len(packet) <= ARCHIVE_CAP
            and sha(packet) == expected_sha, 'ARCHIVE_SHA_BOUND')
    with gzip.GzipFile(fileobj=io.BytesIO(packet)) as stream:
        raw = stream.read(TAR_CAP+1)
    require(0 < len(raw) <= TAR_CAP and len(raw) % 512 == 0, 'TAR_BOUND')
    payloads, offset = {}, 0
    while offset < len(raw):
        header = raw[offset:offset+512]
        if header == bytes(512):
            require(len(raw)-offset >= 1024 and not any(raw[offset:]), 'TAR_TRAILER')
            break
        require(len(payloads) < ENTRY_COUNT and header[257:265] == b'ustar\x0000'
                and header[156:157] == b'0', 'USTAR_REGULAR_ONLY')
        member = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
        name = member.name
        require(name not in payloads and len(name) <= 200 and '\\' not in name
                and not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/'))
                and not member.linkname and 0 < member.size <= SOURCE_CAP, 'ENTRY')
        start, end = offset+512, offset+512+member.size
        next_offset = start+((member.size+511)//512)*512
        require(next_offset <= len(raw) and not any(raw[end:next_offset]), 'ENTRY_BOUND_PADDING')
        payloads[name] = raw[start:end]
        offset = next_offset
    else:
        raise ValueError('V5_TRAIN_PACKET_TAR_NO_TRAILER')
    require(len(payloads) == ENTRY_COUNT, 'ENTRY_COUNT')
    return payloads, len(raw)


def approval_integrity(cli, parent, sources, evidence, trusted_evidence):
    """Execute only authenticated pure validators under the unchanged byte fence."""
    fence = external(sources[parent.FENCE], '_v5_transport_fence')
    python = {p: sources[p] for p in cli.CORE_FILES if p.endswith('.py')}
    with fence.sealed_imports(python, {p: sha(raw) for p, raw in python.items()}):
        approval = importlib.import_module('src.models.ranking_v5_approval_binding')
        approval.validate_approval_integrity(cli._json(evidence['release.json']),
            {p: sha(sources[p]) for p in cli.RELEASE_SOURCE_FILES},
            evidence['authorization.json'], evidence['review.json'],
            trusted_authorization_sha256=trusted_evidence['authorization.json'],
            trusted_review_sha256=trusted_evidence['review.json'],
            trusted_physical_gate_sha256=trusted_evidence['physical_gate.json'])


def validate(packet, archive_sha256, packet_sha256, root, *,
             trusted_source_sha256, trusted_evidence_sha256):
    # No filesystem reads or writes in validation. Supplied maps are external anchors.
    require(type(root) is str and re.fullmatch(ROOT_PATTERN, root) is not None, 'ROOT')
    require(pin(packet_sha256) and type(trusted_source_sha256) is dict
            and type(trusted_evidence_sha256) is dict
            and len(trusted_source_sha256) == 36 and len(trusted_evidence_sha256) == 8
            and all(pin(p) for p in (*trusted_source_sha256.values(), *trusted_evidence_sha256.values())),
            'EXTERNAL_ANCHORS')
    trusted_source_sha256 = dict(trusted_source_sha256)
    trusted_evidence_sha256 = dict(trusted_evidence_sha256)
    payloads, tar_bytes = unpack(packet, archive_sha256)
    require(MANIFEST in payloads and sha(payloads[MANIFEST]) == packet_sha256, 'PACKET_SHA')
    manifest = decode(payloads[MANIFEST])
    require(set(manifest) == {'schema', 'source_root', 'package_root', 'core_manifest_sha256',
        'source_sha256', 'evidence_sha256', 'prelaunch_sha256'}
        and manifest['schema'] == 'v5-train-serial-launch-packet-v1'
        and manifest['source_root'] == root and manifest['core_manifest_sha256'] == CORE_SHA
        and manifest['source_sha256'] == trusted_source_sha256
        and manifest['evidence_sha256'] == trusted_evidence_sha256, 'MANIFEST_ANCHORS')
    require(CLI in trusted_source_sha256 and PARENT in trusted_source_sha256
        and all(p in payloads and sha(payloads[p]) == value for p, value in trusted_source_sha256.items())
        and all(p in payloads and len(payloads[p]) <= JSON_CAP and sha(payloads[p]) == value
                for p, value in trusted_evidence_sha256.items()), 'RAW_PINS')
    cli = external(payloads[CLI], '_v5_transport_cli')
    parent = external(payloads[PARENT], '_v5_transport_parent')
    required = cli.CORE_FILES | {CLI, PARENT, parent.CPU_PROGRAM, *cli.HELPERS, *parent.EXTRA}
    envelopes = {f'prelaunch_{f}_{s}.json' for f in cli.FAMILIES for s in cli.SEEDS}
    require(len(required) == 36 and len(envelopes) == 18 and set(trusted_source_sha256) == required
        and set(trusted_evidence_sha256) == set(cli.EVIDENCE) | set(parent.CPU_EVIDENCE)
        and type(manifest['prelaunch_sha256']) is dict
        and all(pin(p) for p in manifest['prelaunch_sha256'].values())
        and set(manifest['prelaunch_sha256']) == envelopes
        and set(payloads) == required | set(trusted_evidence_sha256) | envelopes | {MANIFEST, CORE_MANIFEST}
        and manifest['package_root'] == cli.PACKAGE_ROOT and cli.CORE_MANIFEST_SHA256 == CORE_SHA
        and cli.MANIFEST_NAME == CORE_MANIFEST, 'EXACT_SCOPE')
    require(sha(payloads[CORE_MANIFEST]) == CORE_SHA, 'CORE_SHA')
    core = cli._json(payloads[CORE_MANIFEST])
    require(set(core) == {'schema', 'formal_training_release', 'sources'}
        and core['schema'] == 'v5-caller-source-bytes-v1' and core['formal_training_release'] is False
        and core['sources'] == {p: trusted_source_sha256[p] for p in cli.CORE_FILES}, 'CORE_BINDING')
    require(all(trusted_source_sha256[p] == value for p, value in parent.CPU_PINS.items())
        and trusted_source_sha256[parent.FENCE] == parent.FENCE_SHA
        and all(trusted_evidence_sha256[p] == value for p, value in parent.CPU_EVIDENCE.items()), 'FIXED_CPU_FENCE')
    for family in sorted(cli.FAMILIES):
        for seed in cli.SEEDS:
            name = f'prelaunch_{family}_{seed}.json'
            item = cli._envelope(payloads[name], manifest['prelaunch_sha256'][name], root,
                root+f'_{family}_{seed}', cli.PACKAGE_ROOT, family, seed)
            require(item['helper_sha256'] == {p: trusted_source_sha256[p] for p in cli.HELPERS}
                and all(item[field] == trusted_evidence_sha256[p] for p, field in cli.EVIDENCE.items()),
                'ENVELOPE_BINDING')
    evidence = {p: payloads[p] for p in trusted_evidence_sha256}
    for raw in evidence.values():
        cli._json(raw)
    approval_integrity(cli, parent, payloads, evidence, trusted_evidence_sha256)
    return payloads, manifest, tar_bytes


def archive(payloads):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as stream:
        for name, raw in sorted(payloads.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(raw), 0o600, 0
            stream.addfile(info, io.BytesIO(raw))
    require(len(buffer.getvalue()) <= TAR_CAP, 'TAR_BOUND')
    result = gzip.compress(buffer.getvalue(), mtime=0)
    require(len(result) <= ARCHIVE_CAP, 'ARCHIVE_BOUND')
    return result


def build(output, root, evidence_root, *, trusted_source_sha256, trusted_evidence_sha256):
    require(type(root) is str and re.fullmatch(ROOT_PATTERN, root) is not None, 'ROOT')
    repo = Path(__file__).resolve().parents[1]
    # Only fixed names, not caller names or directory discovery, reach source I/O.
    require(type(trusted_source_sha256) is dict and type(trusted_evidence_sha256) is dict
        and len(trusted_source_sha256) == 36 and len(trusted_evidence_sha256) == 8
        and all(pin(p) for p in (*trusted_source_sha256.values(), *trusted_evidence_sha256.values()))
        and pin(trusted_source_sha256.get(CLI)) and pin(trusted_source_sha256.get(PARENT)), 'TRUST_SET')
    trusted_source_sha256 = dict(trusted_source_sha256)
    trusted_evidence_sha256 = dict(trusted_evidence_sha256)
    cli_raw, parent_raw = read(repo/CLI, SOURCE_CAP), read(repo/PARENT, SOURCE_CAP)
    require(sha(cli_raw) == trusted_source_sha256[CLI]
            and sha(parent_raw) == trusted_source_sha256[PARENT], 'BOOTSTRAP_SHA')
    cli = external(cli_raw, '_v5_build_cli')
    parent = external(parent_raw, '_v5_build_parent')
    names = cli.CORE_FILES | {CLI, PARENT, parent.CPU_PROGRAM, *cli.HELPERS, *parent.EXTRA}
    require(set(trusted_source_sha256) == names
        and set(trusted_evidence_sha256) == set(cli.EVIDENCE) | set(parent.CPU_EVIDENCE), 'TRUST_SET')
    sources = {p: read(repo/p, SOURCE_CAP) for p in sorted(names)}
    evidence = {p: read(Path(evidence_root)/p, JSON_CAP) for p in sorted(trusted_evidence_sha256)}
    payloads = {**sources, **evidence, CORE_MANIFEST: read(repo/CORE_MANIFEST, JSON_CAP)}
    envelope_pins = {}
    for family in sorted(cli.FAMILIES):
        for seed in cli.SEEDS:
            name = f'prelaunch_{family}_{seed}.json'
            raw = encode(dict(schema='v5-train-prelaunch-envelope-v1', source_root=root,
                output=root+f'_{family}_{seed}', package_root=cli.PACKAGE_ROOT, family=family, seed=seed,
                roles=['TRAIN'], parent_resource_guard_required=True, core_manifest_sha256=CORE_SHA,
                helper_sha256={p: trusted_source_sha256[p] for p in cli.HELPERS},
                authorization_id=cli.AUTHORIZATION_ID,
                **{field: trusted_evidence_sha256[p] for p, field in cli.EVIDENCE.items()}))
            payloads[name], envelope_pins[name] = raw, sha(raw)
    payloads[MANIFEST] = encode(dict(schema='v5-train-serial-launch-packet-v1', source_root=root,
        package_root=cli.PACKAGE_ROOT, core_manifest_sha256=CORE_SHA,
        source_sha256=trusted_source_sha256, evidence_sha256=trusted_evidence_sha256,
        prelaunch_sha256=envelope_pins))
    packet, packet_pin = archive(payloads), sha(payloads[MANIFEST])
    _, manifest, tar_bytes = validate(packet, sha(packet), packet_pin, root,
        trusted_source_sha256=trusted_source_sha256, trusted_evidence_sha256=trusted_evidence_sha256)
    path = Path(output)
    require(path.suffixes[-2:] == ['.tar', '.gz'], 'OUTPUT')
    for ancestor in path.parents:
        ordinary(ancestor.lstat(), True)
    with path.open('xb') as stream:
        stream.write(packet); stream.flush(); os.fsync(stream.fileno())
    require(read(path, ARCHIVE_CAP) == packet, 'READBACK')
    return dict(status='PASS_LOCAL_TRAIN_LAUNCH_PACKET_ONLY', archive_sha256=sha(packet),
        packet_sha256=packet_pin, entries=len(payloads), archive_bytes=len(packet), tar_bytes=tar_bytes,
        root=root, actual_fits=0, automatic_retries=0, manifest=manifest)


def receive(packet, archive_sha256, packet_sha256, root, *,
            trusted_source_sha256, trusted_evidence_sha256):
    payloads, _, tar_bytes = validate(packet, archive_sha256, packet_sha256, root,
        trusted_source_sha256=trusted_source_sha256, trusted_evidence_sha256=trusted_evidence_sha256)
    # All bytes, review and destination identity validated before first filesystem I/O.
    target = Path(root)
    for ancestor in target.parents:
        ordinary(ancestor.lstat(), True)
    target.mkdir(mode=0o700)  # exclusive new root; never overwrite/reuse
    for name, raw in sorted(payloads.items()):
        path = target/name
        path.parent.mkdir(parents=True, exist_ok=True)
        for ancestor in path.parents:
            ordinary(ancestor.lstat(), True)
        with path.open('xb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        require(read(path, SOURCE_CAP) == raw, 'READBACK')
    return dict(status='PASS_TRAIN_SOURCE_DEPLOYMENT_ONLY', entries=len(payloads), root=root,
        archive_sha256=archive_sha256, packet_sha256=packet_sha256,
        archive_bytes=len(packet), tar_bytes=tar_bytes, actual_fits=0, automatic_retries=0)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('build', 'receive'))
    parser.add_argument('--archive', required=True)
    parser.add_argument('--root', required=True)
    parser.add_argument('--trust-file', required=True, help='independently reviewed external source/evidence SHA maps')
    parser.add_argument('--evidence-root')
    parser.add_argument('--archive-sha256')
    parser.add_argument('--packet-sha256')
    args = parser.parse_args(argv)
    trust = decode(read(args.trust_file, JSON_CAP))
    require(set(trust) == {'source_sha256', 'evidence_sha256'}, 'TRUST_FIELDS')
    anchors = dict(trusted_source_sha256=trust['source_sha256'], trusted_evidence_sha256=trust['evidence_sha256'])
    if args.action == 'build':
        require(args.evidence_root is not None, 'EVIDENCE_ROOT')
        result = build(args.archive, args.root, args.evidence_root, **anchors)
    else:
        result = receive(read(args.archive, ARCHIVE_CAP), args.archive_sha256,
                         args.packet_sha256, args.root, **anchors)
    print(json.dumps(result, sort_keys=True, allow_nan=False))


if __name__ == '__main__':
    main()
