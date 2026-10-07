"""Generate the same bounded deployment functions exercised by local tests."""
import argparse
import gzip
import hashlib
import inspect
import io
import json
import pathlib
import re
import stat
import sys
import tarfile
from scripts.build_v5_physical_packet import packet_bytes


def target_allowed(text):
    path = pathlib.PurePosixPath(text)
    return (str(path) == text and path.parent == pathlib.PurePosixPath('/ssd/cjc')
            and re.fullmatch(r'gnn_model_ranking_v5_worker_gate_[0-9]{8}_r[1-9][0-9]*', path.name) is not None)


def read_archive(path):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('V5_DEPLOY_SYMLINK')
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError('V5_DEPLOY_NOT_REGULAR')
    with path.open('rb') as stream:
        raw = stream.read(100001)
    if len(raw) > 100000:
        raise ValueError('V5_DEPLOY_ARCHIVE_SHA_BOUND')
    return raw


def validate_archive(raw, metadata):
    if len(raw) > 100000 or hashlib.sha256(raw).hexdigest() != metadata['archive_sha256']:
        raise ValueError('V5_DEPLOY_ARCHIVE_SHA_BOUND')
    if len(metadata['sources']) != 16:
        raise ValueError('V5_DEPLOY_SOURCE_COUNT')
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
        expanded = stream.read(200001)
    if len(expanded) > 200000:
        raise ValueError('V5_DEPLOY_EXPANDED_BOUND')
    contents = {}
    with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
        members = archive.getmembers()
        if len(members) != 17 or {m.name for m in members} != set(metadata['sources']) | {'packet_manifest.json'}:
            raise ValueError('V5_DEPLOY_EXACT_ENTRIES')
        for member in members:
            if not member.isfile() or not 0 <= member.size <= 30000:
                raise ValueError('V5_DEPLOY_ENTRY_TYPE_BOUND')
            path = pathlib.PurePosixPath(member.name)
            if path.is_absolute() or any(p in ('', '..', '.') for p in member.name.split('/')):
                raise ValueError('V5_DEPLOY_ENTRY_PATH')
            value = archive.extractfile(member).read(30001)
            if len(value) != member.size:
                raise ValueError('V5_DEPLOY_ENTRY_SIZE')
            expected = metadata['manifest_sha256'] if member.name == 'packet_manifest.json' else metadata['sources'][member.name]
            if hashlib.sha256(value).hexdigest() != expected:
                raise ValueError('V5_DEPLOY_SOURCE_SHA')
            contents[member.name] = value
    if sum(map(len, contents.values())) > 150000:
        raise ValueError('V5_DEPLOY_TOTAL_BOUND')
    return contents


def deploy_packet(target, metadata, *, allow_test_root=False):
    target = pathlib.Path(target)
    if not allow_test_root and (sys.platform != 'linux' or not target_allowed(str(target))):
        raise ValueError('V5_DEPLOY_FIXED_TARGET')
    if not target.is_absolute() or '..' in target.parts:
        raise ValueError('V5_DEPLOY_FIXED_TARGET')
    if any(p.is_symlink() for p in (target, *target.parents)):
        raise ValueError('V5_DEPLOY_SYMLINK')
    if target.exists():
        raise ValueError('V5_DEPLOY_CREATE_ONCE')
    contents = validate_archive(read_archive(pathlib.Path(str(target) + '.tar.gz')), metadata)
    target.mkdir(mode=0o700)
    for name, value in contents.items():
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with path.open('xb') as stream:
            stream.write(value)
        path.chmod(0o600)
        if hashlib.sha256(path.read_bytes()).hexdigest() != hashlib.sha256(value).hexdigest():
            raise ValueError('V5_DEPLOY_WRITE_READBACK')
    return dict(status='DEPLOYED_GENERATED_SOURCE_PACKET', target=str(target), files=len(contents),
                archive_sha256=metadata['archive_sha256'], manifest_sha256=metadata['manifest_sha256'],
                formal_training_release=False)


def program(target):
    if not target_allowed(target):
        raise ValueError('V5_DEPLOY_ROOT_NAME')
    _, metadata = packet_bytes()
    source = 'import gzip,hashlib,io,json,pathlib,re,stat,sys,tarfile\n'
    for function in (target_allowed, read_archive, validate_archive, deploy_packet):
        source += inspect.getsource(function) + '\n'
    source += 'metadata=' + repr(metadata) + '\nTARGET=' + repr(target) + '\n'
    source += "if not target_allowed(TARGET): raise ValueError('V5_DEPLOY_EXACT_RUNTIME_TARGET')\n"
    source += 'print(json.dumps(deploy_packet(pathlib.Path(TARGET),metadata),sort_keys=True))\n'
    if len(source.encode()) > 20000:
        raise ValueError('V5_DEPLOY_PROGRAM_BOUND')
    return source


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', required=True)
    args = parser.parse_args(argv)
    print(program(args.target))


if __name__ == '__main__':
    main()
