"""Create-once bounded source-only B deployment; no launch, training or retry."""
import argparse
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess

from scripts.build_v5_import_gate_packet import NAMES, PACKET_MANIFEST, MAX_ARCHIVE_BYTES
from scripts.verify_v5_frozen_import_gate import bounded_read

RECEIVER = '''
import base64,gzip,hashlib,io,json,os,re,sys,tarfile
from pathlib import Path,PurePosixPath
EXPECTED = frozenset(REPLACE_NAMES)
MANIFEST = 'import_gate_packet_manifest.json'
def allowed_root(value):
    return type(value) is str and re.fullmatch('/ssd/cjc/gnn_model_ranking_v5_import_gate_[0-9]{8}_r[1-9][0-9]*',value) is not None
def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result: raise ValueError('DEPLOY_DUPLICATE_JSON')
        result[key]=value
    return result
def receive(encoded,sha,root_text):
    if not allowed_root(root_text) or type(sha) is not str or re.fullmatch('[0-9a-f]{64}',sha) is None:
        raise ValueError('DEPLOY_FIXED_ROOT_OR_SHA')
    if type(encoded) is not bytes or len(encoded)>400*1024: raise ValueError('DEPLOY_ENCODED_BOUND')
    packet=base64.b64decode(encoded.strip(),validate=True)
    if not 0<len(packet)<=256*1024 or hashlib.sha256(packet).hexdigest()!=sha:
        raise ValueError('DEPLOY_ARCHIVE_SHA_OR_BOUND')
    with gzip.GzipFile(fileobj=io.BytesIO(packet)) as stream: raw=stream.read(512*1024+1)
    if len(raw)>512*1024: raise ValueError('DEPLOY_TAR_BOUND')
    payloads={}
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
        for member in archive:
            if (len(payloads)>=31 or member.name not in EXPECTED|{MANIFEST}
                    or member.name in payloads or not member.isfile()
                    or not 0<member.size<=64*1024):
                raise ValueError('DEPLOY_ENTRY_GATE')
            stream=archive.extractfile(member)
            data=stream.read(64*1024+1)
            if len(data)!=member.size: raise ValueError('DEPLOY_MEMBER_BOUND')
            payloads[member.name]=data
    if set(payloads)!=EXPECTED|{MANIFEST} or len(payloads)!=31: raise ValueError('DEPLOY_EXACT_ENTRY_SET')
    manifest=json.loads(payloads[MANIFEST],object_pairs_hook=unique)
    if (type(manifest) is not dict or set(manifest)!={'schema','formal_training_release','source_count','core_manifest_sha256','files'}
            or manifest['schema']!='v5-source-import-linux-gate-packet-v1'
            or manifest['formal_training_release'] is not False
            or type(manifest['source_count']) is not int or manifest['source_count']!=30
            or type(manifest['files']) is not dict or set(manifest['files'])!=EXPECTED):
        raise ValueError('DEPLOY_MANIFEST_GATE')
    for name,pin in manifest['files'].items():
        if type(pin) is not str or hashlib.sha256(payloads[name]).hexdigest()!=pin:
            raise ValueError('DEPLOY_FILE_SHA')
    if hashlib.sha256(payloads['data/manifests/ranking_v5_caller_source_bytes_20261008.json']).hexdigest()!=manifest['core_manifest_sha256']:
        raise ValueError('DEPLOY_CORE_MANIFEST_SHA')
    root=Path(root_text)
    if any(p.is_symlink() for p in (root,*root.parents)): raise ValueError('DEPLOY_ROOT_SYMLINK')
    root.mkdir(mode=0o700)  # exclusive; preserve any failure and never overwrite/retry
    for name,data in sorted(payloads.items()):
        path=root/name
        path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
    with (root/'source_packet.tar.gz').open('xb') as stream: stream.write(packet)
    result=dict(status='PASS_SOURCE_ONLY_IMPORT_GATE_DEPLOYMENT',root=root_text,
                archive_sha256=sha,entries=31,archive_bytes=len(packet),tar_bytes=len(raw),
                formal_training_release=False,real_fits=0,automatic_retries=0)
    with (root/'deployment_receipt.json').open('x') as stream:
        json.dump(result,stream,sort_keys=True);stream.flush();os.fsync(stream.fileno())
    return result
if __name__=='__main__':
    print(json.dumps(receive(sys.stdin.buffer.read(400*1024+1),sys.argv[1],sys.argv[2]),sort_keys=True))
'''.replace('REPLACE_NAMES',repr(tuple(sorted(NAMES))))


def _unique(pairs):
    result = {}
    for key,value in pairs:
        if key in result: raise ValueError('IMPORT_DEPLOY_DUPLICATE_RECEIPT')
        result[key] = value
    return result


def deploy(archive_path, *, archive_sha256, root):
    if (type(root) is not str or re.fullmatch('/ssd/cjc/gnn_model_ranking_v5_import_gate_[0-9]{8}_r[1-9][0-9]*',root) is None
            or type(archive_sha256) is not str or re.fullmatch('[0-9a-f]{64}',archive_sha256) is None):
        raise ValueError('IMPORT_DEPLOY_ROOT_OR_SHA')
    packet = bounded_read(Path(archive_path),MAX_ARCHIVE_BYTES)
    if hashlib.sha256(packet).hexdigest()!=archive_sha256: raise ValueError('IMPORT_DEPLOY_ARCHIVE_SHA')
    program = base64.b64encode(RECEIVER.encode()).decode()
    command = "python3 -I -B -c " + shlex.quote("import base64;exec(base64.b64decode('"+program+"'))")
    command += ' ' + archive_sha256 + ' ' + root
    process = subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8',
                              '-o','StrictHostKeyChecking=yes','cjc@10.161.89.11',command],
                             input=base64.b64encode(packet),stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,timeout=30,check=False)
    if len(process.stdout)>20000 or len(process.stderr)>20000:
        raise ValueError('IMPORT_DEPLOY_OUTPUT_BOUND')
    if type(process.returncode) is not int or process.returncode!=0:
        raise RuntimeError('IMPORT_DEPLOY_FAILED_NO_RETRY:' + process.stderr.decode(errors='replace')[:2000])
    try:
        result = json.loads(process.stdout,object_pairs_hook=_unique)
    except (UnicodeError,json.JSONDecodeError,RecursionError) as error:
        raise ValueError('IMPORT_DEPLOY_RECEIPT_JSON') from error
    if (type(result) is not dict or set(result)!={'status','root','archive_sha256','entries',
            'archive_bytes','tar_bytes','formal_training_release','real_fits','automatic_retries'}
            or type(result['status']) is not str or result['status']!='PASS_SOURCE_ONLY_IMPORT_GATE_DEPLOYMENT'
            or type(result['root']) is not str or result['root']!=root
            or type(result['archive_sha256']) is not str or result['archive_sha256']!=archive_sha256
            or type(result['entries']) is not int or result['entries']!=31
            or type(result['archive_bytes']) is not int or result['archive_bytes']!=len(packet)
            or type(result['tar_bytes']) is not int or not 0<result['tar_bytes']<=512*1024
            or type(result['real_fits']) is not int or result['real_fits']!=0
            or type(result['automatic_retries']) is not int or result['automatic_retries']!=0
            or result['formal_training_release'] is not False):
        raise ValueError('IMPORT_DEPLOY_RECEIPT')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive',required=True);parser.add_argument('--archive-sha256',required=True)
    parser.add_argument('--root',required=True);args=parser.parse_args()
    print(json.dumps(deploy(args.archive,archive_sha256=args.archive_sha256,root=args.root),sort_keys=True))
