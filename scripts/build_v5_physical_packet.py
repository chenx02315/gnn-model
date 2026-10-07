"""Create-once small source-only tar.gz for the generated physical worker gate."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile

from scripts.launch_v5_physical_gate import FILES, bounded_read

ROOT = Path(__file__).resolve().parents[1]
MAX_ARCHIVE = 100000


def packet_bytes(root=ROOT):
    contents={name:bounded_read(root/name,30000) for name in sorted(FILES)}
    if len(contents)!=16 or sum(map(len,contents.values()))>150000:
        raise ValueError('V5_PACKET_SOURCE_COUNT_OR_BOUND')
    sources={name:hashlib.sha256(raw).hexdigest() for name,raw in contents.items()}
    manifest=(json.dumps({'schema':'v5-generated-physical-sources-v1','formal':False,'sources':sources},
                         sort_keys=True,separators=(',',':'))+'\n').encode()
    contents['packet_manifest.json']=manifest
    tar_buffer=io.BytesIO()
    with tarfile.open(fileobj=tar_buffer,mode='w') as archive:
        for name,raw in contents.items():
            entry=tarfile.TarInfo(name); entry.size=len(raw); entry.mode=0o600; entry.mtime=0
            archive.addfile(entry,io.BytesIO(raw))
    packed=gzip.compress(tar_buffer.getvalue(),mtime=0)
    if len(packed)>MAX_ARCHIVE: raise ValueError('V5_PACKET_COMPRESSED_BOUND')
    return packed, {'entries':17, 'files':17, 'source_bytes':sum(map(len,contents.values())),
                    'archive_bytes':len(packed), 'archive_sha256':hashlib.sha256(packed).hexdigest(),
                    'manifest_sha256':hashlib.sha256(manifest).hexdigest(), 'sources':sources,
                    'formal_training_release':False}


def main(argv=None):
    parser=argparse.ArgumentParser(); parser.add_argument('--output',required=True)
    args=parser.parse_args(argv); path=Path(args.output)
    if not path.is_absolute() or any(p.is_symlink() for p in (path,*path.parents)):
        raise ValueError('V5_PACKET_OUTPUT_PATH')
    raw,metadata=packet_bytes()
    with path.open('xb') as stream: stream.write(raw)
    if hashlib.sha256(bounded_read(path,MAX_ARCHIVE)).hexdigest()!=metadata['archive_sha256']:
        raise ValueError('V5_PACKET_READBACK')
    print(json.dumps(metadata,sort_keys=True))


if __name__=='__main__': main()
