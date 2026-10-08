"""Create one small source-only packet for a synthetic Linux import/RSS gate."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile

from src.models.ranking_v5_caller_source_binding import FILES, validate_source_bytes
from scripts.verify_v5_frozen_import_gate import bounded_read

CORE_MANIFEST = 'data/manifests/ranking_v5_caller_source_bytes_20261008.json'
EXTRAS = frozenset(('src/models/ranking_v5_frozen_import_fence.py',
                    'scripts/verify_v5_frozen_import_gate.py',
                    'scripts/launch_v5_frozen_import_linux_gate.py', CORE_MANIFEST))
NAMES = FILES | EXTRAS
PACKET_MANIFEST = 'import_gate_packet_manifest.json'
MAX_TAR_BYTES = 512 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024


def build(output, *, trusted_core_manifest_sha256):
    root = Path(__file__).resolve().parents[1]
    raw_manifest = bounded_read(root/CORE_MANIFEST,20000)
    core = {name:bounded_read(root/name,64*1024) for name in FILES}
    validate_source_bytes(raw_manifest,core,trusted_manifest_sha256=trusted_core_manifest_sha256)
    payloads = dict(core)
    for name in EXTRAS: payloads[name] = bounded_read(root/name,64*1024)
    manifest = dict(schema='v5-source-import-linux-gate-packet-v1',formal_training_release=False,
                    source_count=len(payloads),core_manifest_sha256=trusted_core_manifest_sha256,
                    files={name:hashlib.sha256(raw).hexdigest() for name,raw in sorted(payloads.items())})
    payloads[PACKET_MANIFEST] = (json.dumps(manifest,sort_keys=True)+'\n').encode()
    if len(NAMES) != 30 or len(payloads) != 31: raise ValueError('IMPORT_PACKET_ENTRY_COUNT')
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer,mode='w',format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(payloads.items()):
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode, entry.mtime = len(raw), 0o600, 0
            archive.addfile(entry,io.BytesIO(raw))
    tar_raw = tar_buffer.getvalue()
    if len(tar_raw) > MAX_TAR_BYTES: raise ValueError('IMPORT_PACKET_TAR_BOUND')
    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed,mode='wb',mtime=0) as stream: stream.write(tar_raw)
    packet = compressed.getvalue()
    if len(packet) > MAX_ARCHIVE_BYTES: raise ValueError('IMPORT_PACKET_ARCHIVE_BOUND')
    output = Path(output)
    if output.suffixes[-2:] != ['.tar','.gz']: raise ValueError('IMPORT_PACKET_OUTPUT_NAME')
    if any(path.is_symlink() for path in (output,*output.parents)):
        raise ValueError('IMPORT_PACKET_OUTPUT_SYMLINK')
    with output.open('xb') as stream: stream.write(packet)
    return dict(status='SOURCE_ONLY_SYNTHETIC_IMPORT_PACKET',entries=len(payloads),
                archive_bytes=len(packet),tar_bytes=len(tar_raw),
                archive_sha256=hashlib.sha256(packet).hexdigest(),
                core_manifest_sha256=trusted_core_manifest_sha256,
                helper_sha256=manifest['files']['src/models/ranking_v5_frozen_import_fence.py'],
                verifier_sha256=manifest['files']['scripts/verify_v5_frozen_import_gate.py'],
                launcher_sha256=manifest['files']['scripts/launch_v5_frozen_import_linux_gate.py'],
                formal_training_release=False,real_fits=0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True)
    parser.add_argument('--core-manifest-sha256',required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.output,trusted_core_manifest_sha256=args.core_manifest_sha256),sort_keys=True))
