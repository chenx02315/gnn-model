"""Create-once local freeze artifact, with digest readback before label access."""
import json
import os
from pathlib import Path
from src.models.runtime_ranking_v3 import digest

def persist_freeze(path,payload,sha):
    path=Path(path)
    # Parent provisioning is explicit. Never follow a caller-supplied symlink.
    if digest(payload)!=sha or not path.parent.is_dir():
        raise ValueError('FREEZE_INPUT_OR_PARENT')
    if any(p.is_symlink() for p in (path,*path.parents)):
        raise ValueError('FREEZE_SYMLINK')
    raw=(json.dumps({'payload':payload,'sha256':sha},sort_keys=True,
                    separators=(',',':'),allow_nan=False)+'\n').encode()
    # Exclusive create prohibits silent overwrite; partial write is NOT a receipt.
    with path.open('xb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    value=json.loads(path.read_text())
    if value!={'payload':payload,'sha256':sha} or digest(value['payload'])!=sha:
        raise ValueError('FREEZE_READBACK_FAILED')
    return sha

def read_freeze(path,expected_sha):
    path=Path(path)
    if any(p.is_symlink() for p in (path,*path.parents)):
        raise ValueError('FREEZE_SYMLINK')
    value=json.loads(path.read_text())
    if value.get('sha256')!=expected_sha or digest(value['payload'])!=expected_sha:
        raise ValueError('FREEZE_READBACK_SHA')
    return value['payload']
