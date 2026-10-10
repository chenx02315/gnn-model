"""Bounded five-file synthetic gate deployment; external trust required.

No discovery, package data, retry, dependency installation or ML in receiver.
The local caller must obtain independent review before using these primitives.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat

PROGRAM = 'scripts/run_v5_controlled_optimizer_gate.py'
TRANSPORT = 'scripts/run_v5_controlled_runtime_gate.py'
OBS = 'src/models/ranking_v5_locked_runtime_observations.py'
CONTEXT = 'src/models/ranking_v5_locked_runtime_imports.py'
AUTH = 'auth/user_authorization.raw.txt'
FILES = {PROGRAM, TRANSPORT, OBS, CONTEXT, AUTH}
FIXED = {
    TRANSPORT: '0a4bb0389cce25c2ac50f3adcc721ac2b2545acbf2d15df3c41d5ac8bca5c462',
    OBS: '0524a7b8cce7d017c3fe9fe38dcc86b29a440ed7b373c1c2361ebbb7738459c8',
    CONTEXT: 'b1bddbda1ef6ea2323a1b3face282fbb21cd1a01db64d68dff8deaa28308b1da',
    AUTH: 'ce5ccf8f630991863bed31ac2a38aad521aa7b23d493b04cb80a5a64079124e2'}
CAP = 65536
TOTAL_CAP = 196608
ENVELOPE_CAP = 270000


def require(ok, code):
    if not ok:
        raise ValueError('V5_OPTIMIZER_TRANSPORT_' + code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def validate(root, payloads, pins):
    """Pure validation before remote destination I/O; pins must be external."""
    require(type(root) is str and re.fullmatch(
        r'/ssd/cjc/gnn_model_ranking_v5_optimizer_gate_[0-9]{8}_r[1-9][0-9]*', root), 'ROOT')
    require(type(payloads) is dict and type(pins) is dict
        and set(payloads) == FILES and set(pins) == FILES, 'EXACT_FIVE')
    require(all(type(v) is str and re.fullmatch('[0-9a-f]{64}', v) for v in pins.values())
        and all(pins[p] == v for p, v in FIXED.items()), 'EXTERNAL_PINS')
    require(all(type(raw) is bytes and 0 < len(raw) <= CAP and sha(raw) == pins[p]
        for p, raw in payloads.items()) and sum(map(len, payloads.values())) <= TOTAL_CAP, 'BYTES')
    return dict(payloads)


def ordinary(path, directory=False):
    info = Path(path).lstat()
    require(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400,
        'LINK')
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), 'ORDINARY')
    return info


def read(path):
    path = Path(path)
    for parent in path.parents:
        ordinary(parent, True)
    before = ordinary(path)
    require(0 < before.st_size <= CAP, 'FILE_BOUND')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(CAP + 1)
        after = os.fstat(stream.fileno())
    final = ordinary(path)
    identity = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns)
    require(0 < len(raw) == before.st_size <= CAP
        and all(identity(v) == identity(before) for v in (opened, after, final)), 'CHANGED')
    return raw


def receive(root, payloads, pins):
    payloads = validate(root, payloads, pins)
    target = Path(root)
    for parent in target.parents:
        ordinary(parent, True)
    target.mkdir(mode=0o700)  # create once; existing roots remain immutable
    for name, raw in sorted(payloads.items()):
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        for parent in path.parents:
            ordinary(parent, True)
        with path.open('xb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        require(read(path) == raw, 'READBACK')
    return readback(root, payloads, pins, status='PASS_SYNTHETIC_FIVE_FILE_DEPLOYMENT_ONLY')


def readback(root, payloads, pins, status='PASS_SYNTHETIC_FIVE_FILE_READBACK_ONLY'):
    payloads = validate(root, payloads, pins)
    require(all(read(Path(root) / p) == raw for p, raw in payloads.items()), 'READBACK')
    return dict(status=status, root=root, entries=5, source_sha256=dict(pins),
        actual_invocations=0, formal_package_reads=0, automatic_retries=0)


def envelope(payloads):
    require(type(payloads) is dict and set(payloads) == FILES, 'EXACT_FIVE')
    raw = json.dumps({p: base64.b64encode(v).decode('ascii') for p, v in payloads.items()},
        sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    require(0 < len(raw) <= ENVELOPE_CAP, 'ENVELOPE_BOUND')
    return raw


def decode(raw):
    require(type(raw) is bytes and 0 < len(raw) <= ENVELOPE_CAP, 'ENVELOPE_BOUND')
    def unique(pairs):
        result = {}
        for p, v in pairs:
            require(p not in result, 'DUPLICATE')
            result[p] = v
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    require(type(value) is dict and set(value) == FILES
        and all(type(v) is str for v in value.values()), 'EXACT_FIVE')
    return {p: base64.b64decode(v, validate=True) for p, v in value.items()}
