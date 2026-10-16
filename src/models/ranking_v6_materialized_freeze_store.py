"""Fixture-only ordinary-file persistence, never a real held-data release.

The temp parent is selected lexically from trusted host environment settings;
this is not authenticated temp provenance. Opaque model/normalizer bytes are
hash-bound, not executed or certified. This module assumes a trusted local
hierarchy, not hostile concurrent path mutation. No OS sandbox, adversarial
TOCTOU protection or directory power-loss durability guarantee is claimed.
Failed writes remain for diagnosis; no overwrite or cleanup is performed.
"""
import hashlib
import json
import math
import os
import re
import stat

from .runtime_ranking_v3 import FAMILIES


MODEL_CAP = 1024 * 1024
NORMALIZER_CAP = 16 * 1024
FREEZE_CAP = 256 * 1024
SEEDS = (20260824, 20260825, 20260826)
SCHEMA = 'ranking_v6_materialized_fixture_freeze_v1'
_ROOT_NAME = re.compile(r'gnn_v6_freeze_fixture_[A-Za-z0-9_-]{1,80}')
_UID = re.compile(r'[A-Za-z0-9_.-]{1,64}')
_SHA = re.compile(r'[0-9a-f]{64}')
_KEYS = frozenset(('schema', 'held_family', 'seed', 'action_uids', 'scores', 'ranking',
                   'model_sha256', 'normalizer_sha256', 'feature_snapshot_sha256',
                   'fitting_uids_sha256'))
_FILES = (('model.bin', MODEL_CAP), ('normalizer.json', NORMALIZER_CAP), ('freeze.json', FREEZE_CAP))


def _require(condition, code):
    if not condition:
        raise ValueError('MATERIALIZED_FREEZE_STORE_' + code)


def _bytes(value, cap, code):
    _require(type(value) is bytes and 1 <= len(value) <= cap, code)


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _canonical(value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'),
                     allow_nan=False, ensure_ascii=True).encode('ascii')
    _bytes(raw, FREEZE_CAP, 'FREEZE_BYTE_CAP')
    return raw


def make_freeze(*, model_bytes, normalizer_bytes, feature_snapshot_sha256,
                fitting_uids_sha256, held_family, seed, scores, implementation_only=False):
    """Encode the bounded explicit feature/score schema; no labels or costs."""
    _require(implementation_only is True, 'IMPLEMENTATION_OPT_IN')
    _bytes(model_bytes, MODEL_CAP, 'MODEL_BYTES')
    _bytes(normalizer_bytes, NORMALIZER_CAP, 'NORMALIZER_BYTES')
    for digest in (feature_snapshot_sha256, fitting_uids_sha256):
        _require(type(digest) is str and _SHA.fullmatch(digest) is not None, 'INPUT_SHA256')
    _require(type(held_family) is str and held_family in FAMILIES.values(), 'HELD_FAMILY')
    _require(type(seed) is int and seed in SEEDS, 'SEED')
    _require(type(scores) is dict and 1 <= len(scores) <= 1024, 'SCORES_SCHEMA')
    for uid, value in scores.items():
        _require(type(uid) is str and _UID.fullmatch(uid) is not None, 'UID')
        _require(type(value) in (int, float) and -20 <= value <= 20
                 and math.isfinite(value), 'SCORE_DOMAIN')
    uids = sorted(scores)
    return _canonical(dict(schema=SCHEMA, held_family=held_family, seed=seed,
                           action_uids=uids, scores=[scores[uid] for uid in uids],
                           ranking=sorted(uids, key=lambda uid: (-scores[uid], uid)),
                           model_sha256=_sha(model_bytes), normalizer_sha256=_sha(normalizer_bytes),
                           feature_snapshot_sha256=feature_snapshot_sha256,
                           fitting_uids_sha256=fitting_uids_sha256))


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def _bad_constant(value):
    raise ValueError('MATERIALIZED_FREEZE_STORE_JSON_CONSTANT')


def _validate_expected(model, normalizer, freeze):
    # All three exact builtin types and caps precede any decode or disk access.
    _bytes(model, MODEL_CAP, 'MODEL_BYTES')
    _bytes(normalizer, NORMALIZER_CAP, 'NORMALIZER_BYTES')
    _bytes(freeze, FREEZE_CAP, 'FREEZE_BYTES')
    try:
        decoded = json.loads(freeze.decode('ascii'), object_pairs_hook=_pairs,
                             parse_constant=_bad_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ValueError('MATERIALIZED_FREEZE_STORE_FREEZE_JSON') from exc
    _require(type(decoded) is dict and decoded.keys() == _KEYS, 'FREEZE_SCHEMA')
    _require(decoded['schema'] == SCHEMA and type(decoded['schema']) is str, 'FREEZE_SCHEMA')
    uids, values = decoded['action_uids'], decoded['scores']
    _require(type(uids) is list and type(values) is list and 1 <= len(uids) <= 1024
             and len(values) == len(uids), 'FREEZE_UID_SCORE_SCHEMA')
    _require(all(type(uid) is str and _UID.fullmatch(uid) is not None for uid in uids)
             and uids == sorted(set(uids)), 'FREEZE_UID_ORDER')
    _require(type(decoded['ranking']) is list and all(type(uid) is str for uid in decoded['ranking']),
             'RANKING_SCHEMA')
    for name in ('model_sha256', 'normalizer_sha256'):
        _require(type(decoded[name]) is str and _SHA.fullmatch(decoded[name]) is not None, 'WIRE_SHA256')
    _require(decoded['model_sha256'] == _sha(model)
             and decoded['normalizer_sha256'] == _sha(normalizer), 'WIRE_HASH_MISMATCH')
    expected = make_freeze(model_bytes=model, normalizer_bytes=normalizer,
                           feature_snapshot_sha256=decoded['feature_snapshot_sha256'],
                           fitting_uids_sha256=decoded['fitting_uids_sha256'],
                           held_family=decoded['held_family'], seed=decoded['seed'],
                           scores=dict(zip(uids, values)), implementation_only=True)
    _require(freeze == expected, 'FREEZE_CANONICAL_MISMATCH')
    return (_sha(model), _sha(normalizer), _sha(freeze))


def _temp_parent():
    # Unlike tempfile.gettempdir(), this performs no candidate probe writes.
    names = ('TEMP', 'TMP') if os.name == 'nt' else ('TMPDIR', 'TEMP', 'TMP')
    for name in names:
        if os.environ.get(name):
            return os.environ[name]
    _require(os.name != 'nt', 'TEMP_CONFIGURATION')
    return '/tmp'


def _forbidden_lexical(path):
    portable = path.replace('\\', '/').casefold()
    if len(portable) >= 3 and portable[1:3] == ':/':
        portable = portable[2:]  # reject the same protected suffix on Windows
    return (portable == '/ssd' or portable.startswith('/ssd/')
            or portable == '/temp/jiangchuanc' or portable.startswith('/temp/jiangchuanc/')
            or '/multimode_ate_gnn_v1' in portable)


def _lexical_root(root):
    _require(type(root) is str and bool(root), 'ROOT_STRING')
    parent = _temp_parent()
    _require(type(parent) is str and not _forbidden_lexical(root)
             and not _forbidden_lexical(parent), 'PROTECTED_ROOT')
    _require(os.path.isabs(root) and os.path.isabs(parent), 'ABSOLUTE_ROOT')
    # normpath is lexical, not resolve/realpath; reject traversal rather than
    # normalize it into an accepted path. Only the configured parent is used.
    parent = os.path.normpath(parent)
    _require(root == os.path.normpath(root) and '\x00' not in root, 'ROOT_LEXICAL')
    _require(_ROOT_NAME.fullmatch(os.path.basename(root)) is not None, 'ROOT_BASENAME')
    supplied_parent = os.path.dirname(root)
    if os.name == 'nt':
        same_parent = os.path.normcase(supplied_parent).casefold() == os.path.normcase(parent).casefold()
    else:
        same_parent = supplied_parent == parent
    _require(same_parent, 'TEMP_DIRECT_CHILD')
    if os.name == 'nt':
        drive, remainder = os.path.splitdrive(root)
        _require(bool(drive) and not drive.startswith('\\\\') and ':' not in remainder,
                 'ROOT_DRIVE_OR_ADS')
    return root


def _ordinary(info, *, directory):
    _require(not stat.S_ISLNK(info.st_mode)
             and not (getattr(info, 'st_file_attributes', 0)
                      & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)), 'LINK_OR_REPARSE')
    _require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode),
             'ORDINARY_DIRECTORY' if directory else 'ORDINARY_FILE')
    if not directory:
        _require(info.st_nlink == 1, 'HARDLINK')


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size)


def _ancestors(root, *, include_root):
    paths, cursor = [], root if include_root else os.path.dirname(root)
    while True:
        paths.append(cursor)
        parent = os.path.dirname(cursor)
        if parent == cursor:
            break
        cursor = parent
    for path in reversed(paths):
        _ordinary(os.lstat(path), directory=True)


class Store:
    """Exclusive new fixture directory below the configured existing temp parent."""
    def __init__(self, root, *, implementation_only=False):
        _require(implementation_only is True, 'IMPLEMENTATION_OPT_IN')
        self._root = _lexical_root(root)
        _ancestors(self._root, include_root=False)
        os.mkdir(self._root, 0o700)  # exclusive: an existing root is never adopted
        _ancestors(self._root, include_root=True)
        created = os.lstat(self._root)
        self._root_identity = (created.st_dev, created.st_ino)
        self._persist_attempted = False
        self._persisted = False
        self._persist_ack_hashes = None

    def _check(self):
        _lexical_root(self._root)
        _ancestors(self._root, include_root=True)
        current = os.lstat(self._root)
        _require((current.st_dev, current.st_ino) == self._root_identity, 'ROOT_IDENTITY')

    def _contents(self):
        self._check()
        _require(set(os.listdir(self._root)) == {name for name, _ in _FILES},
                 'EXACT_ARTIFACT_CONTENTS')

    def _write(self, name, raw):
        self._check()
        path = os.path.join(self._root, name)
        extra = getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
        def opener(filename, flags):
            return os.open(filename, flags | extra, 0o600)
        with open(path, 'xb', opener=opener) as stream:
            before = os.fstat(stream.fileno())
            _ordinary(before, directory=False)
            _require(before.st_size == 0, 'NEW_FILE_NOT_EMPTY')
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
            after = os.fstat(stream.fileno())
            _ordinary(after, directory=False)
            _require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
                     and after.st_size == len(raw), 'WRITE_IDENTITY_OR_SIZE')
        self._check()

    def _read(self, name, cap):
        self._check()
        path = os.path.join(self._root, name)
        before = os.lstat(path)
        _ordinary(before, directory=False)
        _require(1 <= before.st_size <= cap, 'FILE_SIZE_CAP')
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            _ordinary(opened, directory=False)
            _require(_identity(opened) == _identity(before), 'OPEN_IDENTITY_OR_SIZE')
            chunks, remaining = [], cap + 1
            while remaining:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b''.join(chunks)
            after = os.fstat(descriptor)
            _ordinary(after, directory=False)
            _require(_identity(after) == _identity(opened)
                     and len(raw) == opened.st_size and len(raw) <= cap, 'READ_IDENTITY_OR_SIZE')
        finally:
            os.close(descriptor)
        self._check()
        last = os.lstat(path)
        _ordinary(last, directory=False)
        _require(_identity(last) == _identity(before), 'READBACK_PATH_IDENTITY')
        return raw

    def _receipt(self, hashes):
        return dict(status='PASS_FIXTURE_ORDINARY_FILE_READBACK_ONLY',
                    model_sha256=hashes[0], normalizer_sha256=hashes[1], freeze_sha256=hashes[2],
                    scope='generated_local_fixture_only', implementation_only=True,
                    ordinary_files_verified=True, expected_bytes_exact=True,
                    real_held_release=False, model_ready=False,
                    model_authenticity_verified=False, normalizer_authenticity_verified=False,
                    candidate_lineage_verified=False, os_sandbox=False,
                    adversarial_concurrent_toctou_protection=False,
                    directory_power_loss_durability_guaranteed=False)

    def persist(self, model_bytes, normalizer_bytes, freeze_bytes):
        hashes = _validate_expected(model_bytes, normalizer_bytes, freeze_bytes)
        _require(not self._persist_attempted, 'PERSIST_ONCE')
        self._persist_attempted = True
        payloads = (model_bytes, normalizer_bytes, freeze_bytes)
        for (name, _), raw in zip(_FILES, payloads):
            self._write(name, raw)
        self._contents()
        for (name, cap), expected in zip(_FILES, payloads):
            actual = self._read(name, cap)
            _require(actual == expected and _sha(actual) == _sha(expected), 'PERSIST_READBACK_MISMATCH')
        self._contents()
        self._persist_ack_hashes = hashes
        self._persisted = True
        return self._receipt(hashes)

    def release(self, expected_model_bytes, expected_normalizer_bytes, expected_freeze_bytes,
                outcome_loader):
        hashes = _validate_expected(expected_model_bytes, expected_normalizer_bytes,
                                     expected_freeze_bytes)
        _require(self._persisted, 'PERSIST_ACK_REQUIRED')
        _require(hashes == self._persist_ack_hashes, 'PERSIST_ACK_HASH_MISMATCH')
        self._contents()
        for (name, cap), expected, digest in zip(
                _FILES, (expected_model_bytes, expected_normalizer_bytes, expected_freeze_bytes), hashes):
            actual = self._read(name, cap)
            _require(actual == expected and _sha(actual) == digest, 'RELEASE_READBACK_MISMATCH')
        self._contents()
        # No loader callable/attribute/len/iter access until all three readbacks.
        _require(callable(outcome_loader), 'OUTCOME_LOADER')
        outcome = outcome_loader()
        receipt = self._receipt(hashes)
        receipt.update(fixture_outcome_release=True, loader_calls=1,
                       all_readbacks_before_loader_access=True,
                       loader_call_count_scope='this_release_invocation_only',
                       experiment_once_authorization_created=False)
        return dict(outcome=outcome, receipt=receipt)
