"""Released TRAIN-only physical ranking-v3 fold packages.

This module deliberately has a schema and scope distinct from the synthetic
fixture package.  It has no source loader: callers must supply the already
authorized in-memory TRAIN rows and outcomes together with an exact release.
"""
import hashlib
import json
import math
from pathlib import Path

from src.models.runtime_ranking_v3 import (
    FEATURES, digest, freeze_ranking, plan_folds, prepare_fold, validate_metadata,
)

SCOPE = 'REAL_TRAIN_ONLY_RELEASED_SIX_FOLD'
SCHEMA_VERSION = 'ranking-v3-real-train-fold-v1'
RELEASE_STATUS = 'PASS_TRAIN_ONLY_DATA_RELEASE'
RELEASE_KEYS = ('independent_review_pass', 'roles', 'source_sha256', 'status')
SHARD_NAMES = (
    'fit_features.json', 'fit_outcomes.json',
    'heldout_features.json', 'heldout_outcomes.json',
)
METADATA = ('action_uid', 'circuit', 'family', 'role')
OPTIONAL = ('graph_key', 'action_scheme', 'h_limit', 'm_limit')
OUTCOME_FIELDS = (
    'execution_status', 'is_d95_feasible', 'total_cycles',
    'policy_charged_runtime_s',
)


def file_sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _write_once(path, value):
    with Path(path).open('xb') as stream:
        stream.write((json.dumps(value, sort_keys=True, separators=(',', ':'),
                                 allow_nan=False) + '\n').encode('utf-8'))


def _is_sha256(value):
    return (isinstance(value, str) and len(value) == 64 and
            all(char in '0123456789abcdef' for char in value))


def _validate_release(release, source_sha256):
    """Pure in-memory gate; call before any target path is examined."""
    if not _is_sha256(source_sha256):
        raise ValueError('REAL_FOLD_SOURCE_SHA')
    if not isinstance(release, dict) or set(release) != set(RELEASE_KEYS):
        raise ValueError('REAL_FOLD_RELEASE')
    if (release.get('status') != RELEASE_STATUS or
            release.get('source_sha256') != source_sha256 or
            release.get('independent_review_pass') is not True or
            release.get('roles') != ['TRAIN']):
        raise ValueError('REAL_FOLD_RELEASE')


def _validate_outcomes(rows, outcomes):
    if not isinstance(outcomes, dict) or set(outcomes) != {r['action_uid'] for r in rows}:
        raise ValueError('REAL_FOLD_OUTCOME_JOIN')
    for uid, outcome in outcomes.items():
        if not isinstance(outcome, dict) or set(outcome) != set(OUTCOME_FIELDS):
            raise ValueError('REAL_FOLD_OUTCOME_SCHEMA:' + str(uid))
        if outcome['execution_status'] != 'SUCCESS':
            raise ValueError('REAL_FOLD_UNSAFE_OUTCOME:' + str(uid))
        # bool is an int subclass, but is not an accepted recorded D95 value.
        if type(outcome['is_d95_feasible']) is not int or outcome['is_d95_feasible'] != 1:
            raise ValueError('REAL_FOLD_UNSAFE_OUTCOME:' + str(uid))
        for field in ('total_cycles', 'policy_charged_runtime_s'):
            value = outcome[field]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError('REAL_FOLD_OUTCOME_TYPE:' + str(uid))
            if not math.isfinite(float(value)) or float(value) <= 0:
                raise ValueError('REAL_FOLD_UNSAFE_OUTCOME:' + str(uid))


def _validate_source(rows, outcomes, fold):
    validate_metadata(rows)
    if fold not in plan_folds(rows):
        raise ValueError('REAL_FOLD_FORGED_FOLD')
    _validate_outcomes(rows, outcomes)
    if set(fold.fitting) | set(fold.heldout) != set(outcomes) or set(fold.fitting) & set(fold.heldout):
        raise ValueError('REAL_FOLD_MEMBERSHIP')
    # This also validates only the fitting target outcome semantics and feature
    # matrix.  The loop above applies equivalent safety/type checks to heldout.
    prepare_fold(rows, {uid: outcomes[uid] for uid in fold.fitting}, fold, 20260824)


def _reject_symlink(path):
    path = Path(path)
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError('REAL_FOLD_SYMLINK')


def _read_json_once(path, expected_sha, error):
    """Hash and decode one immutable byte buffer, avoiding check/read TOCTOU."""
    path = Path(path)
    if path.is_symlink():
        raise ValueError(error)
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        raise ValueError(error)
    try:
        return json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(error) from exc


def _read_persisted_freeze(path, expected_sha):
    """Read the persisted freeze exactly once before any held-label access."""
    path = Path(path)
    _reject_symlink(path)
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError('REAL_FOLD_FREEZE_READ') from exc
    if (not isinstance(value, dict) or set(value) != {'payload', 'sha256'} or
            value['sha256'] != expected_sha or digest(value['payload']) != expected_sha):
        raise ValueError('REAL_FOLD_FREEZE_READ')
    return value['payload']


def export_real_fold(root, rows, outcomes, fold, *, release, source_sha256):
    """Create exactly four physical shards plus a digest-bound manifest.

    ``release`` must be an independently approved TRAIN-only release.  All
    release and in-memory source validation happens before target-path I/O.
    The returned manifest SHA is intentionally external to the manifest.
    """
    _validate_release(release, source_sha256)
    _validate_source(rows, outcomes, fold)
    root = Path(root)
    _reject_symlink(root)
    root.mkdir(exist_ok=False)
    projected = [
        {field: row[field] for field in (*METADATA, *FEATURES, *OPTIONAL) if field in row}
        for row in sorted(rows, key=lambda row: row['action_uid'])
    ]
    values = {
        'fit_features.json': [row for row in projected if row['action_uid'] in fold.fitting],
        'fit_outcomes.json': {uid: outcomes[uid] for uid in fold.fitting},
        'heldout_features.json': [row for row in projected if row['action_uid'] in fold.heldout],
        'heldout_outcomes.json': {uid: outcomes[uid] for uid in fold.heldout},
    }
    for name in SHARD_NAMES:
        _write_once(root / name, values[name])
    manifest = {
        'schema_version': SCHEMA_VERSION,
        'scope': SCOPE,
        'release': release,
        'source_sha256': source_sha256,
        'family': fold.family,
        'fitting': list(fold.fitting),
        'heldout': list(fold.heldout),
        'sha256': {name: file_sha(root / name) for name in SHARD_NAMES},
    }
    _write_once(root / 'manifest.json', manifest)
    return file_sha(root / 'manifest.json')


class RealFoldReader:
    """Read a released fold; held labels are unavailable until a fold freeze."""
    def __init__(self, root, expected_manifest_sha, fold):
        self.root = Path(root)
        self.fold = fold
        _reject_symlink(self.root)
        manifest_path = self.root / 'manifest.json'
        self.manifest = _read_json_once(manifest_path, expected_manifest_sha,
                                        'REAL_FOLD_MANIFEST_SHA')
        manifest = self.manifest
        try:
            _validate_release(manifest['release'], manifest['source_sha256'])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError('REAL_FOLD_MANIFEST_RELEASE') from error
        if (set(manifest) != {'schema_version', 'scope', 'release', 'source_sha256',
                             'family', 'fitting', 'heldout', 'sha256'} or
                manifest['schema_version'] != SCHEMA_VERSION or manifest['scope'] != SCOPE or
                manifest['family'] != fold.family or
                manifest['fitting'] != list(fold.fitting) or
                manifest['heldout'] != list(fold.heldout) or
                set(manifest['sha256']) != set(SHARD_NAMES)):
            raise ValueError('REAL_FOLD_MANIFEST_MEMBERSHIP')

    def _read(self, name):
        path = self.root / name
        return _read_json_once(path, self.manifest['sha256'][name],
                               'REAL_FOLD_FILE_SHA:' + name)

    def fitting(self, uids):
        if tuple(uids) != self.fold.fitting:
            raise ValueError('REAL_FOLD_FIT_UIDS')
        value = self._read('fit_outcomes.json')
        if set(value) != set(uids):
            raise ValueError('REAL_FOLD_FIT_OUTCOME_SET')
        _validate_outcomes([{'action_uid': uid} for uid in uids], value)
        return value

    def feature_rows(self):
        fitting = self._read('fit_features.json')
        heldout = self._read('heldout_features.json')
        if ({row['action_uid'] for row in fitting} != set(self.fold.fitting) or
                {row['action_uid'] for row in heldout} != set(self.fold.heldout)):
            raise ValueError('REAL_FOLD_FEATURE_UIDS')
        rows = fitting + heldout
        if self.fold not in plan_folds(rows):
            raise ValueError('REAL_FOLD_FEATURE_FOLD')
        return rows

    def heldout(self, uids, freeze_path, freeze_sha):
        if tuple(uids) != self.fold.heldout:
            raise ValueError('REAL_FOLD_HELD_UIDS')
        payload = _read_persisted_freeze(freeze_path, freeze_sha)
        expected, expected_sha = freeze_ranking(payload['scores'], self.fold)
        if payload != expected or freeze_sha != expected_sha:
            raise ValueError('REAL_FOLD_FREEZE_BINDING')
        # The first held-label shard access is deliberately after exact freeze validation.
        value = self._read('heldout_outcomes.json')
        if set(value) != set(uids):
            raise ValueError('REAL_FOLD_HELD_OUTCOME_SET')
        _validate_outcomes([{'action_uid': uid} for uid in uids], value)
        return value
