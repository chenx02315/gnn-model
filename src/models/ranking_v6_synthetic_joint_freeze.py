"""In-memory generated HELDOUT freeze/readback gate, not a real-data release.

Only a canonical identity declaration for bounded generated features is
supported. No normalizer fitting, model execution, filesystem or data reader
exists here. Synthetic opt-in is a declaration, not provenance evidence.
"""
import hashlib
import json
import math
import re

from .runtime_ranking_v3 import FEATURES


MAX_BYTES = 2 * 1024 * 1024
_IDENTIFIER = re.compile(r'[A-Za-z0-9_.-]{1,64}')
_SHA256 = re.compile(r'[0-9a-f]{64}')
_FEATURE_KEYS = frozenset(('action_uid', 'family', 'circuit', 'role', *FEATURES))
_OUTCOME_KEYS = frozenset(('action_uid', 'total_cycles', 'policy_charged_runtime_s',
                           'is_d95_feasible', 'execution_status'))


def _require(condition, code):
    if not condition:
        raise ValueError('SYNTHETIC_JOINT_FREEZE_' + code)


def _canonical(value):
    result = json.dumps(value, sort_keys=True, separators=(',', ':'),
                        ensure_ascii=True, allow_nan=False).encode('ascii')
    _require(len(result) <= MAX_BYTES, 'BYTE_CAP')
    return result


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def identity_normalizer_bytes():
    """Declaration only, for generated bounded fixtures; no fit or real scaler."""
    return _canonical(dict(type='identity_generated_bounded_v1', fit_only=True,
                           feature_names=list(FEATURES)))


def _number(value, lower, upper, code):
    _require(type(value) in (int, float) and lower <= value <= upper
             and math.isfinite(value), code)


def _inputs(feature_rows, scores, normalizer_bytes, model_sha256):
    _require(type(normalizer_bytes) is bytes and len(normalizer_bytes) <= MAX_BYTES,
             'NORMALIZER_BYTES')
    _require(normalizer_bytes == identity_normalizer_bytes(), 'IDENTITY_NORMALIZER_ONLY')
    _require(type(model_sha256) is str and _SHA256.fullmatch(model_sha256) is not None,
             'MODEL_SHA256')
    _require(type(feature_rows) in (list, tuple) and 1 <= len(feature_rows) <= 1024,
             'FEATURE_ROWS')
    by_uid, circuit, family = {}, None, None
    for row in feature_rows:
        _require(type(row) is dict and row.keys() == _FEATURE_KEYS, 'FEATURE_SCHEMA')
        _require(type(row['role']) is str and row['role'] == 'HELDOUT', 'HELDOUT_ONLY')
        for name in ('action_uid', 'circuit', 'family'):
            _require(type(row[name]) is str and _IDENTIFIER.fullmatch(row[name]) is not None,
                     'IDENTIFIER')
        if circuit is None:
            circuit, family = row['circuit'], row['family']
        _require(row['circuit'] == circuit and row['family'] == family, 'ONE_CIRCUIT_FAMILY')
        _require(row['action_uid'] not in by_uid, 'DUPLICATE_UID')
        for name in FEATURES:
            _number(row[name], 0, 2, 'FEATURE_DOMAIN')
        _require(row['scheme_hf'] in (0, 1) and row['scheme_hmf'] in (0, 1)
                 and row['scheme_hf'] + row['scheme_hmf'] == 1, 'SCHEME_ONEHOT')
        for name in ('h_limit_fraction_of_circuit_max', 'm_limit_fraction_of_circuit_max'):
            _require(row[name] <= 1, 'FRACTION_DOMAIN')
        by_uid[row['action_uid']] = [row[name] for name in FEATURES]
    uids = sorted(by_uid)
    _require(type(scores) is dict and set(scores) == set(uids), 'SCORE_UID_JOIN')
    for uid, value in scores.items():
        _require(type(uid) is str, 'SCORE_UID_TYPE')
        _number(value, -20, 20, 'SCORE_DOMAIN')
    return dict(schema='synthetic_joint_heldout_freeze_v1', scope='generated_bounded_fixture_only',
                role='HELDOUT', circuit=circuit, family=family, action_uids=uids,
                feature_names=list(FEATURES), features=[by_uid[uid] for uid in uids],
                scores=[scores[uid] for uid in uids],
                ranking=sorted(uids, key=lambda uid: (-scores[uid], uid)),
                model_sha256=model_sha256, normalizer_sha256=_sha(normalizer_bytes),
                normalizer_type='identity_generated_bounded_v1',
                normalizer_fitted=False, features_clipped=False,
                features_standardized=False, synthetic_only=True)


def freeze_snapshot(feature_rows, scores, *, normalizer_bytes, model_sha256,
                    synthetic_only=False):
    """Canonicalize UID order; feature input permutation does not change bytes."""
    _require(synthetic_only is True, 'SYNTHETIC_ONLY')
    payload = _inputs(feature_rows, scores, normalizer_bytes, model_sha256)
    payload_bytes = _canonical(payload)
    return _canonical(dict(snapshot=payload, snapshot_sha256=_sha(payload_bytes)))


def release_outcomes(frozen_bytes, readback_bytes, feature_rows, scores, *,
                     normalizer_bytes, model_sha256, outcome_loader,
                     synthetic_only=False):
    """Validate exact current freeze/readback before inspecting the loader.

    This gate only controls one supplied in-memory generated-fixture callback.
    Its declaration is not authorization or protection for real heldout data.
    """
    _require(synthetic_only is True, 'SYNTHETIC_ONLY')
    # Byte caps precede all parsing. Exact canonical comparison is stricter than
    # accepting arbitrary JSON: no JSON reader or permissive schema path exists.
    for value in (frozen_bytes, readback_bytes):
        _require(type(value) is bytes and 1 <= len(value) <= MAX_BYTES, 'FREEZE_BYTES')
    expected = freeze_snapshot(feature_rows, scores, normalizer_bytes=normalizer_bytes,
                               model_sha256=model_sha256, synthetic_only=True)
    _require(frozen_bytes == expected and readback_bytes == expected, 'FREEZE_READBACK_MISMATCH')
    digest = _sha(expected)
    _require(_sha(frozen_bytes) == digest and _sha(readback_bytes) == digest,
             'FREEZE_HASH_MISMATCH')
    # No len/iter/callable/property access to outcome_loader above this barrier.
    _require(callable(outcome_loader), 'OUTCOME_LOADER')
    outcomes = outcome_loader()
    _require(type(outcomes) in (list, tuple) and 1 <= len(outcomes) <= 1024,
             'OUTCOME_ROWS')
    expected_uids = set(scores)
    checked = {}
    for row in outcomes:
        _require(type(row) is dict and row.keys() == _OUTCOME_KEYS, 'OUTCOME_SCHEMA')
        uid = row['action_uid']
        _require(type(uid) is str and uid in expected_uids and uid not in checked,
                 'OUTCOME_UID_JOIN')
        cycles = row['total_cycles']
        _require(type(cycles) is int and 1 <= cycles <= 10**15, 'CYCLES_DOMAIN')
        cost = row['policy_charged_runtime_s']
        _require(type(cost) in (int, float) and 0 < cost <= 1e9
                 and math.isfinite(cost), 'COST_DOMAIN')
        _require(type(row['is_d95_feasible']) is int and row['is_d95_feasible'] == 1,
                 'D95_REQUIRED')
        _require(type(row['execution_status']) is str and row['execution_status'] == 'SUCCESS',
                 'SUCCESS_REQUIRED')
        checked[uid] = dict(row)
    _require(set(checked) == expected_uids, 'OUTCOME_EXACT_JOIN')
    return dict(held_outcome_release=True, outcome_count=len(checked),
                freeze_sha256=digest, readback_sha256=digest,
                outcome_sha256=_sha(_canonical([checked[uid] for uid in sorted(checked)])),
                scope='generated_bounded_fixture_only', synthetic_only=True,
                synthetic_declaration_is_provenance_detector=False,
                freeze_verified_before_loader_access=True, loader_calls=1,
                fit_performed=False, actual_training=False, normalizer_fitted=False,
                real_data_access=False, real_heldout_release=False,
                generalization_claim=False, online_cost_replay=False)
