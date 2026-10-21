"""Pure request-control binding, not checkpoint compatibility or execution release.

Only pre-execution requested limits are accepted. Observed pattern counts and
quality/runtime fields cannot enter this schema. Pins name supplied identities;
this function does not authenticate bytes, endpoints, or historical invocations.
"""
import hashlib
import json
import re


IDENTITIES = ('driver', 'common_tcl', 'incremental_tcl', 'config', 'netlist',
              'cell_library', 'fault_universe', 'graph', 'checkpoint',
              'feature_schema', 'environment', 'resource_policy')
ROW_KEYS = {'action_uid', 'scheme', 'h_request', 'm_request'}


def require(ok, code):
    if not ok:
        raise ValueError(code)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=True, allow_nan=False).encode('ascii')).hexdigest()


def positive(value):
    return type(value) is int and 1 <= value <= 2**31 - 1


def bind_requests(circuit, rows, identities):
    """Validate an entire caller-declared frozen roster, without model features.

    Whole-roster SHA and maxima are returned for downstream binding. This cannot
    tell whether a caller omitted rows: a later freeze/readback must compare this
    SHA against an externally preregistered roster before any top-k selection.
    HMF's M request is conditional on its exact H prefix. HF has no M stage.
    """
    require(type(circuit) is str and circuit in ('aes_core', 'spi'), 'TRAIN_SCOPE')
    require(type(rows) is list and 1 <= len(rows) <= 462, 'BOUNDED_ROSTER')
    require(type(identities) is dict and set(identities) == set(IDENTITIES), 'IDENTITY_SCHEMA')
    for pin in identities.values():
        require(pin is None or (type(pin) is str and
                re.fullmatch('[0-9a-f]{64}', pin) is not None), 'SHA256_OR_UNKNOWN')
    seen_ids, seen_coordinates, controls = set(), set(), []
    for row in rows:
        require(type(row) is dict and set(row) == ROW_KEYS, 'REQUEST_ONLY_SCHEMA')
        uid, scheme, h, m = (row[k] for k in ('action_uid', 'scheme', 'h_request', 'm_request'))
        require(type(uid) is str and re.fullmatch('[A-Za-z0-9_:.-]{1,128}', uid) is not None,
                'ACTION_UID')
        require(uid not in seen_ids, 'DUPLICATE_ACTION_UID')
        require(type(scheme) is str and scheme in ('HF', 'HMF'), 'SCHEME')
        require(positive(h), 'H_REQUEST')
        require((scheme == 'HF' and m is None) or (scheme == 'HMF' and positive(m)), 'M_REQUEST')
        coordinate = (scheme, h, m)
        require(coordinate not in seen_coordinates, 'COLLAPSE_ALIASES_BEFORE_BINDING')
        seen_ids.add(uid)
        seen_coordinates.add(coordinate)
        stages = [dict(mode='H', pattern_limit=h)]
        if scheme == 'HMF':
            stages.append(dict(mode='M', pattern_limit=m, conditional_h_request=h))
        # F completion can require multiple probes; no free final call is assumed.
        controls.append(dict(action_uid=uid, scheme=scheme, stages=stages,
                             f_probe_policy='UNRESOLVED_CHARGE_EVERY_PHYSICAL_PROBE'))
    canonical = sorted([dict(row) for row in rows], key=lambda row: row['action_uid'])
    max_h = max(row['h_request'] for row in rows)
    max_m = max([row['m_request'] for row in rows if row['m_request'] is not None] or [0])
    payload = dict(schema='prospective-input-binding-v1', circuit=circuit,
        mode_chain_counts=dict(H=64, M=16, F=4), requested_roster=canonical,
        identities=dict(identities), control_semantics='REQUESTED_PATTERN_COUNT_CAP_NOT_REALIZED_COUNT',
        normalization_scope='ENTIRE_SUPPLIED_ROSTER_BEFORE_POLICY_SELECTION',
        requested_max_h=max_h, requested_max_m=max_m)
    return dict(schema='prospective-input-binding-assessment-v1',
        status='LOCAL_REQUEST_BINDING_ONLY_NOT_EXECUTABLE', binding_sha256=digest(payload),
        roster_sha256=digest(canonical), payload=payload,
        controls=sorted(controls, key=lambda row: row['action_uid']),
        missing_identity_names=[key for key in IDENTITIES if identities[key] is None],
        supplied_identity_bytes_authenticated=False,
        requested_vs_realized_equivalence_verified=False,
        legacy_model_compatible=False, model_feature_vector=None,
        future_unknown_actions_d95_preverified=False,
        actual_atpg_execution=False, execution_ready=False, training_release=False)
