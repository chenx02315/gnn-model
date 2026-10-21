"""Outcome-free symbolic HF/HMF templates; never reads endpoints or executes ATPG."""
import hashlib
import json

CIRCUITS = ('aes_core', 'spi')
ANCHORS = ('one',) + tuple('p%03d' % p for p in range(5, 101, 5))


def require(ok, code):
    if not ok:
        raise ValueError(code)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=True, allow_nan=False).encode('ascii')).hexdigest()


def templates():
    rows = []
    for circuit in CIRCUITS:
        for h in ANCHORS:
            rows.append(dict(template_uid='%s:HF:%s' % (circuit, h),
                circuit=circuit, scheme='HF', h_anchor=h, m_anchor=None))
            for m in ANCHORS:
                rows.append(dict(template_uid='%s:HMF:%s:%s' % (circuit, h, m),
                    circuit=circuit, scheme='HMF', h_anchor=h, m_anchor=m))
    return rows


def pattern_limit(anchor, full_patterns):
    require(type(full_patterns) is int and 1 <= full_patterns <= 2**31-1,
            'POSITIVE_BOUNDED_FULL_PATTERN_COUNT_REQUIRED')
    require(type(anchor) is str and anchor in ANCHORS, 'FIXED_ANCHOR_REQUIRED')
    if anchor == 'one':
        return 1
    percent = int(anchor[1:])
    # Exact integer half-up; no float or outcome-dependent tie breaking.
    return max(1, min(full_patterns, (full_patterns * percent + 50) // 100))


def expand(circuit, h_full, m_full_by_h):
    """Pure mapping from caller-supplied positive counts, not trusted observations.

    No file reads. Real endpoint provenance/authentication and all endpoint ATPG
    costs remain outside this function. M-full must be measured after each actual
    H prefix, not substituted with independent full-M or previous circuit counts.
    """
    require(circuit in CIRCUITS and type(circuit) is str, 'FIXED_TRAIN_CIRCUIT')
    h_limits = {pattern_limit(h, h_full) for h in ANCHORS}
    require(type(m_full_by_h) is dict and all(type(k) is int for k in m_full_by_h)
            and set(m_full_by_h) == h_limits, 'EXACT_PER_H_M_ENDPOINT_MAP_REQUIRED')
    for value in m_full_by_h.values():
        pattern_limit('one', value)
    groups = {}
    for row in templates():
        if row['circuit'] != circuit:
            continue
        h = pattern_limit(row['h_anchor'], h_full)
        m = None if row['scheme'] == 'HF' else pattern_limit(row['m_anchor'], m_full_by_h[h])
        uid = '%s:%s:h%d' % (circuit, row['scheme'], h)
        if m is not None:
            uid += ':m%d' % m
        action = groups.setdefault(uid, dict(action_uid=uid, circuit=circuit,
            scheme=row['scheme'], h_limit=h, m_limit=m, template_uids=[]))
        action['template_uids'].append(row['template_uid'])
    return [groups[key] for key in sorted(groups)]


def seeded_template_order(circuit, seed):
    """Versioned hash permutation, a proposed random comparator, not model scores."""
    require(type(circuit) is str and circuit in CIRCUITS, 'FIXED_TRAIN_CIRCUIT')
    require(type(seed) is int and 0 <= seed <= 2**63-1, 'BOUNDED_INTEGER_SEED')
    rows = [r for r in templates() if r['circuit'] == circuit]
    return [r['template_uid'] for r in sorted(rows, key=lambda row: (
        digest(dict(version='sha256-template-order-v1', seed=seed, uid=row['template_uid'])),
        row['template_uid']))]


def collapse_order(template_order, actions):
    """First occurrence of an integer-action alias wins; unknown/duplicate IDs reject."""
    require(type(template_order) is list and all(type(uid) is str for uid in template_order), 'ORDER_LIST')
    alias = {}
    for action in actions:
        for uid in action['template_uids']:
            require(uid not in alias, 'DUPLICATE_ALIAS')
            alias[uid] = action['action_uid']
    require(len(template_order) == len(set(template_order)) and set(template_order) == set(alias),
            'EXACT_TEMPLATE_PERMUTATION_REQUIRED')
    seen = set()
    result = []
    for uid in template_order:
        aid = alias[uid]
        if aid not in seen:
            seen.add(aid)
            result.append(aid)
    return result


def summary():
    rows = templates()
    return dict(schema='prospective-candidate-template-v1',
        status='SYMBOLIC_TEMPLATE_ONLY_NO_ENDPOINTS_OR_RELEASE',
        template_count=len(rows), per_circuit_template_count=462,
        per_circuit_scheme_counts=dict(HF=21, HMF=441),
        template_sha256=digest(rows), fixed_mode_chain_counts=dict(H=64, M=16, F=4),
        anchors=list(ANCHORS), integer_action_count=None,
        current_model_accepts_symbolic_features_verified=False,
        real_endpoint_provenance_verified=False, real_roster_frozen=False,
        endpoint_measurement_costs_included=False,
        actual_atpg_execution=False, execution_ready=False, training_release=False)
