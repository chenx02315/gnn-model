"""Fixed TRAIN feature-only support diagnostics. No labels, models or training.

Only aggregate diagnostics leave this module. Distances describe support, not
causality or ranking quality; no clipping or data-selected thresholds are used.
"""
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import stat

# Frozen v3 constants: standalone to support the isolated -I -S worker.
FEATURES = ('scheme_hf','scheme_hmf','log1p_h_limit','log1p_m_limit',
            'h_limit_fraction_of_circuit_max','m_limit_fraction_of_circuit_max',
            'log1p_common_fault_count')
FAMILIES = {'aes_core':'iwls_aes_core','s13207':'iscas89_s13207',
            's15850':'iscas89_s15850','s35932':'iscas89_s35932',
            's38417':'iscas89_s38417','spi':'iwls_spi'}


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

FIXED_ROOT = '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/train_folds'
RECEIPT_SHA256 = '964703dc441fea95c3b1b301dfd6dd01a2cf38f817d82597ff00450287e43868'
SOURCE_SHA256 = 'b89b455ace9d545c0afd54fe9fded98e4db4abd56f58fe09a0cce28b88215d9c'
MAX_BYTES = 16 * 1024 * 1024
SCOPE = 'REAL_TRAIN_ONLY_RELEASED_SIX_FOLD'
FAMILY_NAMES = tuple(sorted(FAMILIES.values()))
SHARDS = {'fit_features.json', 'heldout_features.json', 'fit_outcomes.json', 'heldout_outcomes.json'}
REQUIRED = {'action_uid', 'circuit', 'family', 'role', *FEATURES}
OPTIONAL = {'graph_key', 'action_scheme', 'h_limit', 'm_limit'}


def _require(ok, code):
    if not ok:
        raise ValueError('FEATURE_SUPPORT_' + code)


def _sha(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def _ordinary(path):
    for ancestor in reversed((path, *path.parents)):
        info = os.lstat(ancestor)
        _require(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400,
                 'SYMLINK_OR_REPARSE')
        _require(stat.S_ISDIR(info.st_mode) if ancestor != path else stat.S_ISREG(info.st_mode), 'ORDINARY')
    info = os.lstat(path)
    _require(info.st_nlink == 1 and info.st_size <= MAX_BYTES, 'LINK_OR_SIZE')
    return info


def _identity(info):
    # Windows lstat reports creation time while fstat can report change time in
    # st_ctime; retain ctime on the production POSIX platform, not across these
    # incomparable Windows fields. Inode/mtime/size/link count remain checked.
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns if os.name != 'nt' else None, info.st_nlink)


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        _require(key not in value, 'DUPLICATE_KEY')
        value[key] = item
    return value


def _constant(value):
    raise ValueError('FEATURE_SUPPORT_NONFINITE_JSON')


def _read_json(path, expected_sha):
    _require(_sha(expected_sha), 'HASH_FORMAT')
    before = _ordinary(path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    try:
        opened = os.fstat(descriptor)
        _require(stat.S_ISREG(opened.st_mode) and _identity(before) == _identity(opened), 'IDENTITY')
        chunks = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(65536, MAX_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            _require(size <= MAX_BYTES, 'SIZE')
        _require(_identity(opened) == _identity(os.fstat(descriptor)), 'MUTATED')
    finally:
        os.close(descriptor)
    _require(_identity(before) == _identity(_ordinary(path)), 'REPLACED')
    raw = b''.join(chunks)
    _require(hashlib.sha256(raw).hexdigest() == expected_sha, 'HASH')
    try:
        return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
    except (UnicodeError, RecursionError, OverflowError) as exc:
        raise ValueError('FEATURE_SUPPORT_JSON') from exc


@dataclass(frozen=True)
class FixturePin:
    """Explicit local synthetic test pin; never used by the production entry."""
    root: str
    receipt_sha256: str
    source_sha256: str
    action_count: int


def analyze_package(root=FIXED_ROOT):
    # Deliberately no resolve(), exists(), stat(), Path or reader before this gate.
    _require(type(root) is str and root == FIXED_ROOT, 'FIXED_ROOT')
    return _analyze_package(root, RECEIPT_SHA256, SOURCE_SHA256, 1706)


def _analyze_fixture_package(root, *, fixture_pin):
    _require(type(fixture_pin) is FixturePin and type(root) is str and root == fixture_pin.root,
             'FIXTURE_PIN')
    _require(root != FIXED_ROOT and Path(root).is_absolute(), 'FIXTURE_ROOT')
    _require(_sha(fixture_pin.receipt_sha256) and _sha(fixture_pin.source_sha256)
             and type(fixture_pin.action_count) is int and 6 <= fixture_pin.action_count <= 1706,
             'FIXTURE_BOUNDS')
    return _analyze_package(root, fixture_pin.receipt_sha256, fixture_pin.source_sha256,
                            fixture_pin.action_count)


def _analyze_package(root, receipt_sha, source_sha, count):
    root = Path(root)
    receipt = _read_json(root / 'receipt.json', receipt_sha)
    keys = {'schema_version', 'scope', 'release_sha256', 'source_sha256', 'source_input_sha256',
            'graph_sha256', 'family_metadata_sha256', 'train_action_count', 'train_outcome_count',
            'graph_count', 'fold_manifest_sha256'}
    _require(type(receipt) is dict and set(receipt) == keys, 'RECEIPT_SCHEMA')
    _require(receipt['schema_version'] == 'ranking-v3-real-input-export-receipt-v1'
             and receipt['scope'] == SCOPE and receipt['source_sha256'] == source_sha, 'RECEIPT_SCOPE')
    for field, expected in [('train_action_count', count), ('train_outcome_count', count), ('graph_count', 6)]:
        _require(type(receipt[field]) is int and receipt[field] == expected, 'RECEIPT_COUNT')
    for field in ('release_sha256', 'family_metadata_sha256'):
        _require(_sha(receipt[field]), 'RECEIPT_SHA')
    for field, names in [('source_input_sha256', {'features.tsv', 'train_outcomes.tsv', 'graph_manifest.tsv'}),
                         ('graph_sha256', set(FAMILIES)), ('fold_manifest_sha256', set(FAMILY_NAMES))]:
        _require(type(receipt[field]) is dict and set(receipt[field]) == names
                 and all(_sha(v) for v in receipt[field].values()), 'RECEIPT_MAP')
    _require(digest({'source_input_sha256': receipt['source_input_sha256'],
                     'graph_sha256': receipt['graph_sha256']}) == source_sha, 'SOURCE_BINDING')
    folds = {}
    for family in FAMILY_NAMES:
        directory = root / ('fold_' + family)
        manifest = _read_json(directory / 'manifest.json', receipt['fold_manifest_sha256'][family])
        _require(type(manifest) is dict and set(manifest) == {'schema_version', 'scope', 'release',
                 'source_sha256', 'family', 'fitting', 'heldout', 'sha256'}, 'MANIFEST_SCHEMA')
        release = {'status': 'PASS_TRAIN_ONLY_DATA_RELEASE', 'source_sha256': source_sha,
                   'independent_review_pass': True, 'roles': ['TRAIN']}
        _require(manifest['release'] == release and type(manifest['release'].get('independent_review_pass')) is bool
                 and manifest['schema_version'] == 'ranking-v3-real-train-fold-v1'
                 and manifest['scope'] == SCOPE and manifest['source_sha256'] == source_sha
                 and manifest['family'] == family, 'MANIFEST_RELEASE')
        _require(type(manifest['sha256']) is dict and set(manifest['sha256']) == SHARDS
                 and all(_sha(v) for v in manifest['sha256'].values()), 'MANIFEST_HASHES')
        for key in ('fitting', 'heldout'):
            uids = manifest[key]
            _require(type(uids) is list and uids and all(type(u) is str and u for u in uids)
                     and uids == sorted(set(uids)) and len(uids) <= count, 'MANIFEST_UIDS')
        _require(not set(manifest['fitting']) & set(manifest['heldout'])
                 and len(manifest['fitting']) + len(manifest['heldout']) == count, 'MANIFEST_JOIN')
        fit = _read_json(directory / 'fit_features.json', manifest['sha256']['fit_features.json'])
        held = _read_json(directory / 'heldout_features.json', manifest['sha256']['heldout_features.json'])
        _require(type(fit) is list and type(held) is list, 'ROWS')
        _require([r.get('action_uid') if type(r) is dict else None for r in fit] == manifest['fitting']
                 and [r.get('action_uid') if type(r) is dict else None for r in held] == manifest['heldout'], 'FEATURE_JOIN')
        folds[family] = {'fit': fit, 'heldout': held}
    result = analyze_rows(folds, expected_count=count)
    result.update(receipt_sha256=receipt_sha, source_sha256=source_sha,
                  fold_manifest_sha256=receipt['fold_manifest_sha256'])
    return result


def _rows(rows, count):
    _require(type(rows) is list and 0 < len(rows) <= count, 'ROWS')
    for row in rows:
        _require(type(row) is dict and REQUIRED <= set(row) <= REQUIRED | OPTIONAL, 'ROW_SCHEMA')
        _require(all(type(row[f]) is str and row[f] for f in ('action_uid', 'circuit', 'family', 'role')),
                 'METADATA_TYPE')
        _require(row['role'] == 'TRAIN' and FAMILIES.get(row['circuit']) == row['family'], 'ROLE_FAMILY')
        for name in FEATURES:
            value = row[name]
            _require(type(value) in (int, float), 'NUMERIC_TYPE')
            try:
                _require(math.isfinite(float(value)), 'NONFINITE')
            except OverflowError as exc:
                raise ValueError('FEATURE_SUPPORT_NONFINITE') from exc
        pair = (row['scheme_hf'], row['scheme_hmf'])
        _require(pair in ((1, 0), (0, 1)), 'SCHEME_ONEHOT')
        _require(all(row[n] >= 0 for n in FEATURES[2:])
                 and all(row[n] <= 1 for n in FEATURES[4:6]), 'FEATURE_DOMAIN')
        if 'action_scheme' in row:
            _require(row['action_scheme'] == ('HF' if pair == (1, 0) else 'HMF'), 'SCHEME_MATCH')
        for name in ('h_limit', 'm_limit'):
            if name in row:
                _require(type(row[name]) is int and row[name] >= 0, 'LIMIT_TYPE')
                _require(math.isclose(math.log1p(row[name]), row['log1p_' + name], rel_tol=1e-12, abs_tol=1e-12),
                         'LIMIT_MATCH')
        if 'graph_key' in row:
            _require(type(row['graph_key']) is str and bool(row['graph_key']), 'GRAPH_KEY')
    ids = [r['action_uid'] for r in rows]
    _require(ids == sorted(set(ids)), 'SORTED_UNIQUE_UID')


def _quantile(values, fraction):
    index = (len(values) - 1) * fraction
    lower = int(index)
    upper = math.ceil(index)
    return values[lower] + (values[upper] - values[lower]) * (index - lower)


def _summary(fit, held, normalizer=None, *, distances_enabled=True):
    columns = list(zip(*(tuple(float(r[f]) for f in FEATURES) for r in fit)))
    if normalizer is None:
        means = [sum(c) / len(c) for c in columns]
        raw_std = [math.sqrt(sum((v - m) ** 2 for v in c) / len(c)) for c, m in zip(columns, means)]
        std = [max(s, 1e-12) for s in raw_std]
    else:
        means, raw_std, std = normalizer
    features = {}
    for index, name in enumerate(FEATURES):
        fc = columns[index]
        hc = [float(r[name]) for r in held]
        low, high = min(fc), max(fc)
        outside = sum(v < low or v > high for v in hc)
        features[name] = {'fit_min': low, 'fit_max': high, 'heldout_min': min(hc) if hc else None,
                          'heldout_max': max(hc) if hc else None, 'fit_mean': means[index],
                          'fit_population_std': raw_std[index], 'normalizer_std': std[index],
                          'std_floor_triggered': raw_std[index] < 1e-12,
                          'heldout_out_of_range_count': outside,
                          'heldout_out_of_range_rate': outside / len(hc) if hc else None,
                          'heldout_max_abs_z': max((abs((v - means[index]) / std[index]) for v in hc), default=None)}
    weights = {f: {'count': sum(r['family'] == f for r in fit),
               'weight': sum(r['family'] == f for r in fit) / len(fit)} for f in FAMILY_NAMES}
    if not distances_enabled:
        return {'features': features}
    standardized = {scheme: [tuple((float(r[n]) - m) / s for n, m, s in zip(FEATURES, means, std))
                             for r in fit if r['scheme_hf'] == flag]
                    for scheme, flag in [('HF', 1), ('HMF', 0)]}
    distances = {}
    for scheme, flag in [('HF', 1), ('HMF', 0)]:
        candidates = standardized[scheme]
        targets = [r for r in held if r['scheme_hf'] == flag]
        nearest = []
        if candidates:
            for row in targets:
                vector = tuple((float(row[n]) - m) / s for n, m, s in zip(FEATURES, means, std))
                nearest.append(min(math.dist(vector, other) for other in candidates))
        nearest.sort()
        distances[scheme] = {'fit_count': len(candidates), 'heldout_count': len(targets),
                             'unsupported_scheme_count': len(targets) if not candidates else 0,
                             'min': min(nearest) if nearest else None,
                             'median': _quantile(nearest, .5) if nearest else None,
                             'p90': _quantile(nearest, .9) if nearest else None,
                             'max': max(nearest) if nearest else None}
    return {'features': features, 'nearest_fit_distance': distances,
            'fit_count': len(fit), 'heldout_count': len(held),
            'fit_family_candidate_weights': weights}


def analyze_rows(folds, *, expected_count=1706):
    """Pure synthetic-friendly API; each fold has sorted fit/heldout row lists."""
    _require(type(expected_count) is int and 6 <= expected_count <= 1706, 'COUNT_BOUND')
    _require(type(folds) is dict and set(folds) == set(FAMILY_NAMES), 'SIX_FOLDS')
    reference = None
    results = {}
    for family in FAMILY_NAMES:
        fold = folds[family]
        _require(type(fold) is dict and set(fold) == {'fit', 'heldout'}, 'FOLD_SCHEMA')
        fit, held = fold['fit'], fold['heldout']
        _rows(fit, expected_count)
        _rows(held, expected_count)
        rows = sorted(fit + held, key=lambda r: r['action_uid'])
        _require(len(rows) == expected_count and len({r['action_uid'] for r in rows}) == expected_count,
                 'EXACT_JOIN')
        _require({r['family'] for r in rows} == set(FAMILY_NAMES)
                 and all(r['family'] != family for r in fit)
                 and all(r['family'] == family for r in held), 'FAMILY_SPLIT')
        if reference is None:
            reference = rows
        _require(rows == reference, 'CROSS_FOLD_DRIFT')
        summary = _summary(fit, held)
        summary['by_scheme'] = {}
        normalizer = tuple([summary['features'][name][field] for name in FEATURES]
                           for field in ('fit_mean', 'fit_population_std', 'normalizer_std'))
        for scheme, flag in [('HF', 1), ('HMF', 0)]:
            sf = [r for r in fit if r['scheme_hf'] == flag]
            sh = [r for r in held if r['scheme_hf'] == flag]
            # Every subgroup reuses this fold's single fitting normalizer.
            summary['by_scheme'][scheme] = _summary(sf, sh, normalizer, distances_enabled=False)['features'] if sf else None
        results[family] = summary
    groups = {}
    for row in reference:
        vector = tuple(float(row[n]) for n in FEATURES)
        counts = groups.setdefault(vector, {})
        counts[row['family']] = counts.get(row['family'], 0) + 1
    colliding = [counts for counts in groups.values() if len(counts) > 1]
    pair_count = sum(sum(a * b for i, a in enumerate(c.values()) for b in list(c.values())[i+1:])
                     for c in colliding)
    result = {'scope': 'TRAIN_FEATURE_ONLY_SUPPORT_DIAGNOSTIC_NO_CAUSAL_CLAIM',
              'feature_order': list(FEATURES), 'action_count': expected_count, 'folds': results,
              'cross_family_exact_vector_collisions': {'vector_count': len(colliding),
                  'action_count': sum(sum(c.values()) for c in colliding), 'cross_family_pair_count': pair_count},
              'distance_quantile': 'linear_interpolation_(n-1)*p', 'clipping': False,
              'threshold_selection': False, 'labels_read': False}
    # Reject arithmetic overflow rather than emit nonfinite diagnostics.
    json.dumps(result, allow_nan=False)
    return result
