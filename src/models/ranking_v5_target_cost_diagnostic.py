"""Bounded, aggregate-only released TRAIN target/cost diagnostics.

No fitting, threshold selection, online replay or non-TRAIN access. Static
policy charged runtime is not measured online wall time, and omits any unknown
prefix/session-dependent cost. Only the existing feature reader is imported.
"""
import itertools
import json
import math
from pathlib import Path

from src.models import ranking_v5_feature_support as base

OUTCOME_KEYS = {'execution_status', 'is_d95_feasible', 'total_cycles',
                'policy_charged_runtime_s'}
MAX_OUTPUT_BYTES = 65536
K = 10


def _require(ok, code):
    if not ok:
        raise ValueError('TARGET_COST_' + code)


def _outcomes(rows, outcomes):
    _require(type(outcomes) is dict and set(outcomes) == {r['action_uid'] for r in rows},
             'OUTCOME_JOIN')
    for outcome in outcomes.values():
        _require(type(outcome) is dict and set(outcome) == OUTCOME_KEYS, 'OUTCOME_SCHEMA')
        _require(type(outcome['execution_status']) is str and outcome['execution_status'] == 'SUCCESS'
                 and type(outcome['is_d95_feasible']) is int and outcome['is_d95_feasible'] == 1,
                 'SAFE_SUCCESS')
        _require(type(outcome['total_cycles']) is int and outcome['total_cycles'] > 0,
                 'CYCLES')
        cost = outcome['policy_charged_runtime_s']
        _require(type(cost) is float and math.isfinite(cost) and cost > 0, 'COST')


def _ranks(values):
    ordered = sorted(range(len(values)), key=values.__getitem__)
    ranks = [0.] * len(values)
    start = 0
    while start < len(values):
        stop = start + 1
        while stop < len(values) and values[ordered[stop]] == values[ordered[start]]:
            stop += 1
        for index in ordered[start:stop]:
            ranks[index] = (start + stop - 1) / 2 + 1
        start = stop
    return ranks


def _spearman(cycles, costs):
    if len(cycles) < 2:
        return {'rho': None, 'null_reason': 'insufficient_actions', 'count': len(cycles)}
    x, y = _ranks(cycles), _ranks(costs)
    midpoint = (len(x) + 1) / 2
    x, y = [v - midpoint for v in x], [v - midpoint for v in y]
    sx, sy = sum(v*v for v in x), sum(v*v for v in y)
    reason = ('constant_cycles_and_cost' if not sx and not sy else
              'constant_cycles' if not sx else 'constant_cost' if not sy else None)
    return {'rho': None if reason else sum(a*b for a, b in zip(x, y)) / math.sqrt(sx*sy),
            'null_reason': reason, 'count': len(cycles)}


def _cost_summary(values):
    values = sorted(values)
    return {'count': len(values), 'min': values[0] if values else None,
            'median': base._quantile(values, .5) if values else None,
            'p90': base._quantile(values, .9) if values else None,
            'max': values[-1] if values else None}


def _group(rows, outcomes, oracle):
    positive, negative = [], []
    cycles, costs = [], []
    for row in rows:
        outcome = outcomes[row['action_uid']]
        cycle, cost = outcome['total_cycles'], outcome['policy_charged_runtime_s']
        cycles.append(cycle)
        costs.append(cost)
        (positive if 100 * cycle <= 101 * oracle else negative).append(cost)
    return {'action_count': len(rows), 'positive_count': len(positive),
            'negative_count': len(negative),
            'positive_rate': len(positive) / len(rows) if rows else None,
            'negative_count_lt_k': len(negative) < K,
            'guaranteed_hit_within_k_without_replacement': bool(positive) and len(negative) < K,
            'policy_charged_runtime_s': {'overall': _cost_summary(costs),
                                        'positives': _cost_summary(positive),
                                        'negatives': _cost_summary(negative)},
            'spearman_cycles_vs_policy_charged_runtime': _spearman(cycles, costs)}


def _grid_key(row):
    return ('HF' if row['scheme_hf'] == 1 else 'HMF',
            row['h_limit_fraction_of_circuit_max'], row['m_limit_fraction_of_circuit_max'])


def analyze_rows(rows, outcomes, *, expected_count=1706):
    """Pure API for 6..1706 unique, sorted synthetic or authenticated actions."""
    _require(type(expected_count) is int and 6 <= expected_count <= 1706, 'COUNT_BOUND')
    base._rows(rows, expected_count)
    _require(len(rows) == expected_count and {r['family'] for r in rows} == set(base.FAMILY_NAMES),
             'EXACT_SIX_FAMILY_JOIN')
    _outcomes(rows, outcomes)
    families, grids = {}, {}
    for family in base.FAMILY_NAMES:
        selected = [r for r in rows if r['family'] == family]
        oracle = min(outcomes[r['action_uid']]['total_cycles'] for r in selected)
        summary = _group(selected, outcomes, oracle)
        summary['family_wide_oracle_cycles'] = oracle
        summary['by_scheme'] = {scheme: _group([r for r in selected if _grid_key(r)[0] == scheme],
                                               outcomes, oracle) for scheme in ('HF', 'HMF')}
        grid = {}
        for row in selected:
            grid.setdefault(_grid_key(row), []).append(outcomes[row['action_uid']]['total_cycles'])
        ambiguous = [values for values in grid.values() if len(values) != 1]
        summary['comparable_grid'] = {'key_count': len(grid), 'ambiguous_key_count': len(ambiguous),
                                      'ambiguous_action_count': sum(map(len, ambiguous)),
                                      'unique_key_count': len(grid) - len(ambiguous)}
        families[family] = summary
        grids[family] = {key: values[0] for key, values in grid.items() if len(values) == 1}
    pairs, comparisons = [], 0
    for a, b in itertools.combinations(base.FAMILY_NAMES, 2):
        ga, gb = grids[a], grids[b]
        common = sorted(set(ga) & set(gb))
        counts = dict(concordant=0, discordant=0, tie_first_only=0, tie_second_only=0, tie_both=0)
        for left, right in itertools.combinations(common, 2):
            comparisons += 1
            _require(comparisons <= 1706 ** 2, 'COMPARISON_BOUND')
            da = (ga[left] > ga[right]) - (ga[left] < ga[right])
            db = (gb[left] > gb[right]) - (gb[left] < gb[right])
            key = ('tie_both' if not da and not db else 'tie_first_only' if not da else
                   'tie_second_only' if not db else 'concordant' if da == db else 'discordant')
            counts[key] += 1
        pairs.append({'first_family': a, 'second_family': b, 'common_unique_key_count': len(common),
                      'first_unmatched_unique_key_count': len(ga) - len(common),
                      'second_unmatched_unique_key_count': len(gb) - len(common),
                      'first_unique_key_coverage': len(common) / len(ga) if ga else None,
                      'second_unique_key_coverage': len(common) / len(gb) if gb else None,
                      'unordered_key_pair_count': len(common)*(len(common)-1)//2,
                      'directions': counts})
    result = {'scope': 'TRAIN_TARGET_COST_AGGREGATE_DIAGNOSTIC', 'action_count': expected_count,
              'epsilon': {'numerator': 101, 'denominator': 100, 'oracle': 'family_all_HF_HMF'},
              'k': K, 'families': families, 'pairwise_grid_directions': pairs,
              'total_unordered_key_pair_comparisons': comparisons,
              'cost_meaning': 'existing frozen policy charged runtime; not online wall time',
              'primary_online_cost_replay': False,
              'online_replay_blocker': 'prefix/session-dependent costs absent from outcome schema',
              'correlation_scale': 'within_family_only; oracle scaling preserves ranks',
              'rank_ties': 'average_ranks', 'cost_quantile': 'linear_interpolation_(n-1)*p',
              'threshold_selection': False, 'interpolation_or_nearest_join': False,
              'labels_read': True}
    _bounded(result)
    return result


def _bounded(result):
    _require(len(json.dumps(result, sort_keys=True, allow_nan=False).encode()) <= MAX_OUTPUT_BYTES,
             'OUTPUT_BOUND')


def analyze_package(root=base.FIXED_ROOT):
    # Zero filesystem/path operations before this exact string gate.
    _require(type(root) is str and root == base.FIXED_ROOT, 'FIXED_ROOT')
    return _analyze_package(root, base.RECEIPT_SHA256, base.SOURCE_SHA256, 1706)


def _analyze_fixture_package(root, *, fixture_pin):
    _require(type(fixture_pin) is base.FixturePin and type(root) is str and root == fixture_pin.root,
             'FIXTURE_PIN')
    _require(root != base.FIXED_ROOT and Path(root).is_absolute(), 'FIXTURE_ROOT')
    _require(base._sha(fixture_pin.receipt_sha256) and base._sha(fixture_pin.source_sha256)
             and type(fixture_pin.action_count) is int and 6 <= fixture_pin.action_count <= 1706,
             'FIXTURE_BOUNDS')
    return _analyze_package(root, fixture_pin.receipt_sha256, fixture_pin.source_sha256,
                            fixture_pin.action_count)


def _analyze_package(root, receipt_sha, source_sha, count):
    root = Path(root)
    receipt = base._read_json(root / 'receipt.json', receipt_sha)
    keys = {'schema_version', 'scope', 'release_sha256', 'source_sha256', 'source_input_sha256',
            'graph_sha256', 'family_metadata_sha256', 'train_action_count', 'train_outcome_count',
            'graph_count', 'fold_manifest_sha256'}
    _require(type(receipt) is dict and set(receipt) == keys, 'RECEIPT_SCHEMA')
    _require(receipt['schema_version'] == 'ranking-v3-real-input-export-receipt-v1'
             and receipt['scope'] == base.SCOPE and receipt['source_sha256'] == source_sha,
             'RECEIPT_SCOPE')
    for field, expected in [('train_action_count', count), ('train_outcome_count', count), ('graph_count', 6)]:
        _require(type(receipt[field]) is int and receipt[field] == expected, 'RECEIPT_COUNT')
    _require(all(base._sha(receipt[f]) for f in ('release_sha256', 'family_metadata_sha256')), 'RECEIPT_SHA')
    for field, names in [('source_input_sha256', {'features.tsv', 'train_outcomes.tsv', 'graph_manifest.tsv'}),
                         ('graph_sha256', set(base.FAMILIES)), ('fold_manifest_sha256', set(base.FAMILY_NAMES))]:
        _require(type(receipt[field]) is dict and set(receipt[field]) == names
                 and all(base._sha(v) for v in receipt[field].values()), 'RECEIPT_MAP')
    _require(base.digest({'source_input_sha256': receipt['source_input_sha256'],
                          'graph_sha256': receipt['graph_sha256']}) == source_sha, 'SOURCE_BINDING')
    reference_rows = reference_outcomes = None
    for family in base.FAMILY_NAMES:
        directory = root / ('fold_' + family)
        manifest = base._read_json(directory / 'manifest.json', receipt['fold_manifest_sha256'][family])
        _require(type(manifest) is dict and set(manifest) == {'schema_version', 'scope', 'release',
                 'source_sha256', 'family', 'fitting', 'heldout', 'sha256'}, 'MANIFEST_SCHEMA')
        release = {'status': 'PASS_TRAIN_ONLY_DATA_RELEASE', 'source_sha256': source_sha,
                   'independent_review_pass': True, 'roles': ['TRAIN']}
        _require(manifest['release'] == release
                 and type(manifest['release']['independent_review_pass']) is bool
                 and manifest['schema_version'] == 'ranking-v3-real-train-fold-v1'
                 and manifest['scope'] == base.SCOPE and manifest['source_sha256'] == source_sha
                 and manifest['family'] == family, 'MANIFEST_RELEASE')
        _require(type(manifest['sha256']) is dict and set(manifest['sha256']) == base.SHARDS
                 and all(base._sha(v) for v in manifest['sha256'].values()), 'MANIFEST_HASHES')
        for key in ('fitting', 'heldout'):
            uids = manifest[key]
            _require(type(uids) is list and uids and all(type(u) is str and u for u in uids)
                     and uids == sorted(set(uids)) and len(uids) <= count, 'MANIFEST_UIDS')
        _require(not set(manifest['fitting']) & set(manifest['heldout'])
                 and len(manifest['fitting']) + len(manifest['heldout']) == count, 'MANIFEST_JOIN')
        shards = {name: base._read_json(directory / name, manifest['sha256'][name])
                  for name in ('fit_features.json', 'heldout_features.json', 'fit_outcomes.json', 'heldout_outcomes.json')}
        combined, outcomes = [], {}
        for prefix, membership in [('fit', 'fitting'), ('heldout', 'heldout')]:
            rows, labels = shards[prefix + '_features.json'], shards[prefix + '_outcomes.json']
            base._rows(rows, count)
            _require([r['action_uid'] for r in rows] == manifest[membership], 'FEATURE_JOIN')
            _outcomes(rows, labels)
            _require(all((r['family'] == family) == (prefix == 'heldout') for r in rows), 'FAMILY_SPLIT')
            combined.extend(rows)
            outcomes.update(labels)
        combined.sort(key=lambda r: r['action_uid'])
        if reference_rows is None:
            reference_rows, reference_outcomes = combined, outcomes
        _require(combined == reference_rows and outcomes == reference_outcomes, 'CROSS_FOLD_DRIFT')
    result = analyze_rows(reference_rows, reference_outcomes, expected_count=count)
    result.update(receipt_sha256=receipt_sha, source_sha256=source_sha,
                  fold_manifest_sha256=receipt['fold_manifest_sha256'], authenticated_file_count=31)
    _bounded(result)
    return result
