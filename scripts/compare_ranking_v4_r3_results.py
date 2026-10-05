"""Bounded descriptive comparison for projected r3 results and sealed v3 manifests."""
import argparse
import json
import math
from pathlib import Path

from src.models.runtime_ranking_v3 import FAMILIES
from src.models.run_runtime_ranking_v3 import SEEDS
from src.models.run_runtime_ranking_v3_real import MODELS as V3_MODELS

V3_DEFAULT = Path('data/manifests/ranking_v3_train_results_r2_20261005.json')
V3_LEGACY_DEFAULT = Path('data/manifests/ranking_v3_train_results_20261005.json')
NONEXHAUSTIVE_EXCLUDED_FAMILY = 'iscas89_s35932'
METRICS = ('hit_at_10', 'best_cycle_regret_at_10', 'charged_runtime_s', 'attempt_count')
BASELINES = ('candidate_mlp', 'xgboost', 'fixed_heuristic')


def _metric_valid(row):
    metrics = row.get('metrics')
    if not isinstance(metrics, dict) or type(metrics.get('hit_at_10')) is not int or metrics['hit_at_10'] not in (0, 1):
        raise ValueError('COMPARISON_HIT_DOMAIN')
    for name in ('best_cycle_regret_at_10', 'charged_runtime_s'):
        value = metrics.get(name)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise ValueError('COMPARISON_METRIC_DOMAIN:' + name)
    attempts = metrics.get('attempt_count')
    if type(attempts) is not int or not 1 <= attempts <= 10:
        raise ValueError('COMPARISON_ATTEMPT_DOMAIN')
    if 'hit_found' in metrics and (type(metrics['hit_found']) is not bool or metrics['hit_found'] != bool(metrics['hit_at_10'])):
        raise ValueError('COMPARISON_HIT_FOUND_DOMAIN')


def _v3_rows(payload):
    rows = [item['data'] for key, item in payload.get('records', {}).items() if key.endswith('/evaluation.json')]
    expected = {(family, seed, model) for family in FAMILIES.values() for seed in SEEDS for model in V3_MODELS}
    keys = [(row.get('family'), row.get('seed'), row.get('model')) for row in rows]
    if len(rows) != 72 or len(set(keys)) != len(keys) or set(keys) != expected:
        raise ValueError('V3_COMPARISON_AUTHORITATIVE_GRID')
    for row in rows: _metric_valid(row)
    return dict(zip(keys, rows))


def _v4_rows(payload):
    rows = [item['data'] for key, item in payload.get('records', {}).items() if key.endswith('/evaluation.json')]
    expected = {(family, seed, 'candidate_mlp') for family in FAMILIES.values() for seed in SEEDS}
    keys = [(row.get('family'), row.get('seed'), row.get('model')) for row in rows]
    if len(rows) != 18 or len(set(keys)) != len(keys) or set(keys) != expected:
        raise ValueError('V4_COMPARISON_GRID')
    for row in rows: _metric_valid(row)
    return dict(zip(keys, rows))


def _aggregate(rows):
    return {'count': len(rows), 'hit_count': sum(row['metrics']['hit_at_10'] for row in rows),
            'hit_rate': sum(row['metrics']['hit_at_10'] for row in rows) / len(rows),
            **{'mean_' + field: sum(row['metrics'][field] for row in rows) / len(rows)
               for field in METRICS if field != 'hit_at_10'}}


def verify_v3_manifest_agreement(primary_payload, legacy_payload):
    """Require the two retained v3 manifests to describe identical comparison cells."""
    primary, legacy = _v3_rows(primary_payload), _v3_rows(legacy_payload)
    def projection(rows):
        return {key: tuple(rows[key]['metrics'][field] for field in METRICS) for key in rows}
    if projection(primary) != projection(legacy):
        raise ValueError('V3_COMPARISON_MANIFEST_DISAGREEMENT')


def compare(v4_payload, v3_payload):
    expected = {(family, seed) for family in FAMILIES.values() for seed in SEEDS}
    v4, v3 = _v4_rows(v4_payload), _v3_rows(v3_payload)
    result = {'schema_version': 'ranking-v4-r3-v3-descriptive-comparison-v1',
              'scope': 'DESCRIPTIVE_ONLY_NO_MODEL_SELECTION_OR_SPEEDUP_CLAIM',
              'nonexhaustive_excluded_family': NONEXHAUSTIVE_EXCLUDED_FAMILY,
              'paired_unit_note': 'family-seed observations are paired; seeds are not independent families.',
              'comparisons': {}}
    for baseline in BASELINES:
        keys = {(family, seed) for family, seed, model in v3 if model == baseline}
        if keys != expected:
            raise ValueError('V3_COMPARISON_GRID:' + baseline)
        all_rows = [(v4[(family, seed, 'candidate_mlp')], v3[(family, seed, baseline)]) for family, seed in sorted(expected)]
        nonexhaustive = [(left, right) for left, right in all_rows if left['family'] != NONEXHAUSTIVE_EXCLUDED_FAMILY]
        def block(pairs):
            left, right = [pair[0] for pair in pairs], [pair[1] for pair in pairs]
            common = [(a, b) for a, b in pairs if a['metrics']['hit_at_10'] == b['metrics']['hit_at_10'] == 1]
            cost = [a['metrics']['charged_runtime_s'] - b['metrics']['charged_runtime_s'] for a, b in common]
            return {'v4': _aggregate(left), 'v3_baseline': _aggregate(right),
                    'hit_count_delta_v4_minus_baseline': sum(a['metrics']['hit_at_10'] - b['metrics']['hit_at_10'] for a, b in pairs),
                    'common_hit_paired_cost_count': len(common),
                    'common_hit_charged_runtime_deltas_v4_minus_baseline': cost,
                    'common_hit_mean_charged_runtime_delta_v4_minus_baseline': sum(cost) / len(cost) if cost else None,
                    'miss_cost_is_not_speedup': True}
        result['comparisons'][baseline] = {'all_18': block(all_rows), 'nonexhaustive_15': block(nonexhaustive)}
    return result


def render_markdown(result):
    lines = ['# Ranking v4 r3 与 v3 的描述性比较', '',
             '仅比较同一 family/seed。种子不是独立家族样本；未命中时的较低成本不构成加速结论。', '']
    for baseline, item in result['comparisons'].items():
        summary = item['nonexhaustive_15']
        lines.extend([f'## v4 candidate_mlp vs v3 {baseline}', '',
                      f"非穷举 15 项：v4 命中 {summary['v4']['hit_count']}/{summary['v4']['count']}；"
                      f"基线命中 {summary['v3_baseline']['hit_count']}/{summary['v3_baseline']['count']}；"
                      f"共同命中成本配对数 {summary['common_hit_paired_cost_count']}。", ''])
    return '\n'.join(lines)


def write_outputs(result, json_output=None, markdown_output=None):
    for path in (json_output, markdown_output):
        if path is not None and Path(path).exists(): raise FileExistsError('V4_COMPARISON_CREATE_ONCE')
    if json_output is not None: Path(json_output).write_text(json.dumps(result, sort_keys=True, allow_nan=False) + '\n', encoding='utf-8')
    if markdown_output is not None: Path(markdown_output).write_text(render_markdown(result), encoding='utf-8')


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--v4-results', required=True); parser.add_argument('--v3-results', default=str(V3_DEFAULT))
    parser.add_argument('--v3-legacy-results', default=str(V3_LEGACY_DEFAULT))
    parser.add_argument('--json-output'); parser.add_argument('--markdown-output')
    args = parser.parse_args(argv)
    v3 = json.loads(Path(args.v3_results).read_text())
    verify_v3_manifest_agreement(v3, json.loads(Path(args.v3_legacy_results).read_text()))
    result = compare(json.loads(Path(args.v4_results).read_text()), v3)
    write_outputs(result, args.json_output, args.markdown_output)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__': main()
