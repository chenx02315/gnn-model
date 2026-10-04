#!/usr/bin/env python3
"""Descriptive attribution of the sealed ranking-v3 TRAIN-only result artifact.

This module never fits, re-ranks, changes K/epsilon, or reads any remote path.
"""
import argparse
import hashlib
import json
from pathlib import Path

from scripts.collect_ranking_v3_results import validate
from src.models.run_runtime_ranking_v3_real import MODELS

DEFAULT_INPUT = Path('data/manifests/ranking_v3_train_results_20261005.json')
DEFAULT_INPUT_SHA256 = '6f3336eb3acbbf87609ceff6e26141258956e0606f861f0673721ac2d1d91660'
BASELINE = 'fixed_heuristic'


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _evaluations(payload):
    values = [entry['data'] for key, entry in payload['records'].items()
              if key.endswith('/evaluation.json')]
    keys = [(row.get('family'), row.get('seed'), row.get('model')) for row in values]
    if len(values) != 72 or len(set(keys)) != len(keys):
        raise ValueError('ATTRIBUTION_EVALUATION_GRID')
    return values


def _record(row, heuristic):
    metrics, order = row['metrics'], row['freeze']['order']
    if not isinstance(order, list) or len(order) != len(set(order)) or not order:
        raise ValueError('ATTRIBUTION_ORDER')
    hit = metrics['hit_at_10']
    if hit not in (0, 1) or bool(metrics.get('hit_found')) != bool(hit):
        raise ValueError('ATTRIBUTION_HIT')
    attempts = metrics['attempt_count']
    if type(attempts) is not int or not 1 <= attempts <= 10:
        raise ValueError('ATTRIBUTION_ATTEMPTS')
    # A replay reports attempts through its first hit.  We deliberately do not
    # search the remainder of an order to infer a hit after the top-10 budget.
    first_hit_rank = attempts if hit == 1 else None
    return {'hit_at_10': hit, 'charged_runtime_s': metrics['charged_runtime_s'],
            'best_cycle_regret_at_10': metrics['best_cycle_regret_at_10'],
            'attempt_count': attempts,
            'first_hit_rank': first_hit_rank, 'exhaustive_heldout': len(order) <= 10,
            'top10_uid_overlap_with_fixed_heuristic': len(set(order[:10]) & set(heuristic['freeze']['order'][:10])),
            'full_order': tuple(order)}


def describe(payload, input_sha256):
    """Build a deterministic descriptive report after the collector validator."""
    validate(payload)
    rows = _evaluations(payload)
    indexed = {(row['family'], row['seed'], row['model']): row for row in rows}
    if any((family, seed, BASELINE) not in indexed
           for family, seed, model in indexed):
        raise ValueError('ATTRIBUTION_BASELINE_GRID')
    result = {'schema_version': 'ranking-v3-frozen-result-attribution-v1',
              'scope': 'TRAIN_ONLY_REAL_SIX_FOLD_V3_DESCRIPTIVE_ONLY',
              'input_sha256': input_sha256,
              'input_record_count': 148,
              'models': {}}

    def aggregate(entries):
        count = len(entries)
        if not count:
            return {'evaluation_count': 0, 'hit_count': 0, 'hit_rate': None,
                    'mean_charged_runtime_s': None, 'mean_best_cycle_regret_at_10': None,
                    'mean_attempt_count': None}
        return {'evaluation_count': count,
                'hit_count': sum(item['hit_at_10'] for item in entries),
                'hit_rate': sum(item['hit_at_10'] for item in entries) / count,
                'mean_charged_runtime_s': sum(item['charged_runtime_s'] for item in entries) / count,
                'mean_best_cycle_regret_at_10': sum(item['best_cycle_regret_at_10'] for item in entries) / count,
                'mean_attempt_count': sum(item['attempt_count'] for item in entries) / count}

    for model in MODELS:
        model_rows = [row for row in rows if row['model'] == model]
        families = {}
        for family in sorted({row['family'] for row in model_rows}):
            entries = []
            for row in sorted((item for item in model_rows if item['family'] == family), key=lambda item: item['seed']):
                base = indexed[(family, row['seed'], BASELINE)]
                entries.append(_record(row, base))
            held_counts = {len(item['full_order']) for item in entries}
            if len(held_counts) != 1:
                raise ValueError('ATTRIBUTION_FOLD_SIZE')
            families[family] = {
                'heldout_action_count': held_counts.pop(),
                'hits_over_3': sum(item['hit_at_10'] for item in entries),
                'mean_charged_runtime_s': sum(item['charged_runtime_s'] for item in entries) / 3,
                'mean_best_cycle_regret_at_10': sum(item['best_cycle_regret_at_10'] for item in entries) / 3,
                'first_hit_ranks': [item['first_hit_rank'] for item in entries],
                'top10_uid_overlap_with_fixed_heuristic': [item['top10_uid_overlap_with_fixed_heuristic'] for item in entries],
                'unique_full_order_count_across_3_seeds': len({item['full_order'] for item in entries}),
                'exhaustive_heldout_flags': [item['exhaustive_heldout'] for item in entries],
            }
        paired = []
        paired_nonexhaustive = []
        excluded = 0
        if model != BASELINE:
            for row in model_rows:
                baseline = indexed[(row['family'], row['seed'], BASELINE)]
                if row['metrics']['hit_at_10'] == baseline['metrics']['hit_at_10'] == 1:
                    delta = row['metrics']['charged_runtime_s'] - baseline['metrics']['charged_runtime_s']
                    paired.append(delta)
                    if len(row['freeze']['order']) > 10:
                        paired_nonexhaustive.append(delta)
                else:
                    # This includes every no-hit lower-cost case: it is excluded,
                    # never converted into a performance gain.
                    excluded += 1
        entries = [_record(row, indexed[(row['family'], row['seed'], BASELINE)]) for row in model_rows]
        result['models'][model] = {
            'family': families,
            'aggregate': {'evaluation_count_all_18': len(entries),
                          'nonexhaustive_evaluation_count': sum(not item['exhaustive_heldout'] for item in entries),
                          'exhaustive_evaluation_count': sum(item['exhaustive_heldout'] for item in entries),
                          'all_evaluations_descriptive_joint': aggregate(entries),
                          'nonexhaustive_evaluations_descriptive_joint': aggregate(
                              [item for item in entries if not item['exhaustive_heldout']]),
                          'paired_cost_deltas_shared_hit_only': paired,
                          'paired_cost_delta_mean_shared_hit_only': (sum(paired) / len(paired)) if paired else None,
                          'paired_shared_hit_count': len(paired),
                          'paired_cost_deltas_nonexhaustive_shared_hit_only': paired_nonexhaustive,
                          'paired_nonexhaustive_shared_hit_count': len(paired_nonexhaustive),
                          'paired_cost_delta_mean_nonexhaustive_shared_hit_only': (
                              sum(paired_nonexhaustive) / len(paired_nonexhaustive)) if paired_nonexhaustive else None,
                          'nonshared_hit_cost_comparisons_excluded': excluded,
                          'no_hit_lower_cost_is_not_a_gain': True},
        }
    return result


def analyze(input_path=DEFAULT_INPUT, *, expected_input_sha256=DEFAULT_INPUT_SHA256, output_path=None):
    input_path = Path(input_path)
    raw = input_path.read_bytes()
    if _sha(raw) != expected_input_sha256:
        raise ValueError('ATTRIBUTION_INPUT_SHA')
    payload = json.loads(raw)
    report = describe(payload, expected_input_sha256)
    if output_path is not None:
        output_path = Path(output_path)
        with output_path.open('xb') as stream:
            stream.write((json.dumps(report, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8'))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', default=str(DEFAULT_INPUT))
    parser.add_argument('--expected-input-sha256', default=DEFAULT_INPUT_SHA256)
    parser.add_argument('--output')
    args = parser.parse_args(argv)
    print(json.dumps(analyze(args.input, expected_input_sha256=args.expected_input_sha256,
                             output_path=args.output), sort_keys=True))


if __name__ == '__main__':
    main()
