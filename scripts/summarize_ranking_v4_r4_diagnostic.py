"""Validate old-model diagnostic bindings and produce aggregate-only evidence."""
import hashlib
import json
import math
from pathlib import Path

from scripts.compare_ranking_v4_r3_results import _v4_rows, NONEXHAUSTIVE_EXCLUDED_FAMILY
from src.models.runtime_ranking_v3 import FAMILIES, FEATURES
from src.models.run_runtime_ranking_v3 import SEEDS

RAW = Path('../runtime_training_staging_20260928/r4_fit_transfer_20261006_r1.json')
SEALED = Path('data/manifests/ranking_v4_r4_train_results_20261005.json')
OUTPUT = Path('data/manifests/ranking_v4_r4_fit_transfer_diagnostic_20261006.json')
RELEASE_SHA = 'ad5dd0e57459ee74ba018aebe72bc8e6f9f95dcc63cf8ce44941f167813e96cb'
PACKAGE_SHA = '964703dc441fea95c3b1b301dfd6dd01a2cf38f817d82597ff00450287e43868'
AUDIT = Path('data/manifests/ranking_v4_r4_result_audit_20261005.json')
AUDIT_SHA = 'a6002053d39a32c6ed71ba35722e2d166aeb4d638eb3c056ae071f8cfcedded7'
DIAGNOSTIC_SHA = '4241fdff276a55cc932a99960eb2b1a9eaf6f23584c36b0b4ea9870b1819896d'


def verify_model_identity(payload, audit_raw):
    if hashlib.sha256(audit_raw).hexdigest() != AUDIT_SHA:
        raise ValueError('DIAGNOSTIC_HISTORICAL_AUDIT_SHA')
    audit = json.loads(audit_raw)
    models = {r['held_family'] + '_' + str(r['seed']) + '_candidate_mlp': r['model_sha256']
              for r in payload['results']}
    if len(models) != 18 or len(payload['results']) != 18:
        raise ValueError('DIAGNOSTIC_MODEL_IDENTITY_GRID')
    aggregate = hashlib.sha256(json.dumps(sorted(models.items()), separators=(',', ':')).encode()).hexdigest()
    if (audit['status'] != 'PASS_R4_COMPLETE_RESULT_AUDIT' or audit['release_sha256'] != RELEASE_SHA
            or audit['exit_receipt_sha256'] != 'fd2454fa90c611b1e2ce91d0d5448c86ee2930a2d697dd46b6422a9e82851b26'
            or payload['release_sha256'] != RELEASE_SHA or payload['package_sha256'] != PACKAGE_SHA
            or aggregate != audit['aggregate_evidence_sha256']['models']):
        raise ValueError('DIAGNOSTIC_HISTORICAL_MODEL_AGGREGATE')
    return aggregate


def summarize(payload, sealed):
    if (payload.get('status') != 'PASS_EXISTING_R4_READ_ONLY_DIAGNOSTIC'
            or payload.get('role') != 'TRAIN' or payload.get('new_fits') != 0
            or payload.get('optimizer_steps') != 0 or payload.get('held_outcome_files_read') != 0
            or payload.get('checkpoint_bytes_exported') != 0
            or payload.get('raw_labels_features_or_scores_exported') is not False
            or payload.get('peak_process_rss_bytes', 2 ** 40) > 1024 ** 3):
        raise ValueError('DIAGNOSTIC_SCOPE_RESOURCE')
    if payload.get('release_sha256') != RELEASE_SHA or payload.get('package_sha256') != PACKAGE_SHA:
        raise ValueError('DIAGNOSTIC_RELEASE_PACKAGE_PIN')
    records = payload.get('results', [])
    expected = {(family, seed) for family in FAMILIES.values() for seed in SEEDS}
    keys = [(r['held_family'], r['seed']) for r in records]
    if len(keys) != 18 or set(keys) != expected:
        raise ValueError('DIAGNOSTIC_EXACT_GRID')
    evaluations = _v4_rows(sealed)
    for r in records:
        family, seed = r['held_family'], r['seed']
        prefix = 'experiment/' + family + '_' + str(seed) + '_candidate_mlp/'
        worker = sealed['records'][prefix + 'worker_receipt.json']
        evaluation = sealed['records'][prefix + 'evaluation.json']
        if (r['worker_sha256'] != worker['sha256'] or r['evaluation_sha256'] != evaluation['sha256']
                or r['request_sha256'] != worker['data']['request_sha256']
                or r['freeze_sha256'] != worker['data']['freeze_sha256']
                or r['existing_held_metrics'] != evaluations[family, seed, 'candidate_mlp']['metrics']
                or r['model_held_scores_exact'] is not True):
            raise ValueError('DIAGNOSTIC_SEALED_BINDING')
        groups = r['fitting_families']
        if len(groups) != 5 or {g['fitting_family'] for g in groups} != set(FAMILIES.values()) - {family}:
            raise ValueError('DIAGNOSTIC_FIT_FAMILY_GRID')
        if len(r['feature_ranges']) != 7 or {g['feature'] for g in r['feature_ranges']} != set(FEATURES):
            raise ValueError('DIAGNOSTIC_FEATURE_GRID')
        for g in groups:
            for field in ('pair_accuracy_ties_half', 'selected_pair_softplus_mean', 'mean_positive_negative_margin'):
                if not math.isfinite(g[field]): raise ValueError('DIAGNOSTIC_NONFINITE')
            if not 0 <= g['pair_accuracy_ties_half'] <= 1 or g['fit_hit_at_10'] not in (0, 1):
                raise ValueError('DIAGNOSTIC_METRIC_DOMAIN')
    family_rows = []
    for family in sorted(FAMILIES.values()):
        fits = [g for r in records for g in r['fitting_families'] if g['fitting_family'] == family]
        held = [r for r in records if r['held_family'] == family]
        assert len(fits) == 15 and len(held) == 3
        family_rows.append({'family': family, 'fit_observations': 15,
            'fit_hits_at_10': sum(g['fit_hit_at_10'] for g in fits),
            'held_observations': 3, 'held_hits_at_10': sum(r['existing_held_metrics']['hit_at_10'] for r in held),
            'mean_fit_pair_accuracy_ties_half': sum(g['pair_accuracy_ties_half'] for g in fits) / 15,
            'mean_fit_selected_pair_softplus': sum(g['selected_pair_softplus_mean'] for g in fits) / 15,
            'fit_first_positive_ranks': [g['first_positive_rank'] for g in fits],
            'feature_ranges_seed_invariant': all(r['feature_ranges'] == held[0]['feature_ranges'] for r in held),
            'feature_ranges': held[0]['feature_ranges']})
    primary_fit = [g for r in records if r['held_family'] != NONEXHAUSTIVE_EXCLUDED_FAMILY
                   for g in r['fitting_families'] if g['fitting_family'] != NONEXHAUSTIVE_EXCLUDED_FAMILY]
    return {'status': 'PASS_BOUND_FIT_TRANSFER_DIAGNOSTIC', 'role': 'TRAIN', 'epsilon': .01, 'K': 10,
        'family_rows': family_rows,
        'nonexhaustive_primary': {'held_observations': 15,
            'held_hits_at_10': sum(r['existing_held_metrics']['hit_at_10'] for r in records
                                   if r['held_family'] != NONEXHAUSTIVE_EXCLUDED_FAMILY),
            'fit_observations': len(primary_fit), 'fit_hits_at_10': sum(g['fit_hit_at_10'] for g in primary_fit),
            'fit_pair_accuracy_macro_mean': sum(g['pair_accuracy_ties_half'] for g in primary_fit) / len(primary_fit),
            'fit_selected_pair_softplus_macro_mean': sum(g['selected_pair_softplus_mean'] for g in primary_fit) / len(primary_fit)},
        'provenance': {'release_sha256': payload['release_sha256'], 'package_sha256': payload['package_sha256'],
            'all_18_model_held_predictions_exact': True,
            'models_sha256': {r['held_family'] + '_' + str(r['seed']): r['model_sha256'] for r in records},
            'all_18_worker_evaluation_request_freeze_bound_to_sealed_export': True},
        'resources': {'peak_process_rss_bytes': payload['peak_process_rss_bytes'], 'threads': 1, 'workers': 1, 'retries': 0},
        'new_fits': 0, 'optimizer_steps': 0, 'held_outcome_files_read': 0,
        'epoch_trajectory': 'UNAVAILABLE_NOT_PERSISTED_NO_REFIT',
        'interpretation': 'Mixed failure: fit top-10 weaknesses in s13207/s15850 coexist with fit-to-held collapse in aes_core/spi/s38417. Not proof of convergence or causal mechanism.',
        'denominator_note': '15 fitting observations per family = 5 other held-family folds x 3 seeds; 3 held observations per family. These repeated fits and seeds are not independent family samples.',
        'next_boundary': 'No new training, tuning, epsilon/K relaxation, candidate release or BLIND access authorized by this diagnostic.'}


def main():
    if OUTPUT.exists(): raise FileExistsError('DIAGNOSTIC_SUMMARY_CREATE_ONCE')
    raw = RAW.read_bytes()
    if len(raw) > 200 * 1024: raise ValueError('DIAGNOSTIC_OUTPUT_BOUND')
    sealed_raw = SEALED.read_bytes()
    if hashlib.sha256(sealed_raw).hexdigest() != '55253ab1685b683dc93469407ac4422d57cc142f07e836497a943e02ad74e353':
        raise ValueError('DIAGNOSTIC_SEALED_EXPORT_SHA')
    payload = json.loads(raw.decode('utf-8-sig'))
    verify_model_identity(payload, AUDIT.read_bytes())
    script_sha = hashlib.sha256(Path('scripts/diagnose_ranking_v4_r4_existing.py').read_bytes()).hexdigest()
    if script_sha != DIAGNOSTIC_SHA:
        raise ValueError('DIAGNOSTIC_SCRIPT_PIN')
    result = summarize(payload, json.loads(sealed_raw))
    result['raw_diagnostic_sha256'] = hashlib.sha256(raw).hexdigest()
    result['diagnostic_script_sha256'] = hashlib.sha256(Path('scripts/diagnose_ranking_v4_r4_existing.py').read_bytes()).hexdigest()
    with OUTPUT.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(json.dumps(result, sort_keys=True, ensure_ascii=False, allow_nan=False, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'primary': result['nonexhaustive_primary'], 'output': str(OUTPUT)}))


if __name__ == '__main__': main()
