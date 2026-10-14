"""E18 design protocol only: no Torch, optimizer, reader, sampling or runner."""
import copy
import hashlib
import json
import math

from .ranking_v6_synthetic_fit_no_prior import _tasks


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    allow_nan=False).encode('ascii')).hexdigest()


def plan():
    tasks = _tasks()
    return {
        'status': 'DESIGN_FROZEN_LOCAL_CHECKS_ONLY_INDEPENDENT_REVIEW_PENDING',
        'experiment_id': 'E18_COMPLETE_COST_PAIRED_OBJECTIVE_PLAN',
        'date_local': '2026-10-15',
        'authorization': 'Protocol design and local validation only; no new fitting or remote execution release',
        'base_commit': '7fa556bf9089a653f05ec3ba455b095085431265',
        'seeds': [11, 29, 47], 'n': 6, 'k': 3, 'tasks': tasks,
        'task_sha256': digest(tasks),
        'model': 'existing seven-feature MLP CPU float64, 1345 parameters, not GraphSAGE',
        'factory_sha256': 'd64eb0fe17a00886d6464ae016805b1474e7324e95ad8e223aba44502709759c',
        'initialization': 'same manual_seed(seed) and factory for both arms; initial parameter hashes must match',
        'arms': [
            {'id': 'EXACT_TRUNCATED_CONTROL', 'risk_weight': 0.5,
             'normalized_cost_weight': 0.5, 'cost_denominator': 'K*max_cost',
             'cost_horizon': 3, 'gradient_method': 'exact small-n PL enumeration'},
            {'id': 'EXACT_COMPLETE_TREATMENT', 'risk_weight': 0.5,
             'normalized_cost_weight': 1.0, 'cost_denominator': 'N*max_cost',
             'cost_horizon': 6, 'gradient_method': 'exact singleton pairwise full-cost gradient + exact PL risk'}
        ],
        'relative_raw_cost_coefficient_preserved': True,
        'optimizer': {'type': 'SGD', 'learning_rate': 0.2, 'momentum': 0.0,
                      'weight_decay': 0.0, 'steps_per_model': 24},
        'task_reduction': 'mean of the two FIT-task parameter gradients at the same pre-update weights',
        'planned_models': 6, 'planned_total_optimizer_steps': 144,
        'budget_matching': 'same updates per arm/model, not equal total work to historical E14; no equal wall-time claim',
        'historical_e14_result_sha256': 'dc8d09347592c7cc7c84eeb28a38467f883bfe5faa31c788178c1deffe2c9e44',
        'historical_comparison': 'reference only; E14 stochastic estimator not rerun, not isolated objective comparison',
        'evaluation': {
            'risk': 'exact miss probability R@3', 'primary_cost': 'raw complete first-hit C6',
            'secondary': ['normalized C6', 'truncated C3', 'deterministic positive rank', 'top3 hit'],
            'fixed_baselines': ['initial model', 'uniform PL', 'cost-prior PL: -cost/max_cost'],
            'risk_tolerance': 1e-8, 'strict_cost_improvement': 1e-8,
            'rows_per_arm': 12, 'fit_rows_per_arm': 6, 'unseen_rows_per_arm': 6,
            'pass_vs_initial': 'all 12 rows: final R3 <= initial R3 + tolerance AND final C6 < initial C6 - threshold',
            'treatment_advantage': 'all 12 paired rows: treatment R3 <= control R3 + tolerance AND treatment C6 < control C6 - threshold',
            'means_cannot_override_failed_rows': True,
            'fit_and_unseen_pass_reported_separately': True,
            'unseen_labels_never_in_gradient_or_selection': True,
            'all_model_score_snapshots_frozen_before_comparative_evaluation': True,
            'fit_exact_oracle_allowed_for_fixed_training_gradient_only_if_future_run_authorized': True
        },
        'no_adaptation': ['no tuning', 'no early stop', 'no oracle rollback', 'no clipping',
                          'no best checkpoint', 'no seed/task deletion', 'no extra steps'],
        'planned_resources': {'memory_bytes': 1073741824, 'extra_swap_bytes': 0,
                              'cpu': 1, 'workers': 1, 'models_live_at_once': 1,
                              'automatic_retries': 0, 'network': 'none'},
        'fail_closed': ['nonfinite scores/weights/gradients', 'domain error', 'source or initial hash mismatch',
                        'unseen access during fit', 'resource or once-marker violation'],
        'final_risk_guard_is_evaluation_not_update_acceptance': True,
        'independent_review_required_before_implementation_release': True,
        'future_actual_fit_requires_new_specific_authorization_and_fresh_gates': True,
        'fitting_executed': False, 'remote_execution_authorized': False,
        'train_release': False, 'real_label_access': False,
        'limitations': ['one known positive, static additive synthetic costs',
                        'toy signal labels, not real circuit generalization',
                        'no measured ATPG runtime or ATE-cycle improvement',
                        'risk safeguard is not guaranteed by scalar objective',
                        'same SGD steps do not equal estimator compute or wall time']
    }


def validate(candidate):
    """Reject every deviation, including bool/int or int/float substitutions."""
    try:
        valid = type(candidate) is dict and digest(candidate) == digest(plan())
    except (ValueError, TypeError, OverflowError):
        valid = False
    if not valid:
        raise ValueError('COMPLETE_COST_FIT_PROTOCOL_MISMATCH')
    return copy.deepcopy(candidate)


def scalar_values(risk, truncated_cost, complete_cost, max_cost):
    """Pure numeric scaling proof only, no gradient or fit entry point."""
    for x in (risk, truncated_cost, complete_cost, max_cost):
        try:
            finite = type(x) in (int, float) and math.isfinite(x)
        except OverflowError:
            finite = False
        if not finite:
            raise ValueError('FINITE_NUMERIC_VALUES')
    if not 0 <= risk <= 1 or not 0 < max_cost <= 1e9 or not 0 < truncated_cost <= 3*max_cost or not truncated_cost <= complete_cost <= 6*max_cost:
        raise ValueError('COST_RISK_DOMAIN')
    return {'control': 0.5*risk + 0.5*truncated_cost/(3*max_cost),
            'treatment': 0.5*risk + complete_cost/(6*max_cost)}
