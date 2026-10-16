"""Bounded, materialized FIT-only accounting/fold seam; not a real-data reader.

The complete feature/split barrier precedes inspection of action outcomes or
attempt rows. This module checks canonical joins, not source authenticity,
physical outcome freezes, online prefix reuse, model support or training.
"""
from .ranking_v6_materialized_fold import feature_split, prepare_fold
from ..replay.ranking_v6_attempt_charges import aggregate_charges


def _require(condition, code):
    if not condition:
        raise ValueError('ACCOUNTED_FOLD_' + code)


def prepare_accounted_fold(feature_rows, fit_action_rows, fit_attempt_rows, *,
                           held_family, seed, implementation_only=False):
    """Join five fitting families only; terminal failures are never filtered.

    A caller must supply canonical per-invocation records. Any terminal failed
    action is retained by accounting, then rejected by the current fit interface
    rather than silently omitted. Held action outcomes must not be supplied.
    """
    _require(implementation_only is True, 'IMPLEMENTATION_OPT_IN')
    split = feature_split(feature_rows, held_family=held_family, seed=seed,
                          implementation_only=True)
    fit_uids = set(split['fit_uids'])
    # UID-only barrier before other action fields or any attempt inspection.
    _require(type(fit_action_rows) is list and len(fit_action_rows) == len(fit_uids),
             'FIT_ACTION_CONTAINER')
    action_by_uid = {}
    for row in fit_action_rows:
        _require(type(row) is dict and 'action_uid' in row, 'ACTION_UID_SCHEMA')
        uid = row['action_uid']
        _require(type(uid) is str and uid in fit_uids and uid not in action_by_uid,
                 'FIT_ONLY_UNIQUE_UID_JOIN')
        action_by_uid[uid] = row
    _require(set(action_by_uid) == fit_uids, 'EXACT_FIT_UID_COVERAGE')
    for uid, row in action_by_uid.items():
        feature = split['feature_rows_by_uid'][uid]
        for field in ('circuit', 'family', 'role'):
            _require(type(row.get(field)) is str and row[field] == feature[field],
                     'FEATURE_ACTION_METADATA_JOIN')
        scheme = 'HF' if feature['scheme_hf'] == 1 else 'HMF'
        _require(type(row.get('action_scheme')) is str and row['action_scheme'] == scheme,
                 'FEATURE_ACTION_SCHEME_JOIN')
    ledger = aggregate_charges(fit_action_rows, fit_attempt_rows, implementation_only=True)
    cohorts = {}
    for record in ledger['records'].values():
        circuit, cohort = record['circuit'], record['environment_cohort']
        _require(cohorts.setdefault(circuit, cohort) == cohort,
                 'CIRCUIT_ENVIRONMENT_COHORT_JOIN')
    outcomes = {
        uid: {field: record[field] for field in (
            'execution_status', 'is_d95_feasible', 'total_cycles',
            'policy_charged_runtime_s')}
        for uid, record in ledger['records'].items()
    }
    prepared = prepare_fold(feature_rows, outcomes, held_family=held_family,
                            seed=seed, implementation_only=True)
    return dict(status='IMPLEMENTATION_ONLY_ACCOUNTED_FIT_FOLD', fold=prepared,
                fit_accounting=ledger, canonical_uid_join_checked=True,
                held_action_rows_supplied=False, held_outcomes_accessed=False,
                terminal_failed_fit_support=False,
                source_provenance_verified=False, real_data_release=False,
                real_training_release=False, physical_freeze_implemented=False,
                model_ready=False, optimizer_calls=0)
