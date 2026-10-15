"""E21 specifically authorized injected-Torch paired diagnostic runtime.

No Torch import or fitting occurs at import. Public entry validates the fixed
one-run release contract before any injected Torch API. Mock orchestration
is implementation evidence, never a measured fitting result.
"""
import copy

from . import ranking_v6_complete_cost_paired_fit as e19
from . import ranking_v6_synthetic_fit_no_prior as e14

SCOPE = 'E21_PAIRED_COST_RUNTIME_DIAGNOSTIC_ONLY'
EXECUTION_RELEASED = True
CONTROL, TREATMENT = e19.CONTROL, e19.TREATMENT
_TorchSession = e14._TorchSession


def _require(ok, code):
    if not ok:
        raise ValueError('E21_' + code)


PROTOCOL_SHA256 = '5075785d758137c37bae3a5e352d3e9c9846cb87585ea48f94bc606a48da815c'
AUTHORIZATION_ID = 'E21_FULL_STAGE_20261015_ONE_RUN'


def _source_release_guard():
    _require(EXECUTION_RELEASED is True, 'RUNTIME_EXECUTION_LOCKED')


def _validate_release(release):
    """Validate exact trusted budget values without consulting injected Torch."""
    _require(type(release) is dict, 'RELEASE_CONTRACT')
    expected = {
        'authorization_id': AUTHORIZATION_ID,
        'execution_authorized': True,
        'formal_runs': 1,
        'automatic_retries': 0,
        'scope': SCOPE,
        'planned_models': 6,
        'planned_optimizer_steps_total': 144,
        'memory_bytes': 1073741824,
        'workers': 1,
        'cpus': 1,
        'swap_extra_bytes': 0,
        'protocol_sha256': PROTOCOL_SHA256,
    }
    for key, value in expected.items():
        actual = release.get(key)
        _require(type(actual) is type(value) and actual == value,
                 'RELEASE_CONTRACT_' + key.upper())
    config = e19.protocol.validate(e19.protocol.plan())
    _require(e19._hash(config) == PROTOCOL_SHA256, 'PROTOCOL_DIGEST')


def run(torch, *, release=None):
    """A valid one-run contract and released source precede every Torch API."""
    _validate_release(release)
    _source_release_guard()
    return _run_released(torch)


def _run_core(session_factory, *, mock_only=True):
    """Explicit mock-only seam: fixed six sessions and 144 mock updates."""
    _require(mock_only is True, 'MOCK_FACTORY_REQUIRED')
    _validate_mock_factory(session_factory)
    return _collect(session_factory, real_execution=False)


def _validate_mock_factory(session_factory):
    _require(callable(session_factory) and
             session_factory is not _TorchSession and
             getattr(session_factory, 'mock_only', None) is True,
             'MOCK_FACTORY_REQUIRED')


def _collect(session_factory, *, real_execution):
    """Own collector; reuse E19's numerical helpers, never its mock collector."""
    _require(type(real_execution) is bool, 'EXECUTION_MODE')
    if real_execution:
        _source_release_guard()
    else:
        _validate_mock_factory(session_factory)
    config = e19.protocol.validate(e19.protocol.plan())
    config_hash = e19._hash(config)
    records, restored = [], []
    created = completed_steps = observed_steps = verified_real_sessions = 0
    cleanup_failed = False
    result = dict(scope=SCOPE, protocol=config, protocol_sha256=config_hash,
                  records=records, freezes=records, mock_steps=0,
                  real_optimizer_steps=0, optimizer_steps=0,
                  fitting_executed=False, actual_torch_proof=False,
                  synthetic_fitting_runs=0, protocol_completed=False,
                  execution_released=False, train_release=False,
                  real_label_reads=0, checkpoint_reads=0, checkpoint_writes=0,
                  remote_execution=False, retry_count=0,
                  mock_window_completed=False, planned_mock_budget_completed=False,
                  all_snapshots_frozen_before_comparative_evaluation=False)
    try:
        for seed in config['seeds']:
            paired_hash = paired_scores = None
            for arm in (CONTROL, TREATMENT):
                session = None
                try:
                    session = session_factory(seed)
                    created += 1
                    if real_execution:
                        _require(type(session) is e14._TorchSession, 'REAL_SESSION_BINDING')
                        verified_real_sessions += 1
                    initial_hash = e19._weight_hash(session)
                    _require(initial_hash == session.initial_hash, 'INITIAL_STATE_HASH')
                    if paired_hash is None:
                        paired_hash = initial_hash
                    _require(initial_hash == paired_hash, 'PAIRED_INITIAL_HASH')
                    initial = {t['case_id']: e19._scores(session, t) for t in config['tasks']}
                    if paired_scores is None:
                        paired_scores = copy.deepcopy(initial)
                    _require(initial == paired_scores, 'PAIRED_INITIAL_SCORES')
                    _require(e19._weight_hash(session) == initial_hash, 'INITIAL_FORWARD_MUTATION')
                    logs = []
                    for step in range(24):
                        logs.append(e19._fit_step(session,
                            [t for t in config['tasks'] if t['split'] == 'fit'], arm, step))
                        completed_steps += 1
                    final_hash = e19._weight_hash(session)
                    states = {t['case_id']: dict(initial=initial[t['case_id']],
                        final=e19._scores(session, t),
                        uniform_PL={u: 0. for u in t['uids']},
                        cost_prior_PL={u: -t['costs'][u]/max(t['costs'].values())
                                       for u in t['uids']}) for t in config['tasks']}
                    _require(e19._weight_hash(session) == final_hash, 'FINAL_FORWARD_MUTATION')
                    # E19 validates its own schema/scope before any comparison;
                    # preserve that provenance rather than relabeling its schema.
                    payload = dict(seed=seed, arm=arm, scope=e19.SCOPE,
                        protocol_sha256=config_hash, score_states=states,
                        initial_parameter_sha256=initial_hash,
                        final_parameter_sha256=final_hash, steps=24, fit_step_logs=logs)
                    records.append(dict(payload=payload, freeze_sha256=e19._hash(payload)))
                finally:
                    if session is not None:
                        try:
                            if real_execution:
                                count = session.optimizer_steps
                                _require(type(count) is int and 0 <= count <= 24,
                                         'OPTIMIZER_COUNTER')
                                observed_steps += count
                        finally:
                            try:
                                ok = session.restore()
                                _require(ok is True and e19._weight_hash(session) ==
                                         session.initial_hash, 'RESTORE_FAILED')
                                restored.append(True)
                            except Exception:
                                cleanup_failed = True
                                raise
                            finally:
                                session = None
        _require(e19._hash(config) == config_hash, 'PROTOCOL_MUTATED')
        _require(len(records) == 6 and completed_steps == 144, 'INCOMPLETE_WINDOW')
        # E19's inner scope names its historical schema, NOT execution origin.
        # Bind the actual collector provenance in a separately hashed envelope.
        envelope = dict(runtime_scope=SCOPE, inner_schema_scope=e19.SCOPE,
                        execution_kind='injected_torch' if real_execution else 'mock',
                        protocol_sha256=config_hash,
                        freeze_sha256=[r['freeze_sha256'] for r in records])
        result.update(runtime_freeze_envelope=envelope,
                      runtime_freeze_envelope_sha256=e19._hash(envelope),
                      inner_freeze_scope_is_schema_only=True)
        result.update(e19._evaluate(records, config))
        _require(e19._hash(envelope) == result['runtime_freeze_envelope_sha256'],
                 'RUNTIME_ENVELOPE_MUTATED')
        result.update(all_snapshots_frozen_before_comparative_evaluation=True,
                      status=('COMPLETE_PAIRED_SYNTHETIC_FIT_DIAGNOSTIC_ONLY'
                              if real_execution else 'PASS_MOCK_IMPLEMENTATION_ONLY'))
        if real_execution:
            _require(observed_steps == 144, 'OPTIMIZER_COUNTER')
            result.update(protocol_completed=True)
        else:
            result.update(mock_window_completed=True, planned_mock_budget_completed=True)
    except Exception as exc:
        result.update(status='FAIL_CLOSED', failure=str(exc), scientific_status='NOT_EVIDENCE',
                      protocol_completed=False)
    cleanup_ok = created == len(restored) and created > 0 and not cleanup_failed
    result.update(all_parameters_restored=cleanup_ok, restored_sessions=len(restored),
                  final_weights_discarded=cleanup_ok, sessions_created=created)
    if real_execution:
        result.update(real_optimizer_steps=observed_steps, optimizer_steps=observed_steps,
                      fitting_executed=observed_steps > 0,
                      actual_torch_proof=verified_real_sessions > 0 and observed_steps > 0,
                      execution_released=verified_real_sessions > 0,
                      synthetic_fitting_runs=verified_real_sessions)
    else:
        result['mock_steps'] = completed_steps
    return result


def _with_rng_restored(torch, callback):
    """Small independently mock-testable RNG lifecycle, no fitting by itself."""
    rng = torch.get_rng_state().clone()
    try:
        result = callback()
    finally:
        torch.set_rng_state(rng)
    result['rng_restored'] = True
    return result


def _run_released(torch):
    """Fixed real path; public entry validates the one-run release contract."""
    _source_release_guard()
    _require(EXECUTION_RELEASED is True, 'RUNTIME_EXECUTION_LOCKED')
    _require(_TorchSession is e14._TorchSession, 'SESSION_BINDING')
    _require(torch.get_num_threads() == 1, 'CPU_THREADS')
    return _with_rng_restored(torch, lambda: _collect(
        lambda seed: _TorchSession(torch, seed), real_execution=True))
