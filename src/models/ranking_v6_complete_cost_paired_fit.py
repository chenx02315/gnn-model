"""E18 bounded paired orchestration: injected-session implementation evidence only.

The actual Torch entry remains closed. The private seam executes only explicitly
declared mock sessions, never imports Torch, and does not establish fitting,
resource enforcement, generalization, or execution authorization.
"""
import copy
import math
import re

from . import ranking_v6_complete_cost_fit_protocol as protocol
from . import ranking_v6_complete_first_hit_reference as complete
from . import ranking_v6_first_hit_exact_gradient as exact
from . import ranking_v6_synthetic_fit_no_prior as e14

SCOPE = 'E18_INJECTED_MOCK_IMPLEMENTATION_EVIDENCE_ONLY'
CONTROL = 'EXACT_TRUNCATED_CONTROL'
TREATMENT = 'EXACT_COMPLETE_TREATMENT'
# Future binding only: construction remains unreachable from the public entry.
# E14 fixes factory=1345 parameters, CPU float64 and SGD(lr=.2, momentum=0).
_TorchSession = e14._TorchSession
_hash = protocol.digest


def _require(ok, code):
    if not ok:
        raise ValueError('E18_' + code)


def run_synthetic_pair(torch, *, scope=None):
    """No execution release exists, regardless of caller scope or Torch object."""
    raise ValueError('E18_EXECUTION_NOT_RELEASED')


def _weight_hash(session):
    value = session.weight_hash()
    _require(_is_digest(value), 'WEIGHT_HASH')
    return value


def _is_digest(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _validate_scores(scores, task):
    _require(type(scores) is dict and set(scores) == set(task['uids']), 'SCORE_JOIN')
    _require(all(type(v) in (int, float) and math.isfinite(v) and abs(v) <= 20
                 for v in scores.values()), 'SCORE_DOMAIN')


def _scores(session, task):
    scores = session.scores(copy.deepcopy(task))
    _validate_scores(scores, task)
    return copy.deepcopy(scores)


def _score_maps(task, scores, arm):
    """Separate exact risk/cost derivatives; no comparative evaluation here."""
    _require(task['split'] == 'fit', 'UNSEEN_GRADIENT_FORBIDDEN')
    _require(arm in (CONTROL, TREATMENT), 'ARM')
    result = exact.enumerate_exact_gradient(scores, set(task['positive_uids']), task['costs'], k=3)
    if arm == CONTROL:
        cost = {u: result['cost_score_gradient'][u] / (3 * max(task['costs'].values()))
                for u in task['uids']}
    else:
        cost = complete.evaluate(scores, task['positive_uids'], task['costs'],
                                 synthetic_only=True)['normalized_cost_score_gradient']
    return {'risk': result['miss_score_gradient'], 'cost': cost}


def _fit_step(session, tasks, arm, step):
    before = _weight_hash(session)
    gradients, logs = [], []
    for task in tasks:
        _require(_weight_hash(session) == before, 'SHARED_PREUPDATE_STATE')
        scores = _scores(session, task)
        maps = _score_maps(task, scores, arm)
        vjp = session.vjp(copy.deepcopy(task), copy.deepcopy(maps))
        _require(vjp['weights_unchanged'] is True and vjp['weights_sha256'] == before
                 and _weight_hash(session) == before, 'SHARED_PREUPDATE_STATE')
        risk, cost = vjp['risk_parameter_gradient'], vjp['cost_parameter_gradient']
        _require(len(risk) == len(cost) == 1345 and
                 all(type(v) in (int, float) and math.isfinite(v) for v in (*risk, *cost)),
                 'PARAMETER_GRADIENT_DOMAIN')
        weight = .5 if arm == CONTROL else 1.
        gradient = [.5*r + weight*c for r, c in zip(risk, cost)]
        _require(all(math.isfinite(v) for v in gradient), 'GRADIENT_DOMAIN')
        gradients.append(gradient)
        logs.append({'task_id': task['case_id'], 'preupdate_sha256': before,
                     'score_sha256': _hash(scores), 'maps_sha256': _hash(maps)})
    _require(len(gradients) == 2 and _weight_hash(session) == before, 'SHARED_PREUPDATE_STATE')
    mean = [math.fsum(values)/2 for values in zip(*gradients)]
    _require(all(math.isfinite(v) for v in mean), 'GRADIENT_DOMAIN')
    session.step(mean)
    return {'step': step, 'parameter_before_sha256': before,
            'parameter_after_sha256': _weight_hash(session),
            'gradient_sha256': _hash(mean), 'tasks': logs}


def _metrics(task, scores):
    result = exact.enumerate_exact_gradient(scores, task['positive_uids'], task['costs'], k=3)
    full = complete.evaluate(scores, task['positive_uids'], task['costs'], synthetic_only=True)
    order = sorted(scores, key=lambda u: (-scores[u], u))
    rank = order.index(task['positive_uids'][0])+1
    return {'risk': result['expected_miss_probability'],
            'raw_C6': full['complete_first_hit_cost'],
            'normalized_C6': full['normalized_complete_first_hit_cost'],
            'raw_C3': result['expected_truncated_static_cost'],
            'deterministic_positive_rank': rank, 'top3_hit': rank <= 3}


def _guard(reference, candidate):
    return (candidate['risk'] <= reference['risk']+1e-8 and
            candidate['raw_C6'] < reference['raw_C6']-1e-8)


def _summary(rows):
    return {split: {'rows': len(selected), 'passing_rows': sum(r['pass'] for r in selected),
                    'all_pass': len(selected) == (12 if split == 'all' else 6) and
                    all(r['pass'] for r in selected)}
            for split in ('all', 'fit', 'unseen')
            for selected in [[r for r in rows if split == 'all' or r['split'] == split]]}


def _evaluate(records, config):
    """Verify ALL six endpoint freezes before any comparative oracle call."""
    protocol.validate(config)
    _require(type(records) is list and len(records) == 6, 'FREEZE_COUNT')
    expected = [(seed, arm) for seed in config['seeds'] for arm in (CONTROL, TREATMENT)]
    for record, (seed, arm) in zip(records, expected):
        payload = record['payload']
        _require(record['freeze_sha256'] == _hash(payload), 'FREEZE_HASH')
        _require(payload['seed'] == seed and payload['arm'] == arm and
                 payload['protocol_sha256'] == _hash(config) and payload['scope'] == SCOPE,
                 'FREEZE_BINDING')
        _require(type(payload['steps']) is int and 1 <= payload['steps'] <= 24 and
                 len(payload['fit_step_logs']) == payload['steps'], 'FREEZE_STEPS')
        _require(_is_digest(payload['initial_parameter_sha256']) and
                 _is_digest(payload['final_parameter_sha256']), 'FREEZE_WEIGHT_HASH')
        previous = payload['initial_parameter_sha256']
        fit_ids = [t['case_id'] for t in config['tasks'] if t['split'] == 'fit']
        for index, log in enumerate(payload['fit_step_logs']):
            _require(type(log['step']) is int and log['step'] == index and
                     log['parameter_before_sha256'] == previous and
                     _is_digest(log['parameter_after_sha256']) and
                     _is_digest(log['gradient_sha256']), 'FREEZE_LOG_CHAIN')
            _require([t['task_id'] for t in log['tasks']] == fit_ids and
                     all(t['preupdate_sha256'] == previous and
                         _is_digest(t['score_sha256']) and _is_digest(t['maps_sha256'])
                         for t in log['tasks']), 'FREEZE_LOG_TASKS')
            previous = log['parameter_after_sha256']
        _require(previous == payload['final_parameter_sha256'], 'FREEZE_LOG_ENDPOINT')
        _require(set(payload['score_states']) == {t['case_id'] for t in config['tasks']},
                 'FREEZE_TASKS')
        for task in config['tasks']:
            states = payload['score_states'][task['case_id']]
            _require(set(states) == {'initial', 'final', 'uniform_PL', 'cost_prior_PL'},
                     'FREEZE_STATES')
            for scores in states.values():
                _validate_scores(scores, task)
            _require(states['uniform_PL'] == {u: 0. for u in task['uids']} and
                     states['cost_prior_PL'] ==
                     {u: -task['costs'][u]/max(task['costs'].values()) for u in task['uids']},
                     'FREEZE_BASELINES')
    _require(len({r['payload']['steps'] for r in records}) == 1, 'UNEQUAL_STEPS')
    for control_record, treatment_record in zip(records[::2], records[1::2]):
        control_payload, treatment_payload = control_record['payload'], treatment_record['payload']
        _require(control_payload['initial_parameter_sha256'] ==
                 treatment_payload['initial_parameter_sha256'], 'PAIRED_INITIAL_HASH')
        _require(all(control_payload['score_states'][t['case_id']]['initial'] ==
                     treatment_payload['score_states'][t['case_id']]['initial']
                     for t in config['tasks']), 'PAIRED_INITIAL_SCORES')
    original = _hash(records)
    arms = {arm: [] for arm in (CONTROL, TREATMENT)}
    for record in records:
        payload = record['payload']
        for task in config['tasks']:
            states = payload['score_states'][task['case_id']]
            metrics = {name: _metrics(task, scores) for name, scores in states.items()}
            arms[payload['arm']].append({'seed': payload['seed'], 'task_id': task['case_id'],
                'split': task['split'], 'metrics': metrics,
                'pass': _guard(metrics['initial'], metrics['final'])})
    paired = []
    for control, treatment in zip(arms[CONTROL], arms[TREATMENT]):
        _require((control['seed'], control['task_id']) ==
                 (treatment['seed'], treatment['task_id']), 'PAIR_JOIN')
        paired.append({'seed': control['seed'], 'task_id': control['task_id'],
                       'split': control['split'],
                       'pass': _guard(control['metrics']['final'], treatment['metrics']['final'])})
    _require(_hash(records) == original, 'FREEZE_MUTATED')
    return {'arms': {arm: {'rows': rows, 'summary': _summary(rows)} for arm, rows in arms.items()},
            'paired_rows': paired, 'paired_summary': _summary(paired)}


def _collect_for_test(session_factory, *, scope, steps=24):
    """Bounded mock-only seam. It is NOT a provenance detector or fit release."""
    _require(type(scope) is str and scope == SCOPE, 'MOCK_SCOPE_REQUIRED')
    _require(type(steps) is int and 1 <= steps <= 24, 'BOUNDED_STEPS')
    _require(callable(session_factory) and session_factory is not _TorchSession and
             getattr(session_factory, 'mock_only', None) is True,
             'MOCK_FACTORY_REQUIRED')
    config = protocol.validate(protocol.plan())
    config_hash = _hash(config)
    records, steps_done, restored, created = [], 0, [], 0
    result = {'scope': SCOPE, 'protocol': config, 'protocol_sha256': config_hash,
              'mock_steps': 0, 'records': records, 'freezes': records,
              'actual_torch_proof': False, 'fitting_executed': False,
              'synthetic_fitting_runs': 0, 'optimizer_steps': 0,
              'train_release': False, 'execution_released': False,
              'real_label_reads': 0, 'checkpoint_reads': 0, 'checkpoint_writes': 0,
              'remote_execution': False, 'retry_count': 0, 'protocol_completed': False}
    result.update(mock_window_completed=False, planned_mock_budget_completed=False)
    try:
        for seed in config['seeds']:
            paired_initial = None
            paired_scores = None
            for arm in (CONTROL, TREATMENT):
                session = None
                try:
                    session = session_factory(seed)
                    created += 1
                    initial_hash = _weight_hash(session)
                    _require(session.initial_hash == initial_hash, 'INITIAL_STATE_HASH')
                    if paired_initial is None:
                        paired_initial = initial_hash
                    _require(initial_hash == paired_initial, 'PAIRED_INITIAL_HASH')
                    initial = {t['case_id']: _scores(session, t) for t in config['tasks']}
                    if paired_scores is None:
                        paired_scores = copy.deepcopy(initial)
                    _require(initial == paired_scores, 'PAIRED_INITIAL_SCORES')
                    _require(_weight_hash(session) == initial_hash, 'INITIAL_FORWARD_MUTATION')
                    logs = []
                    for step in range(steps):
                        logs.append(_fit_step(session, [t for t in config['tasks'] if t['split'] == 'fit'], arm, step))
                        steps_done += 1
                    final_hash = _weight_hash(session)
                    states = {}
                    for task in config['tasks']:
                        states[task['case_id']] = {'initial': initial[task['case_id']],
                            'final': _scores(session, task),
                            'uniform_PL': {u: 0. for u in task['uids']},
                            'cost_prior_PL': {u: -task['costs'][u]/max(task['costs'].values())
                                              for u in task['uids']}}
                    _require(_weight_hash(session) == final_hash, 'FINAL_FORWARD_MUTATION')
                    payload = {'seed': seed, 'arm': arm, 'scope': SCOPE,
                               'protocol_sha256': config_hash, 'score_states': states,
                               'initial_parameter_sha256': initial_hash,
                               'final_parameter_sha256': final_hash, 'steps': steps,
                               'fit_step_logs': logs}
                    records.append({'payload': payload, 'freeze_sha256': _hash(payload)})
                finally:
                    if session is not None:
                        ok = session.restore()
                        _require(ok is True and _weight_hash(session) == session.initial_hash, 'RESTORE_FAILED')
                        restored.append(True)
                        session = None
        _require(_hash(config) == config_hash, 'PROTOCOL_MUTATED')
        result.update(_evaluate(records, config))
        result.update(status='PASS_MOCK_IMPLEMENTATION_ONLY', mock_window_completed=True,
                      planned_mock_budget_completed=steps == 24 and steps_done == 144,
                      all_snapshots_frozen_before_comparative_evaluation=True)
    except Exception as exc:
        result.update(status='FAIL_CLOSED', failure=str(exc), scientific_status='NOT_EVIDENCE')
    cleanup_ok = len(restored) == created and bool(restored)
    result.update(mock_steps=steps_done, all_parameters_restored=cleanup_ok,
                  restored_sessions=len(restored), final_weights_discarded=cleanup_ok)
    return result
