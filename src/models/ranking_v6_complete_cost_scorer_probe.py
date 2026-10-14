"""E17 injected-Torch synthetic chain proof only; NOT_TRAINER, NOFIT.

No Torch import, optimizer, accepted update, checkpoint, file or remote I/O.
The fixed singleton fixture tests derivatives, not capacity, generalization,
online cost, or joint objective improvement. Risk is exact miss probability
at three; cost is normalized full-six first-hit cost, NOT truncated cost.
"""
import hashlib
import json
import math

SCOPE = 'SYNTHETIC_COMPLETE_COST_SCORER_VJP_ONLY'
EPSILON = 1e-6
TOLERANCE = 1e-5
_FEATURES = (
    (0., 1., .2, -.4, .1, .8, -.2),
    (1., 0., -.3, .5, .7, -.1, .4),
    (0., 1., .9, -.2, .3, .4, -.6),
    (1., 0., -.7, .6, -.4, .2, .8),
    (0., 1., .4, .1, -.8, .9, .3),
    (1., 0., -.1, -.9, .6, -.5, .7),
)
_UIDS = ('synthetic_0', 'synthetic_1', 'synthetic_2',
         'synthetic_3', 'synthetic_4', 'synthetic_5')
_COSTS = (.5, 1., 2., 4., 7., 10.)


def _require(ok, code):
    if not ok:
        raise ValueError('COMPLETE_COST_SCORER_PROBE_' + code)


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode()).hexdigest()


def fixture():
    """Return fresh copies of the only permitted handwritten synthetic fixture."""
    return {'features': [list(row) for row in _FEATURES], 'uids': list(_UIDS),
            'positive_uids': [_UIDS[2]], 'costs': dict(zip(_UIDS, _COSTS)),
            'k': 3, 'seed': 11, 'synthetic_only': True}


def objective_maps(scores):
    """Recompute both nonlinear objectives and independent exact score maps."""
    from src.models.ranking_v6_first_hit_exact_gradient import enumerate_exact_gradient
    from src.models.ranking_v6_complete_first_hit_reference import evaluate
    fixed = fixture()
    _require(type(scores) is dict and set(scores) == set(fixed['uids']), 'SCORE_JOIN')
    risk = enumerate_exact_gradient(scores, fixed['positive_uids'], fixed['costs'], k=3)
    cost = evaluate(scores, fixed['positive_uids'], fixed['costs'], synthetic_only=True)
    return {'risk': risk['expected_miss_probability'],
            'cost': cost['normalized_complete_first_hit_cost'],
            'maps': {'risk': risk['miss_score_gradient'],
                     'cost': cost['normalized_cost_score_gradient']},
            'probability_mass': risk['probability_mass'],
            'cost_normalization_B': cost['cost_normalization_B']}


def _active_coordinate(gradient):
    _require(bool(gradient) and all(math.isfinite(v) for v in gradient), 'FINITE_GRADIENT')
    index = max(range(len(gradient)), key=lambda i: abs(gradient[i]))
    norm = math.sqrt(math.fsum(v * v for v in gradient))
    _require(math.isfinite(norm) and norm > 1e-12 and abs(gradient[index]) > 1e-12,
             'DEGENERATE_GRADIENT')
    return index, norm


def _score_proofs(scores, objectives):
    proofs = {}
    for phase in ('risk', 'cost'):
        values = [objectives['maps'][phase][uid] for uid in _UIDS]
        index, norm = _active_coordinate(values)
        uid = _UIDS[index]
        plus, minus = dict(scores), dict(scores)
        plus[uid] += EPSILON
        minus[uid] -= EPSILON
        difference = (objective_maps(plus)[phase] - objective_maps(minus)[phase]) / (2 * EPSILON)
        error = abs(values[index] - difference)
        _require(math.isfinite(error) and error <= TOLERANCE, 'SCORE_FINITE_DIFFERENCE')
        proofs[phase] = {'uid': uid, 'coordinate': index, 'gradient_norm': norm,
                         'analytic_coordinate': values[index], 'finite_difference': difference,
                         'absolute_error': error}
    return proofs


def _parameter_proofs(torch, model, matrix, vjp):
    proofs = {}
    for phase in ('risk', 'cost'):
        gradient = vjp[phase + '_parameter_gradient']
        index, norm = _active_coordinate(gradient)
        offset = index
        for parameter in model.parameters():
            if offset < parameter.numel():
                break
            offset -= parameter.numel()
        original = parameter.detach().clone()
        try:
            with torch.no_grad():
                parameter.reshape(-1)[offset].add_(EPSILON)
                plus = model(matrix).detach().tolist()
                parameter.copy_(original)
                parameter.reshape(-1)[offset].add_(-EPSILON)
                minus = model(matrix).detach().tolist()
            # Recompute full nonlinear objectives, not a frozen-map linear loss.
            difference = (objective_maps(dict(zip(_UIDS, plus)))[phase]
                          - objective_maps(dict(zip(_UIDS, minus)))[phase]) / (2 * EPSILON)
            error = abs(gradient[index] - difference)
            _require(math.isfinite(error) and error <= TOLERANCE, 'PARAMETER_FINITE_DIFFERENCE')
            proofs[phase] = {'coordinate': index, 'gradient_norm': norm,
                             'analytic_coordinate': gradient[index], 'finite_difference': difference,
                             'absolute_error': error, 'gradient_sha256': _digest(gradient)}
        finally:
            with torch.no_grad():
                parameter.copy_(original)
    return proofs


def verify(torch, scope=None):
    """Explicit authorized injected CPU float64 proof, with state restoration.

    Scope refusal precedes every Torch API. CPU RNG and thread count, all
    probe-created parameters, and deliberately preexisting sentinel grads are
    restored in finally even on failure. No model escapes this function.
    """
    _require(type(scope) is str and scope == SCOPE, 'SCOPE')
    from src.models.runtime_ranking_v3 import make_candidate_ranker
    from src.models.ranking_v6_scorer_vjp_bridge import (
        tensor_scores_to_parameter_gradients, SCOPE as BRIDGE_SCOPE)
    threads = torch.get_num_threads()
    _require(threads == 1, 'THREADS')
    rng = torch.get_rng_state().clone()
    parameters, snapshots, sentinel_snapshots = (), [], []
    report = None
    try:
        torch.set_num_threads(1)
        torch.manual_seed(11)
        model = make_candidate_ranker(torch).double().cpu()
        parameters = tuple(model.parameters())
        _require(sum(p.numel() for p in parameters) == 1345, 'FACTORY_COUNT')
        snapshots = [p.detach().clone() for p in parameters]
        for parameter in parameters:
            parameter.grad = torch.full_like(parameter, .125)
        sentinel_snapshots = [(p.grad, p.grad.detach().clone()) for p in parameters]
        fixed = fixture()
        matrix = torch.tensor(fixed['features'], dtype=torch.float64, device='cpu')

        def run():
            with torch.no_grad():
                raw = model(matrix).detach().tolist()
            scores = dict(zip(_UIDS, raw))  # Raw factory scores, no offset/shift.
            objectives = objective_maps(scores)
            vjp = tensor_scores_to_parameter_gradients(
                torch, model, fixed['features'], fixed['uids'], objectives['maps'], scope=BRIDGE_SCOPE)
            _require(vjp['risk_parameter_gradient'] != vjp['cost_parameter_gradient'],
                     'IDENTICAL_PHASE_GRADIENTS')
            return {'scores': scores, 'objectives': objectives, 'vjp': vjp,
                    'score_coordinate_proofs': _score_proofs(scores, objectives),
                    'parameter_coordinate_proofs': _parameter_proofs(torch, model, matrix, vjp)}

        first = run()
        second = run()
        _require(first == second, 'DETERMINISM')
        _require(all(torch.equal(p.detach(), original) for p, original in zip(parameters, snapshots)),
                 'WEIGHTS_CHANGED')
        _require(all(p.grad is original and torch.equal(original, values)
                     for p, (original, values) in zip(parameters, sentinel_snapshots)), 'GRADS_CHANGED')
        report = {'status': 'PASS_REAL_FACTORY_COMPLETE_COST_VJP_ONLY',
                  'scope': SCOPE, 'parameter_count': 1345, 'action_count': 6, 'feature_count': 7,
                  'seed': 11, 'cpu_threads_during_probe': 1, 'dtype': 'float64',
                  'risk_objective': 'exact_miss_probability_R_at_3',
                  'cost_objective': 'normalized_complete_first_hit_C_6',
                  'objectives': first['objectives'], 'raw_scores': first['scores'],
                  'score_sha256': first['vjp']['score_sha256'],
                  'weights_sha256': first['vjp']['weights_sha256'], 'fixture_sha256': _digest(fixed),
                  'source_bytes_sha256_owned_by_external_runner_manifest': True,
                  'score_coordinate_proofs': first['score_coordinate_proofs'],
                  'parameter_coordinate_proofs': first['parameter_coordinate_proofs'],
                  'finite_difference_epsilon': EPSILON, 'finite_difference_tolerance': TOLERANCE,
                  'full_nonlinear_objectives_recomputed': True, 'score_offset_applied': False,
                  'separate_phase_vjps': True, 'deterministic': True, 'weights_unchanged': True,
                  'existing_grad_unchanged': True, 'preexisting_grad_sentinel': .125,
                  'fitting_performed': False, 'accepted_update': False, 'optimizer_implemented': False,
                  'checkpoint_io': False, 'file_io': False, 'remote_io': False,
                  'capacity_claim': False, 'generalization_claim': False,
                  'joint_improvement_claim': False, 'online_cost_claim': False}
    finally:
        try:
            with torch.no_grad():
                for parameter, original in zip(parameters, snapshots):
                    parameter.copy_(original)
                for parameter, (original, values) in zip(parameters, sentinel_snapshots):
                    parameter.grad = original
                    original.copy_(values)
        finally:
            try:
                torch.set_rng_state(rng)
            finally:
                torch.set_num_threads(threads)
    _require(torch.equal(torch.get_rng_state(), rng), 'RNG_RESTORE')
    _require(torch.get_num_threads() == threads, 'THREAD_RESTORE')
    report['rng_preserved'] = True
    report['threads_preserved'] = True
    return report
