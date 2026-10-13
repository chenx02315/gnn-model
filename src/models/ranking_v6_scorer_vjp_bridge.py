"""Injected CPU float64 synthetic scorer VJP only; no torch import or fitting."""
import hashlib
import json
import math

SCOPE = 'SYNTHETIC_SCORER_VJP_ONLY'


def _require(ok, code):
    if not ok:
        raise ValueError('SCORER_VJP_' + code)


def _digest(values):
    return hashlib.sha256(json.dumps(values, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def _active_coordinate(gradient):
    _require(bool(gradient) and all(math.isfinite(v) for v in gradient), 'ACTIVE_GRADIENT')
    norm = math.sqrt(math.fsum(v * v for v in gradient))
    index = max(range(len(gradient)), key=lambda i: abs(gradient[i]))
    _require(math.isfinite(norm) and norm > 1e-12 and abs(gradient[index]) > 1e-12, 'DEGENERATE_GRADIENT')
    return index, norm


def _number(value, limit):
    _require(type(value) in (int, float), 'NUMERIC_TYPE')
    try:
        _require(math.isfinite(value) and abs(value) <= limit, 'NUMERIC_BOUND')
    except OverflowError as exc:
        raise ValueError('SCORER_VJP_NUMERIC_BOUND') from exc


def _inputs(features, uids, gradient_maps):
    _require(type(uids) is list and 1 <= len(uids) <= 1024
             and all(type(u) is str and 1 <= len(u) <= 128 and u.isascii()
                     and all(32 <= ord(c) < 127 for c in u) for u in uids), 'UIDS')
    _require(uids == sorted(set(uids)), 'SORTED_UNIQUE_UIDS')
    _require(type(features) is list and len(features) == len(uids), 'FEATURE_JOIN')
    for row in features:
        _require(type(row) is list and len(row) == 7, 'FEATURE_SHAPE')
        for value in row:
            _number(value, 2)
    _require(type(gradient_maps) is dict and set(gradient_maps) == {'risk', 'cost'}, 'GRADIENT_SCHEMA')
    for mapping in gradient_maps.values():
        _require(type(mapping) is dict and set(mapping) == set(uids), 'GRADIENT_JOIN')
        for value in mapping.values():
            _number(value, 20)


def tensor_scores_to_parameter_gradients(torch, model, features, uids, gradient_maps, *, scope=None):
    """Two separate autograd.grad VJPs; no .grad accumulation or parameter writes.

    The scope gate and all plain-Python input checks precede every torch/model
    API. Caller supplies the existing factory model already CPU float64.
    Returned tuples/digests contain no tensor or retained autograd graph.
    """
    _require(type(scope) is str and scope == SCOPE, 'SCOPE')
    _inputs(features, uids, gradient_maps)
    parameters = tuple(model.parameters())
    _require(parameters and sum(p.numel() for p in parameters) <= 4096, 'PARAMETER_COUNT')
    for parameter in parameters:
        _require(1 <= parameter.ndim <= 2 and parameter.numel() > 0
                 and parameter.device.type == 'cpu' and parameter.dtype == torch.float64
                 and parameter.requires_grad and bool(torch.isfinite(parameter).all().item()), 'PARAMETER')
    snapshots = [p.detach().clone() for p in parameters]
    existing_gradients = [(p.grad, None if p.grad is None else p.grad.detach().clone()) for p in parameters]
    matrix = torch.tensor(features, dtype=torch.float64, device='cpu')
    scores = model(matrix)
    _require(tuple(scores.shape) == (len(uids),) and scores.device.type == 'cpu'
             and scores.dtype == torch.float64 and bool(torch.isfinite(scores).all().item())
             and bool((scores.detach().abs() <= 20).all().item()), 'SCORES')
    gradients = {}
    for phase in ('risk', 'cost'):
        vector = torch.tensor([gradient_maps[phase][u] for u in uids], dtype=torch.float64, device='cpu')
        tensors = torch.autograd.grad(scores, parameters, grad_outputs=vector, retain_graph=phase == 'risk')
        _require(len(tensors) == len(parameters)
                 and all(g.shape == p.shape and g.dtype == torch.float64 and g.device.type == 'cpu'
                         and bool(torch.isfinite(g).all().item()) for g, p in zip(tensors, parameters)), 'VJP')
        gradients[phase] = tuple(v for tensor in tensors for v in tensor.detach().reshape(-1).tolist())
    _require(tuple(id(p) for p in model.parameters()) == tuple(id(p) for p in parameters), 'PARAMETER_IDENTITY')
    _require(all(torch.equal(p.detach(), snapshot) for p, snapshot in zip(parameters, snapshots)), 'WEIGHTS_CHANGED')
    _require(all(p.grad is original and (original is None or torch.equal(original, snapshot))
                 for p, (original, snapshot) in zip(parameters, existing_gradients)), 'GRAD_CHANGED')
    return {'status': SCOPE, 'risk_parameter_gradient': gradients['risk'],
            'cost_parameter_gradient': gradients['cost'], 'parameter_count': sum(p.numel() for p in parameters),
            'score_sha256': _digest(scores.detach().tolist()),
            'weights_sha256': _digest([p.detach().reshape(-1).tolist() for p in parameters]),
            'weights_unchanged': True, 'existing_grad_unchanged': True,
            'optimizer_implemented': False, 'fitting_performed': False, 'graph_retained': False}


def verify_synthetic_scorer(torch):
    """Caller-authorized real torch proof only; fixed seed restored afterwards.

    Reuses only the frozen seven-feature factory. No checkpoint/data/fit entry.
    Caller must set CPU threads to one. Temporary finite-difference parameter
    perturbations are restored in finally; no chosen/applicable update exists.
    """
    _require(torch.get_num_threads() == 1, 'THREADS')
    rng_state = torch.get_rng_state().clone()
    from src.models.runtime_ranking_v3 import make_candidate_ranker
    try:
        torch.manual_seed(11)
        model = make_candidate_ranker(torch).double().cpu()
        features = [[-.2 + .4 * (row * 7 + column) / 27 for column in range(7)] for row in range(4)]
        uids = ['synthetic_0', 'synthetic_1', 'synthetic_2', 'synthetic_3']
        maps = {'risk': dict(zip(uids, [.1, -.2, .05, .05])),
                'cost': dict(zip(uids, [-.3, .1, .1, .1]))}
        # Deliberately nonempty existing grads: autograd.grad must preserve them.
        for parameter in model.parameters():
            parameter.grad = torch.full_like(parameter, .125)
        result = tensor_scores_to_parameter_gradients(torch, model, features, uids, maps, scope=SCOPE)
        _require(result['parameter_count'] == 1345, 'FACTORY_COUNT')
        repeated = tensor_scores_to_parameter_gradients(torch, model, features, uids, maps, scope=SCOPE)
        _require(result == repeated, 'DETERMINISM')
        matrix = torch.tensor(features, dtype=torch.float64)
        def prove_active_coordinates(vjp, objective):
            proofs = {}
            _require(vjp['risk_parameter_gradient'] != vjp['cost_parameter_gradient'], 'IDENTICAL_PHASE_GRADIENTS')
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
                        parameter.reshape(-1)[offset].add_(1e-6)
                        plus = model(matrix).detach().tolist()
                        parameter.copy_(original)
                        parameter.reshape(-1)[offset].add_(-1e-6)
                        minus = model(matrix).detach().tolist()
                    difference = (objective(phase, plus) - objective(phase, minus)) / 2e-6
                    error = abs(gradient[index] - difference)
                    _require(math.isfinite(error) and error <= 1e-5, 'FINITE_DIFFERENCE')
                    proofs[phase] = {'coordinate': index, 'gradient_norm': norm,
                                     'analytic_coordinate': gradient[index], 'finite_difference': difference,
                                     'absolute_error': error, 'gradient_sha256': _digest(gradient)}
                finally:
                    with torch.no_grad():
                        parameter.copy_(original)
            return proofs
        direct_proofs = prove_active_coordinates(
            result, lambda phase, values: math.fsum(s * maps[phase][u] for s, u in zip(values, uids)))
        from src.models.ranking_v6_first_hit_exact_gradient import enumerate_exact_gradient
        synthetic_costs = dict(zip(uids, [10., 7., 2., 4.]))
        positive_uids = {uids[2]}
        with torch.no_grad():
            current_scores = dict(zip(uids, model(matrix).detach().tolist()))
        oracle = enumerate_exact_gradient(current_scores, positive_uids, synthetic_costs, k=2)
        chain_maps = {'risk': oracle['miss_score_gradient'], 'cost': oracle['cost_score_gradient']}
        chain_vjp = tensor_scores_to_parameter_gradients(torch, model, features, uids, chain_maps, scope=SCOPE)
        def full_objective(phase, values):
            evaluated = enumerate_exact_gradient(dict(zip(uids, values)), positive_uids, synthetic_costs, k=2)
            return evaluated['expected_miss_probability' if phase == 'risk' else 'expected_truncated_static_cost']
        chain_proofs = prove_active_coordinates(chain_vjp, full_objective)
        final = tensor_scores_to_parameter_gradients(torch, model, features, uids, maps, scope=SCOPE)
        _require(final == result, 'RESTORE')
        return {'status': 'PASS_REAL_FACTORY_SYNTHETIC_VJP_ONLY', 'parameter_count': 1345,
                'score_sha256': result['score_sha256'], 'weights_sha256': result['weights_sha256'],
                'directional_finite_difference_errors': {p: v['absolute_error'] for p, v in direct_proofs.items()},
                'active_coordinate_proofs': direct_proofs,
                'objective_chain_errors': {p: v['absolute_error'] for p, v in chain_proofs.items()},
                'objective_chain_norms': {p: v['gradient_norm'] for p, v in chain_proofs.items()},
                'objective_chain_coordinate_proofs': chain_proofs,
                'oracle_inputs_sha256': _digest({'scores': current_scores, 'positives': sorted(positive_uids),
                                                'costs': synthetic_costs, 'k': 2}),
                'oracle_output_sha256': _digest(oracle), 'oracle_probability_mass': oracle['probability_mass'],
                'weights_unchanged': True,
                'existing_grad_unchanged': True, 'deterministic': True, 'fitting_performed': False}
    finally:
        torch.set_rng_state(rng_state)
