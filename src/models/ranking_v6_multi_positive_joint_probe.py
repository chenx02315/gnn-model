"""E29 injected-Torch generated multi-positive derivative proof, NOT_TRAINER.

The MC vector is drawn ONCE at theta0 and frozen for linear-surrogate FD.
The distinct exact-small proof recomputes the nonlinear expected objective.
No optimizer, accepted update, checkpoint, data reader or I/O is implemented.
"""
import hashlib
import json
import math

SCOPE = 'SYNTHETIC_MULTI_POSITIVE_JOINT_VJP_ONLY'
EPSILON = 1e-6
ATOL = 1e-8
RTOL = 1e-5
RISK_WEIGHT = .5
COST_WEIGHT = 1.
PHASES = ('risk', 'cost', 'joint')


def _require(ok, code):
    if not ok:
        raise ValueError('MULTI_JOINT_PROBE_' + code)


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode()).hexdigest()


def _combine(vjp):
    risk, cost = vjp['risk_parameter_gradient'], vjp['cost_parameter_gradient']
    _require(len(risk) == len(cost) == 1345, 'PARAMETER_JOIN')
    joint = tuple(math.fsum((RISK_WEIGHT*r, COST_WEIGHT*c)) for r, c in zip(risk, cost))
    _require(all(math.isfinite(v) for values in (risk, cost, joint) for v in values), 'FINITE_VJP')
    return {'risk': list(risk), 'cost': list(cost), 'joint': list(joint)}


def _select(gradient):
    _require(bool(gradient) and all(math.isfinite(v) for v in gradient), 'FINITE_GRADIENT')
    index = max(range(len(gradient)), key=lambda i: abs(gradient[i]))
    norm = math.sqrt(math.fsum(v*v for v in gradient))
    _require(norm > 1e-12 and abs(gradient[index]) > 10*ATOL, 'DEGENERATE_GRADIENT')
    return index, norm


def _check(analytic, numerical):
    error = abs(analytic-numerical)
    tolerance = ATOL + RTOL*max(abs(analytic), abs(numerical))
    _require(math.isfinite(error) and error <= tolerance, 'FINITE_DIFFERENCE')
    return {'analytic': analytic, 'finite_difference': numerical,
            'absolute_error': error, 'allowed_error': tolerance, 'pass': True}


def verify(torch, scope=None):
    """One generated-model session; temporary perturbations always restored.

    One MC caller invocation, not one per FD. Two separated proof layers and
    their original component maps are retained; neither is a fitting step.
    """
    _require(type(scope) is str and scope == SCOPE, 'SCOPE')
    _require(torch.get_num_threads() == 1, 'THREADS')
    from src.models.runtime_ranking_v3 import make_candidate_ranker
    from src.models import ranking_v6_multi_positive_joint_caller as caller
    from src.models.ranking_v6_synthetic_real_bridge_adapter import prepare_fit_fixture
    from src.models import ranking_v6_synthetic_joint_freeze as held_gate
    from src.models.ranking_v6_scorer_vjp_bridge import (
        tensor_scores_to_parameter_gradients, SCOPE as BRIDGE_SCOPE)
    rng = torch.get_rng_state().clone()
    threads = torch.get_num_threads()
    parameters, snapshots, sentinels = (), [], []
    report = None
    try:
        feature_rows, outcome_rows = caller.generated_fixture()
        task = prepare_fit_fixture(feature_rows, outcome_rows, synthetic_only=True)['tasks'][0]
        uids = list(task['action_uids'])
        features = [list(row) for row in task['features']]
        _require(uids == [f'u{i:03d}' for i in range(6)] and
                 task['positive_uids'] == ('u000', 'u001'), 'FIXTURE')
        torch.manual_seed(11)
        model = make_candidate_ranker(torch).double().cpu()
        parameters = tuple(model.parameters())
        _require(sum(p.numel() for p in parameters) == 1345, 'FACTORY_COUNT')
        snapshots = [p.detach().clone() for p in parameters]
        for p in parameters:
            p.grad = torch.full_like(p, .125)
        sentinels = [(p.grad, p.grad.detach().clone()) for p in parameters]
        matrix = torch.tensor(features, dtype=torch.float64, device='cpu')

        def read_scores():
            with torch.no_grad():
                direct = model(matrix)
                value, masks = matrix, []
                for layer in model.layers:
                    value = layer(value)
                    if isinstance(layer, torch.nn.ReLU):
                        masks.append((value > 0).reshape(-1).tolist())
                _require(torch.equal(direct, value.squeeze(1)), 'FACTORY_FORWARD_MATCH')
                values = direct.detach().tolist()
            _require(all(math.isfinite(v) and abs(v) <= 20 for v in values), 'SCORE_BOUND')
            return dict(zip(uids, values)), masks

        scores, original_masks = read_scores()
        # Mirrored generated features exercise the release boundary, NOT an
        # independent held-out population or a fitted-model generalization test.
        held_features = [dict(row, role='HELDOUT') for row in feature_rows]
        normalizer_bytes = held_gate.identity_normalizer_bytes()
        model_sha = _digest([s.reshape(-1).tolist() for s in snapshots])
        frozen = held_gate.freeze_snapshot(held_features, scores,
                                          normalizer_bytes=normalizer_bytes,
                                          model_sha256=model_sha, synthetic_only=True)
        held_calls = [0]

        def held_loader():
            held_calls[0] += 1
            return outcome_rows

        try:
            held_gate.release_outcomes(frozen, frozen+b'!', held_features, scores,
                                       normalizer_bytes=normalizer_bytes, model_sha256=model_sha,
                                       outcome_loader=held_loader, synthetic_only=True)
        except ValueError:
            pass
        else:
            raise ValueError('MULTI_JOINT_PROBE_HELD_CORRUPTION_NOT_REJECTED')
        _require(held_calls[0] == 0, 'HELD_EARLY_READ')
        held_proof = held_gate.release_outcomes(
            frozen, frozen, held_features, scores, normalizer_bytes=normalizer_bytes,
            model_sha256=model_sha, outcome_loader=held_loader, synthetic_only=True)
        _require(held_calls[0] == 1, 'HELD_LOADER_COUNT')
        common = dict(k=3, risk_weight=RISK_WEIGHT,
                      normalized_cost_weight=COST_WEIGHT, synthetic_only=True)
        # The only stochastic objective call in the entire formal session.
        mc = caller.evaluate_control(feature_rows, outcome_rows, scores, seed=11,
                                     pilot_samples=32, samples=480, **common)
        exact = caller.evaluate_exact_reference(feature_rows, outcome_rows, scores, **common)
        _require(mc['cost_normalization_B'] == exact['cost_normalization_B'] == 60., 'FIXED_B')
        _require(mc['risk_component']['nominal_work'] == 9216, 'MC_WORK')
        frozen_maps = {phase: dict(mc['gradient_maps'][phase]) for phase in ('risk', 'cost')}
        frozen_maps['joint'] = dict(mc['joint_score_gradient'])
        frozen_map_sha = _digest(frozen_maps)
        vector_layers = {}
        for name, objective in (('frozen_mc_surrogate', mc), ('exact_nonlinear', exact)):
            vjp = tensor_scores_to_parameter_gradients(
                torch, model, features, uids, objective['gradient_maps'], scope=BRIDGE_SCOPE)
            _require(vjp['score_sha256'] == objective['score_snapshot_sha256'], 'SCORE_SNAPSHOT')
            repeated = tensor_scores_to_parameter_gradients(
                torch, model, features, uids, objective['gradient_maps'], scope=BRIDGE_SCOPE)
            _require(vjp == repeated, 'DETERMINISTIC_VJP')
            vector_layers[name] = _combine(vjp)

        direction = [(-1. if i % 2 else 1.) / math.sqrt(1345) for i in range(1345)]

        def perturb(displacement):
            offset = 0
            try:
                with torch.no_grad():
                    for p, base in zip(parameters, snapshots):
                        segment = torch.tensor(displacement[offset:offset+p.numel()],
                                               dtype=torch.float64).reshape(p.shape)
                        p.copy_(base + segment)
                        offset += p.numel()
                perturbed, masks = read_scores()
                _require(masks == original_masks, 'RELU_MASK_CHANGED')
                return perturbed
            finally:
                with torch.no_grad():
                    for p, base in zip(parameters, snapshots):
                        p.copy_(base)

        def objective_values(name, values):
            if name == 'frozen_mc_surrogate':
                return {phase: math.fsum(frozen_maps[phase][u]*values[u] for u in uids)
                        for phase in PHASES}
            reference = caller.evaluate_exact_reference(feature_rows, outcome_rows, values, **common)
            _require(reference['cost_normalization_B'] == 60., 'FD_FIXED_B')
            return {'risk': reference['risk_component']['expected_miss_probability'],
                    'cost': reference['cost_component']['normalized_complete_first_hit_cost'],
                    'joint': reference['joint_scalar']}

        proofs = {}
        for name, gradients in vector_layers.items():
            directional_plus = objective_values(name, perturb([EPSILON*v for v in direction]))
            directional_minus = objective_values(name, perturb([-EPSILON*v for v in direction]))
            rows = {}
            for phase in PHASES:
                gradient = gradients[phase]
                index, norm = _select(gradient)
                displacement = [0.]*1345
                displacement[index] = EPSILON
                plus = objective_values(name, perturb(displacement))[phase]
                displacement[index] = -EPSILON
                minus = objective_values(name, perturb(displacement))[phase]
                coordinate = _check(gradient[index], (plus-minus)/(2*EPSILON))
                coordinate.update(coordinate=index, gradient_norm=norm)
                directional = _check(math.fsum(g*d for g, d in zip(gradient, direction)),
                                     (directional_plus[phase]-directional_minus[phase])/(2*EPSILON))
                rows[phase] = {'active_coordinate': coordinate, 'fixed_direction': directional,
                               'gradient_sha256': _digest(gradient)}
            proofs[name] = rows
        _require(_digest(frozen_maps) == frozen_map_sha, 'FROZEN_MAP_CHANGED')
        final_scores, final_masks = read_scores()
        _require(final_scores == scores and final_masks == original_masks, 'SCORE_RESTORE')
        _require(all(torch.equal(p.detach(), s) for p, s in zip(parameters, snapshots)), 'WEIGHTS_CHANGED')
        _require(all(p.grad is original and torch.equal(original, s)
                     for p, (original, s) in zip(parameters, sentinels)), 'GRADS_CHANGED')
        report = {
            'status': 'PASS_REAL_FACTORY_MULTI_POSITIVE_JOINT_VJP_ONLY', 'scope': SCOPE,
            'action_count': 6, 'positive_count': 2, 'k': 3, 'seed': 11,
            'parameter_count': 1345, 'cpu_threads_during_probe': 1, 'dtype': 'float64',
            'features': features, 'uids': uids, 'feature_rows': feature_rows,
            'outcome_rows': outcome_rows, 'raw_scores': scores,
            'mc_objective': mc, 'exact_objective': exact,
            'synthetic_held_freeze_proof': held_proof,
            'held_corrupt_readback_loader_calls': 0,
            'held_fixture_mirrors_fit_features_not_independent_population': True,
            'parameter_gradients': vector_layers, 'proofs': proofs,
            'initial_parameter_shapes': [list(p.shape) for p in parameters],
            'initial_parameter_values': [s.reshape(-1).tolist() for s in snapshots],
            'weights_sha256': _digest([s.reshape(-1).tolist() for s in snapshots]),
            'score_sha256': mc['score_snapshot_sha256'], 'frozen_score_maps_sha256': frozen_map_sha,
            'fixture_sha256': _digest([feature_rows, outcome_rows]),
            'finite_difference_epsilon': EPSILON, 'absolute_tolerance': ATOL, 'relative_tolerance': RTOL,
            'active_coordinate_min_absolute_derivative': 10*ATOL,
            'mc_estimator_calls': 1, 'mc_nominal_work': 9216,
            'full_nonlinear_exact_objectives_recomputed': True,
            'mc_finite_difference_is_frozen_linear_surrogate_only': True,
            'separate_phase_vjps': True, 'deterministic_vjp': True, 'relu_masks_unchanged': True,
            'weights_unchanged': True, 'existing_grad_unchanged': True,
            'fitting_performed': False, 'accepted_update': False, 'optimizer_implemented': False,
            'optimizer_calls': 0, 'training_runs': 0, 'checkpoint_reads': 0, 'real_label_reads': 0,
            'blind_access': False, 'lsf_tessent_calls': 0,
            'online_cost_claim': False, 'capacity_claim': False, 'generalization_claim': False,
            'real_training_release': False}
    finally:
        try:
            with torch.no_grad():
                for p, original in zip(parameters, snapshots):
                    p.copy_(original)
                for p, (original, values) in zip(parameters, sentinels):
                    p.grad = original
                    original.copy_(values)
        finally:
            try:
                torch.set_rng_state(rng)
            finally:
                torch.set_num_threads(threads)
    _require(torch.equal(torch.get_rng_state(), rng), 'RNG_RESTORE')
    _require(torch.get_num_threads() == threads, 'THREAD_RESTORE')
    report.update(rng_preserved=True, threads_preserved=True)
    return report
