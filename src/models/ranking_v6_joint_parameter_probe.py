"""Bounded E11 initialized-factory synthetic parameter proposal, not training.

No optimizer, checkpoint, data reader, retry or fallback. The existing VJP
factory is a seven-feature MLP: graph topology is fixed provenance, NOT an
input to this scorer. All eight pilot proposals precede any full PL oracle.
Temporary finite parameter changes are always restored (including RNG).
Torch is caller-injected only; importing this module needs only stdlib.
"""
import hashlib
import inspect
import json
import math
import sys

from . import ranking_v6_joint_score_update_reference as joint
from . import ranking_v6_scorer_vjp_bridge as bridge
from .runtime_ranking_v3 import FEATURES, make_candidate_ranker

SEED_NAMESPACE = 'v6-synthetic-joint-parameter-e11-v1'
SEEDS, FIXTURES = joint.SEEDS, joint.FIXTURES
N, K = 6, 3
BASELINE_SAMPLES, GRADIENT_SAMPLES = 32, 32


def _require(ok, code):
    if not ok:
        raise ValueError('JOINT_PARAMETER_PROBE_' + code)


def _hash(value):
    return joint._hash(value)


def _source_hash(function):
    return hashlib.sha256(inspect.getsource(function).encode('utf-8')).hexdigest()


def _inputs(case_id, values, charges):
    """Handwritten fixed synthetic features, no production preprocessing/data."""
    uids = [str(i) for i in range(N)]
    features = [[values[i] / 3., charges[i] / 10., i / 5., (5 - i) / 5.,
                 (-1.) ** i * .25, (i % 3) / 2., 1.] for i in range(N)]
    graph = {'nodes': uids, 'directed_edges': [[str(i), str((i + 1) % N)] for i in range(N)]}
    costs = dict(zip(uids, charges))
    return dict(case_id=case_id, uids=uids, features=features, graph=graph,
                costs=costs, positive_uids=['5'], feature_names=list(FEATURES),
                features_sha256=_hash(features), graph_sha256=_hash(graph),
                graph_consumed_by_model=False, fixture_template_scores=list(values))


def _select_parameter_candidate(risk, cost):
    _require(len(risk) == len(cost) and 0 < len(risk) <= 4096, 'GRADIENT_SHAPE')
    dr, dc, grid, selected = joint._select_candidate(risk, cost)
    # Retain the selected parameter direction only, never fifteen big vectors.
    compact = [{key: value for key, value in candidate.items() if key != 'direction'}
               for candidate in grid]
    return compact, selected, _hash(dr), _hash(dc)


class _TorchSession:
    def __init__(self, torch, inputs, initialization_seed):
        self.torch, self.inputs = torch, inputs
        torch.manual_seed(initialization_seed)
        self.model = make_candidate_ranker(torch).double().cpu().eval()
        self.parameters = tuple(self.model.parameters())
        self.snapshots = tuple(p.detach().clone() for p in self.parameters)
        self.gradients = tuple(p.grad for p in self.parameters)
        self.initial_flat = self.flat()
        self.initial_hash = self.weight_hash()
        self.layout = [{'name': name, 'shape': list(p.shape), 'dtype': str(p.dtype),
                        'device': str(p.device), 'numel': p.numel()}
                       for name, p in self.model.named_parameters()]
        _require(len(self.initial_flat) == 1345, 'FACTORY_PARAMETER_COUNT')

    def flat(self):
        return [v for p in self.parameters for v in p.detach().reshape(-1).tolist()]

    def weight_hash(self):
        # Exact same serialization as the existing VJP bridge weights hash.
        return bridge._digest([p.detach().reshape(-1).tolist() for p in self.parameters])

    def scores(self):
        with self.torch.no_grad():
            result = self.model(self.torch.tensor(self.inputs['features'],
                               dtype=self.torch.float64, device='cpu'))
        values = result.detach().tolist()
        _require(tuple(result.shape) == (N,) and all(math.isfinite(v) and abs(v) <= 20 for v in values),
                 'SCORE_DOMAIN')
        return dict(zip(self.inputs['uids'], values))

    def vjp(self, maps):
        return bridge.tensor_scores_to_parameter_gradients(
            self.torch, self.model, self.inputs['features'], self.inputs['uids'], maps, scope=bridge.SCOPE)

    def apply(self, selected):
        _require(len(selected['direction']) == len(self.initial_flat), 'UPDATE_SHAPE')
        values = [v + selected['step'] * d for v, d in zip(self.initial_flat, selected['direction'])]
        _require(all(math.isfinite(v) for v in values), 'UPDATE_FINITE')
        offset = 0
        with self.torch.no_grad():
            for parameter in self.parameters:
                count = parameter.numel()
                parameter.copy_(self.torch.tensor(values[offset:offset + count], dtype=self.torch.float64)
                                .reshape(parameter.shape))
                offset += count
        return self.weight_hash()

    def restore(self):
        with self.torch.no_grad():
            for p, snapshot in zip(self.parameters, self.snapshots):
                p.copy_(snapshot)
        _require(tuple(id(p) for p in self.model.parameters()) == tuple(id(p) for p in self.parameters),
                 'PARAMETER_IDENTITY')
        _require(all(self.torch.equal(p.detach(), s) for p, s in zip(self.parameters, self.snapshots)),
                 'RESTORE_TENSOR_EQUALITY')
        _require(all(p.grad is g for p, g in zip(self.parameters, self.gradients)), 'GRAD_RESTORE')
        _require(self.weight_hash() == self.initial_hash, 'RESTORE_HASH')
        return True


def _protocol(baseline_samples, gradient_samples):
    return dict(joint._protocol(baseline_samples, gradient_samples),
                seed_namespace=SEED_NAMESPACE, seed_case_id_prefix='e11-fixed-',
                pilot_seed_namespace=joint.control.SEED_NAMESPACE,
                proposal_space='model_parameters', model_factory='runtime_ranking_v3.make_candidate_ranker',
                parameter_max_coordinate_update=.2, model_output_score_absolute_bound=20.,
                graph_consumed_by_model=False, factory_initialization='sha256_case_seed_init_first8hex',
                source_sha256={name: _source_hash(function) for name, function in (
                    ('factory', make_candidate_ranker), ('vjp_module', bridge),
                    ('control_module', joint.control), ('selection', joint._select_candidate),
                    ('oracle_module', joint.full_oracle),
                    ('probe_module', sys.modules[__name__]))})


def _freeze(session, inputs, seed, baseline_samples, gradient_samples, protocol=None):
    scores = session.scores()
    joint._preflight(scores, inputs['costs'])
    case_pin = 'e11-fixed-' + inputs['case_id']
    pilot = joint.control.estimate(scores, {'5'}, inputs['costs'], k=K, seed=seed,
                                   case_id=case_pin, pilot_samples=baseline_samples,
                                   main_samples=gradient_samples)
    maps = {'risk': pilot['miss_score_gradient'], 'cost': pilot['normalized_cost_score_gradient']}
    vjp = session.vjp(maps)
    _require(vjp['weights_sha256'] == session.initial_hash and vjp['weights_unchanged'], 'VJP_WEIGHTS')
    grid, selected, risk_hash, cost_hash = _select_parameter_candidate(
        vjp['risk_parameter_gradient'], vjp['cost_parameter_gradient'])
    payload = dict(inputs, seed=seed, seed_case_id=case_pin,
                   protocol=protocol if protocol is not None else _protocol(baseline_samples, gradient_samples),
                   initialization_seed=int(_hash([SEED_NAMESPACE, inputs['case_id'], seed, 'init'])[:8], 16),
                   seed_namespace=SEED_NAMESPACE, baseline_samples=baseline_samples,
                   pilot_seed_namespace=pilot['seed_namespace'],
                   gradient_samples=gradient_samples, derived_seed_sha256=pilot['derived_seed_sha256'],
                   baseline_risk=pilot['baseline_risk'], baseline_static_cost=pilot['baseline_static_cost'],
                   baselines_frozen_before_gradient=True, baseline_derivative_taken=False,
                   pilot_score_gradient_sha256=_hash(maps), scores=scores,
                   base_score_state_sha256=_hash(scores), parameter_layout=session.layout,
                   parameter_count=vjp['parameter_count'], initial_parameter_sha256=session.initial_hash,
                   parameter_gradient_sha256={p: bridge._digest(vjp[p + '_parameter_gradient'])
                                             for p in ('risk', 'cost')},
                   risk_direction_sha256=risk_hash, normalized_cost_direction_sha256=cost_hash,
                   candidates=grid, selected_candidate=selected,
                   proposal_status='ONE_PROPOSAL' if selected else 'NO_PROPOSAL',
                   frozen_before_any_full_oracle=True, oracle_used_for_selection=False,
                   cost_normalization_B=K * max(inputs['costs'].values()))
    payload = json.loads(json.dumps(payload, allow_nan=False))
    return {'payload': payload, 'payload_sha256': _hash(payload)}


def _verify(session, record):
    payload = record['payload']
    summary = dict(pilot_freeze_payload=payload, pilot_freeze_sha256=record['payload_sha256'],
                   accepted=False, numerical_guard_failed=False, exact_oracle_calls=0,
                   fallback_attempted=False, proposed_scores=None, proposed_parameter_sha256=None,
                   committed_parameter_sha256=payload['initial_parameter_sha256'],
                   committed_risk_delta=0., committed_normalized_cost_delta=0.)
    try:
        _require(_hash(payload) == record['payload_sha256'], 'FREEZE_HASH')
        _require(session.weight_hash() == payload['initial_parameter_sha256'] and
                 session.scores() == payload['scores'], 'BASE_STATE')
        summary['exact_oracle_calls'] += 1
        base = joint.full_oracle.enumerate_exact_gradient(dict(payload['scores']), {'5'}, dict(payload['costs']), k=K)
        rb, cb = joint._oracle_values(base, payload['cost_normalization_B'])
        summary.update(risk_before=rb, normalized_cost_before=cb, oracle_probability_mass={'base': base['probability_mass']})
        summary.update(committed_risk_after=rb, committed_normalized_cost_after=cb)
        if payload['selected_candidate'] is not None:
            summary['proposed_parameter_sha256'] = session.apply(payload['selected_candidate'])
            proposed = session.scores()  # Actual updated model forward, never injected score delta.
            summary['proposed_scores'] = proposed
            summary['proposed_score_state_sha256'] = _hash(proposed)
            summary['exact_oracle_calls'] += 1
            after = joint.full_oracle.enumerate_exact_gradient(dict(proposed), {'5'}, dict(payload['costs']), k=K)
            ra, ca = joint._oracle_values(after, payload['cost_normalization_B'])
            rd, cd = ra - rb, ca - cb
            summary.update(proposed_risk_after=ra, proposed_normalized_cost_after=ca,
                           proposed_risk_delta=rd, proposed_normalized_cost_delta=cd)
            summary['oracle_probability_mass']['proposed'] = after['probability_mass']
            summary['accepted'] = rd <= joint.RISK_TOLERANCE and cd <= -joint.COST_DECREASE_MIN
            if summary['accepted']:
                summary.update(committed_parameter_sha256=summary['proposed_parameter_sha256'],
                               committed_risk_delta=rd, committed_normalized_cost_delta=cd,
                               committed_risk_after=ra, committed_normalized_cost_after=ca)
        _require(_hash(payload) == record['payload_sha256'], 'FREEZE_MUTATED')
    except (ValueError, ArithmeticError) as exc:
        summary.update(accepted=False, numerical_guard_failed=True, numerical_guard_error=str(exc),
                       committed_parameter_sha256=payload['initial_parameter_sha256'],
                       committed_risk_delta=0., committed_normalized_cost_delta=0.,
                       committed_risk_after=summary.get('risk_before'),
                       committed_normalized_cost_after=summary.get('normalized_cost_before'))
    finally:
        summary['parameters_restored_exactly'] = session.restore()
        summary['restored_parameter_sha256'] = session.weight_hash()
    return summary


def _run_fixed_fixtures(torch, *, baseline_samples=32, gradient_samples=32):
    for count in (baseline_samples, gradient_samples):
        _require(type(count) is int and 1 <= count <= 32, 'PILOT_SAMPLES')
    _require(torch.get_num_threads() == 1, 'CPU_THREADS')
    config = _protocol(baseline_samples, gradient_samples)
    rng = torch.get_rng_state().clone()
    sessions, records = [], []
    try:
        for case, values, charges in FIXTURES:
            inputs = _inputs(case, values, charges)
            for seed in SEEDS:
                init = int(_hash([SEED_NAMESPACE, case, seed, 'init'])[:8], 16)
                session = _TorchSession(torch, inputs, init)
                sessions.append(session)
                records.append(_freeze(session, inputs, seed, baseline_samples, gradient_samples, config))
        _require(len(records) == 8, 'FIXED_EIGHT_CASES')
        summaries = [_verify(session, record) for session, record in zip(sessions, records)]
        accepted = sum(s['accepted'] for s in summaries)
        failed = any(s['numerical_guard_failed'] for s in summaries)
        return dict(status='FAIL_NUMERICAL' if failed else 'PASS_FIXED_PARAMETER_JOINT_PROBES_ONLY'
                    if accepted == 8 else 'PARTIAL_SAFE_REJECTION' if accepted else 'NO_ACCEPTED_UPDATE',
                    config=config, config_sha256=_hash(config), per_case_seed=summaries,
                    accepted_count=accepted, rejected_count=8 - accepted,
                    proposal_count=sum(r['payload']['selected_candidate'] is not None for r in records),
                    numerical_guard_failures=sum(s['numerical_guard_failed'] for s in summaries),
                    exact_oracle_calls=sum(s['exact_oracle_calls'] for s in summaries),
                    total_work=config['nominal_pilot_work'],
                    actual_parameter_proposals=True, temporary_parameter_updates=True,
                    persistent_parameter_updates=False, train_release=False, fitting_performed=False,
                    trainer_implemented=False, optimizer_implemented=False, synthetic_only=True,
                    real_data_access=False, adaptive_sampling=False, trajectories_retained=False,
                    checkpoint_access=False, no_fallback=True, no_grid_expansion=True, retry_count=0,
                    all_parameters_restored=True, parameters_restored=True, oracle_used_for_selection=False,
                    optimizer_calls=0, training_runs=0, checkpoint_reads=0, real_label_reads=0,
                    all_committed_updates_safe=not failed and all(not s['accepted'] or (
                        s['committed_risk_delta'] <= joint.RISK_TOLERANCE and
                        s['committed_normalized_cost_delta'] <= -joint.COST_DECREASE_MIN) for s in summaries))
    finally:
        try:
            for session in sessions:
                session.restore()
        finally:
            torch.set_rng_state(rng)


def run_joint_parameter_probe(torch):
    """Injected formal entry, eight fixed 32+32 pilots; caller limits CPU/RAM."""
    return _run_fixed_fixtures(torch)
