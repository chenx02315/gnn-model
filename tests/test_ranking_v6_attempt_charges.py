"""Generated canonical attempt accounting tests; no real logs or data I/O."""
import ast
import builtins
import copy
import math
from pathlib import Path
import random
import sys
import unittest
from unittest.mock import patch

from src.replay import ranking_v6_attempt_charges as accounting


def action(uid, *, status='SUCCESS', cycles=100, circuit='aes_core', feasible=None,
           scheme='HF', cohort='env.1'):
    if feasible is None: feasible = 1 if status == 'SUCCESS' else 0
    return dict(action_uid=uid, circuit=circuit, family=accounting.FAMILIES[circuit],
                role='TRAIN', execution_status=status, is_d95_feasible=feasible,
                action_scheme=scheme, measurement_sha256='b'*64, environment_cohort=cohort,
                total_cycles=cycles if status == 'SUCCESS' else None)


def attempt(uid, name=None, *, stage='H', retry=0, status='SUCCESS', wall=1., cohort='env.1'):
    return dict(attempt_id=name or uid+'.'+stage+'.'+str(retry), action_uid=uid,
                stage=stage, retry_order=retry, execution_status=status, wall_s=wall,
                environment_cohort=cohort, source_sha256='a'*64)


def aggregate(actions, attempts):
    # Most tests specify only the elapsed-bearing H attempts. Explicitly append
    # generated zero-elapsed terminal evidence for omitted required success stages.
    # Missing-stage rejection tests below call the public function DIRECTLY.
    if (type(actions) is not list or type(attempts) is not list
            or not 1 <= len(actions) <= accounting.MAX_ACTIONS
            or not 1 <= len(attempts) <= accounting.MAX_ATTEMPTS):
        return accounting.aggregate_charges(actions, attempts, implementation_only=True)
    complete = list(attempts)
    for row in actions:
        if row['execution_status'] == 'SUCCESS':
            present = {a['stage'] for a in complete if a['action_uid'] == row['action_uid']}
            for stage in row['action_scheme']:
                if stage not in present:
                    complete.append(attempt(row['action_uid'], stage=stage, wall=0.,
                                            cohort=row['environment_cohort']))
    return accounting.aggregate_charges(actions, complete, implementation_only=True)


def replay(records, ranking, k=10):
    return accounting.replay_prefix(records, ranking, k=k, implementation_only=True)


class AttemptChargesTests(unittest.TestCase):
    def failure_fixture(self):
        actions = [action('a', status='FAILED'), action('b', status='TIMEOUT'), action('c')]
        attempts = [attempt('a', retry=0, status='FAILED', wall=2.),
                    attempt('a', retry=1, status='SUCCESS', wall=3.),
                    attempt('b', status='TIMEOUT', wall=7.), attempt('c', wall=11.)]
        return actions, attempts

    def test_two_failed_actions_retry_then_hit_charges_every_attempt_first(self):
        actions, attempts = self.failure_fixture()
        result = aggregate(actions, attempts)
        self.assertEqual(result['total_policy_charged_runtime_s'], 23.)
        self.assertEqual(result['attempt_status_counts'], {'SUCCESS': 3, 'FAILED': 1, 'TIMEOUT': 1})
        self.assertEqual(result['action_status_counts'], {'SUCCESS': 1, 'FAILED': 1, 'TIMEOUT': 1})
        self.assertEqual(result['records']['a']['policy_charged_runtime_s'], 5.)
        self.assertEqual(result['records']['a']['execution_status'], 'FAILED')
        for source in actions:
            self.assertEqual({key: result['records'][source['action_uid']][key]
                              for key in accounting.ACTION_FIELDS}, source)
        row = replay(result['records'], ['a', 'b', 'c'])
        self.assertTrue(row['hit']); self.assertFalse(row['censored'])
        self.assertEqual(row['hit_rank'], 3); self.assertEqual(row['hit_action_uid'], 'c')
        self.assertEqual(row['charged_prefix_s'], 23.)
        self.assertEqual([r['cumulative_charged_runtime_s'] for r in row['visited']], [5., 12., 23.])
        self.assertEqual(row['visited_attempt_ids'], ['a.H.0', 'a.H.1', 'b.H.0', 'c.H.0', 'c.F.0'])
        self.assertEqual([r['epsilon_hit'] for r in row['visited']], [False, False, True])

    def test_all_failed_has_accounting_but_no_oracle(self):
        rows = [action('a', status='FAILED', feasible=1), action('b', status='TIMEOUT', feasible=1)]
        result = aggregate(rows, [attempt('a', status='SUCCESS'), attempt('b', status='TIMEOUT')])
        with self.assertRaisesRegex(ValueError, 'UNSUPPORTED_NO_SAFE_REFERENCE'):
            replay(result['records'], ['a', 'b'])

    def test_miss_charges_all_ten_and_cycles_do_not_define_runtime(self):
        actions = [action(f'a{i:02d}', cycles=200 if i < 10 else 100) for i in range(11)]
        attempts = [attempt(row['action_uid'], wall=float(i+1)) for i, row in enumerate(actions)]
        result = aggregate(actions, attempts)
        miss = replay(result['records'], [a['action_uid'] for a in actions])
        self.assertFalse(miss['hit']); self.assertTrue(miss['censored'])
        self.assertEqual(len(miss['visited']), 10)
        self.assertEqual(miss['charged_prefix_s'], 55.)
        self.assertEqual(miss['oracle_min_successful_cycles'], 100)
        hit = replay(result['records'], ['a10']+[f'a{i:02d}' for i in range(10)])
        self.assertEqual(hit['charged_prefix_s'], 11.)
        self.assertEqual(hit['hit_total_cycles'], 100)

    def test_epsilon_is_inclusive_exact_integer_arithmetic(self):
        base = 10**12
        result = aggregate([action('a', cycles=base), action('b', cycles=101*base//100),
                            action('c', cycles=101*base//100+1)],
                           [attempt('a'), attempt('b'), attempt('c')])
        row = replay(result['records'], ['c', 'b', 'a'])
        self.assertEqual(row['epsilon_action_uids'], ['a', 'b'])
        self.assertEqual(row['hit_rank'], 2)
        self.assertEqual(row['charged_prefix_s'], 2.)

    def test_zero_elapsed_attempt_allowed_but_zero_action_total_rejected(self):
        row = aggregate([action('a')], [attempt('a', retry=0, status='FAILED', wall=0),
                                       attempt('a', retry=1, wall=2.)])
        self.assertEqual(row['records']['a']['policy_charged_runtime_s'], 2.)
        for value in (0, 0., -0.):
            with self.assertRaisesRegex(ValueError, 'ACTION_TOTAL_RUNTIME_POSITIVE'):
                aggregate([action('a')], [attempt('a', wall=value)])

    def test_missing_elapsed_cpu_fallback_and_unknown_fields_rejected(self):
        for mode in ('missing', 'none', 'user_only', 'extra_cpu'):
            row = attempt('a')
            if mode == 'missing': del row['wall_s']
            elif mode == 'none': row['wall_s'] = None
            elif mode == 'user_only': del row['wall_s']; row['user_s'] = 1.
            else: row['cpu_s'] = 1.
            with self.assertRaises(ValueError): aggregate([action('a')], [row])

    def test_bad_elapsed_and_aggregate_overflow_rejected(self):
        class DerivedFloat(float): pass
        for value in (-1., float('nan'), float('inf'), True, '1.0', DerivedFloat(1.), 10**1000, 1e9+1):
            with self.subTest(value=repr(value)[:30]), self.assertRaises(ValueError):
                aggregate([action('a')], [attempt('a', wall=value)])
        with self.assertRaisesRegex(ValueError, 'ACTION_TOTAL_RUNTIME'):
            aggregate([action('a')], [attempt('a', retry=0, wall=6e8, status='FAILED'),
                                      attempt('a', retry=1, wall=6e8)])

    def test_ambiguous_action_or_orphan_join_rejected(self):
        for actions, attempts in [([action('a'), action('a')], [attempt('a')]),
                                  ([action('a')], [attempt('other')]),
                                  ([action('a'), action('b')], [attempt('a')])]:
            with self.assertRaises(ValueError): aggregate(actions, attempts)

    def test_shared_attempt_identity_and_duplicate_stage_retry_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SHARED_ATTEMPT'):
            aggregate([action('a'), action('b')], [attempt('a', 'shared'), attempt('b', 'shared')])
        with self.assertRaisesRegex(ValueError, 'SHARED_ATTEMPT'):
            aggregate([action('a')], [attempt('a'), attempt('a')])
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_STAGE_RETRY'):
            aggregate([action('a')], [attempt('a', 'one'), attempt('a', 'two')])

    def test_retry_gaps_and_noncanonical_orders_rejected(self):
        for retries in ([1], [0, 2], [0, 1, 3]):
            with self.assertRaisesRegex(ValueError, 'RETRY_ORDER_GAP'):
                aggregate([action('a')], [attempt('a', retry=i) for i in retries])
        for value in (True, -1, 1., '0', 65536):
            with self.assertRaises(ValueError): aggregate([action('a')], [attempt('a', retry=value)])
        result = aggregate([action('a')], [attempt('a', stage='F', retry=0, wall=1.),
                                          attempt('a', stage='H', retry=1, wall=2.),
                                          attempt('a', stage='H', retry=0, wall=3., status='FAILED')])
        self.assertEqual(result['records']['a']['attempt_ids'], ['a.H.0', 'a.H.1', 'a.F.0'])
        self.assertFalse(result['stage_completeness_verified'])

    def test_mixed_environment_within_action_is_not_pooled(self):
        with self.assertRaisesRegex(ValueError, 'ENVIRONMENTS_NOT_COMPARABLE'):
            aggregate([action('a')], [attempt('a', retry=0, cohort='env.1'),
                                      attempt('a', retry=1, cohort='env.2')])

    def test_six_train_family_map_partial_circuits_and_no_blind(self):
        actions = [action('a'), action('b', circuit='spi')]
        result = aggregate(actions, [attempt('a'), attempt('b')])
        self.assertEqual(result['action_count'], 2)
        with self.assertRaisesRegex(ValueError, 'ONE_CIRCUIT'):
            replay(result['records'], ['a', 'b'])
        for change in ({'role': 'BLIND'}, {'role': 'HELDOUT'}, {'circuit': 'unknown'},
                       {'family': 'iwls_spi'}, {'role': True}):
            with self.assertRaises(ValueError): aggregate([dict(action('a'), **change)], [attempt('a')])

    def test_action_terminal_outcome_rules_are_not_stage_inference(self):
        invalid = [dict(action('a'), total_cycles=None), dict(action('a'), total_cycles=0),
                   dict(action('a'), total_cycles=True), dict(action('a'), is_d95_feasible=0),
                   dict(action('a'), is_d95_feasible=True),
                   dict(action('a', status='FAILED'), total_cycles=100),
                   dict(action('a'), execution_status='PARTIAL'), dict(action('a'), extra=1)]
        for row in invalid:
            with self.assertRaises(ValueError): aggregate([row], [attempt('a')])
        # Every supplied stage is SUCCESS, but the explicit terminal action FAILED.
        actions = [action('failed', status='FAILED', feasible=1), action('hit')]
        result = aggregate(actions, [attempt('failed'), attempt('hit')])
        self.assertEqual(replay(result['records'], ['failed', 'hit'])['hit_rank'], 2)

    def test_attempt_stage_status_environment_and_hash_domains(self):
        invalid = [('stage', 'HM'), ('stage', None), ('execution_status', 'ERROR'),
                   ('environment_cohort', ''), ('environment_cohort', 'with space'),
                   ('environment_cohort', '环境'), ('source_sha256', 'A'*64),
                   ('source_sha256', 'a'*63), ('attempt_id', '../bad/uid')]
        for key, value in invalid:
            with self.assertRaises(ValueError): aggregate([action('a')], [dict(attempt('a'), **{key: value})])

    def test_measured_action_scheme_sha_cycles_and_stage_evidence(self):
        for change in ({'action_scheme': 'H'}, {'measurement_sha256': 'A'*64},
                       {'measurement_sha256': None}, {'total_cycles': 10**15+1}):
            with self.assertRaises(ValueError): aggregate([dict(action('a'), **change)], [attempt('a')])
        call = accounting.aggregate_charges
        for a, rows in [(action('a'), [attempt('a')]),
                        (action('a', scheme='HMF'), [attempt('a'), attempt('a', stage='F')]),
                        (action('a'), [attempt('a'), attempt('a', stage='M'), attempt('a', stage='F')]),
                        (action('a'), [attempt('a', status='FAILED'), attempt('a', stage='F')]),
                        (action('a'), [attempt('a'), attempt('a', stage='F', status='TIMEOUT')]),
                        (action('a', status='FAILED'), [attempt('a'), attempt('a', retry=1, status='FAILED')])]:
            with self.assertRaises(ValueError): call([a], rows, implementation_only=True)
        valid = call([action('a', scheme='HMF')],
                     [attempt('a', stage='H', wall=1.), attempt('a', stage='M', wall=0.),
                      attempt('a', stage='F', wall=2.)], implementation_only=True)
        self.assertEqual(valid['records']['a']['policy_charged_runtime_s'], 3.)
        self.assertTrue(valid['canonical_scheme_stage_constraints_checked'])
        self.assertTrue(valid['provenance_not_verified'])

    def test_attempt_matches_action_environment_and_replay_never_pools_cohorts(self):
        with self.assertRaisesRegex(ValueError, 'ACTION_ATTEMPT_ENVIRONMENT_JOIN'):
            accounting.aggregate_charges([action('a')],
                [attempt('a', cohort='other'), attempt('a', stage='F', cohort='other')],
                implementation_only=True)
        actions = [action('a'), action('b', cohort='env.2')]
        rows = [attempt('a'), attempt('b', cohort='env.2')]
        result = aggregate(actions, rows)
        self.assertEqual(result['environment_cohorts'], ['env.1', 'env.2'])
        self.assertFalse(result['cross_action_environment_comparability_verified'])
        with self.assertRaisesRegex(ValueError, 'REPLAY_ENVIRONMENTS_NOT_COMPARABLE'):
            replay(result['records'], ['a', 'b'])

    def test_opt_in_bounds_builtin_types_and_lazy_iterables(self):
        class DerivedList(list): pass
        class DerivedDict(dict): pass
        for value in (False, 1, None, 'true'):
            with self.assertRaises(ValueError): accounting.aggregate_charges([action('a')], [attempt('a')], implementation_only=value)
        for actions, attempts in [((), []), ([], []), (DerivedList([action('a')]), [attempt('a')]),
                                  ([DerivedDict(action('a'))], [attempt('a')]),
                                  ([action('a')], DerivedList([attempt('a')])),
                                  ([action('a')]*6145, [attempt('a')]),
                                  ([action('a')], [attempt('a')]*65537)]:
            with self.assertRaises(ValueError): aggregate(actions, attempts)
        class Trap:
            def __iter__(self): raise AssertionError('lazy source accessed')
            def __len__(self): raise AssertionError('lazy source accessed')
        with self.assertRaises(ValueError): aggregate(Trap(), Trap())

    def test_rankings_must_be_materialized_complete_unique_and_k_bounded(self):
        records = aggregate([action('a'), action('b')], [attempt('a'), attempt('b')])['records']
        for ranking in (('a', 'b'), ['a'], ['a', 'a'], ['a', 'x'], ['a', True]):
            with self.assertRaises(ValueError): replay(records, ranking)
        for k in (True, 0, 1, 9, 11, 10.0):
            with self.assertRaises(ValueError): replay(records, ['a', 'b'], k=k)
        with self.assertRaises(ValueError): accounting.replay_prefix(records, ['a', 'b'])

    def test_validate_unvisited_records_and_reject_tampered_derived_costs(self):
        records = aggregate([action('a'), action('b')], [attempt('a'), attempt('b')])['records']
        for key, value in [('policy_charged_runtime_s', 999.), ('attempt_count', True),
                           ('record_sha256', '0'*64), ('status_counts', {'SUCCESS': 1}),
                           ('attempt_ids', ['changed'])]:
            changed = copy.deepcopy(records); changed['b'][key] = value
            with self.assertRaises(ValueError): replay(changed, ['a', 'b'])
        changed = copy.deepcopy(records); changed['b']['attempt_rows'][0]['wall_s'] = None
        with self.assertRaises(ValueError): replay(changed, ['a', 'b'])

    def test_canonical_order_determinism_no_mutation_no_io_or_rng(self):
        actions, attempts = self.failure_fixture()
        before = copy.deepcopy((actions, attempts)); rng = random.getstate()
        modules = set(sys.modules)
        with patch.object(builtins, 'open', side_effect=AssertionError('file I/O')):
            result = aggregate(actions, attempts)
            repeated = aggregate(list(reversed(actions)), list(reversed(attempts)))
            ranking = ['a', 'b', 'c']; frozen = copy.deepcopy(result)
            row = replay(result['records'], ranking)
        self.assertEqual(result, repeated)
        self.assertEqual((actions, attempts), before)
        self.assertEqual(result, frozen); self.assertEqual(ranking, ['a', 'b', 'c'])
        self.assertEqual(random.getstate(), rng)
        self.assertEqual(set(sys.modules), modules)
        self.assertTrue(row['provenance_not_verified'])
        self.assertFalse(row['online_prefix_reuse_equivalence_claim'])
        self.assertFalse(row['real_training_release'])
        self.assertFalse(row['stage_completeness_verified'])
        self.assertFalse(row['hit_only_mean_reported'])

    def test_fsum_not_fastest_success_or_last_stage_elapsed(self):
        result = aggregate([action('a')], [attempt('a', retry=0, wall=1e8, status='FAILED'),
                                          attempt('a', retry=1, wall=1e-8, status='TIMEOUT'),
                                          attempt('a', retry=2, wall=1e-8, status='SUCCESS')])
        self.assertEqual(result['records']['a']['policy_charged_runtime_s'], math.fsum([1e8, 1e-8, 1e-8]))
        self.assertNotEqual(result['records']['a']['policy_charged_runtime_s'], 1e-8)

    def test_module_imports_only_stdlib_and_no_io_adapter(self):
        tree = ast.parse(Path(accounting.__file__).read_text(encoding='utf-8'))
        imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        self.assertEqual(imported, {'hashlib', 'json', 'math', 're'})
        self.assertFalse(any(isinstance(node, ast.ImportFrom) for node in ast.walk(tree)))


if __name__ == '__main__':
    unittest.main()
