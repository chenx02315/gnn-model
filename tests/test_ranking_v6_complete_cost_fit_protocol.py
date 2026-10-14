"""Pure local plan checks; no fitting, Torch, RNG or remote execution."""
import copy
import json
from pathlib import Path
import unittest
from src.models import ranking_v6_complete_cost_fit_protocol as protocol
from src.models import ranking_v6_synthetic_fit_no_prior as e14


class ProtocolTests(unittest.TestCase):
    def test_frozen_contract_matches_builder(self):
        path = Path(__file__).resolve().parents[1]/'contracts/ranking_v6_complete_cost_fit_protocol_v1.json'
        candidate = json.loads(path.read_text(encoding='utf-8'))
        self.assertEqual(protocol.validate(candidate), protocol.plan())

    def test_historical_tasks_and_per_model_budget_preserved(self):
        p = protocol.plan()
        self.assertEqual(p['tasks'], e14._tasks())
        self.assertEqual(p['seeds'], list(e14.SEEDS))
        self.assertEqual(p['optimizer']['steps_per_model'], e14.STEPS)
        self.assertEqual(p['optimizer']['learning_rate'], e14.LR)
        self.assertEqual(p['planned_total_optimizer_steps'], 2*3*24)
        self.assertEqual(p['evaluation']['rows_per_arm'], 3*4)
        self.assertEqual(sum(t['split']=='fit' for t in p['tasks']), 2)
        self.assertTrue(all(all(v == 0 for v in t['offsets'].values()) for t in p['tasks']))

    def test_normalization_keeps_raw_cost_coefficient(self):
        r = protocol.scalar_values(.4, 12., 21., 10.)
        self.assertAlmostEqual(r['treatment'], .5*.4 + .5*21/30)
        self.assertAlmostEqual(r['control'], .5*.4 + .5*12/30)
        # Keeping .5 on new B_N would silently halve the cost weight.
        self.assertNotEqual(r['treatment'], .5*.4 + .5*21/60)

    def test_no_single_step_or_fit_permission(self):
        p = protocol.plan()
        for key in ('fitting_executed', 'remote_execution_authorized', 'train_release', 'real_label_access'):
            self.assertIs(p[key], False)
        self.assertTrue(p['final_risk_guard_is_evaluation_not_update_acceptance'])
        self.assertTrue(p['evaluation']['means_cannot_override_failed_rows'])
        self.assertEqual(p['planned_resources']['models_live_at_once'], 1)

    def test_all_deviations_and_type_substitutions_rejected(self):
        for key, value in [('seeds',[11]), ('planned_total_optimizer_steps',72),
                           ('train_release',True), ('fitting_executed',0), ('n',6.0)]:
            p = protocol.plan(); p[key] = value
            with self.assertRaises(ValueError): protocol.validate(p)
        p = protocol.plan(); p['extra'] = 1
        with self.assertRaises(ValueError): protocol.validate(p)
        p = protocol.plan(); p['arms'][1]['normalized_cost_weight'] = .5
        with self.assertRaises(ValueError): protocol.validate(p)

    def test_plan_copies_and_finite_inputs(self):
        p = protocol.plan(); snapshot = copy.deepcopy(p)
        validated = protocol.validate(p); validated['seeds'].clear()
        self.assertEqual(p, snapshot)
        for values in ((True,1,2,3), (.2,1,2,0), (.2,4,2,3), (.2,float('nan'),2,3), (2,1,2,3), (.2,1,2,10**1000)):
            with self.assertRaises(ValueError): protocol.scalar_values(*values)


if __name__ == '__main__': unittest.main()
