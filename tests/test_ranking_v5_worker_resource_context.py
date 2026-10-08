import copy
import unittest
from unittest.mock import patch

from src.models import ranking_v5_worker_resource_context as context


def observations():
    return ['linux', context.INTERPRETER, dict(context.ENVIRONMENT),
            (8*1024**3, 8*1024**3), (0, 0), context.guard.policy()]


class ResourceContextTests(unittest.TestCase):
    def test_observations_do_not_prove_parent_monitoring(self):
        result = context.validate_observations(*observations())
        self.assertFalse(result['parent_sampled_rss_enforcement_proven'])
        self.assertFalse(result['authentic_user_consent_proven'])

    def test_wrong_platform_interpreter_environment_hard_caps_and_policy(self):
        cases = [(0, 'win32'), (1, 'python'), (3, (8*1024**3, -1)),
                 (3, (float(8*1024**3), 8*1024**3)), (4, (False, 0))]
        for index, value in cases:
            args = observations(); args[index] = value
            with self.assertRaises(ValueError): context.validate_observations(*args)
        for key, value in [('OMP_NUM_THREADS', '2'), ('CUDA_VISIBLE_DEVICES', '0'),
                           ('PYTHONPATH', ''), ('VIRTUAL_ENV', 'old')]:
            args = observations(); args[2][key] = value
            with self.assertRaisesRegex(ValueError, 'ENVIRONMENT'):
                context.validate_observations(*args)
        for key, value in [('combined_rss_cap_bytes', 2*1024**3), ('retries', True),
                           ('max_concurrent_workers', 2), ('poll_seconds', 1)]:
            args = observations(); args[5][key] = value
            with self.assertRaisesRegex(ValueError, 'GUARD_POLICY'):
                context.validate_observations(*args)

    def test_nonlinux_refuses_before_resource_or_environment_observation(self):
        with patch.object(context.sys, 'platform', 'win32'), \
             patch.object(context.guard, 'policy') as policy:
            with self.assertRaisesRegex(ValueError, 'LINUX_INTERPRETER'):
                context.check_current_process()
            policy.assert_not_called()


if __name__ == '__main__': unittest.main()
