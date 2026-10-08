"""Read-only child prerequisites, not proof of parent RSS monitoring or consent."""
import os
import sys

from src.models import ranking_v4_memory_guard as guard
from src.models import ranking_v5_execution_boundary as boundary

INTERPRETER = '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/venv/bin/python'
ENVIRONMENT = dict(OMP_NUM_THREADS='1', MKL_NUM_THREADS='1', OPENBLAS_NUM_THREADS='1',
                   NUMEXPR_NUM_THREADS='1', CUDA_VISIBLE_DEVICES='',
                   PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1')


def validate_observations(platform, interpreter, environment, address_limits, core_limits, policy):
    """Pure checks; observations supplied by tests do not establish Linux proof."""
    if platform != 'linux' or interpreter != INTERPRETER:
        raise ValueError('V5_CHILD_LINUX_INTERPRETER')
    if (not isinstance(environment, dict)
            or any(environment.get(key) != value for key, value in ENVIRONMENT.items())
            or 'PYTHONPATH' in environment or 'VIRTUAL_ENV' in environment):
        raise ValueError('V5_CHILD_ENVIRONMENT')
    if (type(address_limits) is not tuple or len(address_limits) != 2
            or any(type(value) is not int or value != boundary.WORKER_AS_LIMIT_BYTES
                   for value in address_limits)
            or type(core_limits) is not tuple or len(core_limits) != 2
            or any(type(value) is not int or value != 0 for value in core_limits)):
        raise ValueError('V5_CHILD_HARD_LIMITS')
    expected = dict(max_concurrent_workers=1, combined_rss_cap_bytes=1024**3,
                    child_address_space_cap_bytes=8*1024**3, reserve_min_bytes=4*1024**3,
                    reserve_fraction=.1, poll_seconds=.25, timeout_seconds=1800, retries=0,
                    limitation='RSS is sampled; brief overshoot can occur. RLIMIT_AS caps address space, not RSS.')
    if (not isinstance(policy, dict) or policy != expected
            or any(type(policy[key]) is not int for key in ('max_concurrent_workers',
                   'combined_rss_cap_bytes', 'child_address_space_cap_bytes', 'reserve_min_bytes',
                   'timeout_seconds', 'retries'))
            or any(type(policy[key]) is not float for key in ('reserve_fraction', 'poll_seconds'))):
        raise ValueError('V5_CHILD_GUARD_POLICY')
    return dict(status='PASS_CHILD_PREREQUISITES_ONLY', address_space_limits=list(address_limits),
                core_limits=list(core_limits), threads=1,
                parent_sampled_rss_enforcement_proven=False,
                authentic_user_consent_proven=False)


def check_current_process():
    """Reject unsupported process before imports/data/output; change no limits.

    RLIMIT_AS is checked in this child. A separate trusted launcher must still
    call guard.run_bounded and verify its final sampled combined-RSS receipt.
    Environment variables do not prove runtime Torch thread counts.
    """
    if sys.platform != 'linux' or sys.executable != INTERPRETER:
        raise ValueError('V5_CHILD_LINUX_INTERPRETER')
    import resource
    return validate_observations(sys.platform, sys.executable, dict(os.environ),
                                 resource.getrlimit(resource.RLIMIT_AS),
                                 resource.getrlimit(resource.RLIMIT_CORE), guard.policy())
