"""Pure, fail-closed consistency check for a caller-supplied cgroup-v2 snapshot.

``evaluate_snapshot(snapshot)`` accepts exactly a built-in dict with these keys:
platform ('linux'), cgroup_version (integer 2), memory_max_bytes (positive
integer), memory_swap_max_bytes (integer 0), memory_current_bytes (nonnegative
integer no greater than memory_max_bytes), memory_oom_group (integer 1),
pids_max (integer 1..64), cgroup_empty, scope_is_dedicated,
guard_installed_before_launch (all exactly bool True), and
expected_memory_limit_bytes (integer 1..512 MiB, equal to memory_max_bytes).
All integers exclude bool and are bounded by signed 64-bit maximum. String
'max' is never an accepted limit. Unknown keys and missing preconditions fail
with ValueError. Duplicate JSON keys must be rejected before making the dict.

This describes a proposed kernel-enforced cgroup memory.max design, not RSS
polling or RLIMIT_AS. It neither reads nor authenticates kernel/OS state, and
cannot prove that any guard was installed. Even an entirely forged but
consistent snapshot never releases actual jobs or training. The 512 MiB cap
is solely a fixed synthetic guard-design cap, NOT an ATPG memory budget.
No filesystem, process, network, or memory-allocation experiment is performed.
"""

MAX_INTEGER = 2**63 - 1
MAX_PIDS = 64
MAX_SYNTHETIC_GUARD_MEMORY_BYTES = 512 * 1024 * 1024
GUARD_DESIGN = 'cgroup_v2_memory.max_not_rss_polling_or_rlimit_as'
_FIELDS = frozenset((
    'platform', 'cgroup_version', 'memory_max_bytes', 'memory_swap_max_bytes',
    'memory_current_bytes', 'memory_oom_group', 'pids_max', 'cgroup_empty',
    'scope_is_dedicated', 'guard_installed_before_launch',
    'expected_memory_limit_bytes',
))


def _require(condition, code):
    if not condition:
        raise ValueError(code)


def _integer(value, minimum=0, maximum=MAX_INTEGER):
    _require(type(value) is int and minimum <= value <= maximum, 'INTEGER_BOUND')


def evaluate_snapshot(snapshot):
    """Return detached design evidence only; never authenticate or release work."""
    _require(type(snapshot) is dict and len(snapshot) == len(_FIELDS),
             'SNAPSHOT_SCHEMA')
    _require(set(snapshot) == _FIELDS, 'SNAPSHOT_SCHEMA')
    _require(type(snapshot['platform']) is str and snapshot['platform'] == 'linux',
             'LINUX_REQUIRED')
    _integer(snapshot['cgroup_version'], 2, 2)
    _integer(snapshot['memory_max_bytes'], 1)
    _integer(snapshot['memory_swap_max_bytes'], 0, 0)
    _integer(snapshot['memory_current_bytes'])
    _integer(snapshot['memory_oom_group'], 1, 1)
    _integer(snapshot['pids_max'], 1, MAX_PIDS)
    _integer(snapshot['expected_memory_limit_bytes'], 1,
             MAX_SYNTHETIC_GUARD_MEMORY_BYTES)
    _require(snapshot['memory_max_bytes'] == snapshot['expected_memory_limit_bytes'],
             'MEMORY_LIMIT_MISMATCH')
    _require(snapshot['memory_current_bytes'] <= snapshot['memory_max_bytes'],
             'CURRENT_EXCEEDS_LIMIT')
    for field in ('cgroup_empty', 'scope_is_dedicated',
                  'guard_installed_before_launch'):
        _require(type(snapshot[field]) is bool and snapshot[field] is True,
                 'PRELAUNCH_PRECONDITION')
    return {
        'snapshot_consistent': True,
        'os_state_authenticated': False,
        'synthetic_guard_design_only': True,
        'guard_design': GUARD_DESIGN,
        'synthetic_guard_memory_limit_bytes': snapshot['memory_max_bytes'],
        'max_synthetic_guard_memory_bytes': MAX_SYNTHETIC_GUARD_MEMORY_BYTES,
        'pids_max': snapshot['pids_max'],
        'actual_processes_executed': 0,
        'execution_ready': False,
        'training_release': False,
    }
