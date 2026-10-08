"""Pure final parent-receipt checks; not execution, consent, or release proof.

The caller must independently reread the guard's JSON receipt. This module
cannot establish the provenance of either supplied object and performs no I/O.
"""
import math

from src.models import ranking_v4_memory_guard as guard


_REQUIRED = frozenset(('status', 'memory_policy', 'initial_available_bytes',
                       'effective_total_bytes', 'reserve_bytes', 'sample_count',
                       'peak_group_rss_bytes', 'peak_combined_rss_bytes',
                       'exit_code', 'process_group', 'elapsed_seconds'))
_BOUNDARY = frozenset(('rss_exit_boundary', 'rss_exit_boundary_resolution'))
_BOUNDARY_FIELDS = frozenset(('unreadable_pid', 'observed_stat_state',
                             'leader_exit_code', 'live_group_member_count',
                             'live_group_pids', 'pids_truncated'))
_LIVE_STATES = frozenset(('R', 'S', 'D', 'T', 't', 'W', 'I', 'P'))


def _int(value, minimum=0):
    return type(value) is int and value >= minimum


def _validate(payload):
    if (type(payload) is not dict or len(payload) not in (len(_REQUIRED), len(_REQUIRED | _BOUNDARY))
            or any(type(key) is not str for key in payload)):
        raise ValueError('V5_PARENT_RECEIPT_FIELDS')
    fields = frozenset(payload)
    if fields not in (_REQUIRED, _REQUIRED | _BOUNDARY):
        # Unknown fields also reject errors, cleanup evidence, and leftovers.
        raise ValueError('V5_PARENT_RECEIPT_FIELDS')
    if type(payload['status']) is not str or payload['status'] != 'PASS_BOUNDED_WORKER':
        raise ValueError('V5_PARENT_RECEIPT_STATUS')
    expected = guard.policy()
    policy = payload['memory_policy']
    if (type(policy) is not dict or len(policy) != len(expected) or policy.keys() != expected.keys()
            or any(type(key) is not str for key in policy)
            or any(type(policy[key]) is not type(value) or policy[key] != value
                   for key, value in expected.items())):
        raise ValueError('V5_PARENT_RECEIPT_POLICY')
    if not _int(payload['exit_code']) or payload['exit_code'] != 0:
        raise ValueError('V5_PARENT_RECEIPT_EXIT')
    if not _int(payload['sample_count'], 1):
        raise ValueError('V5_PARENT_RECEIPT_SAMPLES')
    if not _int(payload['process_group'], 1):
        raise ValueError('V5_PARENT_RECEIPT_GROUP')
    elapsed = payload['elapsed_seconds']
    # Deliberately no cleanup margin: fail closed at the policy timeout.
    if type(elapsed) is not float or not math.isfinite(elapsed) or not 0 < elapsed <= guard.TIMEOUT_S:
        raise ValueError('V5_PARENT_RECEIPT_ELAPSED')
    group, combined = payload['peak_group_rss_bytes'], payload['peak_combined_rss_bytes']
    if not _int(group) or not _int(combined, 1) or not group <= combined <= guard.RSS_CAP:
        raise ValueError('V5_PARENT_RECEIPT_RSS')
    total, available, reserve = (payload['effective_total_bytes'],
                                 payload['initial_available_bytes'], payload['reserve_bytes'])
    if (not _int(total, 1) or not _int(available) or available > total
            or not _int(reserve)):
        raise ValueError('V5_PARENT_RECEIPT_MEMORY')
    try:
        required_reserve = guard.check_available(total, available)
    except (ValueError, RuntimeError) as error:
        raise ValueError('V5_PARENT_RECEIPT_MEMORY') from error
    if reserve != required_reserve:
        raise ValueError('V5_PARENT_RECEIPT_MEMORY')
    if _BOUNDARY <= fields:
        resolution = payload['rss_exit_boundary_resolution']
        boundary = payload['rss_exit_boundary']
        if (type(resolution) is not str or resolution != 'EXIT_ZERO_NO_LIVE_GROUP'
                or type(boundary) is not dict or len(boundary) != len(_BOUNDARY_FIELDS)
                or frozenset(boundary) != _BOUNDARY_FIELDS
                or any(type(key) is not str for key in boundary)
                or not _int(boundary['unreadable_pid'], 1)
                or type(boundary['observed_stat_state']) is not str
                or boundary['observed_stat_state'] not in _LIVE_STATES
                or type(boundary['leader_exit_code']) is not int
                or boundary['leader_exit_code'] != 0
                or type(boundary['live_group_member_count']) is not int
                or boundary['live_group_member_count'] != 0
                or type(boundary['live_group_pids']) is not list
                or boundary['live_group_pids'] != []
                or type(boundary['pids_truncated']) is not bool
                or boundary['pids_truncated'] is not False):
            raise ValueError('V5_PARENT_RECEIPT_RSS_BOUNDARY')


def validate_parent_guard_receipt(returned_result, reread_receipt):
    """Validate two strict, bounded payloads without reading or executing anything.

    At least one real sample is mandatory, including an exit-boundary receipt;
    supplied sample counts cannot independently prove no sample was fabricated.
    """
    _validate(returned_result)
    _validate(reread_receipt)
    # The schema above fixes every nested type, so equality is type-strict here.
    if returned_result != reread_receipt:
        raise ValueError('V5_PARENT_RECEIPT_MISMATCH')
    return dict(status='PASS_PARENT_GUARD_RECEIPT_IMPLEMENTATION_ONLY',
                bounded_worker_receipt_validated=True,
                receipt_provenance_proven=False,
                actual_training_proven=False,
                release_authorization_proven=False,
                authentic_user_consent_proven=False)
