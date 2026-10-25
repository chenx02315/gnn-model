"""Offline-capable observation sealing, not an executor or acceptance policy.

Callbacks must use exclusive anchored publication in a future reviewed runner.
The observation records the returned supervisor evidence before final sampling;
it does not claim that sampling, warning review, or the case itself passed.
"""
import hashlib
import json
import math

from .direct_runtime_compatibility_e102 import warning_inventory


def require(ok):
    if not ok:
        raise ValueError('E102_RETURNED_OBSERVATION_REQUIRED')


def seal_observation(observed, circuit, transition, elapsed,
                     publish_receipt, publish_log, final_sample):
    require(circuit in ('aes_core', 'spi') and
            transition in ('H_TO_M', 'H_TO_F'))
    keys = {'returncode', 'cleaned', 'failure', 'output',
            'sampled_peak_rss_swap_bytes', 'launch_attempted', 'readiness',
            'streams_combined', 'stderr_separately_validated'}
    require(type(observed) is dict and set(observed) == keys)
    require(observed['returncode'] is None or
            type(observed['returncode']) is int)
    require(observed['cleaned'] is True and observed['readiness'] is None)
    require(type(observed['launch_attempted']) is bool and
            observed['streams_combined'] is True and
            observed['stderr_separately_validated'] is False)
    require(observed['failure'] is None or
            (type(observed['failure']) is str and len(observed['failure']) <= 256))
    peak = observed['sampled_peak_rss_swap_bytes']
    require(type(peak) is int and peak >= 0)
    require(type(elapsed) in (int, float) and math.isfinite(elapsed) and elapsed >= 0)
    log = observed['output']
    require(type(log) is bytes and len(log) <= 16777216)
    try:
        warnings = warning_inventory(log)
    except ValueError:
        # Diagnostic parsing failure must not erase returned process evidence.
        # This explicitly blocks use as a reviewed warning inventory.
        warnings = dict(inventory_failed=True,
                        code='BOUNDED_WARNING_INVENTORY_FAILED',
                        warning_acceptance_policy_changed=False, d95_verified=False)
    receipt = {key: value for key, value in observed.items() if key != 'output'}
    receipt.update(schema='direct-returned-observation-e102-v1',
                   circuit=circuit, transition=transition,
                   elapsed_until_supervisor_return_seconds=elapsed,
                   log_bytes=len(log), log_sha256=hashlib.sha256(log).hexdigest(),
                   warning_inventory=warnings,
                   acceptance_evaluated=False,
                   final_scratch_sample_evaluated=False,
                   independent_os_termination_attested=False)
    raw = json.dumps(receipt, sort_keys=True, separators=(',', ':'),
                     ensure_ascii=True, allow_nan=False).encode('ascii') + b'\n'
    require(len(raw) <= 65536)
    # No retry: failure at any publication/sample escapes to the caller.
    publish_receipt('observation_%s_%s.json' % (circuit, transition), raw)
    publish_log('direct_tessent.log', log)
    final_sample()
    return receipt
