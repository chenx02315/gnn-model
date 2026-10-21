"""Pure validation of proposed Tessent lifecycle observations, never a runner.

``summarize_observations(events)`` takes a built-in list of 1..256 flat dicts
describing 1..64 unique physical attempts. Every event has ``event`` (PLANNED,
LAUNCHED, REAPED) and a unique-per-attempt ``attempt_id`` (ASCII identifier).
PLANNED additionally requires circuit (aes_core/spi), command_sha256,
input_binding_sha256 (lowercase hex), and cost_role (endpoint/probe/search).
LAUNCHED requires boot_id, host (bounded ASCII identifiers), pid, start_ticks
(positive integers), and monotonic_ns (nonnegative integer). REAPED repeats
that process identity and requires monotonic_ns, returncode (signed integer),
termination_verified (bool), and status (success/failed/timeout/cancelled).
Success requires returncode zero and failed requires nonzero. Timeout/cancelled
preserve the observed terminal reason even when a clean exit races with it, so
either permits any bounded signed returncode.
Integers are signed-64-bit bounded, and bool is never an integer here.

An attempt may stop at any stage, but another attempt may only be planned or
launched after verified reaping. All attempts share one host/boot clock, and
launch observations cannot precede the prior reap. Process identities cannot
be reused; retry declarations and cache reuse have no schema. Repeated command
bindings are fresh, independently charged physical attempts. Unknown keys
(including quality, cycle and runtime labels) are errors.
The input is already decoded: duplicate JSON keys must be rejected by callers
before constructing dicts. No mutable input objects are returned or retained.

Cost is launch-observation to reap-observation, including dispatch overhead;
it is NOT kernel-only execution time or end-to-end runtime. Every cost role and
terminal status is charged. Any incomplete or unverified attempt makes the
entire measured sum null, never an imputed zero or lower-bound label. A valid
summary is schema evidence only, not evidence a real process ran or was reaped.
"""

import re


MAX_ATTEMPTS = 64
MAX_EVENTS = 256
MAX_INTEGER = 2**63 - 1
COST_SCOPE = 'launch-observation_to_reap-observation_including_dispatch_overhead'
_COMMON = frozenset(('event', 'attempt_id'))
_PLAN = frozenset(('circuit', 'command_sha256', 'input_binding_sha256', 'cost_role'))
_IDENTITY = ('boot_id', 'host', 'pid', 'start_ticks')
_LAUNCH = frozenset(_IDENTITY + ('monotonic_ns',))
_REAP = _LAUNCH | frozenset(('returncode', 'termination_verified', 'status'))


def _require(condition, code):
    if not condition:
        raise ValueError(code)


def _identifier(value):
    _require(type(value) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', value)
             is not None, 'IDENTIFIER')


def _integer(value, minimum=0):
    _require(type(value) is int and minimum <= value <= MAX_INTEGER, 'INTEGER_BOUND')


def _sha(value):
    _require(type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None,
             'SHA256')


def summarize_observations(events):
    """Validate the whole bounded sequence; return a detached, fail-closed summary."""
    _require(type(events) is list and 1 <= len(events) <= MAX_EVENTS, 'EVENT_BOUND')
    attempts = []
    attempt_ids = set()
    process_ids = set()
    current = None
    clock = None
    prior_reap = None
    for event in events:
        _require(type(event) is dict and 2 <= len(event) <= 11, 'EVENT_SCHEMA')
        kind = event.get('event')
        _require(type(kind) is str and kind in ('PLANNED', 'LAUNCHED', 'REAPED'),
                 'EVENT_KIND')
        fields = _PLAN if kind == 'PLANNED' else _LAUNCH if kind == 'LAUNCHED' else _REAP
        _require(set(event) == _COMMON | fields, 'EVENT_SCHEMA')
        aid = event['attempt_id']
        _identifier(aid)
        if kind == 'PLANNED':
            _require(current is None or current['termination_verified'] is True,
                     'UNRESOLVED_PHASE_STOP')
            _require(aid not in attempt_ids, 'DUPLICATE_ATTEMPT')
            _require(len(attempts) < MAX_ATTEMPTS, 'ATTEMPT_BOUND')
            _require(type(event['circuit']) is str and event['circuit'] in ('aes_core', 'spi'),
                     'CIRCUIT')
            _require(type(event['cost_role']) is str and event['cost_role'] in
                     ('endpoint', 'probe', 'search'), 'COST_ROLE')
            _sha(event['command_sha256'])
            _sha(event['input_binding_sha256'])
            attempt_ids.add(aid)
            current = {key: event[key] for key in _PLAN}
            current.update(attempt_id=aid, state='PLANNED', launch_monotonic_ns=None,
                           reap_monotonic_ns=None, termination_verified=None,
                           status=None, returncode=None, observed_interval_ns=None)
            attempts.append(current)
            continue
        _require(current is not None and aid == current['attempt_id'], 'ATTEMPT_ORDER')
        for key in ('boot_id', 'host'):
            _identifier(event[key])
        for key in ('pid', 'start_ticks'):
            _integer(event[key], 1)
        _integer(event['monotonic_ns'])
        identity = tuple(event[key] for key in _IDENTITY)
        if kind == 'LAUNCHED':
            _require(current['state'] == 'PLANNED', 'LAUNCH_TRANSITION')
            event_clock = identity[:2]
            _require(clock is None or event_clock == clock, 'PHASE_CLOCK_BINDING')
            _require(prior_reap is None or event['monotonic_ns'] >= prior_reap,
                     'SEQUENTIAL_CLOCK')
            _require(identity not in process_ids, 'PROCESS_IDENTITY_REUSE')
            process_ids.add(identity)
            clock = event_clock
            current.update({key: event[key] for key in _IDENTITY})
            current.update(state='LAUNCHED', launch_monotonic_ns=event['monotonic_ns'])
        else:
            _require(current['state'] == 'LAUNCHED', 'REAP_TRANSITION')
            _require(identity == tuple(current[key] for key in _IDENTITY), 'PROCESS_BINDING')
            _require(event['monotonic_ns'] >= current['launch_monotonic_ns'], 'MONOTONIC_CLOCK')
            _integer(event['returncode'], -2**63)
            _require(type(event['termination_verified']) is bool, 'TERMINATION_FLAG')
            status = event['status']
            _require(type(status) is str and status in
                     ('success', 'failed', 'timeout', 'cancelled'), 'TERMINAL_STATUS')
            _require(status != 'success' or event['returncode'] == 0, 'RETURN_CODE_STATUS')
            _require(status != 'failed' or event['returncode'] != 0, 'RETURN_CODE_STATUS')
            verified = event['termination_verified']
            current.update(state='REAPED', reap_monotonic_ns=event['monotonic_ns'],
                           termination_verified=verified, status=status,
                           returncode=event['returncode'], observed_interval_ns=(
                               event['monotonic_ns'] - current['launch_monotonic_ns']
                               if verified else None))
            prior_reap = event['monotonic_ns']
    complete = all(item['termination_verified'] is True for item in attempts)
    return dict(schema_version='prospective_process_observation_v1',
                attempt_count=len(attempts), event_count=len(events), attempts=attempts,
                cost_complete=complete,
                raw_observed_interval_ns_sum=(sum(item['observed_interval_ns'] for item in attempts)
                                              if complete else None),
                cost_scope=COST_SCOPE, all_cost_roles_charged=True,
                actual_processes_executed=0, evidence_kind='VALIDATED_OBSERVATIONS_ONLY',
                execution_ready=False, training_release=False)
