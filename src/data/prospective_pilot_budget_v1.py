"""Conditional E79 call envelope, not an ATPG execution budget or permission.

Only caller-declared upper bounds enter this pure calculator. Its F-search
formula mirrors a *counting shape* in the current reference driver, not a
verified prospective runner or a proof that future endpoints are attainable.
No actual roster, process, license wait, dispatch, I/O, or cache is inspected.
"""

FIELDS = ('f_full_pattern_bound', 'candidate_count_upper', 'sessions',
          'endpoint_calls_per_session_upper', 'extra_calls_per_session_upper',
          'prefix_rebuild_per_f_call', 'attempt_timeout_s', 'cleanup_timeout_s')
NUMERIC_CAPS = {'f_full_pattern_bound': 2**31-1,
                'candidate_count_upper': 462,
                'sessions': 1000,
                'endpoint_calls_per_session_upper': 10**6,
                'extra_calls_per_session_upper': 10**6,
                'attempt_timeout_s': 86400,
                'cleanup_timeout_s': 86400}
ZERO_ALLOWED = frozenset(('endpoint_calls_per_session_upper',
                          'extra_calls_per_session_upper'))


def _bounded(value, field):
    if type(value) is not int or not (0 if field in ZERO_ALLOWED else 1) <= value <= NUMERIC_CAPS[field]:
        raise ValueError('INVALID_' + field.upper())
    return value


def f_search_upper(f_full_pattern_bound):
    """Coverage + possible full fallback + <=U integer probes + binary bracket.

    The incoming H/M state supplies F=0. If the boundary is F=1, that
    already-observed incoming state proves F-1; no extra F=0 run is charged.
    This is a count bound under the declared U, not proof of F feasibility.
    """
    bound = _bounded(f_full_pattern_bound, 'f_full_pattern_bound')
    return 2 + bound + (bound-1).bit_length()


def calculate_budget(declared):
    """Return a conditional, summed stage-attempt envelope or all-null bounds.

    A false prefix-rebuild flag assumes an H/M prefix can be retained *within
    each action only*. It never grants cross-candidate, method, or session
    cache reuse. A true flag charges two fresh H/M calls per F probe. Each
    endpoint and extra call is charged once per session as declared. The time
    product is only the sum of allowed attempt + cleanup caps: license wait,
    dispatch, file I/O, deliberation, and other launches are not bounded here.
    """
    if type(declared) is not dict or set(declared) != set(FIELDS):
        raise ValueError('EXACT_DECLARATION_FIELDS_REQUIRED')
    if type(declared['prefix_rebuild_per_f_call']) is not bool:
        raise ValueError('PREFIX_REBUILD_BOOL_REQUIRED')
    missing = []
    for field in NUMERIC_CAPS:
        value = declared[field]
        if value is None:
            missing.append(field)
        else:
            _bounded(value, field)
    base = dict(schema='prospective-pilot-conditional-budget-v1',
                status='INCOMPLETE_DESIGN' if missing else 'CONDITIONAL_DECLARED_CAPS_ONLY',
                missing_fields=missing, declared=dict(declared),
                f_probe_calls_per_action_upper=None,
                hmf_base_calls_per_action_upper=None,
                physical_calls_per_action_upper=None,
                physical_calls_per_session_upper=None,
                total_physical_calls_upper=None,
                summed_attempt_envelope_seconds_upper=None,
                time_scope='SUM_OF_ALLOWED_ATTEMPT_AND_CLEANUP_CAPS_ONLY_NOT_END_TO_END_WALL',
                call_scope='DECLARED_STAGE_CALLS_ONLY_NOT_ALL_REAL_RUNNER_LAUNCHES',
                cross_candidate_cache_assumed=False,
                cross_method_cache_assumed=False,
                cross_session_cache_assumed=False,
                actual_atpg_calls=0, execution_ready=False, training_release=False)
    if missing:
        return base
    probes = f_search_upper(declared['f_full_pattern_bound'])
    # Worst scheme is HMF: two initial stage calls. HF needs only one.
    per_action = 2 + probes * (3 if declared['prefix_rebuild_per_f_call'] else 1)
    per_session = (declared['endpoint_calls_per_session_upper'] +
                   declared['extra_calls_per_session_upper'] +
                   declared['candidate_count_upper'] * per_action)
    total = declared['sessions'] * per_session
    base.update(f_probe_calls_per_action_upper=probes,
                hmf_base_calls_per_action_upper=2,
                physical_calls_per_action_upper=per_action,
                physical_calls_per_session_upper=per_session,
                total_physical_calls_upper=total,
                summed_attempt_envelope_seconds_upper=
                total*(declared['attempt_timeout_s']+declared['cleanup_timeout_s']))
    return base
