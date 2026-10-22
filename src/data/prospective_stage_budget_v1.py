"""Declared task debit prototype; in-memory only, never an execution permit."""
import copy
import hashlib
import json
import re

KINDS = ('STATUS_TRANSLATION', 'TESSENT_STAGE')
NODE_KEYS = {'task_uid', 'kind', 'stage', 'request_sha256', 'depends_on',
             'timeout_ns', 'cleanup_ns'}


def require(ok, code):
    if not ok:
        raise ValueError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def positive(value, high):
    return type(value) is int and 1 <= value <= high


class DeclaredTaskBudget:
    """No processes, persistence, restart/resume, resource guard or authority.

    Exact ordered slots prevent renaming a consumed slot. Recreating this object
    would reset RAM, so it must never be used as a durable production quota.
    A future executor requires separate persistent debit/ACK integration.
    """
    def __init__(self, plan, max_tessent_calls, max_translation_calls, phase_envelope_ns):
        require(type(plan) is list and 1 <= len(plan) <= 128, 'BOUNDED_PLAN')
        require(positive(max_tessent_calls, 128) and type(max_translation_calls) is int and
                0 <= max_translation_calls <= 128 and positive(phase_envelope_ns, 2**63-1),
                'DECLARED_CAPS')
        seen, bindings = {}, set()
        for node in plan:
            require(type(node) is dict and set(node) == NODE_KEYS, 'EXACT_TASK_SCHEMA')
            uid = node['task_uid']
            require(type(uid) is str and re.fullmatch(r'[A-Za-z0-9_:.-]{1,128}', uid) and
                    uid not in seen and type(node['kind']) is str and node['kind'] in KINDS,
                    'TASK_ID_KIND')
            require(type(node['stage']) is str and node['stage'] in ('H', 'M', 'F') and
                    type(node['request_sha256']) is str and
                    re.fullmatch('[0-9a-f]{64}', node['request_sha256']), 'TASK_BINDING')
            binding = (node['kind'], node['request_sha256'])
            require(binding not in bindings, 'DUPLICATE_PHYSICAL_TASK_BINDING')
            require(positive(node['timeout_ns'], 86400*10**9) and
                    positive(node['cleanup_ns'], 86400*10**9), 'TASK_ENVELOPE')
            deps = node['depends_on']
            require(type(deps) is list and len(deps) <= 1 and
                    all(type(d) is str and d in seen for d in deps), 'PRIOR_DEPENDENCY')
            if node['kind'] == 'STATUS_TRANSLATION':
                require(node['stage'] != 'H' and not deps, 'TRANSLATION_STAGE')
            elif node['stage'] == 'H':
                require(not deps, 'H_NO_TRANSLATION')
            else:
                require(len(deps) == 1, 'INCREMENTAL_TRANSLATION_REQUIRED')
                parent = seen[deps[0]]
                require(parent['kind'] == 'STATUS_TRANSLATION' and
                        parent['stage'] == node['stage'] and
                        parent['request_sha256'] == node['request_sha256'],
                        'EXACT_TRANSLATION_BINDING')
            seen[uid] = node
            bindings.add(binding)
        self._plan = copy.deepcopy(plan)
        self._plan_sha = digest(plan)
        self._caps = dict(TESSENT_STAGE=max_tessent_calls, STATUS_TRANSLATION=max_translation_calls)
        self._counts = dict.fromkeys(KINDS, 0)
        self._phase_cap = phase_envelope_ns
        self._reserved_ns = 0
        self._actual_asserted_ns = 0
        self._complete = True
        self._index = 0
        self._active = None
        self._settled = {}
        self._stopped = None

    def reserve(self, task_uid):
        require(self._stopped is None and self._active is None and
                self._index < len(self._plan), 'STOPPED_ACTIVE_OR_FINISHED')
        node = self._plan[self._index]
        require(type(task_uid) is str and task_uid == node['task_uid'], 'EXACT_NEXT_SLOT')
        require(all(self._settled.get(uid) == 'SUCCESS' for uid in node['depends_on']),
                'DEPENDENCY_NOT_SUCCESSFUL')
        ns = node['timeout_ns'] + node['cleanup_ns']
        if self._counts[node['kind']] >= self._caps[node['kind']] or self._reserved_ns + ns > self._phase_cap:
            self._stopped = 'CENSORED_DECLARED_BUDGET_EXHAUSTED'
            raise ValueError(self._stopped)
        # Debit precedes token creation and is never refunded, even on failure.
        self._counts[node['kind']] += 1
        self._reserved_ns += ns
        body = dict(plan_sha256=self._plan_sha, slot=self._index,
            task=copy.deepcopy(node), reserved_envelope_ns=ns, launch_authorized=False)
        token = dict(body, token_sha256=digest(body))
        self._active = copy.deepcopy(token)
        self._index += 1
        return token

    def settle(self, token, status, elapsed_ns, cleanup_verified):
        require(self._active is not None and canonical(token) == canonical(self._active),
                'EXACT_ACTIVE_TOKEN')
        require(type(status) is str and status in
                ('SUCCESS', 'FAILED', 'TIMEOUT', 'CANCELLED', 'UNKNOWN') and
                type(cleanup_verified) is bool and
                (elapsed_ns is None or (type(elapsed_ns) is int and 0 <= elapsed_ns <= 2**63-1)),
                'SETTLEMENT_SCHEMA')
        node = self._active['task']
        if elapsed_ns is None or not cleanup_verified or status == 'UNKNOWN':
            self._complete = False
            self._stopped = 'STOP_UNRESOLVED_OBSERVATION'
        else:
            self._actual_asserted_ns += elapsed_ns
            if elapsed_ns > self._active['reserved_envelope_ns']:
                self._stopped = 'STOP_OBSERVED_ENVELOPE_OVERRUN'
        self._settled[node['task_uid']] = status
        self._active = None
        # Failure is preserved, not retried or relabeled D95 infeasible.
        if status != 'SUCCESS' and self._stopped is None:
            self._stopped = 'STOP_FAILED_TASK_NO_RETRY'
        return self.snapshot()

    def snapshot(self):
        complete = (self._complete and self._active is None)
        return dict(schema='prospective-declared-task-budget-v1',
            state_kind='IN_MEMORY_SYNTHETIC_PROTOCOL_NOT_DURABLE',
            plan_sha256=self._plan_sha, plan_task_count=len(self._plan),
            consumed_counts=dict(self._counts), reserved_envelope_ns=self._reserved_ns,
            settled_task_count=len(self._settled), active_slot=(
                self._active['slot'] if self._active is not None else None),
            stopped_reason=self._stopped,
            asserted_elapsed_ns_sum=self._actual_asserted_ns if complete else None,
            asserted_elapsed_scope='SETTLED_KNOWN_PREFIX_ONLY_NOT_FULL_PLAN_OR_SESSION',
            declared_plan_complete=(self._index == len(self._plan) and
                len(self._settled) == len(self._plan) and self._stopped is None),
            elapsed_is_not_authenticated_atpg_runtime=True, durable_debit_ack_verified=False,
            OS_resource_limits_enforced=False, launch_authorized=False,
            execution_ready=False, training_release=False)
