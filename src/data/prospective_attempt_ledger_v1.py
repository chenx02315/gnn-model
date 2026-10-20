"""Offline prospective physical-attempt ledger. Never launches or retries work."""
import copy
import hashlib
import json
import os
import re
import stat
import sys
import threading
import time
import uuid
from datetime import datetime, timezone

MAX_EVENTS = 10000
MAX_LINE_BYTES = 16384
MAX_TOTAL_BYTES = 16 * 1024 * 1024
TERMINAL = frozenset(('SUCCESS', 'FAILED', 'TIMEOUT', 'CANCELLED'))
PROVENANCE = frozenset(('driver_sha256', 'config_sha256', 'plan_sha256',
    'input_sha256', 'environment_cohort', 'clock_identity', 'command_sha256',
    'output_root', 'job_identity'))
SEMANTIC_PROVENANCE = frozenset(('driver_sha256', 'config_sha256', 'input_sha256',
    'command_sha256', 'environment_cohort'))
COST_NODE = 'ATOMIC_ATPG_PROCESS_ONLY'


def require(ok, code):
    if not ok:
        raise ValueError(code)


def exact(value, keys):
    require(type(value) is dict and set(value) == set(keys), 'SCHEMA')


def text(value, limit=256):
    require(type(value) is str and 0 < len(value) <= limit
            and not any(ord(c) < 32 for c in value), 'TEXT')


def identifier(value):
    require(type(value) is str and re.fullmatch('[A-Za-z0-9_.-]{1,64}', value) is not None,
            'IDENTIFIER')


def sha(value):
    require(type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None, 'SHA256')


def integer(value):
    require(type(value) is int and 0 <= value <= 2**63-1, 'NONNEGATIVE_INTEGER_NS')


def provenance(value, plan):
    exact(value, PROVENANCE)
    for key in ('driver_sha256', 'config_sha256', 'plan_sha256', 'input_sha256', 'command_sha256'):
        sha(value[key])
    require(value['plan_sha256'] == plan, 'PLAN_BINDING')
    for key in ('environment_cohort', 'clock_identity', 'job_identity'):
        text(value[key])
    text(value['output_root'], 1024)


def clock_record(payload):
    text(payload['clock_session'])
    integer(payload['monotonic_ns'])
    value = payload['utc']
    require(type(value) is str and re.fullmatch(
        r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z', value)
        is not None, 'UTC_METADATA')


def bounded_json(value, depth=0, budget=None):
    if budget is None:
        budget = [MAX_LINE_BYTES]
    require(depth <= 12, 'JSON_DEPTH_BOUND')
    budget[0] -= 1
    require(budget[0] >= 0, 'JSON_NODE_BOUND')
    if type(value) is str:
        budget[0] -= len(value)
        require(budget[0] >= 0, 'JSON_STRING_BOUND')
    elif type(value) is int:
        integer(value)
    elif value is None or type(value) is bool:
        pass
    elif type(value) in (dict, list):
        require(len(value) <= MAX_LINE_BYTES, 'JSON_COLLECTION_BOUND')
        items = value.items() if type(value) is dict else enumerate(value)
        for key, child in items:
            if type(value) is dict:
                require(type(key) is str, 'JSON_KEY_TYPE')
                bounded_json(key, depth+1, budget)
            bounded_json(child, depth+1, budget)
    else:
        raise ValueError('JSON_VALUE_TYPE')


def canonical(value):
    bounded_json(value)
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def header(plan):
    sha(plan)
    return dict(schema_version='prospective_attempt_ledger_v1', plan_sha256=plan)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    def reject(value):
        raise ValueError('NONSTANDARD_JSON_CONSTANT')
    return json.loads(raw.decode('ascii'), object_pairs_hook=pairs, parse_constant=reject)


class SystemClock:
    """A helper only; clock sessions must be explicitly bound in provenance."""
    def __init__(self, session=None):
        self.session = session or uuid.uuid4().hex
        text(self.session)

    def capture(self):
        # Python 3.6 fallback has coarser resolution; units remain integer ns.
        now = time.monotonic_ns() if hasattr(time, 'monotonic_ns') else int(time.monotonic()*10**9)
        return dict(clock_session=self.session, monotonic_ns=now,
                    utc=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ'))


class Ledger:
    def __init__(self, plan_sha256):
        self.plan_sha256 = header(plan_sha256)['plan_sha256']
        self._state = dict(attempts={}, actions={}, action_circuits={})
        self.seq = 0
        self.head = digest(header(plan_sha256))
        self.byte_count = len(canonical(header(plan_sha256)))+1

    def snapshot(self):
        return copy.deepcopy(self._state)

    def event(self, kind, payload):
        bounded_json(payload)
        event = dict(seq=self.seq+1, prev_hash=self.head, kind=kind, payload=copy.deepcopy(payload))
        event['event_hash'] = digest(event)
        return event

    def apply(self, event):
        exact(event, ('seq', 'prev_hash', 'kind', 'payload', 'event_hash'))
        require(type(event['seq']) is int and event['seq'] == self.seq+1 <= MAX_EVENTS, 'EVENT_SEQUENCE_BOUND')
        require(event['prev_hash'] == self.head, 'HASH_CHAIN')
        sha(event['event_hash'])
        body = {key: value for key, value in event.items() if key != 'event_hash'}
        require(digest(body) == event['event_hash'], 'EVENT_HASH')
        byte_count = len(canonical(event))+1
        require(byte_count <= MAX_LINE_BYTES, 'LINE_BOUND')
        require(self.byte_count+byte_count <= MAX_TOTAL_BYTES, 'TOTAL_BYTE_BOUND')
        trial = copy.deepcopy(self._state)
        self._apply(trial, event['kind'], event['payload'])
        self._state = trial
        self.seq = event['seq']
        self.head = event['event_hash']
        self.byte_count += byte_count

    def record(self, kind, payload):
        event = self.event(kind, payload)
        self.apply(event)
        return event

    def _apply(self, state, kind, payload):
        attempts, actions = state['attempts'], state['actions']
        def bind_action(action, circuit):
            bound = state['action_circuits']
            require(action not in bound or bound[action] == circuit, 'ACTION_CIRCUIT_BINDING')
            bound[action] = circuit
        if kind == 'PLAN':
            exact(payload, ('attempt_id', 'circuit', 'action', 'call_key', 'parents', 'retry_of', 'provenance', 'cost_node'))
            require(payload['cost_node'] == COST_NODE, 'ATOMIC_COST_NODE_REQUIRED')
            aid = payload['attempt_id']; identifier(aid)
            require(aid not in attempts, 'DUPLICATE_ATTEMPT')
            for key in ('circuit', 'action', 'call_key'):
                text(payload[key])
            provenance(payload['provenance'], self.plan_sha256)
            parents = payload['parents']
            require(type(parents) is list and len(parents) <= 64
                    and len(parents) == len(set(parents)), 'PARENTS')
            for parent in parents:
                identifier(parent); require(parent in attempts, 'UNKNOWN_PARENT_OR_CYCLE')
                require(attempts[parent]['circuit'] == payload['circuit'], 'PARENT_CIRCUIT_BINDING')
            retry = payload['retry_of']
            if retry is not None:
                identifier(retry)
                require(retry in attempts and attempts[retry]['state'] in ('FAILED', 'TIMEOUT', 'CANCELLED'),
                        'RETRY_REQUIRES_OBSERVED_FAILED_TERMINAL')
                prior = attempts[retry]
                require(prior['circuit'] == payload['circuit'] and prior['call_key'] == payload['call_key'],
                        'RETRY_IDENTITY')
                require(all(prior['provenance'][key] == payload['provenance'][key]
                            for key in SEMANTIC_PROVENANCE), 'RETRY_SEMANTIC_PROVENANCE')
            attempts[aid] = dict(copy.deepcopy(payload), state='PLANNED', start=None, end=None)
            bind_action(payload['action'], payload['circuit'])
            actions.setdefault(payload['action'], []).append(aid)
        elif kind == 'START':
            exact(payload, ('attempt_id', 'clock_session', 'monotonic_ns', 'utc', 'execution_identity'))
            aid = payload['attempt_id']; identifier(aid)
            require(aid in attempts and attempts[aid]['state'] == 'PLANNED', 'START_TRANSITION')
            clock_record(payload)
            execution = payload['execution_identity']
            exact(execution, ('host', 'job_id', 'pid'))
            text(execution['host'])
            if execution['job_id'] is not None:
                text(execution['job_id'])
            if execution['pid'] is not None:
                integer(execution['pid']); require(execution['pid'] > 0, 'PID')
            item = attempts[aid]
            require(payload['clock_session'] == item['provenance']['clock_identity'], 'CLOCK_IDENTITY')
            item['start'] = copy.deepcopy(payload); item['state'] = 'RUNNING'
        elif kind == 'END':
            exact(payload, ('attempt_id', 'state', 'clock_session', 'monotonic_ns', 'utc',
                            'termination_verified', 'd95', 'ate_cycles', 'output_artifact_sha256'))
            aid = payload['attempt_id']; identifier(aid)
            require(aid in attempts and payload['state'] in TERMINAL, 'END_TRANSITION')
            item = attempts[aid]
            require(item['state'] == 'RUNNING' or item['state'] == 'PLANNED'
                    and payload['state'] == 'CANCELLED', 'END_TRANSITION')
            clock_record(payload)
            require(payload['clock_session'] == item['provenance']['clock_identity'], 'CLOCK_IDENTITY')
            require(type(payload['termination_verified']) is bool, 'TERMINATION_FLAG')
            require(payload['d95'] is None or type(payload['d95']) is bool, 'D95_TYPE')
            if payload['ate_cycles'] is not None:
                integer(payload['ate_cycles'])
            if payload['output_artifact_sha256'] is not None:
                sha(payload['output_artifact_sha256'])
            if item['start'] is None:
                require(payload['termination_verified'] and payload['d95'] is None
                        and payload['ate_cycles'] is None and payload['output_artifact_sha256'] is None, 'PRESTART_CANCEL')
            else:
                require(payload['clock_session'] == item['start']['clock_session']
                        and payload['monotonic_ns'] >= item['start']['monotonic_ns'], 'MONOTONIC_CLOCK')
            require(payload['state'] in ('TIMEOUT', 'CANCELLED') or payload['termination_verified'],
                    'UNVERIFIED_TERMINAL')
            item['end'] = copy.deepcopy(payload); item['state'] = payload['state']
        elif kind in ('LINK', 'CACHE'):
            expected = ('action', 'attempt_id') if kind == 'LINK' else (
                'action', 'attempt_id', 'circuit', 'call_key', 'provenance', 'output_artifact_sha256')
            exact(payload, expected)
            text(payload['action']); identifier(payload['attempt_id'])
            aid = payload['attempt_id']
            require(aid in attempts, 'UNKNOWN_OR_EXTERNAL_PROVIDER')
            if kind == 'CACHE':
                provenance(payload['provenance'], self.plan_sha256)
                item = attempts[aid]
                require(item['state'] == 'SUCCESS' and item['end']['termination_verified'], 'CACHE_REQUIRES_PRIOR_SUCCESS')
                for key in ('circuit', 'call_key'):
                    require(payload[key] == item[key], 'CACHE_IDENTITY')
                require(all(payload['provenance'][key] == item['provenance'][key]
                            for key in SEMANTIC_PROVENANCE), 'CACHE_SEMANTIC_PROVENANCE')
                sha(payload['output_artifact_sha256'])
                require(payload['output_artifact_sha256'] == item['end']['output_artifact_sha256'],
                        'CACHE_OUTPUT_ARTIFACT_BINDING')
            linked = actions.setdefault(payload['action'], [])
            bind_action(payload['action'], attempts[aid]['circuit'])
            require(aid not in linked, 'DUPLICATE_ACTION_REFERENCE')
            linked.append(aid)
        else:
            raise ValueError('EVENT_KIND')

    def aggregate(self, requested_actions):
        require(type(requested_actions) is list and 0 < len(requested_actions) <= MAX_EVENTS,
                'REQUESTED_ACTIONS')
        actions = self._state['actions']; attempts = self._state['attempts']
        pending = []
        for action in requested_actions:
            text(action); require(action in actions, 'UNKNOWN_OR_EXTERNAL_COST')
            pending.extend(actions[action])
        selected = set()
        while pending:
            aid = pending.pop()
            if aid in selected:
                continue
            selected.add(aid); item = attempts[aid]
            pending.extend(item['parents'])
            if item['retry_of'] is not None:
                pending.append(item['retry_of'])
        total = 0; incomplete = []; unverified = []
        for aid in sorted(selected):
            item = attempts[aid]
            if item['end'] is None:
                incomplete.append(aid)
                continue
            if item['start'] is not None:
                total += item['end']['monotonic_ns']-item['start']['monotonic_ns']
            if not item['end']['termination_verified']:
                unverified.append(aid)
        complete = not incomplete and not unverified
        return dict(attempt_ids=sorted(selected), physical_atpg_wall_ns_sum=total, complete=complete,
                    incomplete_attempt_ids=incomplete, unverified_termination_ids=unverified,
                    cost_kind='COMPLETE_SUM_OF_PHYSICAL_WALL_INTERVALS' if complete else 'LOWER_BOUND_INCOMPLETE',
                    wall_clock_makespan_computed=False, quality_used_to_filter_cost=False,
                    runner_integration_verified=False, execution_ready=False, online_cost_complete=False,
                    cache_lookup_overhead_unmeasured=True)


def file_identity(info, cross_api=False):
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    # Windows stat/fstat ctime semantics differ. Same-API comparisons stay full.
    if cross_api and sys.platform == 'win32':
        fields = fields[:-1]
    return tuple(getattr(info, key) for key in fields)


class Journal:
    """Exclusive-create, one owning writer. I/O failures poison it; never repairs."""
    def __init__(self):
        raise TypeError('USE_CREATE')

    @classmethod
    def create(cls, path, plan_sha256):
        ledger = Ledger(plan_sha256)
        raw = canonical(header(plan_sha256))+b'\n'
        require(len(raw) <= MAX_LINE_BYTES and len(raw) <= MAX_TOTAL_BYTES, 'HEADER_BOUND')
        stream = open(path, 'xb')
        try:
            require(stream.write(raw) == len(raw), 'SHORT_WRITE')
            stream.flush(); os.fsync(stream.fileno())
            instance = object.__new__(cls)
            instance._stream = stream; instance._path = path; instance._ledger = ledger
            instance._size = len(raw); instance._identity = file_identity(os.fstat(stream.fileno()))
            instance._path_identity = file_identity(os.stat(path, follow_symlinks=False))
            instance._poisoned = False; instance._lock = threading.Lock()
            instance._check_identity()
            return instance
        except Exception:
            stream.close()
            raise

    def _check_identity(self):
        fd = os.fstat(self._stream.fileno())
        path = os.stat(self._path, follow_symlinks=False)
        require(stat.S_ISREG(fd.st_mode) and fd.st_nlink == 1
                and file_identity(fd) == self._identity and file_identity(path) == self._path_identity
                and file_identity(fd, True) == file_identity(path, True)
                and fd.st_size == self._size, 'JOURNAL_CHANGED_OR_STALE_TAIL')

    def append(self, kind, payload):
        with self._lock:
            require(not self._poisoned and not self._stream.closed, 'JOURNAL_UNAVAILABLE')
            trial = copy.deepcopy(self._ledger)
            event = trial.record(kind, payload)
            raw = canonical(event)+b'\n'
            require(self._size+len(raw) <= MAX_TOTAL_BYTES, 'TOTAL_BYTE_BOUND')
            try:
                self._check_identity()
                require(self._stream.write(raw) == len(raw), 'SHORT_WRITE')
                self._stream.flush(); os.fsync(self._stream.fileno())
                expected_size = self._size+len(raw)
                observed = os.fstat(self._stream.fileno())
                require(observed.st_size == expected_size, 'JOURNAL_CHANGED_OR_STALE_TAIL')
                self._size = expected_size; self._identity = file_identity(observed)
                self._path_identity = file_identity(os.stat(self._path, follow_symlinks=False))
                self._check_identity()
            except Exception:
                self._poisoned = True
                raise
            self._ledger = trial
            return copy.deepcopy(event)

    def snapshot(self):
        """Acknowledged in-memory state only, even if later I/O poisoned writer."""
        return self._ledger.snapshot()

    def aggregate(self, actions):
        with self._lock:
            require(not self._poisoned and not self._stream.closed, 'JOURNAL_UNAVAILABLE')
            try:
                self._check_identity()
            except Exception:
                self._poisoned = True
                raise
            return self._ledger.aggregate(actions)

    def close(self):
        self._stream.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def load(path):
    """Strict replay integrity is not fsync ACK or execution completeness proof.

    A torn tail is an error, not zero cost, truncation or automatic repair.
    """
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as stream:
        path_before = os.stat(path, follow_symlinks=False)
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size <= MAX_TOTAL_BYTES
                and file_identity(before, True) == file_identity(path_before, True), 'JOURNAL_FILE_BOUND')
        total = 0; ledger = None
        while True:
            raw = stream.readline(MAX_LINE_BYTES+1)
            if not raw:
                break
            total += len(raw)
            require(total <= MAX_TOTAL_BYTES and len(raw) <= MAX_LINE_BYTES, 'JOURNAL_BYTE_BOUND')
            require(raw.endswith(b'\n'), 'INCOMPLETE_PARTIAL_TAIL')
            value = strict_json(raw)
            require(canonical(value)+b'\n' == raw, 'NONCANONICAL_JOURNAL')
            if ledger is None:
                exact(value, ('schema_version', 'plan_sha256'))
                require(value['schema_version'] == 'prospective_attempt_ledger_v1', 'SCHEMA_VERSION')
                ledger = Ledger(value['plan_sha256'])
            else:
                ledger.apply(value)
        require(ledger is not None, 'MISSING_HEADER')
        fd_after = os.fstat(stream.fileno()); path_after = os.stat(path, follow_symlinks=False)
        require(total == before.st_size and file_identity(before) == file_identity(fd_after)
                and file_identity(path_before) == file_identity(path_after)
                and file_identity(fd_after, True) == file_identity(path_after, True), 'JOURNAL_CHANGED_DURING_REPLAY')
        return ledger
