"""E76 local synthetic lifecycle journal. No process runner or command interface.

The E75 gate pin is historical provenance, not fresh kernel authentication.
Injected backends are test doubles only; this module cannot release ATPG work.
"""
import copy
import hashlib
import json
import os
import re
import stat
import threading

SCHEMA = 'prospective-lifecycle-journal-v2'
E75_GATE_RAW_SHA256 = 'ba40af43a9a3d6f79f8abcf0c563cbb42705cf639222a384044ef51f87d66e8e'
E75_REVIEW_RESPONSE_SHA256 = 'e7a2ccdcaa900b12d9ab813c8940791a1edd731914eb0517b15012e8e93762ef'
E75_GATE_SOURCE_SHA256 = '3a777175d1f4687e03950c5dd0aa97b8c3cba3a90905be672af274f7c28dea15'
PROFILES = ('success', 'failure', 'timeout_group')
FIXED_PROFILES = PROFILES
COST_SCOPE = 'SYNTHETIC_PRE_INTENT_ACK_TO_POST_VERIFIED_CLEANUP_PRE_TERMINAL_ACK'
EXPECTED = {'success': ('SUCCESS', 0, False), 'failure': ('FAILURE', 7, False),
            'timeout_group': ('TIMEOUT', -9, True)}
MAX_ATTEMPTS = 64
MAX_EVENTS = 256
MAX_LINE = 16384
MAX_TOTAL = 1048576
ZERO = '0' * 64
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z')
_WORKER = threading.Lock()


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'DUPLICATE_JSON_KEY')
        value[key] = item
    return value


def reject_constant(value):
    raise ValueError('NONFINITE_JSON:' + value)


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique_pairs, parse_constant=reject_constant)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def exact(value, keys, reason):
    require(type(value) is dict and set(value) == set(keys), reason)


def clock_value(clock):
    value = clock.capture()
    require(type(value) is tuple and len(value) == 2, 'CLOCK_TUPLE')
    session, ns = value
    require(type(session) is str and ID.fullmatch(session) and
            type(ns) is int and 0 <= ns < 2**63, 'CLOCK_VALUE')
    return session, ns


def file_id(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns)


def identity_valid(value):
    if type(value) is not dict or set(value) != {'host', 'boot_id', 'pid', 'start_ticks'}:
        return False
    return (type(value['host']) is str and value['host'].startswith('synthetic-') and
            len(value['host']) <= 128 and ID.fullmatch(value['host']) and
            type(value['boot_id']) is str and len(value['boot_id']) <= 128 and
            ID.fullmatch(value['boot_id']) and type(value['pid']) is int and
            1 <= value['pid'] <= 2**31-1 and type(value['start_ticks']) is int and
            1 <= value['start_ticks'] < 2**63)


def header():
    body = dict(kind='HEADER', schema=SCHEMA, e75_gate_raw_sha256=E75_GATE_RAW_SHA256,
                e75_review_response_sha256=E75_REVIEW_RESPONSE_SHA256,
                e75_gate_source_sha256=E75_GATE_SOURCE_SHA256,
                evidence_kind='REVIEWED_HISTORICAL_FIXED_SYNTHETIC_ONLY', prev=ZERO)
    return dict(body, sha256=sha(canonical(body)))


class State:
    def __init__(self):
        self.head = header()['sha256']
        self.events = 0
        self.attempts = {}
        self.active = None

    def event(self, kind, aid, payload):
        return dict(seq=self.events+1, kind=kind, attempt_id=aid,
                    payload=payload, prev=self.head)

    def apply(self, row):
        exact(row, ('seq', 'kind', 'attempt_id', 'payload', 'prev', 'sha256'), 'EVENT_KEYS')
        body = {key: row[key] for key in ('seq', 'kind', 'attempt_id', 'payload', 'prev')}
        require(type(row['seq']) is int and row['seq'] == self.events+1 and
                self.events < MAX_EVENTS and row['prev'] == self.head and
                type(row['sha256']) is str and row['sha256'] == sha(canonical(body)),
                'EVENT_CHAIN')
        kind, aid, payload = row['kind'], row['attempt_id'], row['payload']
        require(type(aid) is str and ID.fullmatch(aid), 'ATTEMPT_ID')
        if kind == 'INTENT':
            exact(payload, ('profile', 'clock_session', 'prelaunch_ns'), 'INTENT_KEYS')
            prior = next(reversed(self.attempts.values())) if self.attempts else None
            require(self.active is None and aid not in self.attempts and
                    len(self.attempts) < MAX_ATTEMPTS and payload['profile'] in PROFILES and
                    type(payload['clock_session']) is str and ID.fullmatch(payload['clock_session']) and
                    type(payload['prelaunch_ns']) is int and
                    0 <= payload['prelaunch_ns'] < 2**63 and
                    (prior is None or (prior['session'] == payload['clock_session'] and
                     prior['end_ns'] is not None and payload['prelaunch_ns'] >= prior['end_ns'])),
                    'INTENT_STATE')
            self.attempts[aid] = dict(profile=payload['profile'], phase='INTENT',
                                      start_ns=payload['prelaunch_ns'],
                                      session=payload['clock_session'], identity=None,
                                      end_ns=None, interval_ns=None)
            self.active = aid
        elif kind == 'LAUNCHED':
            exact(payload, ('identity',), 'LAUNCHED_KEYS')
            require(self.active == aid and self.attempts[aid]['phase'] == 'INTENT' and
                    identity_valid(payload['identity']) and
                    all(item['identity'] != payload['identity'] for item in self.attempts.values()),
                    'LAUNCHED_STATE')
            self.attempts[aid]['phase'] = 'LAUNCHED'
            self.attempts[aid]['identity'] = payload['identity']
        elif kind == 'REAPED':
            exact(payload, ('identity', 'clock_session', 'end_ns', 'interval_ns',
                            'status', 'returncode', 'timed_out', 'leader_reaped',
                            'observed_group_empty'), 'REAPED_KEYS')
            require(self.active == aid and self.attempts[aid]['phase'] == 'LAUNCHED', 'REAPED_STATE')
            item = self.attempts[aid]
            expect = EXPECTED[item['profile']]
            require(payload['identity'] == item['identity'] and
                    payload['clock_session'] == item['session'] and
                    type(payload['end_ns']) is int and
                    item['start_ns'] <= payload['end_ns'] < 2**63 and
                    type(payload['interval_ns']) is int and
                    payload['interval_ns'] == payload['end_ns']-item['start_ns'] and
                    (payload['status'], payload['returncode'], payload['timed_out']) == expect and
                    type(payload['returncode']) is int and
                    type(payload['timed_out']) is bool and
                    payload['leader_reaped'] is True and
                    payload['observed_group_empty'] is True, 'REAPED_PROOF')
            item.update(phase='REAPED', end_ns=payload['end_ns'],
                        interval_ns=payload['interval_ns'])
            self.active = None
        else:
            raise ValueError('EVENT_KIND')
        self.events += 1
        self.head = row['sha256']

    def summary(self, acknowledged=False, available=True):
        complete = bool(self.attempts) and self.active is None and all(item['phase'] == 'REAPED'
                                                for item in self.attempts.values())
        usable = acknowledged and available and complete
        return dict(schema=SCHEMA, head_sha256=self.head, event_count=self.events,
                    e75_gate_raw_sha256=E75_GATE_RAW_SHA256,
                    e75_review_response_sha256=E75_REVIEW_RESPONSE_SHA256,
                    synthetic_only=True, os_authenticated=False, actual_processes=0,
                    attempt_count=len(self.attempts), active_attempt_id=self.active,
                    structural_complete=complete, fsync_acknowledgments_verified=acknowledged and available,
                    complete_live_acknowledged=usable, observed_interval_ns_sum_or_None=(sum(item['interval_ns']
                    for item in self.attempts.values()) if usable else None),
                    cost_scope=COST_SCOPE, cost_kind='SYNTHETIC_ACKED_PRELAUNCH_TO_VERIFIED_CLEANUP' if usable else None,
                    attempts=copy.deepcopy(self.attempts),
                    production_execution_ready=False, training_release=False,
                    real_atpg_jobs=0, physical_atpg_runtime_ns=None)


class Journal:
    """Exclusive owner; no reopen-as-writer and no automatic repair or retry."""
    def __init__(self):
        raise TypeError('USE_CREATE')

    @classmethod
    def create(cls, path):
        raw = canonical(header()) + b'\n'
        require(len(raw) <= MAX_LINE, 'HEADER_BOUND')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, 'O_NOFOLLOW', 0), 0o600)
        stream = os.fdopen(fd, 'wb', buffering=0)
        try:
            require(stream.write(raw) == len(raw), 'SHORT_WRITE')
            os.fsync(stream.fileno())
            instance = object.__new__(cls)
            instance._path = path
            instance._stream = stream
            instance._state = State()
            instance._size = len(raw)
            instance._identity = file_id(os.fstat(stream.fileno()))
            instance._poisoned = False
            instance._lock = threading.Lock()
            instance._check()
            return instance
        except BaseException:
            stream.close()
            raise

    def _check(self):
        fd = os.fstat(self._stream.fileno())
        path = os.stat(self._path, follow_symlinks=False)
        require(stat.S_ISREG(fd.st_mode) and fd.st_nlink == 1 and
                file_id(fd) == self._identity and file_id(path) == self._identity and
                fd.st_size == self._size, 'JOURNAL_IDENTITY_CHANGED')

    def append(self, kind, aid, payload):
        with self._lock:
            require(not self._poisoned and not self._stream.closed, 'JOURNAL_UNAVAILABLE')
            trial = copy.deepcopy(self._state)
            body = trial.event(kind, aid, copy.deepcopy(payload))
            row = dict(body, sha256=sha(canonical(body)))
            trial.apply(row)
            raw = canonical(row) + b'\n'
            require(len(raw) <= MAX_LINE and self._size + len(raw) <= MAX_TOTAL,
                    'JOURNAL_BYTE_BOUND')
            try:
                self._check()
                require(self._stream.write(raw) == len(raw), 'SHORT_WRITE')
                os.fsync(self._stream.fileno())
                observed = os.fstat(self._stream.fileno())
                require(observed.st_size == self._size + len(raw), 'JOURNAL_SIZE_CHANGED')
                self._size = observed.st_size
                self._identity = file_id(observed)
                self._check()
            except BaseException:
                self._poisoned = True
                raise
            self._state = trial
            return copy.deepcopy(row)

    def run(self, attempt_id, profile, backend, clock):
        """One in-process fake attempt; callbacks are never production authority."""
        require(type(attempt_id) is str and ID.fullmatch(attempt_id) and
                type(profile) is str and profile in PROFILES, 'FIXED_SYNTHETIC_ATTEMPT')
        require(getattr(backend, 'synthetic_only', None) is True and
                getattr(backend, 'os_authenticated', None) is False and
                getattr(backend, 'actual_processes', None) == 0,
                'SYNTHETIC_BACKEND_ONLY')
        require(_WORKER.acquire(False), 'SINGLE_WORKER_BUSY')
        try:
            require(not self._poisoned and not self._stream.closed and
                    self._state.active is None and attempt_id not in self._state.attempts and
                    all(item['phase'] == 'REAPED' for item in self._state.attempts.values()),
                    'UNRESOLVED_OR_DUPLICATE_ATTEMPT')
            session, start_ns = clock_value(clock)
            self.append('INTENT', attempt_id,
                        dict(profile=profile, clock_session=session, prelaunch_ns=start_ns))
            try:
                handle, identity = backend.launch(profile)
                require(handle is not None, 'UNKNOWN_SPAWN_HANDLE')
            except BaseException:
                self._poisoned = True  # A spawn without a handle is uncertain.
                raise
            problem = None
            result = None
            try:
                require(identity_valid(identity), 'SYNTHETIC_IDENTITY')
                identity = copy.deepcopy(identity)
                self.append('LAUNCHED', attempt_id, dict(identity=identity))
                result = backend.finish(handle, profile)
            except BaseException as exc:
                problem = exc
            try:
                cleanup = backend.cleanup(handle)
                exact(cleanup, ('leader_reaped', 'observed_group_empty'), 'CLEANUP_KEYS')
                require(cleanup['leader_reaped'] is True and
                        cleanup['observed_group_empty'] is True, 'CLEANUP_UNVERIFIED')
            except BaseException as cleanup_error:
                self._poisoned = True
                if problem is not None:
                    raise cleanup_error from problem
                raise
            if problem is not None:
                self._poisoned = True
                raise problem
            try:
                exact(result, ('status', 'returncode', 'timed_out'), 'FINISH_KEYS')
                require((result['status'], result['returncode'], result['timed_out']) ==
                        EXPECTED[profile], 'FINISH_PROFILE')
                end_session, end_ns = clock_value(clock)
                payload = dict(identity=identity, clock_session=end_session, end_ns=end_ns,
                               interval_ns=end_ns-start_ns, status=result['status'],
                               returncode=result['returncode'], timed_out=result['timed_out'],
                               leader_reaped=True, observed_group_empty=True)
                self.append('REAPED', attempt_id, payload)
                return self.snapshot()
            except BaseException:
                self._poisoned = True
                raise
        finally:
            _WORKER.release()

    def snapshot(self):
        if not self._poisoned and not self._stream.closed:
            try:
                self._check()
            except BaseException:
                self._poisoned = True
        return self._state.summary(acknowledged=True,
                                   available=not self._poisoned and not self._stream.closed)

    def close(self):
        self._stream.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def load(path):
    """Strict structure replay; bytes cannot prove historical fsync ACK."""
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        path_before = os.stat(path, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                before.st_size <= MAX_TOTAL and file_id(before) == file_id(path_before),
                'JOURNAL_FILE_BOUND')
        total = 0
        state = State()
        first = True
        while True:
            raw = stream.readline(MAX_LINE+1)
            if not raw:
                break
            total += len(raw)
            require(len(raw) <= MAX_LINE and total <= MAX_TOTAL and raw.endswith(b'\n'),
                    'TORN_OR_OVERSIZE_LINE')
            row = parse(raw)
            require(canonical(row)+b'\n' == raw, 'NONCANONICAL_JOURNAL')
            if first:
                require(row == header(), 'HEADER_PIN')
                first = False
            else:
                state.apply(row)
        require(not first, 'MISSING_HEADER')
        after = os.fstat(stream.fileno())
        path_after = os.stat(path, follow_symlinks=False)
        require(total == before.st_size and file_id(before) == file_id(after) and
                file_id(path_before) == file_id(path_after) and
                file_id(after) == file_id(path_after), 'JOURNAL_CHANGED_DURING_REPLAY')
        return state.summary(acknowledged=False)
