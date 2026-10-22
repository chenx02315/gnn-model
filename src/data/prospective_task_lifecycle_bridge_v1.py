"""Local synthetic-only bridge between E82 debit and E76 lifecycle journals.

No process launcher, ATPG adapter, OS authentication, restart writer, or global
quota. The caller-selected directory is only a local namespace anchor.
"""
import copy
import hashlib
import json
import os
import re
import stat
import threading

from src.data import prospective_lifecycle_journal_v2 as life
from src.data import prospective_stage_budget_journal_v2 as budget

SCHEMA = 'prospective-task-lifecycle-bridge-v1'
MAX_TASKS = 64
MAX_BINDING = 65536
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z')
FILES = ('binding.json', 'budget.jsonl', 'lifecycle.jsonl')


def require(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def exact(value, keys, reason):
    require(type(value) is dict and set(value) == set(keys), reason)


def _root(root, exists):
    fixed = os.path.normpath(os.fspath(root))
    require(type(fixed) is str and os.path.isabs(fixed), 'ABSOLUTE_PHASE_ROOT')
    target = fixed if exists else os.path.dirname(fixed)
    while True:
        info = os.lstat(target)
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and
                info.st_nlink >= 1, 'PHASE_DIRECTORY_IDENTITY')
        parent = os.path.dirname(target)
        if parent == target:
            break
        target = parent
    return fixed


def _file_id(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns)


def _read(path, limit):
    before_path = os.lstat(path)
    require(stat.S_ISREG(before_path.st_mode) and before_path.st_nlink == 1 and
            0 < before_path.st_size <= limit, 'BRIDGE_FILE_BOUND')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) |
                 getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0))
    try:
        before = os.fstat(fd)
        require(_file_id(before) == _file_id(before_path), 'BRIDGE_FILE_CHANGED')
        raw = os.read(fd, before.st_size)
        after = os.fstat(fd)
        after_path = os.lstat(path)
        require(len(raw) == before.st_size and _file_id(before) ==
                _file_id(after) == _file_id(after_path), 'BRIDGE_FILE_CHANGED')
        return raw
    finally:
        os.close(fd)


def _entries(root):
    names=[]
    with os.scandir(root) as stream:
        for entry in stream:
            names.append(entry.name)
            require(len(names) <= len(FILES), 'PHASE_ENTRIES_CHANGED')
    require(set(names) == set(FILES), 'PHASE_ENTRIES_CHANGED')


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE_JSON')))
    require(canonical(value) == raw, 'NONCANONICAL_BRIDGE_JSON')
    return value


def _attempt_id(base_sha256, slot, node):
    body = dict(manifest_base_sha256=base_sha256, slot=slot, task_uid=node['task_uid'],
                request_sha256=node['request_sha256'])
    return 'a' + sha(canonical(body))[:40]


def binding(phase_uid, plan, caps, profiles, clock_session):
    require(type(phase_uid) is str and ID.fullmatch(phase_uid), 'PHASE_UID')
    require(type(clock_session) is str and life.ID.fullmatch(clock_session),
            'CLOCK_SESSION')
    require(type(plan) is list and 1 <= len(plan) <= MAX_TASKS, 'BRIDGE_TASK_BOUND')
    require(type(caps) is dict and set(caps) ==
            {'max_tessent_calls', 'max_translation_calls', 'phase_envelope_ns'},
            'BINDING_CAPS')
    frozen = copy.deepcopy(plan)
    frozen_caps = copy.deepcopy(caps)
    frozen_profiles = copy.deepcopy(profiles)
    # E82/v1 validate the exact ordered plan and caps, before a directory write.
    budget.header(frozen, frozen_caps['max_tessent_calls'],
                  frozen_caps['max_translation_calls'], frozen_caps['phase_envelope_ns'])
    require(type(frozen_profiles) is dict and
            set(frozen_profiles) == {node['task_uid'] for node in frozen} and
            all(type(value) is str and value in life.PROFILES
                for value in frozen_profiles.values()), 'FIXED_PROFILE_MAP')
    base = dict(schema=SCHEMA, phase_uid=phase_uid, plan=frozen,
                caps=frozen_caps, profiles=frozen_profiles,
                clock_session=clock_session, attempt_id_algorithm='manifest-base-sha256-slot-v1',
                synthetic_only=True, execution_ready=False, training_release=False)
    base_sha = sha(canonical(base))
    rows = [dict(task_uid=node['task_uid'], request_sha256=node['request_sha256'],
                 profile=frozen_profiles[node['task_uid']],
                 attempt_id=_attempt_id(base_sha, slot, node))
            for slot, node in enumerate(frozen)]
    body = dict(base, attempts=rows)
    return dict(body, sha256=sha(canonical(body)))


def _binding(raw):
    row = _json(raw)
    exact(row, ('schema', 'phase_uid', 'plan', 'caps', 'profiles', 'clock_session',
                'attempt_id_algorithm', 'attempts', 'synthetic_only',
                'execution_ready', 'training_release', 'sha256'), 'BINDING_KEYS')
    exact(row['caps'], ('max_tessent_calls', 'max_translation_calls',
                        'phase_envelope_ns'), 'BINDING_CAPS')
    expected = binding(row['phase_uid'], row['plan'], row['caps'],
                       row['profiles'], row['clock_session'])
    require(canonical(row) == canonical(expected), 'BINDING_PIN')
    return row


def _rows(path, limit):
    raw = _read(path, limit)
    lines = raw.splitlines(keepends=True)
    require(lines and all(line.endswith(b'\n') and len(line) <=
                          min(budget.MAX_LINE, life.MAX_LINE) for line in lines),
            'TORN_BRIDGE_JOURNAL')
    return [_json(line[:-1]) for line in lines]


def _load_lifecycle(path):
    rows = _rows(path, life.MAX_TOTAL)
    require(rows[0] == life.header() and len(rows)-1 <= life.MAX_EVENTS,
            'LIFECYCLE_HEADER_OR_BOUND')
    state = life.State()
    for row in rows[1:]:
        if type(row) is dict and row.get('kind') == 'REAPED':
            payload = row.get('payload')
            aid = row.get('attempt_id')
            require(type(payload) is dict and
                    life.identity_valid(payload.get('identity')) and
                    aid in state.attempts and
                    canonical(payload['identity']) ==
                    canonical(state.attempts[aid]['identity']),
                    'BRIDGE_REAPED_IDENTITY_ALIAS')
        state.apply(row)
    return state.summary(acknowledged=False)


class _BoundClock:
    def __init__(self, clock, session):
        self._clock = clock
        self._session = session

    def capture(self):
        value = self._clock.capture()
        require(type(value) is tuple and len(value) == 2 and
                value[0] == self._session, 'BRIDGE_CLOCK_SESSION')
        return value


class _BoundBackend:
    def __init__(self, bridge, backend):
        self._bridge = bridge
        self._backend = backend
        self.synthetic_only = getattr(backend, 'synthetic_only', None)
        self.os_authenticated = getattr(backend, 'os_authenticated', None)
        self.actual_processes = getattr(backend, 'actual_processes', None)

    def _ready(self, expected_phase):
        require(not self._bridge._poisoned, 'BRIDGE_UNAVAILABLE')
        self._bridge._check()
        b = self._bridge._budget.snapshot()
        l = self._bridge._life.snapshot()
        require(b['fsync_acknowledgments_verified'] and
                l['fsync_acknowledgments_verified'], 'PRE_CALLBACK_ACK_UNAVAILABLE')
        joined = _join(self._bridge._root, self._bridge._manifest, b, l)
        aid = self._bridge._manifest['attempts'][self._bridge._next]['attempt_id']
        require(joined['paired_task_count'] == self._bridge._next and
                b['active_slot'] == self._bridge._next and
                l['active_attempt_id'] == aid and
                l['attempts'][aid]['phase'] == expected_phase,
                'PRE_CALLBACK_STATE_BINDING')

    def launch(self, profile):
        self._ready('INTENT')
        return self._backend.launch(profile)

    def finish(self, handle, profile):
        self._ready('LAUNCHED')
        return self._backend.finish(handle, profile)

    def cleanup(self, handle):
        # Never obstruct cleanup of an already known handle due to bridge
        # poisoning: E76 must still attempt it on every post-launch path.
        return self._backend.cleanup(handle)


def _join(root, manifest, b, l):
    b_rows = _rows(os.path.join(root, FILES[1]), budget.MAX_TOTAL)
    l_rows = _rows(os.path.join(root, FILES[2]), life.MAX_TOTAL)
    expected_header=budget.header(manifest['plan'], **manifest['caps'])
    require(canonical(b_rows[0]) == canonical(expected_header),
            'BRIDGE_BUDGET_HEADER_BINDING')
    require(canonical(l_rows[0]) == canonical(life.header()),
            'BRIDGE_LIFECYCLE_HEADER_BINDING')
    require(b_rows[-1]['sha256'] == b['head_sha256'] and
            l_rows[-1]['sha256'] == l['head_sha256'] and
            len(b_rows)-1 == b['event_count'] and len(l_rows)-1 == l['event_count'],
            'BRIDGE_JOURNAL_CHANGED')
    debits = [r['payload'] for r in b_rows[1:] if r['kind'] == 'DEBIT']
    settlements = [r['payload'] for r in b_rows[1:] if r['kind'] == 'SETTLE']
    aids = list(l['attempts'])
    require(len(debits) <= len(manifest['attempts']) and len(aids) <= len(debits) and
            len(settlements) <= len(aids), 'BRIDGE_EVENT_COUNTS')
    hosts = set()
    identities = set()
    paired = 0
    for slot, item in enumerate(debits):
        token = item['token']
        expected = manifest['attempts'][slot]
        require(item['task_uid'] == expected['task_uid'] and
                token['task']['task_uid'] == expected['task_uid'] and
                token['task']['request_sha256'] == expected['request_sha256'],
                'BRIDGE_TASK_REQUEST_BINDING')
        if slot >= len(aids):
            continue
        aid = expected['attempt_id']
        require(aids[slot] == aid, 'BRIDGE_ATTEMPT_BINDING')
        attempt = l['attempts'][aid]
        require(attempt['profile'] == expected['profile'] and
                attempt['session'] == manifest['clock_session'],
                'BRIDGE_PROFILE_CLOCK_BINDING')
        if attempt['identity'] is not None:
            identity = attempt['identity']
            hosts.add((identity['host'], identity['boot_id']))
            key = tuple(identity[k] for k in ('host', 'boot_id', 'pid', 'start_ticks'))
            require(key not in identities, 'BRIDGE_IDENTITY_REUSE')
            identities.add(key)
        if slot < len(settlements):
            settlement = settlements[slot]
            require(attempt['phase'] == 'REAPED' and
                    canonical(settlement['token']) == canonical(token) and
                    settlement['status'] == {'success': 'SUCCESS', 'failure': 'FAILED',
                                             'timeout_group': 'TIMEOUT'}[attempt['profile']] and
                    settlement['elapsed_ns'] == attempt['interval_ns'] and
                    settlement['cleanup_verified'] is True, 'BRIDGE_SETTLEMENT_BINDING')
            paired += 1
    require(len(hosts) <= 1 and all(aids[i] == manifest['attempts'][i]['attempt_id']
                                  for i in range(len(aids))), 'BRIDGE_IDENTITY_PHASE')
    require(paired == len(settlements), 'BRIDGE_PAIRED_PREFIX')
    complete = (paired == len(manifest['plan']) and b['declared_plan_complete'] and
                l['structural_complete'])
    return dict(schema=SCHEMA, phase_uid=manifest['phase_uid'],
                binding_sha256=manifest['sha256'], paired_task_count=paired,
                task_count=len(manifest['plan']), structural_full_success=bool(complete),
                structural_paired_prefix_valid=True,
                paired_plan_complete=bool(complete),
                structural_incomplete=not complete, budget=b, lifecycle=l,
                phase_failed_or_stopped=b['stopped_reason'] is not None,
                synthetic_only=True, os_authenticated=False, real_atpg_jobs=0,
                launch_authorized=False, execution_ready=False, training_release=False)


class Bridge:
    """Single-process, non-resumable synthetic coordinator."""
    def __init__(self):
        raise TypeError('USE_CREATE')

    @classmethod
    def create(cls, root, phase_uid, plan, *, max_tessent_calls,
               max_translation_calls, phase_envelope_ns, profiles, clock_session):
        caps = dict(max_tessent_calls=max_tessent_calls,
                    max_translation_calls=max_translation_calls,
                    phase_envelope_ns=phase_envelope_ns)
        manifest = binding(phase_uid, plan, caps, profiles, clock_session)
        raw = canonical(manifest)
        require(len(raw) <= MAX_BINDING, 'BINDING_BOUND')
        fixed = _root(root, False)
        os.mkdir(fixed, 0o700)
        fd = None
        budget_writer = lifecycle_writer = None
        try:
            path = os.path.join(fixed, FILES[0])
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0), 0o600)
            require(os.write(fd, raw) == len(raw), 'SHORT_BINDING_WRITE')
            os.fsync(fd)
            closing_fd = fd
            fd = None
            os.close(closing_fd)
            budget_writer = budget.Journal.create(os.path.join(fixed, FILES[1]),
                manifest['plan'], **manifest['caps'])
            lifecycle_writer = life.Journal.create(os.path.join(fixed, FILES[2]))
            instance = object.__new__(cls)
            instance._root = fixed
            instance._manifest = manifest
            instance._binding_raw = raw
            instance._budget = budget_writer
            instance._life = lifecycle_writer
            instance._lock = threading.Lock()
            instance._poisoned = False
            instance._closed = False
            instance._next = 0
            instance._host_boot = None
            instance._identities = set()
            instance._check()
            return instance
        except BaseException as primary:
            cleanup_errors = []
            if fd is not None:
                try:os.close(fd)
                except BaseException as exc:cleanup_errors.append(exc)
            if lifecycle_writer is not None:
                try:lifecycle_writer.close()
                except BaseException as exc:cleanup_errors.append(exc)
            if budget_writer is not None:
                try:budget_writer.close()
                except BaseException as exc:cleanup_errors.append(exc)
            if cleanup_errors:
                for extra in cleanup_errors[1:]:
                    cleanup_errors[0].add_note('Additional cleanup error: '+repr(extra))
                raise cleanup_errors[0] from primary
            raise

    def _check(self):
        _root(self._root, True)
        require(_read(os.path.join(self._root, FILES[0]), MAX_BINDING) ==
                self._binding_raw, 'BINDING_CHANGED')
        _entries(self._root)

    def run(self, task_uid, profile, backend, clock):
        if not self._lock.acquire(False):
            self._poisoned = True
            raise ValueError('BRIDGE_REENTRANT_OPERATION')
        try:
            require(not self._poisoned and not self._closed, 'BRIDGE_UNAVAILABLE')
            self._check()
            require(self._next < len(self._manifest['plan']) and
                    type(task_uid) is str and
                    task_uid == self._manifest['plan'][self._next]['task_uid'] and
                    type(profile) is str and
                    profile == self._manifest['profiles'][task_uid],
                    'EXACT_NEXT_SYNTHETIC_TASK')
            token = self._budget.reserve(task_uid)  # Durable debit ACK precedes INTENT.
            require(not self._poisoned, 'BRIDGE_UNAVAILABLE')
            self._check()
            aid = self._manifest['attempts'][self._next]['attempt_id']
            result = self._life.run(aid, profile, _BoundBackend(self, backend),
                                    _BoundClock(clock, self._manifest['clock_session']))
            require(not self._poisoned and result['complete_live_acknowledged'],
                    'LIFECYCLE_ACK_UNAVAILABLE')
            attempt = result['attempts'][aid]
            identity = attempt['identity']
            host_boot = (identity['host'], identity['boot_id'])
            key = tuple(identity[k] for k in ('host', 'boot_id', 'pid', 'start_ticks'))
            require(self._host_boot is None or host_boot == self._host_boot,
                    'BRIDGE_HOST_BOOT_CHANGED')
            require(key not in self._identities, 'BRIDGE_IDENTITY_REUSE')
            self._host_boot = host_boot
            self._identities.add(key)
            status = {'success': 'SUCCESS', 'failure': 'FAILED',
                      'timeout_group': 'TIMEOUT'}[profile]
            settled = self._budget.settle(token, status, attempt['interval_ns'], True)
            require(not self._poisoned and settled['fsync_acknowledgments_verified'],
                    'BUDGET_SETTLEMENT_ACK_UNAVAILABLE')
            self._next += 1
            return self._snapshot_locked()
        except BaseException:
            self._poisoned = True
            raise
        finally:
            self._lock.release()

    def _snapshot_locked(self):
        if not self._poisoned and not self._closed:
            try:
                self._check()
                b = self._budget.snapshot()
                l = self._life.snapshot()
                require(b['fsync_acknowledgments_verified'] and
                        l['fsync_acknowledgments_verified'], 'BRIDGE_ACK_UNAVAILABLE')
                state = _join(self._root, self._manifest, b, l)
                require(state['paired_task_count'] == self._next, 'BRIDGE_LIVE_JOIN')
            except BaseException:
                self._poisoned = True
        if self._poisoned or self._closed:
            return dict(schema=SCHEMA, phase_uid=self._manifest['phase_uid'],
                        binding_sha256=self._manifest['sha256'], bridge_poisoned=self._poisoned,
                        poisoned=self._poisoned,
                        task_count=len(self._manifest['plan']),
                        paired_task_count=None, paired_plan_complete=False,
                        structural_paired_prefix_valid=False,
                        phase_failed_or_stopped=True,
                        budget=None, lifecycle=None,
                        fsync_acknowledgments_verified=False, complete_live_acknowledged=False,
                        phase_complete_live_acknowledged=False,
                        observed_interval_ns_sum_or_None=None, synthetic_only=True,
                        os_authenticated=False, real_atpg_jobs=0, launch_authorized=False,
                        execution_ready=False, training_release=False)
        state.update(bridge_poisoned=False, fsync_acknowledgments_verified=True,
                     complete_live_acknowledged=state['structural_full_success'],
                     phase_complete_live_acknowledged=state['structural_full_success'],
                     poisoned=False,
                     observed_interval_ns_sum_or_None=(
                         l['observed_interval_ns_sum_or_None'] if
                         state['structural_full_success'] else None))
        return state

    def snapshot(self):
        if not self._lock.acquire(False):
            self._poisoned = True
            return dict(schema=SCHEMA, bridge_poisoned=True,
                        poisoned=True,
                        phase_uid=self._manifest['phase_uid'],
                        binding_sha256=self._manifest['sha256'],
                        task_count=len(self._manifest['plan']),
                        paired_task_count=None, paired_plan_complete=False,
                        structural_paired_prefix_valid=False,
                        phase_failed_or_stopped=True,
                        budget=None, lifecycle=None,
                        fsync_acknowledgments_verified=False,
                        complete_live_acknowledged=False,
                        phase_complete_live_acknowledged=False,
                        observed_interval_ns_sum_or_None=None,
                        execution_ready=False, training_release=False)
        try:
            return self._snapshot_locked()
        finally:
            self._lock.release()

    def close(self):
        if not self._lock.acquire(False):
            self._poisoned = True
            raise ValueError('BRIDGE_REENTRANT_OPERATION')
        try:
            if not self._closed:
                self._closed = True
                try:
                    try:self._life.close()
                    finally:self._budget.close()
                except BaseException:
                    self._poisoned = True
                    raise
        finally:
            self._lock.release()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def load(root):
    """Read-only structural replay; never restores a writer or historical ACK."""
    fixed = _root(root, True)
    _entries(fixed)
    manifest = _binding(_read(os.path.join(fixed, FILES[0]), MAX_BINDING))
    b = budget.load(os.path.join(fixed, FILES[1]))
    l = _load_lifecycle(os.path.join(fixed, FILES[2]))
    state = _join(fixed, manifest, b, l)
    state.update(fsync_acknowledgments_verified=False,
                 complete_live_acknowledged=False,
                 phase_complete_live_acknowledged=False,
                 poisoned=False,
                 observed_interval_ns_sum_or_None=None,
                 no_writer_resume=True)
    return state
