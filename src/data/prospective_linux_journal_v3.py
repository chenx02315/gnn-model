"""E77 fixed Linux gate + durable journal connection, not a production runner.

Public library only: no CLI, authorization, arbitrary argv/cwd, ATPG or training.
The fixed backend is not to be invoked outside a separately approved Linux
PID-1/cgroup-v2 sandbox. This module has only local mock-test evidence.
"""
import copy
import ctypes
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import threading
import time

from . import prospective_lifecycle_journal_v2 as base
from scripts import verify_prospective_linux_lifecycle_v2 as gate

SCHEMA = 'prospective-linux-lifecycle-journal-v3'
FIXED_PROFILES = gate.PROFILES
COST_SCOPE = 'PRE_INTENT_ACK_TO_POST_VERIFIED_CLEANUP_PRE_TERMINAL_ACK_INCLUSIVE_NOT_ATOMIC_ATPG'
GATE_SOURCE_SHA256 = '3a777175d1f4687e03950c5dd0aa97b8c3cba3a90905be672af274f7c28dea15'
EXPECTED = base.EXPECTED
_WORKER = threading.Lock()
HOST = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
BOOT = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z')


def identity_valid(value):
    if type(value) is not dict or set(value) != {'host', 'boot_id', 'pid', 'pgrp', 'start_ticks'}:
        return False
    return (type(value['host']) is str and HOST.fullmatch(value['host']) and
            type(value['boot_id']) is str and BOOT.fullmatch(value['boot_id']) and
            type(value['pid']) is int and 1 < value['pid'] <= 2**31-1 and
            type(value['pgrp']) is int and value['pgrp'] == value['pid'] and
            type(value['start_ticks']) is int and 1 <= value['start_ticks'] < 2**63)


def header():
    body = dict(kind='HEADER', schema=SCHEMA, gate_source_sha256=GATE_SOURCE_SHA256,
                scope='FIXED_LINUX_SYNTHETIC_GROUP_ONLY', prev=base.ZERO)
    return dict(body, sha256=base.sha(base.canonical(body)))


class State(base.State):
    def __init__(self):
        super().__init__()
        self.head = header()['sha256']

    def apply(self, row):
        base.exact(row, ('seq', 'kind', 'attempt_id', 'payload', 'prev', 'sha256'), 'EVENT_KEYS')
        body = {key: row[key] for key in ('seq', 'kind', 'attempt_id', 'payload', 'prev')}
        base.require(type(row['seq']) is int and row['seq'] == self.events+1 and
                     self.events < base.MAX_EVENTS and row['prev'] == self.head and
                     type(row['sha256']) is str and row['sha256'] == base.sha(base.canonical(body)),
                     'EVENT_CHAIN')
        kind, aid, payload = row['kind'], row['attempt_id'], row['payload']
        base.require(type(aid) is str and base.ID.fullmatch(aid), 'ATTEMPT_ID')
        if kind == 'INTENT':
            base.exact(payload, ('profile', 'clock_session', 'prelaunch_ns'), 'INTENT_KEYS')
            prior = next(reversed(self.attempts.values())) if self.attempts else None
            base.require(self.active is None and aid not in self.attempts and
                         len(self.attempts) < len(FIXED_PROFILES) and
                         payload['profile'] == FIXED_PROFILES[len(self.attempts)] and
                         type(payload['clock_session']) is str and base.ID.fullmatch(payload['clock_session']) and
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
            base.exact(payload, ('identity',), 'LAUNCHED_KEYS')
            first_identity = next((item['identity'] for item in self.attempts.values()
                                   if item['identity'] is not None), None)
            base.require(self.active == aid and self.attempts[aid]['phase'] == 'INTENT' and
                         identity_valid(payload['identity']) and
                         (first_identity is None or
                          (payload['identity']['host'], payload['identity']['boot_id']) ==
                          (first_identity['host'], first_identity['boot_id'])) and
                         all(item['identity'] != payload['identity'] for item in self.attempts.values()),
                         'LAUNCHED_STATE')
            self.attempts[aid]['phase'] = 'LAUNCHED'
            self.attempts[aid]['identity'] = payload['identity']
        elif kind == 'REAPED':
            base.exact(payload, ('identity', 'clock_session', 'end_ns', 'interval_ns',
                                 'status', 'returncode', 'timed_out', 'leader_reaped',
                                 'observed_group_empty'), 'REAPED_KEYS')
            base.require(self.active == aid and self.attempts[aid]['phase'] == 'LAUNCHED', 'REAPED_STATE')
            item = self.attempts[aid]
            base.require(payload['identity'] == item['identity'] and
                         payload['clock_session'] == item['session'] and
                         type(payload['end_ns']) is int and
                         item['start_ns'] <= payload['end_ns'] < 2**63 and
                         type(payload['interval_ns']) is int and
                         payload['interval_ns'] == payload['end_ns']-item['start_ns'] and
                         (payload['status'], payload['returncode'], payload['timed_out']) ==
                         EXPECTED[item['profile']] and
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

    def summary(self, acknowledged=False, available=True, unknown_spawn=False):
        value = super().summary(acknowledged, available)
        prefix = value['structural_complete']
        fixed_complete = (len(self.attempts) == len(FIXED_PROFILES) and prefix and
                          tuple(item['profile'] for item in self.attempts.values()) == FIXED_PROFILES)
        usable = fixed_complete and acknowledged and available
        value.update(schema=SCHEMA, gate_source_sha256=GATE_SOURCE_SHA256,
                     cost_scope=COST_SCOPE, os_authenticated=False,
                     terminated_prefix_complete=prefix,
                     structural_complete=fixed_complete,
                     complete_live_acknowledged=usable,
                     observed_interval_ns_sum_or_None=(sum(item['interval_ns']
                     for item in self.attempts.values()) if usable else None),
                     cost_kind='FIXED_LINUX_SYNTHETIC_INCLUSIVE_INTERVAL_NOT_ATPG' if usable else None,
                     observed_identity_records=sum(item['identity'] is not None
                                                   for item in self.attempts.values()),
                     intent_count=len(self.attempts), launch_attempt_count=None,
                     unknown_spawn=unknown_spawn or
                     (self.active is not None and self.attempts[self.active]['phase'] == 'INTENT'),
                     production_execution_ready=False, training_release=False,
                     real_atpg_jobs=0, physical_atpg_runtime_ns=None)
        value.pop('synthetic_only', None)
        value.pop('actual_processes', None)
        value.pop('e75_gate_raw_sha256', None)
        value.pop('e75_review_response_sha256', None)
        return value


class Handle:
    def __init__(self, proc, profile, marker, scratch, identity):
        self.proc = proc
        self.profile = profile
        self.marker = marker
        self.scratch = scratch
        self.identity = copy.deepcopy(identity)
        self.result = None
        self.cleaned = False


class FixedLinuxBackend:
    """Only the three reviewed Python profiles; no caller command or path knobs."""
    def __init__(self):
        self._used = set()
        self._disabled = False
        self._prepared = False
        self._active = None
        self._launch_attempts = 0

    def disable(self):
        self._disabled = True

    def ready(self, profile):
        try:
            base.require(not self._disabled and self._active is None and
                         type(profile) is str and profile in FIXED_PROFILES and
                         len(self._used) < len(FIXED_PROFILES) and
                         profile == FIXED_PROFILES[len(self._used)], 'BACKEND_UNAVAILABLE_OR_ORDER')
            fd = os.open(gate.__file__, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
            try:
                info = os.fstat(fd)
                base.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'GATE_SOURCE_FILE')
                source = os.read(fd, 14337)
            finally:
                os.close(fd)
            base.require(len(source) <= 14336 and hashlib.sha256(source).hexdigest() ==
                         GATE_SOURCE_SHA256, 'GATE_SOURCE_PIN')
            environment = gate.preflight()  # PID 1, fixed cgroup2 limits and single task.
            base.require(environment['platform'] == 'linux' and
                         environment['memory_limit_bytes'] == 134217728 and
                         environment['swap_limit_bytes'] == 0 and
                         environment['pids_max'] == 16 and
                         environment['oom_group'] in (0, 1), 'FIXED_LINUX_ENVIRONMENT')
            libc = ctypes.CDLL(None, use_errno=True)
            base.require(libc.prctl(36, 1, 0, 0, 0) == 0, 'SUBREAPER_REQUIRED')
            self._prepared = True
            return environment
        except BaseException:
            self._disabled = True
            raise

    def launch(self, profile):
        base.require(self._prepared and not self._disabled and self._active is None and
                     profile in FIXED_PROFILES and profile not in self._used and
                     profile == FIXED_PROFILES[len(self._used)], 'FIXED_LAUNCH_ONLY')
        self._used.add(profile)  # Consumed even when spawn outcome is unknown.
        proc = None
        scratch = None
        try:
            environment = gate.preflight()
            scratch = tempfile.TemporaryDirectory(prefix='gnn_lifecycle_v3_', dir='/tmp')
            marker = Path(scratch.name) / (profile + '.child')
            argv = [sys.executable, '-I', '-S', '-B', '-c', gate.payload(profile, marker)]
            self._launch_attempts += 1
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    shell=False, start_new_session=True, cwd=scratch.name)
            base.require(proc is not None, 'UNKNOWN_SPAWN_HANDLE')
            row = gate.parse_proc_stat(gate.small_read('/proc/%d/stat' % proc.pid))
            base.require(row['pid'] == proc.pid and row['pgrp'] == proc.pid, 'LEADER_NEW_SESSION')
            identity = dict(host=environment['host'], boot_id=environment['boot_id'],
                            pid=proc.pid, pgrp=row['pgrp'], start_ticks=row['start_ticks'])
            base.require(identity_valid(identity), 'LINUX_IDENTITY')
            handle = Handle(proc, profile, marker, scratch, identity)
            self._active = handle
            return handle, copy.deepcopy(identity)
        except BaseException as primary:
            self._disabled = True
            if proc is not None:
                try:
                    gate.cleanup_group(proc)
                    gate.preflight()
                except BaseException as cleanup_error:
                    if scratch is not None:
                        try:
                            scratch.cleanup()
                        except BaseException:
                            pass
                    raise cleanup_error from primary
            if scratch is not None:
                scratch.cleanup()
            raise

    def finish(self, handle, profile):
        try:
            base.require(handle is self._active and type(handle) is Handle and
                         profile == handle.profile and not handle.cleaned, 'HANDLE_BINDING')
            proc = handle.proc
            if profile == 'timeout_group':
                deadline = time.monotonic() + gate.TIMEOUT_S
                while not handle.marker.exists() and proc.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.005)
                base.require(handle.marker.exists(), 'GRANDCHILD_MARKER_REQUIRED')
                child_pid = int(gate.small_read(handle.marker, 32))
                base.require(any(row['pid'] == child_pid for row in gate.group_members(proc.pid)),
                             'GRANDCHILD_GROUP_BINDING')
            timed_out = False
            try:
                proc.wait(timeout=gate.TIMEOUT_S)
            except subprocess.TimeoutExpired:
                timed_out = True
            if profile == 'timeout_group':
                base.require(timed_out, 'EXPECTED_TIMEOUT')
                result = dict(status='TIMEOUT', returncode=-9, timed_out=True)
            else:
                expected = 0 if profile == 'success' else 7
                base.require(not timed_out and type(proc.returncode) is int and
                             proc.returncode == expected, 'FIXED_EXIT')
                result = dict(status='SUCCESS' if profile == 'success' else 'FAILURE',
                              returncode=expected, timed_out=False)
            handle.result = result
            return copy.deepcopy(result)
        except BaseException:
            self._disabled = True
            raise

    def cleanup(self, handle):
        base.require(handle is self._active and type(handle) is Handle and not handle.cleaned,
                     'HANDLE_BINDING')
        try:
            gate.cleanup_group(handle.proc)
            gate.preflight()  # Requires only PID 1 / pids.current=1 again.
            if handle.result is not None:
                base.require(handle.proc.returncode == handle.result['returncode'],
                             'CLEANUP_EXIT_MISMATCH')
            handle.scratch.cleanup()
            handle.cleaned = True
            self._active = None
            return dict(leader_reaped=True, observed_group_empty=True)
        except BaseException:
            self._disabled = True
            raise


class Journal(base.Journal):
    @classmethod
    def create(cls, path):
        raw = base.canonical(header())+b'\n'
        base.require(len(raw) <= base.MAX_LINE, 'HEADER_BOUND')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, 'O_NOFOLLOW', 0), 0o600)
        stream = os.fdopen(fd, 'wb', buffering=0)
        try:
            base.require(stream.write(raw) == len(raw), 'SHORT_WRITE')
            os.fsync(stream.fileno())
            instance = object.__new__(cls)
            instance._path = path
            instance._stream = stream
            instance._state = State()
            instance._size = len(raw)
            instance._identity = base.file_id(os.fstat(stream.fileno()))
            instance._poisoned = False
            instance._unknown_spawn = False
            instance._backend = None
            instance._lock = threading.Lock()
            instance._check()
            return instance
        except BaseException:
            stream.close()
            raise

    def run(self, attempt_id, profile, backend, clock):
        base.require(type(attempt_id) is str and base.ID.fullmatch(attempt_id) and
                     type(profile) is str and profile in FIXED_PROFILES, 'FIXED_PROFILE_ONLY')
        base.require(type(backend) is FixedLinuxBackend, 'EXACT_FIXED_LINUX_BACKEND')
        base.require(_WORKER.acquire(False), 'SINGLE_WORKER_BUSY')
        try:
            base.require(not self._poisoned and not self._stream.closed and
                         self._state.active is None and attempt_id not in self._state.attempts and
                         all(item['phase'] == 'REAPED' for item in self._state.attempts.values()) and
                         (self._backend is None or self._backend is backend),
                         'UNRESOLVED_OR_DUPLICATE_ATTEMPT')
            self._backend = backend
            try:
                backend.ready(profile)  # Before INTENT, scratch or Popen.
            except BaseException:
                self._poisoned = True
                backend.disable()
                raise
            try:
                session, start_ns = base.clock_value(clock)
                self.append('INTENT', attempt_id,
                            dict(profile=profile, clock_session=session, prelaunch_ns=start_ns))
            except BaseException:
                self._poisoned = True
                backend.disable()
                raise
            try:
                handle, identity = backend.launch(profile)
                base.require(handle is not None, 'UNKNOWN_SPAWN_HANDLE')
            except BaseException:
                self._poisoned = True
                self._unknown_spawn = True
                backend.disable()
                raise
            problem = None
            result = None
            try:
                base.require(identity_valid(identity), 'LINUX_IDENTITY')
                identity = copy.deepcopy(identity)
                self.append('LAUNCHED', attempt_id, dict(identity=identity))
                result = backend.finish(handle, profile)
            except BaseException as exc:
                problem = exc
            try:
                cleanup = backend.cleanup(handle)
                base.exact(cleanup, ('leader_reaped', 'observed_group_empty'), 'CLEANUP_KEYS')
                base.require(cleanup['leader_reaped'] is True and
                             cleanup['observed_group_empty'] is True, 'CLEANUP_UNVERIFIED')
            except BaseException as cleanup_error:
                self._poisoned = True
                backend.disable()
                if problem is not None:
                    raise cleanup_error from problem
                raise
            if problem is not None:
                self._poisoned = True
                backend.disable()
                raise problem
            try:
                base.exact(result, ('status', 'returncode', 'timed_out'), 'FINISH_KEYS')
                base.require((result['status'], result['returncode'], result['timed_out']) ==
                             EXPECTED[profile], 'FINISH_PROFILE')
                end_session, end_ns = base.clock_value(clock)
                self.append('REAPED', attempt_id,
                            dict(identity=identity, clock_session=end_session, end_ns=end_ns,
                                 interval_ns=end_ns-start_ns, status=result['status'],
                                 returncode=result['returncode'], timed_out=result['timed_out'],
                                 leader_reaped=True, observed_group_empty=True))
                return self.snapshot()
            except BaseException:
                self._poisoned = True
                backend.disable()
                raise
        finally:
            _WORKER.release()

    def snapshot(self):
        if not self._poisoned and not self._stream.closed:
            try:
                self._check()
            except BaseException:
                self._poisoned = True
        value = self._state.summary(acknowledged=True,
                                   available=not self._poisoned and not self._stream.closed,
                                   unknown_spawn=self._unknown_spawn)
        value['launch_attempt_count'] = (self._backend._launch_attempts
                                         if self._backend is not None else 0)
        return value


def load(path):
    """Structural replay only; complete bytes never certify fsync ACK or OS cleanup."""
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        path_before = os.stat(path, follow_symlinks=False)
        base.require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                     before.st_size <= base.MAX_TOTAL and base.file_id(before) == base.file_id(path_before),
                     'JOURNAL_FILE_BOUND')
        total = 0
        state = State()
        first = True
        while True:
            raw = stream.readline(base.MAX_LINE+1)
            if not raw:
                break
            total += len(raw)
            base.require(len(raw) <= base.MAX_LINE and total <= base.MAX_TOTAL and raw.endswith(b'\n'),
                         'TORN_OR_OVERSIZE_LINE')
            row = base.parse(raw)
            base.require(base.canonical(row)+b'\n' == raw, 'NONCANONICAL_JOURNAL')
            if first:
                base.require(row == header(), 'HEADER_PIN')
                first = False
            else:
                state.apply(row)
        base.require(not first, 'MISSING_HEADER')
        after = os.fstat(stream.fileno())
        path_after = os.stat(path, follow_symlinks=False)
        base.require(total == before.st_size and base.file_id(before) == base.file_id(after) and
                     base.file_id(path_before) == base.file_id(path_after) and
                     base.file_id(after) == base.file_id(path_after), 'JOURNAL_CHANGED_DURING_REPLAY')
        return state.summary(acknowledged=False)
