"""Fixed E94 Linux supervisor. Caller assertion is not authenticated consent.

No CLI or default authorization. Physical operation has not been exercised.
Memory proof covers this worker, not universal migration inescapability.
"""
import ctypes
import hashlib
import math
import os
import re
import selectors
import signal
import stat
import subprocess
import threading
import time

from . import prospective_tessent_acceptance_v1 as recipe
from . import prospective_lsf_memory_preflight_v1 as memory
from .prospective_acceptance_scratch_v1 import ScratchMonitor

_WORKER = threading.Lock()
CAPTURE_LIMIT = 16 * 1024 * 1024
DEADLINE_SECONDS = 600
CLEANUP_RESERVE = 10
LICENSE_KEYS = frozenset(('LM_LICENSE_FILE', 'MGLS_LICENSE_FILE', 'MGC_HOME',
                          'MGC_ROOT', 'TESSENT_HOME'))


def _require(ok, reason):
    if not ok:
        raise ValueError(reason)


def validate_authorization(value, digest):
    _require(type(value) is dict and set(value) == {
        'schema', 'approved', 'job_id', 'memory_cap_bytes', 'recipe_sha256',
        'scope'}, 'AUTHORIZATION_KEYS')
    _require(value['schema'] == 'e96-acceptance-authorization-v1' and
             value['approved'] is True and
             value['scope'] == 'E94_FOUR_NO_PATTERN_ACCEPTANCE_ONLY' and
             value['recipe_sha256'] == digest and
             type(value['job_id']) is int and value['job_id'] > 0 and
             type(value['memory_cap_bytes']) is int and
             0 < value['memory_cap_bytes'] < 2**63, 'AUTHORIZATION_REQUIRED')


def _environment(scratch, supplied):
    _require(type(supplied) is dict and set(supplied) <= LICENSE_KEYS,
             'LICENSE_ENV_KEYS')
    _require(all(type(v) is str and 0 < len(v) <= 4096 and
                 all(32 <= ord(c) < 127 for c in v)
                 for v in supplied.values()), 'LICENSE_ENV_VALUE')
    return dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', HOME=scratch,
                TMPDIR=scratch, **supplied)


def _read(path, bound=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        raw = os.read(fd, bound + 1)
        _require(len(raw) <= bound, 'KERNEL_READ_BOUND')
        return raw
    finally:
        os.close(fd)


def _identity(pid, membership):
    raw = _read('/proc/%d/stat' % pid).decode('ascii')
    tail = raw[raw.rfind(') ') + 2:].split()
    _require(_read('/proc/%d/cgroup' % pid) == membership,
             'CHILD_MEMORY_DOMAIN_CHANGED')
    return (pid, int(tail[19]), int(tail[2]))


class _Domain:
    """Leaf-only proof plus subreaper; no PID-1 or cgroup-v2 assumptions."""
    def __init__(self, authorization):
        self.authorization = authorization
        self.proof = memory.collect_preflight(authorization['job_id'],
                                             authorization['memory_cap_bytes'])
        self.membership = memory._read_fixed('/proc/self/cgroup')
        member = memory._membership(self.membership, authorization['job_id'])
        device = memory._mountinfo(memory._read_fixed('/proc/self/mountinfo'))
        fd = memory._open_mount(device)
        try:
            for part in member['components']:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=fd)
                os.close(fd)
                fd = child
            self.fd = os.dup(fd)
        finally:
            os.close(fd)
        self.self_pid = os.getpid()
        try:
            self._configure()
        except BaseException:
            self.close()
            raise

    def _configure(self):
        _require(self.pids() == {self.self_pid}, 'LEAF_NOT_EXCLUSIVE')
        # Bounded kernel metadata: do not enumerate an unbounded task directory.
        status = _read('/proc/self/status')
        _require(re.search(rb'^Threads:\s+1\s*$', status, re.MULTILINE) is not None,
                 'SINGLE_THREAD_COORDINATOR_REQUIRED')
        _require(not _read('/proc/self/task/%d/children' % self.self_pid).strip(),
                 'PREEXISTING_CHILDREN')
        libc = ctypes.CDLL(None, use_errno=True)
        _require(libc.prctl(36, 1, 0, 0, 0) == 0, 'SUBREAPER_SET')
        enabled = ctypes.c_int()
        _require(libc.prctl(37, ctypes.byref(enabled), 0, 0, 0) == 0 and
                 enabled.value == 1, 'SUBREAPER_VERIFY')

    def pids(self):
        fd = os.open('cgroup.procs', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fd)
        try:
            raw = os.read(fd, 65537)
            _require(len(raw) <= 65536, 'PID_READ_BOUND')
            return {int(x) for x in raw.split()}
        finally:
            os.close(fd)

    def monitor(self):
        _require(self.self_pid in self.pids() and len(self.pids()) <= 64,
                 'PROCESS_MONITOR_THRESHOLD')
        _require(memory._read_fixed('/proc/self/cgroup') == self.membership,
                 'COORDINATOR_DOMAIN_CHANGED')
        self.scratch_monitor.sample()

    def own_children(self):
        raw = _read('/proc/self/task/%d/children' % self.self_pid, 4096)
        fields = raw.split()
        _require(len(fields) <= 64 and all(re.fullmatch(rb'[1-9][0-9]{0,9}', x)
                                         for x in fields), 'CHILDREN_BOUND')
        children = {int(x) for x in fields}
        _require(len(children) == len(fields) and self.self_pid not in children,
                 'CHILDREN_INVALID')
        return children

    def child_identity(self, pid):
        raw = _read('/proc/%d/stat' % pid).decode('ascii')
        end = raw.rfind(') ')
        _require(end > 0 and raw.split(' ', 1)[0] == str(pid), 'CHILD_STAT_PID')
        fields = raw[end + 2:].split()
        _require(len(fields) >= 20 and int(fields[1]) == self.self_pid,
                 'NOT_OWN_CHILD')
        return (pid, int(fields[19]), int(fields[1]), fields[0])

    def cleanup(self, proc, identity, deadline):
        # Kill every newly present leaf member, including setsid grandchildren.
        # Snapshot identity and reverify immediately before every signal.
        while time.monotonic() < deadline:
            for pid in self.pids() - {self.self_pid}:
                try:
                    observed = _identity(pid, self.membership)
                    if _identity(pid, self.membership) == observed:
                        os.kill(pid, signal.SIGKILL)
                except (ProcessLookupError, FileNotFoundError):
                    pass
            if proc is not None:
                proc.poll()  # Only Popen may reap its leader and retain its status.
            # Zombies disappear from cgroup.procs but remain adopted children.
            # Never require a zombie to retain its former live membership.
            for pid in self.own_children():
                if proc is not None and pid == proc.pid:
                    continue
                try:
                    observed = self.child_identity(pid)
                    if observed[3] == 'Z' and self.child_identity(pid) == observed:
                        os.waitpid(pid, os.WNOHANG)
                except (ChildProcessError, ProcessLookupError, FileNotFoundError):
                    pass
            if ((proc is None or proc.returncode is not None) and
                    not self.own_children() and self.pids() == {self.self_pid}):
                return True
            time.sleep(0.01)
        return False

    def close(self):
        os.close(self.fd)


def _capture(proc, domain, deadline, buffers):
    with selectors.DefaultSelector() as selector:
        for name, pipe in (('stdout', proc.stdout), ('stderr', proc.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        while selector.get_map():
            _require(time.monotonic() < deadline, 'TIMEOUT')
            domain.monitor()
            for key, _ in selector.select(min(0.05, max(0, deadline-time.monotonic()))):
                remaining = CAPTURE_LIMIT - sum(map(len, buffers.values()))
                _require(remaining > 0, 'CAPTURE_BUDGET_EXHAUSTED')
                block = os.read(key.fd, min(65536, remaining))
                if block:
                    buffers[key.data].extend(block[:remaining])
                    _require(len(block) <= remaining, 'CAPTURE_OVERFLOW')
                else:
                    selector.unregister(key.fileobj)
        while proc.poll() is None:
            _require(time.monotonic() < deadline, 'TIMEOUT')
            domain.monitor()
            time.sleep(0.01)


def _save_logs(item, buffers, deadline):
    """Exclusive A-only raw files; receipts expose only hashes and byte counts."""
    fd = os.open(item['future_scratch'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name, data in buffers.items():
            _require(time.monotonic() < deadline, 'LOG_DEADLINE')
            log = os.open('tool.%s.log' % name,
                          os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                          0o600, dir_fd=fd)
            try:
                _require(stat.S_ISREG(os.fstat(log).st_mode), 'LOG_NOT_REGULAR')
                view = memoryview(data)
                while view:
                    _require(time.monotonic() < deadline, 'LOG_DEADLINE')
                    count = os.write(log, view[:65536])
                    _require(count > 0, 'LOG_WRITE')
                    view = view[count:]
                os.fsync(log)
                os.lseek(log, 0, os.SEEK_SET)
                digest = hashlib.sha256()
                count = 0
                while True:
                    _require(time.monotonic() < deadline, 'LOG_DEADLINE')
                    chunk = os.read(log, 65536)
                    if not chunk:
                        break
                    count += len(chunk)
                    _require(count <= len(data), 'LOG_READBACK_BOUND')
                    digest.update(chunk)
                _require(count == len(data) and digest.digest() ==
                         hashlib.sha256(data).digest(), 'LOG_READBACK')
            finally:
                os.close(log)
        os.fsync(fd)
    finally:
        os.close(fd)


def _launch_proof(domain, identity, authorization):
    proof = domain.proof
    return dict(pid=identity[0], start_ticks=identity[1], pgrp=identity[2],
                job_id=authorization['job_id'],
                boot_id=proof['process_identity']['boot_id'],
                actual_hard_caps=proof['actual_hard_caps'],
                approved_memory_cap_bytes=authorization['memory_cap_bytes'],
                child_cgroup_sha256=hashlib.sha256(domain.membership).hexdigest(),
                e95_read_evidence=proof['read_evidence'])


class AcceptanceProcess:
    def __init__(self, raw_e85, raw_e93, authorization,
                 license_environment=None, event_sink=None, package_deadline=None):
        self.bundle = recipe.compile_acceptance(raw_e85, raw_e93,
                                               recipe.E85_SHA256, recipe.E93_SHA256)
        self._raw = (raw_e85, raw_e93)
        validate_authorization(authorization, self.bundle['recipe_sha256'])
        self.authorization = dict(authorization)
        self.license_environment = dict(license_environment or {})
        _environment('/fixed', self.license_environment)
        self.event_sink = event_sink
        _require(package_deadline is None or
                 (type(package_deadline) in (int, float) and
                  math.isfinite(package_deadline)), 'PACKAGE_DEADLINE')
        self.package_deadline = package_deadline
        self.cursor = 0
        self.aborted = False

    def run_item(self, circuit, transition):
        _require(_WORKER.acquire(blocking=False), 'ONE_WORKER_ONLY')
        domain = proc = identity = scratch = None
        started = time.monotonic()
        deadline = started + DEADLINE_SECONDS
        if self.package_deadline is not None:
            deadline = min(deadline, self.package_deadline)
        buffers = {'stdout': bytearray(), 'stderr': bytearray()}
        spawn_attempts = 0
        logs_saved = False
        capture_complete = False
        status = 'FAIL'
        cleaned = True
        try:
            _require(not self.aborted and self.cursor < 4, 'PACKAGE_DISABLED')
            compiled = recipe.compile_acceptance(*self._raw,
                recipe.E85_SHA256, recipe.E93_SHA256)
            item = compiled['items'][self.cursor]
            _require((circuit, transition) == (item['circuit'], item['transition']),
                     'EXACT_SERIAL_ROSTER')
            self.cursor += 1  # Every accepted launch attempt is consumed, even spawn failure.
            self.aborted = True
            validate_authorization(self.authorization, compiled['recipe_sha256'])
            domain = _Domain(self.authorization)  # fresh E95 before any subprocess
            from .prospective_acceptance_materializer_v1 import verify_materialized_item
            _require(verify_materialized_item(item)['verified'] is True, 'INPUT_PINS')
            scratch = ScratchMonitor(deadline)
            domain.scratch_monitor = scratch
            scratch.sample()  # Includes prior items and current TSDB before spawn.
            _require(callable(self.event_sink), 'DURABLE_EVENT_SINK_REQUIRED')
            preflight = dict(job_id=self.authorization['job_id'],
                             boot_id=domain.proof['process_identity']['boot_id'],
                             e95=domain.proof,
                             cgroup_sha256=hashlib.sha256(domain.membership).hexdigest())
            ack = self.event_sink('PREFLIGHT', preflight)
            _require(type(ack) is dict and set(ack) == {'seq', 'sha256'} and
                     type(ack['seq']) is int and ack['seq'] > 0 and
                     type(ack['sha256']) is str and
                     re.fullmatch('[0-9a-f]{64}', ack['sha256']) is not None,
                     'PREFLIGHT_DURABLE_ACK_REQUIRED')
            _require(time.monotonic() < deadline-CLEANUP_RESERVE, 'PRELAUNCH_TIMEOUT')
            cleaned = False  # A failed/ambiguous spawn cannot certify no residuals.
            spawn_attempts = 1
            proc = subprocess.Popen(item['argv'], cwd=item['cwd'], shell=False,
                start_new_session=True, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=_environment(item['future_scratch'], self.license_environment))
            cleaned = False
            identity = _identity(proc.pid, domain.membership)
            _require(identity[2] == proc.pid, 'CHILD_PROCESS_GROUP')
            launched = _launch_proof(domain, identity, self.authorization)
            launched['preflight_ack'] = ack
            self.event_sink('LAUNCHED', launched)
            _capture(proc, domain, deadline-CLEANUP_RESERVE, buffers)
            capture_complete = True
            marker = ('E94_TRANSLATED_STATUS_ACCEPTANCE=PASS %s %s' %
                      (circuit, transition)).encode('ascii')
            stdout = buffers['stdout']
            _require(proc.returncode == 0 and stdout.count(marker) == 1 and
                     stdout.splitlines().count(marker) == 1 and
                     buffers['stderr'].count(marker) == 0 and
                     all(not re.search(rb'ERROR|FATAL|invalid pin_pathname|WARNING',
                                       stream, re.IGNORECASE)
                         for stream in buffers.values()), 'TOOL_ACCEPTANCE_FAILED')
            status = 'PASS'
        except Exception:
            status = 'FAIL'
        finally:
            try:
                if domain is not None and spawn_attempts:
                    try:
                        cleaned = domain.cleanup(proc, identity, deadline)
                        if proc is None:
                            cleaned = False  # Unknown spawn remains unknown even if leaf is empty.
                    except Exception:
                        cleaned = False
                    try:
                        _save_logs(item, buffers, deadline)
                        logs_saved = True
                        scratch.sample()
                    except Exception:
                        status = 'FAIL'
                if proc is not None:
                    for pipe in (proc.stdout, proc.stderr):
                        if pipe is not None:
                            try:
                                pipe.close()
                            except Exception:
                                cleaned = False
            finally:
                try:
                    if domain is not None:
                        try:
                            domain.close()
                        except Exception:
                            cleaned = False
                finally:
                    _WORKER.release()
        if not cleaned or time.monotonic() > deadline:
            status = 'CLEANUP_UNKNOWN' if not cleaned else 'FAIL'
        self.aborted = status != 'PASS'
        return dict(schema='e96-acceptance-process-receipt-v1', status=status,
                    accepted=status == 'PASS',
                    returncode=proc.returncode if proc is not None else None,
                    tessent_calls=1 if proc is not None else (None if spawn_attempts else 0),
                    spawn_attempts=spawn_attempts,
                    circuit=circuit, transition=transition, cleanup_verified=cleaned,
                    logs={name: dict(sha256=(hashlib.sha256(data).hexdigest()
                                            if data or capture_complete or not spawn_attempts
                                            else None),
                                     bytes=len(data), complete=capture_complete,
                                     scope='CAPTURED_PREFIX_ONLY')
                          for name, data in buffers.items()},
                    logs_saved=logs_saved,
                    log_capture_complete=capture_complete,
                    consumed_attempts=self.cursor, execution_ready=False,
                    scratch=(scratch.summary() if scratch is not None else None),
                    training_release=False, actual_atpg_calls=0,
                    memory_scope='CURRENT_WORKER_NOT_UNIVERSAL_INESCAPABILITY')
