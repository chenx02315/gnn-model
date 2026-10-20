"""Fixed local Python dummy children only. Not a general executor or ATPG adapter."""
import hashlib
import subprocess
import sys
import tempfile
import threading
from types import MappingProxyType

from . import prospective_attempt_ledger_v1 as ledger

PROFILES = MappingProxyType({
    'success': 'raise SystemExit(0)',
    'failure': 'raise SystemExit(7)',
    'timeout': 'import time; time.sleep(2)',
})
SYNTHETIC_PLAN_SHA256 = hashlib.sha256(b'prospective-dummy-only-plan-v1').hexdigest()
TIMING_SCOPE = 'DUMMY_PRESTART_RECORD_TO_REAP_INCLUDES_JOURNAL_AND_LAUNCH'
REAP_TIMEOUT_S = 1.0
_WORKER = threading.Lock()
_UNREAPED_CHILD = False


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _receipt(status, aid, profile, proc=None, reaped=False, terminal=False, ns=None):
    return dict(status=status, attempt_id=aid, profile=profile,
        pid=None if proc is None else proc.pid,
        returncode=None if proc is None or not reaped else proc.returncode,
        child_reaped=reaped, termination_verified=reaped, ledger_terminal_recorded=terminal,
        recorded_interval_ns=ns, timing_scope=TIMING_SCOPE, dummy_only=True,
        process_tree_termination_proved=False, real_atpg_integration=False,
        execution_ready=False, training_release=False, hard_process_memory_guard_claimed=False)


def _kill_reap(proc):
    """One kill and one bounded reap. Any cleanup error remains an error."""
    global _UNREAPED_CHILD
    clean = True
    try:
        proc.kill()
    except BaseException:
        clean = False
    try:
        code = proc.wait(timeout=REAP_TIMEOUT_S)
        reaped = type(code) is int and proc.returncode == code
    except BaseException:
        reaped = False
    if not reaped:
        _UNREAPED_CHILD = True
    return reaped, clean and reaped


def run_dummy(journal, attempt_id, profile, timeout_s=0.1, clock=None):
    """Record and execute one fixed toy child; never retries or admits real plans.

    PLAN and START fsync acknowledgements precede Popen. The measured interval
    includes START journal latency and launch overhead, not exclusive child time.
    A clock injection is test-only evidence, never trusted runner integration.
    """
    ledger.require(type(journal) is ledger.Journal, 'EXACT_DUMMY_JOURNAL_REQUIRED')
    ledger.require(journal._ledger.plan_sha256 == SYNTHETIC_PLAN_SHA256, 'SYNTHETIC_PLAN_ONLY')
    ledger.identifier(attempt_id)
    ledger.require(type(profile) is str and profile in PROFILES, 'FIXED_DUMMY_PROFILE_ONLY')
    ledger.require(type(timeout_s) in (int, float) and 0.05 <= timeout_s <= 1.0,
                   'DUMMY_TIMEOUT_BOUND')
    ledger.require(_WORKER.acquire(False), 'SINGLE_DUMMY_WORKER_BUSY')
    try:
        ledger.require(not _UNREAPED_CHILD, 'UNREAPED_DUMMY_CHILD_PROCESS_POISON')
        prior = journal.snapshot()['attempts'].values()
        ledger.require(all(item['end'] is not None and item['end']['termination_verified']
                           for item in prior), 'UNRESOLVED_JOURNAL_ATTEMPT')
        return _run(journal, attempt_id, profile, timeout_s, clock or ledger.SystemClock())
    finally:
        _WORKER.release()


def _run(journal, aid, profile, timeout_s, clock):
    global _UNREAPED_CHILD
    argv = [sys.executable, '-I', '-S', '-B', '-c', PROFILES[profile]]
    command_sha = ledger.digest(argv)
    with tempfile.TemporaryDirectory(prefix='prospective_dummy_v1_') as cwd:
        provenance = dict(driver_sha256=_sha(b'fixed-python-dummy-adapter-v1'),
            config_sha256=ledger.digest(dict(profile=profile, timeout_ns=int(timeout_s*10**9))),
            plan_sha256=SYNTHETIC_PLAN_SHA256, input_sha256=_sha(b'NO_REAL_INPUTS'),
            environment_cohort='synthetic-local-python-dummy', clock_identity=clock.session,
            command_sha256=command_sha, output_root=cwd, job_identity='synthetic-dummy-no-job')
        journal.append('PLAN', dict(attempt_id=aid, circuit='toy-circuit',
            action='dummy-'+profile, call_key=ledger.digest(dict(profile=profile,
                command_sha256=command_sha, timeout_ns=int(timeout_s*10**9))),
            parents=[], retry_of=None, provenance=provenance, cost_node=ledger.COST_NODE))
        started = clock.capture()
        journal.append('START', dict(started, attempt_id=aid,
            execution_identity=dict(host='synthetic-local-host', job_id=None, pid=None)))
        _UNREAPED_CHILD = True
        try:
            proc = subprocess.Popen(argv, shell=False, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=cwd)
        except BaseException as exc:
            # No returned process handle means child absence cannot be proved.
            _UNREAPED_CHILD = True
            if not isinstance(exc, Exception):
                raise
            return _receipt('SPAWN_FAILED_RUNNING_INCOMPLETE', aid, profile)
        reaped = False
        try:
            timed_out = False
            try:
                code = proc.wait(timeout=timeout_s)
                reaped = type(code) is int and proc.returncode == code
            except subprocess.TimeoutExpired:
                timed_out = True
                reaped, clean = _kill_reap(proc)
                if not clean:
                    return _receipt('CLEANUP_FAILED_RUNNING_INCOMPLETE', aid, profile, proc, reaped)
            if not reaped:
                reaped, unused = _kill_reap(proc)
                return _receipt('WAIT_UNVERIFIED_RUNNING_INCOMPLETE', aid, profile, proc, reaped)
            finished = clock.capture()
            state = 'TIMEOUT' if timed_out else 'SUCCESS' if proc.returncode == 0 else 'FAILED'
            journal.append('END', dict(finished, attempt_id=aid, state=state,
                termination_verified=True, d95=None, ate_cycles=None, output_artifact_sha256=None))
            _UNREAPED_CHILD = False
            return _receipt('DUMMY_TERMINAL_RECORDED', aid, profile, proc, True, True,
                finished['monotonic_ns']-started['monotonic_ns'])
        except BaseException:
            if not reaped:
                _kill_reap(proc)
            raise
