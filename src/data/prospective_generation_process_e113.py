"""Private fixed-command observation with live spawned-handle /proc identity.

Not an admission, budget, environment-capture, executable-authentication or
receipt-sealing controller. The caller must persist its debit before entry and
seal the returned observation before rejecting a failed/uncertain operation.
"""
import copy
import math
import os
import re
import selectors
import subprocess
import time

from . import prospective_generation_supervision_e109 as legacy
from . import direct_tessent_acceptance_e104 as direct

SCHEMA = 'generation-process-observation-e113-v1'
IDENTITY_SCHEMA = 'generation-spawn-identity-e113-v1'
require = legacy.require
sha = legacy.sha
canonical = legacy.canonical
BOOT_PATH = '/proc/sys/kernel/random/boot_id'


def _validate_launch(launch):
    require(type(launch) is dict and set(launch) == legacy.LAUNCH_KEYS and
            launch.get('schema') == legacy.SCHEMA and
            all(launch[k] is False for k in ('environment_profile_authenticated',
                'execution_authorized', 'execution_ready')) and
            sha(canonical({k: v for k, v in launch.items() if k != 'launch_spec_sha256'})) ==
            launch.get('launch_spec_sha256') and
            launch.get('environment_sha256') == sha(canonical(launch.get('env'))), 'LAUNCH_SPEC_CHANGED')
    legacy._environment(launch['env'], launch['cwd'])
    argv = launch['argv']
    require(type(argv) is list and len(argv) == 8 and
            argv[:5] == [legacy.recipe.identities.LAUNCHER, '-shell', '-license_wait', '5', '-log'] and
            legacy._absolute(argv[5]) and argv[5].startswith(legacy.recipe.ROOT + '/') and
            argv[6] == '-dofile' and argv[7] in (legacy.recipe.ROOT + '/code/common.tcl',
                legacy.recipe.ROOT + '/code/incremental.tcl') and
            legacy._absolute(launch['cwd']) and launch['cwd'].startswith(legacy.recipe.ROOT + '/'),
            'FIXED_TESSENT_ARGV_CWD')


def _boot_id():
    value = direct.base._small(BOOT_PATH, 128).decode('ascii').strip()
    require(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value) is not None,
            'BOOT_ID_FORMAT')
    return value


def _stable(identity):
    return tuple(identity[index] for index in (0, 1, 3, 4, 5))


def _check_worker(domain):
    """Reject a foreign/reused or multithreaded worker before any Popen."""
    require(type(domain.pid) is int and domain.pid == os.getpid(), 'CURRENT_WORKER_REQUIRED')
    before = direct.base._identity(domain.pid)
    require(re.search(rb'^Threads:\s+1\s*$', direct.base._small('/proc/self/status'), re.M) is not None,
            'SINGLE_WORKER_THREAD_REQUIRED')
    after = direct.base._identity(domain.pid)
    require(_stable(before) == _stable(after) and before[:2] == domain.identity[:2] and
            after[2] not in ('Z', 'X', 'x'), 'WORKER_IDENTITY_CHANGED')


def _spawn_identity(proc, domain, launch):
    """Read the real Popen handle PID, never accept a caller-provided PID."""
    pid = proc.pid
    require(type(pid) is int and pid > 0 and type(domain.pid) is int and
            domain.pid == os.getpid() and pid != domain.pid, 'SPAWN_PID_OR_WORKER')
    require(re.search(rb'^Threads:\s+1\s*$', direct.base._small('/proc/self/status'), re.M) is not None,
            'SINGLE_WORKER_THREAD_REQUIRED')
    boot_before = _boot_id()
    worker_before = direct.base._identity(domain.pid)
    child_before = direct.base._identity(pid)
    members = domain.snapshot()
    worker_after = direct.base._identity(domain.pid)
    child_after = direct.base._identity(pid)
    boot_after = _boot_id()
    require(boot_before == boot_after and _stable(worker_before) == _stable(worker_after) and
            worker_before[:2] == domain.identity[:2], 'WORKER_OR_BOOT_CHANGED')
    require(_stable(child_before) == _stable(child_after) and pid in members and
            _stable(members[pid]) == _stable(child_before), 'CHILD_IDENTITY_CHANGED_OR_NOT_OWNED')
    require(child_before[3] == domain.pid and child_before[4] == pid and child_before[5] == pid,
            'CHILD_PARENT_PGRP_SESSION')
    require(worker_after[2] not in ('Z', 'X', 'x') and child_after[2] not in ('Z', 'X', 'x'),
            'SPAWN_ALREADY_EXITED')
    body = dict(schema=IDENTITY_SCHEMA, boot_id=boot_before, worker_pid=domain.pid,
        worker_start_ticks=worker_before[1], child_pid=pid, child_start_ticks=child_before[1],
        child_parent_pid=child_before[3], child_pgrp=child_before[4], child_session=child_before[5],
        launch_spec_sha256=launch['launch_spec_sha256'], environment_sha256=launch['environment_sha256'],
        effective_envelope_sha256=launch['effective_envelope_sha256'],
        identity_source='LIVE_PROC_DOUBLE_READ_AND_OWN_DESCENDANT_MEMBERSHIP',
        process_role='DIRECT_LAUNCHER_CHILD_NOT_ATPG_KERNEL_IDENTITY',
        executable_bytes_authenticated=False, actual_atpg_runtime_ns=None)
    return dict(body, identity_sha256=sha(canonical(body)))


def observe_translation(*args, **kwargs):
    """No translation command/source/launch schema has been frozen yet."""
    raise ValueError('FIXED_TRANSLATION_HELPER_NOT_FROZEN')


def _drain_prefix(proc, end, output_budget, output):
    """After cleanup only, read already-ready bytes without waiting/retrying."""
    with selectors.DefaultSelector() as selector:
        selector.register(proc.stdout, selectors.EVENT_READ)
        while output_budget[0] > 0 and time.monotonic() < end:
            events = selector.select(0)
            if not events:
                break
            raw = os.read(events[0][0].fileobj.fileno(), min(65536, output_budget[0]))
            if not raw:
                break
            output_budget[0] -= len(raw)
            output.extend(raw)


def observe_tessent(launch, end, domain, output_budget, on_spawn, scratch=None):
    """Observe, persist identity via callback, then return even failed evidence.

    on_spawn(identity) must return literal True after caller-owned persistence.
    This return is a persistence claim, not independent durability attestation.
    Failed identity capture/callback never invents a PID or retries Popen.
    """
    launch = copy.deepcopy(launch)
    _validate_launch(launch)
    require(type(end) in (int, float) and math.isfinite(end) and
            type(output_budget) is list and len(output_budget) == 1 and
            type(output_budget[0]) is int and 0 <= output_budget[0] <= 16777216 and
            callable(on_spawn) and isinstance(domain, direct.Descendants), 'OBSERVATION_BOUNDS_OR_DOMAIN')
    proc, output, failure, cleanup_error = None, bytearray(), None, None
    attempted, cleaned, identity_persisted = False, False, False
    callback_error, drain_error, drain_attempted = None, None, False
    identity, started, ended = None, None, None
    try:
        require(time.monotonic() < end - 10, 'PRELAUNCH_TIMEOUT')
        require(output_budget[0] > 0, 'OUTPUT_STOP')
        domain.sample()
        if scratch is not None:
            scratch.sample()
        _check_worker(domain)
        require(time.monotonic() < end - 10, 'PRELAUNCH_TIMEOUT')
        started = time.monotonic()
        attempted = True
        proc = subprocess.Popen(launch['argv'], cwd=launch['cwd'], env=launch['env'],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            close_fds=True, start_new_session=True)
        identity = _spawn_identity(proc, domain, launch)
        try:
            acknowledged = on_spawn(copy.deepcopy(identity))
        except BaseException as exc:
            callback_error = type(exc).__name__
            raise ValueError('SPAWN_IDENTITY_CALLBACK_FAILED')
        require(acknowledged is True, 'SPAWN_IDENTITY_PERSISTENCE_REQUIRED')
        identity_persisted = True
        require(time.monotonic() < end - 10, 'IDENTITY_PERSISTENCE_TIMEOUT')
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            next_scratch = 0
            while selector.get_map() or proc.poll() is None:
                require(time.monotonic() < end - 10, 'CASE_TIMEOUT')
                domain.sample()
                if scratch is not None and time.monotonic() >= next_scratch:
                    scratch.sample()
                    next_scratch = time.monotonic() + 1
                for key, _ in selector.select(.05):
                    require(output_budget[0] > 0, 'OUTPUT_STOP')
                    raw = os.read(key.fileobj.fileno(), min(65536, output_budget[0]))
                    if raw:
                        output_budget[0] -= len(raw)
                        output.extend(raw)
                    else:
                        selector.unregister(key.fileobj)
            proc.wait(timeout=max(.001, end - 10 - time.monotonic()))
    except BaseException as exc:
        failure = str(exc) if type(exc) is ValueError else type(exc).__name__
    finally:
        if proc is not None:
            try:
                cleaned = domain.cleanup(proc, end) is True
            except BaseException as exc:
                cleanup_error = type(exc).__name__
            if proc.stdout is not None:
                if failure is not None and cleaned:
                    try:
                        drain_attempted = True
                        _drain_prefix(proc, end, output_budget, output)
                    except BaseException as exc:
                        drain_error = type(exc).__name__
                try:
                    proc.stdout.close()
                except BaseException as exc:
                    cleanup_error, cleaned = type(exc).__name__, False
        else:
            try:
                remaining, more = domain._direct_batch()
                cleaned = not remaining and not more
            except BaseException as exc:
                cleanup_error = type(exc).__name__
        try:
            ended = time.monotonic()
        except BaseException as exc:
            failure = failure or type(exc).__name__
    if not cleaned:
        failure = failure or 'CLEANUP_UNCONFIRMED'
    interval = (ended - started if type(ended) in (int, float) and type(started) in (int, float) and
                math.isfinite(ended) and math.isfinite(started) and ended >= started else None)
    if attempted and interval is None:
        failure = failure or 'CLOCK_INTERVAL_UNAVAILABLE'
    return dict(schema=SCHEMA, launch_spec_sha256=launch['launch_spec_sha256'],
        effective_envelope_sha256=launch['effective_envelope_sha256'],
        environment_sha256=launch['environment_sha256'], environment_keys=sorted(launch['env']),
        launch_attempted=attempted, known_process_handle=proc is not None,
        returncode=None if proc is None else proc.returncode, cleaned=cleaned,
        failure=failure, cleanup_error=cleanup_error, output=bytes(output),
        identity_callback_error=callback_error, post_failure_prefix_drain_attempted=drain_attempted,
        post_failure_prefix_drain_error=drain_error,
        spawn_identity=identity, spawn_identity_persisted_claim=identity_persisted,
        identity_persistence_independently_attested=False,
        physical_process_identity_observed=identity is not None,
        physical_process_identity_authenticated=False,
        observed_wrapper_interval_seconds=interval,
        interval_scope='PRE_POPEN_THROUGH_CLEANUP_RETURN_INCLUDES_IDENTITY_CALLBACK_NOT_ATPG_KERNEL',
        clock_api='time.monotonic_seconds', sampled_peak_rss_swap_bytes=domain.peak,
        readiness=None, streams_combined=True, stderr_separately_validated=False,
        full_session_cost_qualified=False, actual_atpg_runtime_ns=None,
        execution_ready=False, training_release=False)
