"""V2 fixed Linux group gate: record OOM group mode, keep the hard memory cap.

Requires an already provisioned dedicated cgroup-v2 sandbox. Does not create
containers/cgroups, raise limits, install software, or accept arbitrary commands.
Configuration observation is not an OOM stress test or production runner proof.
"""
import hashlib
import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

MEMORY_BYTES = 128 * 1024 * 1024
PIDS_MAX = 16
TIMEOUT_S = 0.4
KILL_WAIT_S = 2.0
PROFILES = ('success', 'failure', 'timeout_group')
TIME_SCOPE = 'before_popen_to_verified_group_cleanup_includes_dispatch_and_polling'


def require(condition, code):
    if not condition:
        raise ValueError(code)


def small_read(path, limit=4096):
    """Read a fixed kernel pseudo-file without following its final symlink."""
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        raw = os.read(fd, limit + 1)
        require(len(raw) <= limit, 'KERNEL_METADATA_SIZE')
        return raw.decode('ascii').strip()
    finally:
        os.close(fd)


def parse_cgroup_path(text):
    lines = text.splitlines()
    require(len(lines) == 1 and lines[0].startswith('0::/'), 'UNIFIED_CGROUP_ONLY')
    relative = lines[0][3:]
    require(relative.startswith('/') and all(part not in ('.', '..') for part in relative.split('/')),
            'CGROUP_PATH')
    return relative


def parse_proc_stat(text):
    """Return pgrp/starttime/state from Linux proc stat, including ')' in comm."""
    end = text.rfind(') ')
    require(end > 0, 'PROC_STAT')
    fields = text[end + 2:].split()
    require(len(fields) >= 20, 'PROC_STAT_FIELDS')
    require(fields[0] in ('R', 'S', 'D', 'Z', 'T', 't', 'X', 'x', 'K', 'W', 'P', 'I'), 'PROC_STATE')
    pid = int(text.split(' ', 1)[0])
    pgrp, start_ticks = int(fields[2]), int(fields[19])
    require(pid > 0 and pgrp > 0 and start_ticks > 0, 'PROC_IDENTITY')
    return dict(pid=pid, pgrp=pgrp, start_ticks=start_ticks, state=fields[0])


def preflight():
    require(sys.platform == 'linux', 'LINUX_REQUIRED')
    require(os.getpid() == 1, 'DEDICATED_PID_NAMESPACE_INIT_REQUIRED')
    relative = parse_cgroup_path(small_read('/proc/self/cgroup'))
    # The gate intentionally supports the standard cgroup2 mount only, not an
    # arbitrary caller-controlled filesystem snapshot.
    mounts = small_read('/proc/self/mountinfo', 32768).splitlines()
    require(any(' /sys/fs/cgroup ' in line and ' - cgroup2 ' in line for line in mounts),
            'STANDARD_CGROUP2_MOUNT_REQUIRED')
    require(any(' /proc ' in line and ' - proc ' in line for line in mounts), 'STANDARD_PROC_MOUNT_REQUIRED')
    own_stat = parse_proc_stat(small_read('/proc/self/stat'))
    init_stat = parse_proc_stat(small_read('/proc/1/stat'))
    require(own_stat['pid'] == init_stat['pid'] == os.getpid() == 1 and
            own_stat['start_ticks'] == init_stat['start_ticks'], 'PROC_PID_NAMESPACE_VIEW')
    root = Path('/sys/fs/cgroup')
    group = root / relative.lstrip('/')
    require(not group.is_symlink(), 'CGROUP_SYMLINK')
    for ancestor in group.parents:
        if ancestor == root.parent:
            break
        require(not ancestor.is_symlink(), 'CGROUP_ANCESTOR_SYMLINK')
    values = {name: small_read(group / name) for name in
              ('memory.max', 'memory.swap.max', 'memory.oom.group', 'pids.max', 'pids.current', 'cgroup.procs')}
    require(values['memory.max'] == str(MEMORY_BYTES), 'FIXED_SYNTHETIC_MEMORY_LIMIT')
    require(values['memory.swap.max'] == '0', 'NO_SWAP')
    require(values['memory.oom.group'] in ('0', '1'), 'OOM_GROUP_METADATA')
    require(values['pids.max'] == str(PIDS_MAX), 'FIXED_SYNTHETIC_PIDS_LIMIT')
    require(values['pids.current'] == '1', 'NO_EXISTING_DESCENDANT_TASKS')
    require(values['cgroup.procs'].splitlines() == [str(os.getpid())], 'DEDICATED_SINGLE_PROCESS_SANDBOX')
    return dict(platform=sys.platform, kernel=os.uname().release,
        python=list(sys.version_info[:3]), cgroup_relative_path=relative,
        host=os.uname().nodename, boot_id=small_read('/proc/sys/kernel/random/boot_id', 64),
        memory_limit_bytes=MEMORY_BYTES, swap_limit_bytes=0, pids_max=PIDS_MAX,
        kernel_configuration_observed=True, active_oom_test=False,
        oom_group=int(values['memory.oom.group']), oom_group_atomic_kill_guaranteed=False,
        production_atpg_limits_verified=False)


def group_members(pgid):
    """Bounded proc inventory within the dedicated <=16-task synthetic sandbox."""
    result = []
    entries = list(Path('/proc').iterdir())
    require(len(entries) <= 512, 'PROC_INVENTORY_BOUND')
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            stat = parse_proc_stat(small_read(entry / 'stat'))
        except FileNotFoundError:
            continue
        if stat['pgrp'] == pgid:
            require(stat['pid'] == int(entry.name), 'PROC_ENTRY_PID_BINDING')
            result.append(stat)
    return result


def payload(profile, marker):
    require(profile in PROFILES, 'FIXED_PROFILE_ONLY')
    if profile == 'success':
        return 'raise SystemExit(0)'
    if profile == 'failure':
        return 'raise SystemExit(7)'
    # Both the leader and its sole child have finite self-exit bounds. No
    # setsid/daemon escape: process-group scope is intentional, not universal.
    return ("import os,subprocess,sys,time; "
            "p=subprocess.Popen([sys.executable,'-I','-S','-B','-c','import time; time.sleep(3)']); "
            "f=open(%r,'x'); f.write(str(p.pid)); f.close(); time.sleep(3)" % str(marker))


def reap_adopted(pgid):
    """Reap adopted descendants from only the synthetic group, never other jobs."""
    while True:
        try:
            pid, unused = os.waitpid(-pgid, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def cleanup_group(proc):
    """One bounded cleanup on every post-Popen path, including failed checks."""
    clean = True
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except Exception:
        clean = False
    try:
        code = proc.wait(timeout=KILL_WAIT_S)
        reaped = type(code) is int and proc.returncode == code
    except Exception:
        reaped = False
    deadline = time.monotonic() + KILL_WAIT_S
    while True:
        reap_adopted(proc.pid)
        remaining = group_members(proc.pid)
        if not remaining:
            require(clean and reaped, 'INCOMPLETE_STOP_CLEANUP_UNVERIFIED')
            return
        require(time.monotonic() < deadline, 'INCOMPLETE_STOP_GROUP_NOT_EMPTY')
        time.sleep(0.01)


def run_profile(profile, directory):
    marker = directory / ('%s.child' % profile)
    code = payload(profile, marker)
    argv = [sys.executable, '-I', '-S', '-B', '-c', code]
    start = time.monotonic_ns()
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, shell=False, start_new_session=True, cwd=directory)
    timed_out = False
    try:
        leader_identity = parse_proc_stat(small_read('/proc/%d/stat' % proc.pid))
        require(leader_identity['pgrp'] == proc.pid, 'LEADER_NEW_SESSION_REQUIRED')
        if profile == 'timeout_group':
            deadline = time.monotonic() + TIMEOUT_S
            while not marker.exists() and proc.poll() is None and time.monotonic() < deadline:
                time.sleep(0.005)
            require(marker.exists(), 'GRANDCHILD_MARKER_REQUIRED')
            child_pid = int(small_read(marker, 32))
            require(any(row['pid'] == child_pid for row in group_members(proc.pid)), 'GRANDCHILD_GROUP_BINDING')
        else:
            child_pid = None
        try:
            proc.wait(timeout=TIMEOUT_S)
        except subprocess.TimeoutExpired:
            timed_out = True
    finally:
        # Reaping/emptiness checks are mandatory even if marker, identity or
        # result checks failed. An exception here prevents any next profile.
        cleanup_group(proc)
    # Only publish measured completion after successful universal cleanup.
    require((profile == 'success' and not timed_out and proc.returncode == 0) or
            (profile == 'failure' and not timed_out and proc.returncode == 7) or
            (profile == 'timeout_group' and timed_out), 'FIXED_PROFILE_RESULT')
    return dict(profile=profile, leader_pid=proc.pid, grandchild_pid=child_pid,
        leader_start_ticks=leader_identity['start_ticks'],
        returncode=proc.returncode, timed_out=timed_out, leader_reaped=True,
        observed_group_empty=True, observed_interval_ns=time.monotonic_ns() - start,
        time_scope=TIME_SCOPE,
        command_sha256=hashlib.sha256(json.dumps(argv, separators=(',', ':')).encode()).hexdigest())


def run_gate():
    environment = preflight()  # Mandatory before TemporaryDirectory or Popen.
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.prctl(36, 1, 0, 0, 0) == 0, 'SUBREAPER_REQUIRED')
    results = []
    with tempfile.TemporaryDirectory(prefix='gnn_lifecycle_synthetic_') as directory:
        for profile in PROFILES:
            preflight()
            results.append(run_profile(profile, Path(directory)))
    preflight()
    return dict(schema='prospective-linux-lifecycle-gate-v2', status='PASS_SYNTHETIC_GROUP_ONLY',
        gate_pass=True, environment=environment, profiles=results,
        universal_process_tree_termination_proved=False, durable_runner_integrated=False,
        real_atpg_jobs=0, training=False, execution_ready=False, training_release=False)


def main():
    require(len(sys.argv) == 1, 'NO_USER_COMMANDS_OR_PATHS')
    try:
        result = run_gate()
    except Exception as exc:
        print(json.dumps(dict(schema='prospective-linux-lifecycle-gate-v2',
            status='BLOCKED_OR_FAILED_NO_RETRY', gate_pass=False, reason=str(exc),
            execution_ready=False, training_release=False)))
        return 78
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
