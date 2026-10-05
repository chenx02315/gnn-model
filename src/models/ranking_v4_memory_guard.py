"""Linux single-worker resource guard. RSS sampling is not a cgroup hard cap."""
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

GIB = 1024 ** 3
RSS_CAP = GIB
ADDRESS_CAP = 8 * GIB
RESERVE_MIN = 4 * GIB
TIMEOUT_S = 1800
POLL_S = .25
THREAD_KEYS = ('OMP_NUM_THREADS', 'MKL_NUM_THREADS', 'OPENBLAS_NUM_THREADS', 'NUMEXPR_NUM_THREADS')


def policy():
    return dict(max_concurrent_workers=1, combined_rss_cap_bytes=RSS_CAP,
                child_address_space_cap_bytes=ADDRESS_CAP, reserve_min_bytes=RESERVE_MIN,
                reserve_fraction=.1, poll_seconds=POLL_S, timeout_seconds=TIMEOUT_S,
                retries=0, limitation='RSS is sampled; brief overshoot can occur. RLIMIT_AS caps address space, not RSS.')


def available_memory():
    values = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, rest = line.split(':', 1)
        values[key] = int(rest.split()[0]) * 1024
    total, available = values['MemTotal'], values['MemAvailable']
    # Honour a finite cgroup-v2 limit at this session and its ancestors.
    for line in Path('/proc/self/cgroup').read_text().splitlines():
        if line.startswith('0::'):
            relative = Path(line[3:].lstrip('/'))
            if '..' in relative.parts:
                raise ValueError('MEMORY_CGROUP_PATH')
            base = Path('/sys/fs/cgroup')
            current = base / relative
            for directory in (current, *current.parents):
                if directory != base and base not in directory.parents:
                    break
                limit_path, usage_path = directory / 'memory.max', directory / 'memory.current'
                if limit_path.exists() and usage_path.exists():
                    raw = limit_path.read_text().strip()
                    if raw != 'max':
                        limit, used = int(raw), int(usage_path.read_text().strip())
                        total = min(total, limit)
                        available = min(available, max(0, limit - used))
    return total, available


def check_available(total, available):
    if type(total) is not int or type(available) is not int or total <= 0 or available < 0:
        raise ValueError('MEMORY_VALUES')
    reserve = max(RESERVE_MIN, math.ceil(total * .1))
    if available < reserve + RSS_CAP:
        raise RuntimeError('MEMORY_RESERVE_REFUSED')
    return reserve


def rss(pid):
    try:
        for line in Path('/proc', str(pid), 'status').read_text().splitlines():
            if line.startswith('VmRSS:'):
                return int(line.split()[1]) * 1024
    except FileNotFoundError:
        return 0
    # A process can exit between group enumeration and this status read.
    # Only an independently confirmed terminal/disappeared process has zero RSS.
    try:
        stat = Path('/proc', str(pid), 'stat').read_text()
        fields = stat[stat.rfind(')') + 2:].split()
        if stat.rfind(')') < 0 or len(fields) < 3:
            raise RuntimeError('MEMORY_RSS_UNREADABLE')
        if fields[0] in ('Z', 'X'):
            return 0
    except FileNotFoundError:
        return 0
    raise RuntimeError('MEMORY_RSS_UNREADABLE')


def group_members(group):
    members = []
    for item in Path('/proc').iterdir():
        if not item.name.isdigit():
            continue
        try:
            stat = (item / 'stat').read_text()
            fields = stat[stat.rfind(')') + 2:].split()
            if int(fields[2]) == group and fields[0] not in ('Z', 'X'):
                members.append(int(item.name))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return members


def group_rss(group):
    return sum(rss(pid) for pid in group_members(group))


def terminate_group(process):
    # A dead leader does not imply its descendants have exited.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()
    deadline = time.monotonic() + 3
    while group_members(process.pid):
        if time.monotonic() >= deadline:
            raise RuntimeError('MEMORY_GROUP_CLEANUP_FAILED')
        time.sleep(.05)


def child_limits():
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_CAP, ADDRESS_CAP))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run_bounded(argv, log_path, env):
    if sys.platform != 'linux':
        raise RuntimeError('MEMORY_GUARD_LINUX_REQUIRED')
    if not isinstance(argv, list) or not argv or any(not isinstance(a, str) for a in argv):
        raise ValueError('MEMORY_ARGV')
    if any(env.get(key) != '1' for key in THREAD_KEYS):
        raise ValueError('MEMORY_THREAD_ENV')
    total, available = available_memory()
    reserve = check_available(total, available)
    log_path = Path(log_path)
    if any(p.is_symlink() for p in (log_path, *log_path.parents)):
        raise ValueError('MEMORY_LOG_SYMLINK')
    receipt_path = Path(str(log_path) + '.memory.json')
    if receipt_path.exists():
        raise ValueError('MEMORY_RECEIPT_EXISTS')
    result = dict(status='STARTING', memory_policy=policy(), initial_available_bytes=available,
                  effective_total_bytes=total, reserve_bytes=reserve, sample_count=0,
                  peak_group_rss_bytes=0, peak_combined_rss_bytes=0, exit_code=None)
    started, process = time.monotonic(), None
    try:
        with log_path.open('xb') as stream:
            process = subprocess.Popen(argv, env=env, stdout=stream, stderr=subprocess.STDOUT,
                                       start_new_session=True, preexec_fn=child_limits)
            result['process_group'] = process.pid
            while True:
                code = process.poll()
                if code is not None:
                    result['exit_code'] = code
                    if code != 0:
                        raise RuntimeError('MEMORY_WORKER_FAILED')
                    if group_members(process.pid):
                        raise RuntimeError('MEMORY_DESCENDANT_LEFTOVER')
                    break
                used = group_rss(process.pid)
                combined = used + rss(os.getpid())
                result['sample_count'] += 1
                result['peak_group_rss_bytes'] = max(result['peak_group_rss_bytes'], used)
                result['peak_combined_rss_bytes'] = max(result['peak_combined_rss_bytes'], combined)
                _, remaining = available_memory()
                if combined > RSS_CAP or remaining < reserve:
                    raise RuntimeError('MEMORY_PRESSURE_STOP')
                if time.monotonic() - started > TIMEOUT_S:
                    raise RuntimeError('MEMORY_TIMEOUT_STOP')
                time.sleep(POLL_S)
        result['status'] = 'PASS_BOUNDED_WORKER'
        return result
    except BaseException as error:
        result['status'] = 'STOPPED_NO_RETRY'
        result['error'] = str(error)
        if process is not None:
            terminate_group(process)
            result['exit_code'] = process.returncode
            result['live_group_members_after_cleanup'] = len(group_members(process.pid))
        raise
    finally:
        result['elapsed_seconds'] = time.monotonic() - started
        with receipt_path.open('x') as stream:
            json.dump(result, stream, sort_keys=True)
