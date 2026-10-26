"""Fixed two-report TRAIN readback; no launch, environment read, or writes."""
import base64
import hashlib
import os
import platform
import stat
import sys
import time

from src.data import prospective_acceptance_materializer_v1 as io
from src.data import prospective_tessent_acceptance_v1 as pins
from src.data import direct_tessent_acceptance_e104 as direct

SCHEMA = 'e119-readonly-warning-evidence-v1'
BOOT = '3ebeb9bb-410c-476c-a000-5c625f590473'
END = 2382888.679409259
MAX_FILE = 512 * 1024
MAX_RESPONSE = 2 * 1024 * 1024
PATHS = tuple('/temp/jiangchuanc/multimode_ate_phase4_20260825_A/10_circuits/' +
              c + '/logs/H_' + c + '_H_full_phase4_v2.driver.log' for c in ('aes_core', 'spi'))
require = pins.require


class Budget(object):
    def __init__(self, domain, started):
        self.domain, self.end = domain, min(END, started + 30)
        self.bytes = 0

    def tick(self):
        require(time.monotonic() < self.end, 'ORIGINAL_OR_COLLECTOR_DEADLINE')
        require(not self.domain.sample(), 'UNEXPECTED_CHILDREN')
        require(self.domain.peak <= 536870912, 'SAMPLED_MEMORY_STOP')
        require(time.monotonic() < self.end, 'ORIGINAL_OR_COLLECTOR_DEADLINE')


def read_report(path, budget):
    require(path in PATHS, 'FIXED_REPORT_PATH')
    budget.tick()
    parent, name = path.rsplit('/', 1)
    parent_fd = io._directory(parent)
    fd = None
    try:
        parent_identity = io._identity(os.fstat(parent_fd))
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                0 < before.st_size <= MAX_FILE, 'BOUNDED_SINGLE_LINK_REPORT')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        require(io._identity(before) == io._identity(os.fstat(fd)), 'REPORT_CHANGED')
        parts, digest, remaining = [], hashlib.sha256(), before.st_size
        while remaining:
            budget.tick()
            raw = os.read(fd, min(65536, remaining))
            require(bool(raw), 'REPORT_SHORT_READ')
            remaining -= len(raw)
            budget.bytes += len(raw)
            require(budget.bytes <= 2 * MAX_FILE, 'TOTAL_BODY_BOUND')
            digest.update(raw)
            parts.append(raw)
        require(not os.read(fd, 1), 'REPORT_GREW')
        budget.tick()
        require(io._identity(before) == io._identity(os.fstat(fd)) ==
                io._identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)), 'REPORT_CHANGED')
        fresh = io._directory(parent)
        try:
            require(io._identity(os.fstat(fresh)) == parent_identity, 'REPORT_PARENT_CHANGED')
        finally:
            os.close(fresh)
        return dict(path=path, bytes=before.st_size, sha256=digest.hexdigest(),
                    body_base64=base64.b64encode(b''.join(parts)).decode('ascii'), whole_file_hashed=True)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent_fd)


def collect(bootstrap_started=None):
    started = time.monotonic() if bootstrap_started is None else bootstrap_started
    result = dict(schema=SCHEMA, hostname=platform.node(), uid=os.getuid() if hasattr(os, 'getuid') else None,
                  boot_id=None, remote_start_monotonic=started, remote_end_monotonic=None,
                  original_deadline_monotonic=END, clock_must_not_be_reset=True,
                  reports=[], capture_complete=False, error=None, body_bytes_hashed=0,
                  sampled_peak_rss_swap_bytes=0, explicit_filesystem_writes=0, child_launches=0,
                  environment_reads=0, atpg_launches=0, training_runs=0,
                  execution_ready=False, training_release=False, warnings_qualified=False,
                  sampling_is_hard_memory_guarantee=False)
    domain = budget = None
    try:
        require(sys.platform.startswith('linux') and result['hostname'] == 'bupt-vncs2' and
                result['uid'] == 1047, 'FIXED_HOST_UID_PLATFORM')
        require(time.monotonic() < min(END, started + 30), 'ORIGINAL_OR_COLLECTOR_DEADLINE')
        result['boot_id'] = direct.base._small('/proc/sys/kernel/random/boot_id', 128).decode('ascii').strip()
        require(result['boot_id'] == BOOT, 'ORIGINAL_BOOT_REQUIRED')
        domain = direct.Descendants()
        budget = Budget(domain, started)
        for path in PATHS:
            result['reports'].append(read_report(path, budget))
        budget.tick()
        result['capture_complete'] = True
    except Exception as exc:
        result['error'] = dict(type=type(exc).__name__, code=str(exc) if type(exc) is ValueError else 'READONLY_CAPTURE_FAILED')
    finally:
        result['remote_end_monotonic'] = time.monotonic()
        if budget is not None:
            result['body_bytes_hashed'] = budget.bytes
        if domain is not None:
            result['sampled_peak_rss_swap_bytes'] = domain.peak
    require(len(pins.canonical(result)) <= MAX_RESPONSE, 'RESPONSE_BOUND')
    return result
