"""E102 metadata-only monitor; derived from frozen E94 monitor, not a quota.

Adds only exact owned PVM socket metadata classification; never opens sockets.

Counts named files/directories using max(logical size, allocated blocks).
Open-unlinked files and writes outside this bundle are not measurable here.
Concurrent growth can overshoot; sampling errors abort rather than certify.
"""
import os
import stat
import time

from .direct_runtime_compatibility_e102 import classify_leaf

from . import prospective_tessent_acceptance_v1 as recipe
from .prospective_acceptance_materializer_v1 import _directory

LIMIT = 128 * 1024 * 1024
MAX_ENTRIES = 4096
MAX_DEPTH = 24
SAMPLE_SECONDS = 1.0
JOURNAL_RESERVE = 1024 * 1024


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def identity(info):
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))


def _sample(root_fd, deadline):
    """Private fd-anchored walker; never opens file bodies or follows links."""
    end = min(deadline, time.monotonic() + SAMPLE_SECONDS)
    root = os.fstat(root_fd)
    device = root.st_dev
    seen = set()
    # Conservatively reserve a full future coordinator journal in addition to
    # the current tree (even if its existing bytes are already counted).
    total = [JOURNAL_RESERVE]
    count = [0]

    def budget():
        require(time.monotonic() < end, 'SCRATCH_SAMPLE_TIMEOUT')

    def charge(info):
        require(info.st_dev == device, 'SCRATCH_DEVICE_CHANGED')
        require(type(info.st_size) is int and info.st_size >= 0 and
                type(info.st_blocks) is int and info.st_blocks >= 0,
                'SCRATCH_SIZE_INVALID')
        key = (info.st_dev, info.st_ino)
        require(key not in seen, 'SCRATCH_ALIAS_OR_LOOP')
        seen.add(key)
        total[0] += max(info.st_size, info.st_blocks * 512)
        require(total[0] <= LIMIT, 'SCRATCH_BYTES_THRESHOLD')

    def visit(fd, depth):
        budget()
        require(depth <= MAX_DEPTH, 'SCRATCH_DEPTH_BOUND')
        before = os.fstat(fd)
        require(stat.S_ISDIR(before.st_mode), 'SCRATCH_DIRECTORY_REQUIRED')
        charge(before)
        # Python 3.6-compatible streaming enumeration of an already-held fd.
        with os.scandir('/proc/self/fd/%d' % fd) as stream:
            for entry in stream:
                budget()
                count[0] += 1
                require(count[0] <= MAX_ENTRIES, 'SCRATCH_ENTRY_BOUND')
                name = entry.name
                require(type(name) is str and name not in ('', '.', '..') and
                        '/' not in name and '\x00' not in name and len(name) <= 255,
                        'SCRATCH_NAME_INVALID')
                named = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(named.st_mode):
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY |
                                    os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        require(identity(named) == identity(os.fstat(child)),
                                'SCRATCH_DIRECTORY_REPLACED')
                        visit(child, depth + 1)
                        require(identity(named) == identity(os.stat(
                            name, dir_fd=fd, follow_symlinks=False)),
                            'SCRATCH_DIRECTORY_REPLACED')
                    finally:
                        os.close(child)
                else:
                    if stat.S_ISSOCK(named.st_mode):
                        classify_leaf(named, name, os.getuid(), 'bupt-vncs2')
                    else:
                        require(stat.S_ISREG(named.st_mode) and named.st_nlink == 1,
                                'SCRATCH_SINGLE_LINK_FILE_REQUIRED')
                    charge(named)
                    after = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    require(identity(named) == identity(after) and
                            (named.st_size, named.st_blocks, named.st_mtime_ns,
                             named.st_ctime_ns, named.st_nlink) ==
                            (after.st_size, after.st_blocks, after.st_mtime_ns,
                             after.st_ctime_ns, after.st_nlink),
                            'SCRATCH_FILE_CHANGED')
        require(identity(before) == identity(os.fstat(fd)),
                'SCRATCH_DIRECTORY_REPLACED')
        budget()

    visit(root_fd, 0)
    return dict(named_bytes=total[0] - JOURNAL_RESERVE,
                accounted_bytes_with_journal_reserve=total[0], entries=count[0],
                root_identity=list(identity(root)))


class ScratchMonitor:
    def __init__(self, deadline):
        self.deadline = deadline
        self.root_identity = None
        self.samples = 0
        self.peak = 0
        self.last = None
        self.failure_code = None

    def sample(self):
        # Fixed root only; _directory rejects symlinks in every component.
        fd = None
        try:
            fd = _directory(recipe.ROOT)
            observed = _sample(fd, self.deadline)
            require(self.root_identity is None or
                    observed['root_identity'] == self.root_identity,
                    'SCRATCH_ROOT_REPLACED')
            self.root_identity = observed['root_identity']
            self.samples += 1
            self.peak = max(self.peak, observed['accounted_bytes_with_journal_reserve'])
            self.last = observed
            return observed
        except Exception as exc:
            self.failure_code = (str(exc) if isinstance(exc, ValueError) and
                                 str(exc).startswith('SCRATCH_') else
                                 'SCRATCH_INSPECTION_ERROR')
            raise
        finally:
            if fd is not None:
                os.close(fd)

    def summary(self):
        return dict(samples=self.samples, peak_sampled_accounted_bytes=self.peak,
                    last=self.last, threshold_bytes=LIMIT,
                    additional_future_journal_reserve_bytes=JOURNAL_RESERVE,
                    failure_code=self.failure_code,
                    semantics='SAMPLED_NAMED_TREE_MAX_LOGICAL_ALLOCATED_NOT_QUOTA',
                    open_unlinked_or_outside_root_accounted=False)
