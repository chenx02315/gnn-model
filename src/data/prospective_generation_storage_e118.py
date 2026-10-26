"""Exclusive E116 sidecar and bounded root+sidecar metadata sampling.

Samples are not a disk quota or source authentication. Live file growth is
allowed and charged conservatively across each before/after metadata pair.
Open-unlinked files and writes outside the fixed root/sidecar are unmeasurable.
"""
import copy
import os
import stat
import time

from . import prospective_acceptance_materializer_v1 as io
from . import prospective_generation_recipe_e108 as recipe
from .direct_runtime_compatibility_e102 import classify_leaf

ROOT = recipe.ROOT
SIDECAR = ROOT + '.initial_intent.json'
END = 2382888.679409259
LIMIT = 8589934592
UID = 1047
HOST = 'bupt-vncs2'
MAX_ENTRIES = 16384
MAX_DEPTH = 32
SAMPLE_SECONDS = 5.0
CACHE_SECONDS = 1.0
require, sha = io.require, io.sha


def _identity(info):
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))


def _tick(deadline):
    require(time.monotonic() < deadline, 'STORAGE_SAMPLE_DEADLINE')


def _size(info):
    require(type(info.st_size) is int and info.st_size >= 0 and
            type(info.st_blocks) is int and info.st_blocks >= 0, 'STORAGE_SIZE_INVALID')
    return max(info.st_size, info.st_blocks * 512)


def _leaf(info, name, device, sidecar=False):
    require(info.st_dev == device and info.st_uid == UID and info.st_nlink == 1,
            'STORAGE_LEAF_DEVICE_OWNER_OR_LINKS')
    if stat.S_ISREG(info.st_mode):
        return
    require(not sidecar and stat.S_ISSOCK(info.st_mode), 'STORAGE_UNSUPPORTED_LEAF')
    classify_leaf(info, name, UID, HOST)  # Metadata only; socket is never opened.


def persist_initial_intent(raw):
    """One exact sidecar, no overwrite, retry, recovery or partial cleanup."""
    require(type(raw) is bytes and 0 < len(raw) <= 65536, 'INITIAL_INTENT_BYTES')
    require(os.getuid() == UID, 'STORAGE_FIXED_UID')
    _tick(END)
    parent, name = SIDECAR.rsplit('/', 1)
    fd = io._directory(parent)
    try:
        io._publish(fd, name, raw)  # O_EXCL/O_NOFOLLOW + both fsync + stable readback.
        named = os.stat(name, dir_fd=fd, follow_symlinks=False)
        require(stat.S_ISREG(named.st_mode) and named.st_nlink == 1 and named.st_uid == UID,
                'INITIAL_INTENT_IDENTITY')
        _, size, digest = io._read_at(fd, name, [0], expected_bytes=len(raw), max_bytes=65536)
        require(digest == sha(raw), 'INITIAL_INTENT_READBACK_SHA')
        fresh = io._directory(parent)
        try:
            require(_identity(os.fstat(fresh)) == _identity(os.fstat(fd)) and
                    _identity(os.stat(name, dir_fd=fresh, follow_symlinks=False)) == _identity(named),
                    'INITIAL_INTENT_PARENT_OR_LEAF_REPLACED')
        finally:
            os.close(fresh)
        _tick(END)
        return dict(path=SIDECAR, bytes=size, sha256=digest)
    finally:
        os.close(fd)


class DirectoryMonitor(object):
    def __init__(self):
        self.root_identity = self.sidecar_identity = None
        self.last = None
        self.samples = self.cache_hits = 0

    def sample(self):
        now = time.monotonic()
        _tick(END)
        require(os.getuid() == UID, 'STORAGE_FIXED_UID')
        deadline = min(END, now + SAMPLE_SECONDS)
        root_fd = parent_fd = None
        try:
            root_fd = io._directory(ROOT)
            root = os.fstat(root_fd)
            require(stat.S_ISDIR(root.st_mode) and root.st_uid == UID, 'STORAGE_ROOT_OWNER_OR_TYPE')
            root_identity = _identity(root)
            require(self.root_identity is None or self.root_identity == root_identity, 'STORAGE_ROOT_REPLACED')
            parent, sidecar_name = SIDECAR.rsplit('/', 1)
            parent_fd = io._directory(parent)
            sidecar = os.stat(sidecar_name, dir_fd=parent_fd, follow_symlinks=False)
            _leaf(sidecar, sidecar_name, root.st_dev, sidecar=True)
            sidecar_identity = _identity(sidecar)
            require(self.sidecar_identity is None or self.sidecar_identity == sidecar_identity,
                    'STORAGE_SIDECAR_REPLACED')
            _tick(deadline)
            if self.last is not None:
                cache_now = time.monotonic()
                require(cache_now < deadline, 'STORAGE_SAMPLE_DEADLINE')
                age = cache_now - self.last['sampled_at_monotonic']
                if 0 <= age < CACHE_SECONDS:
                    self.cache_hits += 1
                    return dict(copy.deepcopy(self.last), cached=True, cache_age_seconds=age,
                                fresh_root_and_sidecar_identity_checked=True)
            self.root_identity, self.sidecar_identity = root_identity, sidecar_identity
            seen, count = set(), [2]  # Include the fixed root and its sidecar.
            total = [0]

            def charge(before, after):
                require(_identity(before) == _identity(after), 'STORAGE_ENTRY_REPLACED')
                require(before.st_dev == root.st_dev and after.st_dev == root.st_dev,
                        'STORAGE_DEVICE_CHANGED')
                key = (before.st_dev, before.st_ino)
                require(key not in seen, 'STORAGE_ALIAS_OR_LOOP')
                seen.add(key)
                total[0] += max(_size(before), _size(after))
                require(total[0] <= LIMIT, 'STORAGE_BYTES_THRESHOLD')

            def visit(fd, depth):
                _tick(deadline)
                require(depth <= MAX_DEPTH, 'STORAGE_DEPTH_BOUND')
                before = os.fstat(fd)
                require(stat.S_ISDIR(before.st_mode) and before.st_uid == UID and before.st_dev == root.st_dev,
                        'STORAGE_DIRECTORY_OWNER_DEVICE_OR_TYPE')
                with os.scandir('/proc/self/fd/%d' % fd) as stream:
                    for entry in stream:
                        _tick(deadline)
                        count[0] += 1
                        require(count[0] <= MAX_ENTRIES, 'STORAGE_ENTRY_BOUND')
                        name = entry.name
                        require(type(name) is str and name not in ('', '.', '..') and '/' not in name and
                                '\x00' not in name and len(name) <= 255, 'STORAGE_NAME_INVALID')
                        named = os.stat(name, dir_fd=fd, follow_symlinks=False)
                        if stat.S_ISDIR(named.st_mode):
                            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                            try:
                                require(_identity(named) == _identity(os.fstat(child)), 'STORAGE_DIRECTORY_REPLACED')
                                visit(child, depth + 1)
                                after = os.stat(name, dir_fd=fd, follow_symlinks=False)
                                require(_identity(named) == _identity(after) and after.st_uid == UID,
                                        'STORAGE_DIRECTORY_REPLACED')
                            finally:
                                os.close(child)
                        else:
                            _leaf(named, name, root.st_dev)
                            after = os.stat(name, dir_fd=fd, follow_symlinks=False)
                            _leaf(after, name, root.st_dev)
                            charge(named, after)
                after = os.fstat(fd)
                require(after.st_uid == UID, 'STORAGE_DIRECTORY_OWNER_DEVICE_OR_TYPE')
                charge(before, after)  # No mtime/size equality for a live directory.
                _tick(deadline)

            visit(root_fd, 0)
            after_sidecar = os.stat(sidecar_name, dir_fd=parent_fd, follow_symlinks=False)
            _leaf(after_sidecar, sidecar_name, root.st_dev, sidecar=True)
            charge(sidecar, after_sidecar)
            fresh_root = io._directory(ROOT)
            try:
                require(_identity(os.fstat(fresh_root)) == root_identity, 'STORAGE_ROOT_REPLACED')
            finally:
                os.close(fresh_root)
            _tick(deadline)
            ended = time.monotonic()
            require(ended < deadline, 'STORAGE_SAMPLE_DEADLINE')
            self.samples += 1
            self.last = dict(root=ROOT, sidecar=SIDECAR, sidecar_accounted=True,
                threshold_bytes=LIMIT, sampled_named_bytes=total[0], entries=count[0],
                entries_scope='ROOT_PLUS_DESCENDANTS_PLUS_SIDECAR',
                root_identity=list(root_identity), sidecar_identity=list(sidecar_identity),
                scan_started_monotonic=now, sampled_at_monotonic=ended,
                cached=False, cache_age_seconds=0.0, cache_lifetime_seconds_max=CACHE_SECONDS,
                fresh_root_and_sidecar_identity_checked=True,
                sampling_is_disk_quota=False, current_exact_size_proven=False,
                open_unlinked_or_outside_root_accounted=False,
                cooperative_scan_seconds_max=SAMPLE_SECONDS, hard_scan_deadline_guaranteed=False,
                original_package_deadline=END)
            return copy.deepcopy(self.last)
        finally:
            for fd in (parent_fd, root_fd):
                if fd is not None:
                    os.close(fd)
