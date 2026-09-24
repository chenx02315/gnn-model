#!/usr/bin/env python3
"""Design-only r2 inventory primitive; it has no BLIND execution authority.

The production factory deliberately has no arguments and refuses until a future
review freezes its external trust anchors.  The private test issuer below is a
unit-test seam, not an authority boundary.  In particular, Python code running
in the same interpreter is outside this module's threat model: an opaque class
is not claimed to be unforgeable against hostile in-process code.
"""
from __future__ import print_function

import hashlib
import os
import stat
import subprocess
import sys

try:
    import fcntl as _fcntl
except ImportError:  # Windows and non-POSIX platforms must refuse, not emulate.
    _fcntl = None

SORT_ENV = {"LANG": "en_US.UTF-8"}
_ISSUED = set()
_TEST_ISSUER = object()


class Refusal(Exception):
    pass


class _TrustedInventoryControl(object):
    __slots__ = ("_issuer", "_circuits", "_sort_path", "_sort_sha256", "_sort_version", "_closed")

    def __init__(self, issuer, circuits, sort_path, sort_sha256, sort_version):
        if issuer is not _TEST_ISSUER:
            raise TypeError("TRUSTED_CONTROL_CONSTRUCTION_FORBIDDEN")
        self._issuer = issuer
        self._circuits = circuits
        self._sort_path = sort_path
        self._sort_sha256 = sort_sha256
        self._sort_version = sort_version
        self._closed = False


def open_trusted_inventory_control():
    """Production factory.  Anchors are intentionally not guessed from inputs."""
    raise Refusal("TRUST_ANCHORS_NOT_FINALIZED")


def _issue_test_control(circuits, sort_path, sort_sha256, sort_version):
    """Private test-only issuer; never call this from a production launcher."""
    control = _TrustedInventoryControl(_TEST_ISSUER, circuits, sort_path, sort_sha256, sort_version)
    _ISSUED.add(id(control))
    return control


def _close_test_control(control):
    control._closed = True
    _ISSUED.discard(id(control))


def _require_control(control, circuit_name):
    if type(control) is not _TrustedInventoryControl or id(control) not in _ISSUED or control._closed:
        raise Refusal("TRUSTED_CONTROL_REQUIRED")
    if not isinstance(circuit_name, str) or circuit_name not in control._circuits:
        raise Refusal("FROZEN_CIRCUIT_REQUIRED")
    return control._circuits[circuit_name]


def _secure_primitives_available():
    return (os.name == "posix" and sys.platform.startswith("linux") and
            all(hasattr(os, name) for name in ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC")) and
            os.path.isdir("/proc/self/fd"))


def _refuse_unavailable():
    if not _secure_primitives_available():
        raise Refusal("SECURE_DESCRIPTOR_IO_UNAVAILABLE")


def _portable_component(name):
    if not isinstance(name, str) or not name or name in (".", ".."):
        return False
    try:
        name.encode("ascii", "strict")
    except UnicodeEncodeError:
        return False
    return not any(character in name for character in ("/", "\\", "\r", "\n", "\x00"))


def _hash_fd(fd):
    digest = hashlib.sha256()
    while True:
        block = os.read(fd, 1024 * 1024)
        if not block:
            break
        digest.update(block)
    return digest.hexdigest()


def _read_and_hash_fd(fd):
    """Consume one already-open source FD without ever reopening its path."""
    digest = hashlib.sha256()
    payload = bytearray()
    while True:
        block = os.read(fd, 1024 * 1024)
        if not block:
            break
        digest.update(block)
        payload.extend(block)
    return digest.hexdigest(), bytes(payload)


def _create_sealed_sort_fd(payload):
    """Copy verified bytes to an immutable Linux memfd suitable for exec."""
    required_os = ("memfd_create", "MFD_CLOEXEC", "MFD_ALLOW_SEALING")
    required_fcntl = ("F_ADD_SEALS", "F_GET_SEALS", "F_SEAL_WRITE", "F_SEAL_GROW", "F_SEAL_SHRINK", "F_SEAL_SEAL")
    if (not _secure_primitives_available() or _fcntl is None or
            not all(hasattr(os, name) for name in required_os) or
            not all(hasattr(_fcntl, name) for name in required_fcntl)):
        raise Refusal("SECURE_DESCRIPTOR_IO_UNAVAILABLE")
    if not isinstance(payload, bytes):
        raise Refusal("SEALED_SORT_PAYLOAD_INVALID")
    fd = None
    try:
        flags = os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
        fd = os.memfd_create("blind-inventory-sort-r2", flags)
        offset = 0
        while offset < len(payload):
            wrote = os.write(fd, payload[offset:])
            if not isinstance(wrote, int) or wrote <= 0:
                raise Refusal("SEALED_SORT_WRITE_FAILED")
            offset += wrote
        os.fchmod(fd, 0o500)
        os.lseek(fd, 0, os.SEEK_SET)
        seals = (_fcntl.F_SEAL_WRITE | _fcntl.F_SEAL_GROW | _fcntl.F_SEAL_SHRINK | _fcntl.F_SEAL_SEAL)
        _fcntl.fcntl(fd, _fcntl.F_ADD_SEALS, seals)
        actual = _fcntl.fcntl(fd, _fcntl.F_GET_SEALS)
        if (actual & seals) != seals:
            raise Refusal("SEALED_SORT_SEAL_FAILED")
        result = fd
        fd = None
        return result
    except Refusal:
        raise
    except (OSError, ValueError, TypeError):
        raise Refusal("SEALED_SORT_CREATE_FAILED")
    finally:
        if fd is not None:
            os.close(fd)


def _metadata(record):
    """Metadata which must not change while an entry is being consumed."""
    return tuple(getattr(record, name, None) for name in
                 ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))


def _same_directory_entry(left, right):
    return _metadata(left) == _metadata(right)


def _directory_members(parent_fd):
    """Snapshot every direct member, including metadata that records mutation."""
    members = {}
    for name in os.listdir(parent_fd):
        if not _portable_component(name):
            raise Refusal("LOG_PATH_ENCODING")
        members[name] = _metadata(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
    return members


def _open_root(root):
    _refuse_unavailable()
    if not isinstance(root, str) or not root.startswith("/"):
        raise Refusal("LOG_ROOT_INVALID")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for component in [piece for piece in root.split("/") if piece]:
            if not _portable_component(component):
                raise Refusal("LOG_PATH_ENCODING")
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except Exception:
        os.close(fd)
        raise


def _walk_logs(parent_fd, prefix=""):
    """Return {relative: digest}, reading every selected file exactly once."""
    before = os.fstat(parent_fd)
    before_members = _directory_members(parent_fd)
    result = {}
    for name in sorted(before_members):
        entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        relative = prefix + name
        if stat.S_ISLNK(entry.st_mode):
            raise Refusal("LOG_SYMLINK")
        if stat.S_ISDIR(entry.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
            try:
                opened = os.fstat(child)
                if not stat.S_ISDIR(opened.st_mode) or not _same_directory_entry(opened, entry):
                    raise Refusal("LOG_RACE_DETECTED")
                result.update(_walk_logs(child, relative + "/"))
                after_entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if not _same_directory_entry(entry, after_entry):
                    raise Refusal("LOG_RACE_DETECTED")
            finally:
                os.close(child)
        elif relative.endswith(".driver.log"):
            if not stat.S_ISREG(entry.st_mode):
                raise Refusal("LOG_FILE_TYPE")
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent_fd)
            try:
                opened = os.fstat(fd)
                if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (entry.st_dev, entry.st_ino):
                    raise Refusal("LOG_RACE_DETECTED")
                result[relative] = _hash_fd(fd)
                after_file = os.fstat(fd)
                after_entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if _metadata(after_file) != _metadata(opened) or _metadata(after_entry) != _metadata(entry):
                    raise Refusal("LOG_RACE_DETECTED")
            finally:
                os.close(fd)
        elif not stat.S_ISREG(entry.st_mode):
            raise Refusal("LOG_FILE_TYPE")
    after = os.fstat(parent_fd)
    after_members = _directory_members(parent_fd)
    if _metadata(before) != _metadata(after) or before_members != after_members:
        raise Refusal("LOG_RACE_DETECTED")
    return result


def _verified_sort_fd(control):
    _refuse_unavailable()
    path = control._sort_path
    if not isinstance(path, str) or not path.startswith("/"):
        raise Refusal("SORT_ANCHOR_INVALID")
    pieces = [piece for piece in path.split("/") if piece]
    if not pieces or not all(_portable_component(piece) for piece in pieces):
        raise Refusal("SORT_ANCHOR_INVALID")
    parent = _open_root("/" + "/".join(pieces[:-1]))
    fd = None
    try:
        entry = os.stat(pieces[-1], dir_fd=parent, follow_symlinks=False)
        if stat.S_ISLNK(entry.st_mode):
            raise Refusal("SORT_SYMLINK")
        if not stat.S_ISREG(entry.st_mode):
            raise Refusal("SORT_FILE_TYPE")
        fd = os.open(pieces[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or not (opened.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)) or
                (opened.st_dev, opened.st_ino) != (entry.st_dev, entry.st_ino)):
            os.close(fd)
            fd = None
            raise Refusal("SORT_RACE_DETECTED")
        digest, payload = _read_and_hash_fd(fd)
        after_fd = os.fstat(fd)
        after_entry = os.stat(pieces[-1], dir_fd=parent, follow_symlinks=False)
        if _metadata(after_fd) != _metadata(opened) or _metadata(after_entry) != _metadata(entry):
            os.close(fd)
            fd = None
            raise Refusal("SORT_RACE_DETECTED")
        if digest != control._sort_sha256:
            os.close(fd)
            fd = None
            raise Refusal("SORT_DIGEST_MISMATCH")
        result = _create_sealed_sort_fd(payload)
        os.close(fd)
        fd = None
        return result
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def _run_verified_sort(control, paths):
    fd = _verified_sort_fd(control)
    try:
        executable = "/proc/self/fd/{}".format(fd)
        version = subprocess.run([control._sort_path, "--version"], executable=executable, check=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(SORT_ENV),
                                 pass_fds=(fd,), close_fds=True)
        first = version.stdout.decode("utf-8", "strict").splitlines()[0] if version.stdout else ""
        if first != control._sort_version:
            raise Refusal("SORT_VERSION_MISMATCH")
        payload = b"\0".join(("./" + item).encode("utf-8") for item in paths)
        if paths:
            payload += b"\0"
        result = subprocess.run([control._sort_path, "-z"], executable=executable, input=payload, check=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(SORT_ENV),
                                pass_fds=(fd,), close_fds=True)
    except (OSError, subprocess.CalledProcessError):
        raise Refusal("HISTORICAL_SORT_FAILED")
    finally:
        os.close(fd)
    ordered = result.stdout.split(b"\0")
    if ordered and ordered[-1] == b"":
        ordered.pop()
    try:
        decoded = [item.decode("utf-8", "strict") for item in ordered]
    except UnicodeDecodeError:
        raise Refusal("HISTORICAL_SORT_ENCODING")
    expected = ["./" + item for item in paths]
    if len(decoded) != len(expected) or set(decoded) != set(expected):
        raise Refusal("HISTORICAL_SORT_PERMUTATION")
    return [item[2:] for item in decoded]


def _digest_lines(order, digests):
    payload = "".join(digests[item] + "  ./" + item + "\n" for item in order)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_dual_log_inventory(control, circuit_name):
    """Verify both frozen lanes.  No candidate or outcome data is ever opened."""
    circuit = _require_control(control, circuit_name)
    root_fd = _open_root(circuit["log_root"])
    try:
        digests = _walk_logs(root_fd)
    finally:
        os.close(root_fd)
    paths = list(digests)
    historical = _run_verified_sort(control, paths)
    bytewise = sorted(paths, key=lambda item: ("./" + item).encode("utf-8"))
    observed = {"driver_log_count": len(paths), "historical_locale_ordered_sha256": _digest_lines(historical, digests),
                "bytewise_ordered_sha256": _digest_lines(bytewise, digests)}
    expected = circuit["expected"]
    required = set(observed)
    if type(expected) is not dict or set(expected) != required:
        raise Refusal("FROZEN_DUAL_INVENTORY_SCHEMA")
    if observed != expected:
        raise Refusal("DUAL_INPUT_INVENTORY_DRIFT")
    return observed


def main(argv=None):
    del argv
    print("BLIND_UNSEAL_V12_R2=DESIGN_ONLY_NO_EXECUTION")
    return 2


if __name__ == "__main__":
    sys.exit(main())
