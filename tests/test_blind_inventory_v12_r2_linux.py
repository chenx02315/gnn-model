"""Linux syscall integration coverage for the sealed r2 inventory primitive.

This module is deliberately skipped outside Linux.  A skip is evidence that the
positive integration gate remains pending, not that the design-only contract
has passed a platform gate.
"""
from __future__ import print_function

import errno
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data import blind_inventory_v12_r2 as r2


SORT = shutil.which("sort")
SEAL_CONSTANTS = ("F_ADD_SEALS", "F_GET_SEALS", "F_SEAL_WRITE", "F_SEAL_GROW", "F_SEAL_SHRINK", "F_SEAL_SEAL")
LINUX_PREREQUISITES = (sys.version_info >= (3, 8) and sys.platform.startswith("linux") and SORT and
                       r2._secure_primitives_available() and hasattr(os, "mkfifo") and
                       all(hasattr(os, name) for name in ("memfd_create", "MFD_CLOEXEC", "MFD_ALLOW_SEALING")) and
                       r2._fcntl is not None and all(hasattr(r2._fcntl, name) for name in SEAL_CONSTANTS) and
                       os.path.isdir("/proc/self/fd"))


def _sort_version(path):
    return subprocess.run([path, "--version"], check=True, stdout=subprocess.PIPE).stdout.decode("utf-8").splitlines()[0]


def _gnu_sort_available():
    try:
        return bool(SORT and _sort_version(SORT).startswith("sort (GNU coreutils)"))
    except (OSError, subprocess.SubprocessError, UnicodeError, IndexError):
        return False


LINUX_PREREQUISITES = bool(LINUX_PREREQUISITES and _gnu_sort_available())


def _gate_decision(result, prerequisites):
    """Return the direct-entry gate state without treating skips as a pass."""
    failures = len(result.failures)
    errors = len(result.errors)
    gate_pass = bool(prerequisites and result.testsRun > 0 and len(result.skipped) == 0 and
                     failures == 0 and errors == 0 and result.wasSuccessful())
    if gate_pass:
        return {"gate_pass": True, "platform_positive_integration": "PASS_LOCAL_SYNTHETIC_ONLY", "exit_code": 0}
    if failures or errors or not result.wasSuccessful():
        return {"gate_pass": False, "platform_positive_integration": "FAIL_LOCAL_SYNTHETIC", "exit_code": 1}
    return {"gate_pass": False, "platform_positive_integration": "PENDING_LINUX_ONLY", "exit_code": 2}


@unittest.skipUnless(LINUX_PREREQUISITES, "Linux sealed-descriptor prerequisites required")
class BlindInventoryV12R2LinuxTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = self.temporary.name
        self.sort_copy = os.path.join(self.root, "sort-anchor")
        shutil.copy2(SORT, self.sort_copy)
        os.chmod(self.sort_copy, 0o500)
        self.sort_digest = self._digest_path(self.sort_copy)
        self.sort_version = _sort_version(self.sort_copy)
        self.controls = []

    def tearDown(self):
        for control in self.controls:
            r2._close_test_control(control)
        self.temporary.cleanup()

    @staticmethod
    def _digest_path(path):
        digest = hashlib.sha256()
        with open(path, "rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    def _control(self, log_root, expected):
        control = r2._issue_test_control({"synthetic": {"log_root": log_root, "expected": expected}},
                                         self.sort_copy, self.sort_digest, self.sort_version)
        self.controls.append(control)
        return control

    @staticmethod
    def _independent_inventory(log_root):
        digests = {}
        for directory, ignored_dirs, filenames in os.walk(log_root, followlinks=False):
            del ignored_dirs
            for name in filenames:
                if name.endswith(".driver.log"):
                    full_path = os.path.join(directory, name)
                    relative = os.path.relpath(full_path, log_root).replace(os.sep, "/")
                    digests[relative] = BlindInventoryV12R2LinuxTests._digest_path(full_path)
        return digests

    @staticmethod
    def _independent_system_sort(paths):
        payload = b"\0".join(("./" + item).encode("utf-8") for item in paths)
        if payload:
            payload += b"\0"
        completed = subprocess.run([SORT, "-z"], input=payload, check=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env={"LANG": "en_US.UTF-8"})
        return [item.decode("utf-8")[2:] for item in completed.stdout.split(b"\0") if item]

    @staticmethod
    def _independent_digest_lines(order, digests):
        payload = "".join(digests[item] + "  ./" + item + "\n" for item in order)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @classmethod
    def _expected(cls, log_root):
        digests = cls._independent_inventory(log_root)
        paths = list(digests)
        historical = cls._independent_system_sort(paths)
        bytewise = sorted(paths, key=lambda item: ("./" + item).encode("utf-8"))
        return {"driver_log_count": len(paths),
                "historical_locale_ordered_sha256": cls._independent_digest_lines(historical, digests),
                "bytewise_ordered_sha256": cls._independent_digest_lines(bytewise, digests)}

    def test_end_to_end_synthetic_nested_logs_with_gnu_sort(self):
        logs = os.path.join(self.root, "logs")
        os.mkdir(logs)
        os.mkdir(os.path.join(logs, "nested"))
        with open(os.path.join(logs, "z.driver.log"), "wb") as stream:
            stream.write(b"z\n")
        with open(os.path.join(logs, "nested", "a.driver.log"), "wb") as stream:
            stream.write(b"a\n")
        control = self._control(logs, self._expected(logs))
        self.assertEqual(control._circuits["synthetic"]["expected"], r2.verify_dual_log_inventory(control, "synthetic"))

    def test_symlink_file_directory_and_fifo_refuse_without_blocking(self):
        cases = (("link.driver.log", "file"), ("linkdir", "directory"), ("pipe.driver.log", "fifo"))
        for name, kind in cases:
            case_root = os.path.join(self.root, kind)
            os.mkdir(case_root)
            target = os.path.join(case_root, "target")
            if kind == "file":
                with open(target, "wb") as stream:
                    stream.write(b"x")
                os.symlink(target, os.path.join(case_root, name))
            elif kind == "directory":
                os.mkdir(target)
                os.symlink(target, os.path.join(case_root, name))
            else:
                os.mkfifo(os.path.join(case_root, name))
            fd = r2._open_root(case_root)
            started = time.monotonic()
            try:
                with self.assertRaisesRegex(r2.Refusal, "^(LOG_SYMLINK|LOG_FILE_TYPE)$"):
                    r2._walk_logs(fd)
            finally:
                os.close(fd)
            self.assertLess(time.monotonic() - started, 1.0)

    def test_sealed_memfd_rejects_write_and_truncate(self):
        fd = r2._create_sealed_sort_fd(b"sealed")
        try:
            seals = r2._fcntl.fcntl(fd, r2._fcntl.F_GET_SEALS)
            required = (r2._fcntl.F_SEAL_WRITE | r2._fcntl.F_SEAL_GROW |
                        r2._fcntl.F_SEAL_SHRINK | r2._fcntl.F_SEAL_SEAL)
            self.assertEqual(required, seals & required)
            os.lseek(fd, 0, os.SEEK_SET)
            self.assertEqual(b"sealed", os.read(fd, 64))
            with self.assertRaisesOSError(errno.EPERM):
                os.write(fd, b"x")
            with self.assertRaisesOSError(errno.EPERM):
                os.ftruncate(fd, 0)
            with self.assertRaisesOSError(errno.EPERM):
                os.ftruncate(fd, 64)
        finally:
            os.close(fd)

    def test_sealed_sort_exec_survives_source_replacement(self):
        control = self._control(self.root, {"driver_log_count": 0, "historical_locale_ordered_sha256": "0" * 64,
                                             "bytewise_ordered_sha256": "0" * 64})
        fd = r2._verified_sort_fd(control)
        try:
            replacement = os.path.join(self.root, "replacement")
            with open(replacement, "wb") as stream:
                stream.write(b"not the verified sort")
            os.chmod(replacement, 0o500)
            os.replace(replacement, self.sort_copy)
            with mock.patch.object(r2, "_verified_sort_fd", side_effect=lambda ignored: os.dup(fd)):
                self.assertEqual(["a", "z"], r2._run_verified_sort(control, ["z", "a"]))
        finally:
            os.close(fd)

    def test_sort_anchor_fifo_refuses_without_blocking(self):
        fifo = os.path.join(self.root, "sort-fifo")
        os.mkfifo(fifo)
        control = r2._issue_test_control({"synthetic": {"log_root": self.root, "expected": {}}}, fifo,
                                         self.sort_digest, self.sort_version)
        self.controls.append(control)
        started = time.monotonic()
        with self.assertRaisesRegex(r2.Refusal, "^SORT_FILE_TYPE$"):
            r2._verified_sort_fd(control)
        self.assertLess(time.monotonic() - started, 1.0)

    def test_coordinated_directory_member_addition_refuses(self):
        logs = os.path.join(self.root, "race")
        os.mkdir(logs)
        with open(os.path.join(logs, "initial.driver.log"), "wb") as stream:
            stream.write(b"initial")
        original_listdir = r2.os.listdir
        added = [False]

        def coordinated_listdir(fd):
            names = original_listdir(fd)
            if not added[0]:
                added[0] = True
                with open(os.path.join(logs, "added.driver.log"), "wb") as stream:
                    stream.write(b"added")
            return names

        fd = r2._open_root(logs)
        try:
            with mock.patch.object(r2.os, "listdir", side_effect=coordinated_listdir):
                with self.assertRaisesRegex(r2.Refusal, "^LOG_RACE_DETECTED$"):
                    r2._walk_logs(fd)
        finally:
            os.close(fd)


def main():
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    decision = _gate_decision(result, LINUX_PREREQUISITES)
    print("BLIND_INVENTORY_V12_R2_LINUX_SUMMARY=" + json.dumps({
        "platform": sys.platform, "testsRun": result.testsRun, "skipped": len(result.skipped),
        "failures": len(result.failures), "errors": len(result.errors),
        "gate_pass": decision["gate_pass"],
        "platform_positive_integration": decision["platform_positive_integration"],
    }, sort_keys=True))
    return decision["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
