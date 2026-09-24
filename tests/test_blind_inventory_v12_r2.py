import inspect
import os
import stat
import types
import unittest
from unittest import mock

from src.data import blind_inventory_v12_r2 as r2
from tests import test_blind_inventory_v12_r2_linux as linux_r2


class BlindInventoryV12R2Tests(unittest.TestCase):
    def setUp(self):
        self.circuits = {"s9234": {"log_root": "/frozen/logs", "expected": {
            "driver_log_count": 0,
            "historical_locale_ordered_sha256": "0" * 64,
            "bytewise_ordered_sha256": "0" * 64,
        }}}
        self.control = r2._issue_test_control(self.circuits, "/frozen/sort", "0" * 64, "sort (GNU coreutils) 8.22")

    def tearDown(self):
        r2._close_test_control(self.control)

    def test_production_factory_has_no_caller_controlled_inputs_and_fails_closed(self):
        with self.assertRaisesRegex(r2.Refusal, "^TRUST_ANCHORS_NOT_FINALIZED$"):
            r2.open_trusted_inventory_control()
        with self.assertRaises(TypeError):
            r2.open_trusted_inventory_control("/attacker/root")

    def test_none_tuple_dict_lookalike_subclass_closed_and_unknown_controls_refuse_before_io(self):
        class Lookalike(object):
            _closed = False

        class Subclass(r2._TrustedInventoryControl):
            pass

        forged = object.__new__(Subclass)
        shaped_v12_tuple = ("/attacker/CONSUMED", "attacker-contract", "attacker-tools", None)
        for value in (None, shaped_v12_tuple, {}, Lookalike(), forged):
            with self.subTest(kind=type(value).__name__), mock.patch.object(r2, "_open_root") as opened, mock.patch.object(r2, "_run_verified_sort") as sorted_run:
                with self.assertRaisesRegex(r2.Refusal, "^TRUSTED_CONTROL_REQUIRED$"):
                    r2.verify_dual_log_inventory(value, "s9234")
                opened.assert_not_called()
                sorted_run.assert_not_called()
        r2._close_test_control(self.control)
        with self.assertRaisesRegex(r2.Refusal, "^TRUSTED_CONTROL_REQUIRED$"):
            r2.verify_dual_log_inventory(self.control, "s9234")

    def test_unfrozen_circuit_refuses_before_filesystem_or_subprocess(self):
        with mock.patch.object(r2, "_open_root") as opened, mock.patch.object(r2, "_run_verified_sort") as sorted_run:
            with self.assertRaisesRegex(r2.Refusal, "^FROZEN_CIRCUIT_REQUIRED$"):
                r2.verify_dual_log_inventory(self.control, "attacker")
            opened.assert_not_called()
            sorted_run.assert_not_called()

    def test_public_api_cannot_receive_root_expected_or_sort_configuration(self):
        self.assertEqual(list(inspect.signature(r2.open_trusted_inventory_control).parameters), [])
        self.assertEqual(list(inspect.signature(r2.verify_dual_log_inventory).parameters), ["control", "circuit_name"])

    def test_windows_and_missing_secure_primitives_fail_closed(self):
        with mock.patch.object(r2, "_secure_primitives_available", return_value=False):
            with self.assertRaisesRegex(r2.Refusal, "^SECURE_DESCRIPTOR_IO_UNAVAILABLE$"):
                r2._open_root("/frozen/logs")

    def test_descriptor_walk_rejects_symlink_and_nonportable_names(self):
        with mock.patch.object(r2, "_secure_primitives_available", return_value=True), \
             mock.patch.multiple(r2.os, O_NOFOLLOW=1, O_CLOEXEC=2, O_NONBLOCK=4, create=True), \
             mock.patch.object(r2.os, "fstat", return_value=mock.Mock(st_dev=1, st_ino=1)), \
             mock.patch.object(r2.os, "listdir", return_value=["bad\\name.driver.log"]):
            with self.assertRaisesRegex(r2.Refusal, "^LOG_PATH_ENCODING$"):
                r2._walk_logs(9)

    @staticmethod
    def record(mode, inode=1, size=3, mtime=4, ctime=5):
        return mock.Mock(st_mode=mode, st_dev=1, st_ino=inode, st_size=size, st_mtime_ns=mtime, st_ctime_ns=ctime)

    def test_file_symlink_nested_directory_symlink_and_fifo_refuse(self):
        parent = self.record(stat.S_IFDIR)
        cases = (("file.driver.log", self.record(stat.S_IFLNK)),
                 ("nested", self.record(stat.S_IFLNK)),
                 ("pipe.driver.log", self.record(stat.S_IFIFO)))
        for name, entry in cases:
            with self.subTest(name=name), mock.patch.object(r2.os, "fstat", side_effect=(parent, parent)), \
                 mock.patch.object(r2.os, "listdir", return_value=[name]), \
                 mock.patch.object(r2.os, "stat", return_value=entry):
                with self.assertRaisesRegex(r2.Refusal, "^(LOG_SYMLINK|LOG_FILE_TYPE)$"):
                    r2._walk_logs(9)

    def test_file_replacement_after_hash_refuses_and_each_file_is_opened_once(self):
        parent = self.record(stat.S_IFDIR)
        before = self.record(stat.S_IFREG, inode=11)
        after = self.record(stat.S_IFREG, inode=12)
        with mock.patch.multiple(r2.os, O_NOFOLLOW=1, O_CLOEXEC=2, O_NONBLOCK=4, O_DIRECTORY=8, create=True), \
             mock.patch.object(r2.os, "fstat", side_effect=(parent, before, before, parent)), \
             mock.patch.object(r2.os, "listdir", return_value=["one.driver.log"]), \
             mock.patch.object(r2.os, "stat", side_effect=(before, after)), \
             mock.patch.object(r2.os, "open", return_value=51) as opened, \
             mock.patch.object(r2.os, "close"), mock.patch.object(r2, "_hash_fd", return_value="x"):
            with self.assertRaisesRegex(r2.Refusal, "^LOG_RACE_DETECTED$"):
                r2._walk_logs(9)
        self.assertEqual(opened.call_count, 1)
        self.assertEqual(opened.call_args.kwargs["dir_fd"], 9)

    def test_directory_replacement_after_recursion_refuses(self):
        parent = self.record(stat.S_IFDIR)
        before = self.record(stat.S_IFDIR, inode=11)
        after = self.record(stat.S_IFDIR, inode=12)
        child = self.record(stat.S_IFDIR, inode=11)
        with mock.patch.multiple(r2.os, O_NOFOLLOW=1, O_CLOEXEC=2, O_NONBLOCK=4, O_DIRECTORY=8, create=True), \
             mock.patch.object(r2.os, "fstat", side_effect=(parent, child, child, child)), \
             mock.patch.object(r2.os, "listdir", side_effect=(["nested"], [])), \
             mock.patch.object(r2.os, "stat", side_effect=(before, after)), \
             mock.patch.object(r2.os, "open", return_value=51), mock.patch.object(r2.os, "close"):
            with self.assertRaisesRegex(r2.Refusal, "^LOG_RACE_DETECTED$"):
                r2._walk_logs(9)

    def test_verified_sort_never_uses_path_or_inherited_environment(self):
        version = mock.Mock(stdout=b"sort (GNU coreutils) 8.22\n", stderr=b"")
        ordered = mock.Mock(stdout=b"./a.driver.log\0", stderr=b"")
        with mock.patch.object(r2, "_verified_sort_fd", return_value=47), \
             mock.patch.object(r2.os, "close") as closed, \
             mock.patch.object(r2.subprocess, "run", side_effect=(version, ordered)) as run:
            self.assertEqual(["a.driver.log"], r2._run_verified_sort(self.control, ["a.driver.log"]))
        for call in run.call_args_list:
            self.assertEqual(call.kwargs["env"], {"LANG": "en_US.UTF-8"})
            self.assertEqual(call.kwargs["pass_fds"], (47,))
            self.assertEqual(call.kwargs["executable"], "/proc/self/fd/47")
            self.assertEqual(call.args[0][0], "/frozen/sort")
            self.assertNotEqual(call.args[0][0], "sort")
        closed.assert_called_once_with(47)

    def test_sort_version_and_permutation_refuse(self):
        bad_version = mock.Mock(stdout=b"sort (GNU coreutils) 9.0\n", stderr=b"")
        with mock.patch.object(r2, "_verified_sort_fd", return_value=5), mock.patch.object(r2.os, "close"), \
             mock.patch.object(r2.subprocess, "run", return_value=bad_version):
            with self.assertRaisesRegex(r2.Refusal, "^SORT_VERSION_MISMATCH$"):
                r2._run_verified_sort(self.control, ["a.driver.log"])
        version = mock.Mock(stdout=b"sort (GNU coreutils) 8.22\n", stderr=b"")
        duplicate = mock.Mock(stdout=b"./a.driver.log\0./a.driver.log\0", stderr=b"")
        with mock.patch.object(r2, "_verified_sort_fd", return_value=5), mock.patch.object(r2.os, "close"), \
             mock.patch.object(r2.subprocess, "run", side_effect=(version, duplicate)):
            with self.assertRaisesRegex(r2.Refusal, "^HISTORICAL_SORT_PERMUTATION$"):
                r2._run_verified_sort(self.control, ["a.driver.log", "b.driver.log"])

    def test_sort_digest_refusal_happens_before_subprocess_and_path_is_ignored(self):
        with mock.patch.dict(os.environ, {"PATH": "/attacker/bin", "LANG": "bad"}, clear=True), \
             mock.patch.object(r2, "_verified_sort_fd", side_effect=r2.Refusal("SORT_DIGEST_MISMATCH")), \
             mock.patch.object(r2.subprocess, "run") as run:
            with self.assertRaisesRegex(r2.Refusal, "^SORT_DIGEST_MISMATCH$"):
                r2._run_verified_sort(self.control, ["a.driver.log"])
            run.assert_not_called()

    def test_sort_symlink_and_special_file_refuse_before_open(self):
        for mode, code in ((stat.S_IFLNK, "SORT_SYMLINK"), (stat.S_IFIFO, "SORT_FILE_TYPE")):
            with self.subTest(code=code), \
                 mock.patch.object(r2, "_secure_primitives_available", return_value=True), \
                 mock.patch.object(r2, "_open_root", return_value=10), \
                 mock.patch.object(r2.os, "stat", return_value=self.record(mode)), \
                 mock.patch.object(r2.os, "open") as opened, \
                 mock.patch.object(r2.os, "close"):
                with self.assertRaisesRegex(r2.Refusal, "^" + code + "$"):
                    r2._verified_sort_fd(self.control)
                opened.assert_not_called()

    def test_sealed_memfd_requires_linux_primitives_and_handles_short_writes(self):
        fake_fcntl = types.SimpleNamespace(F_ADD_SEALS=10, F_GET_SEALS=11, F_SEAL_WRITE=1,
                                           F_SEAL_GROW=2, F_SEAL_SHRINK=4, F_SEAL_SEAL=8,
                                           fcntl=mock.Mock(side_effect=(0, 15)))
        flags = 64 | 128
        created = mock.Mock(return_value=71)
        with mock.patch.object(r2, "_secure_primitives_available", return_value=True), \
             mock.patch.object(r2, "_fcntl", fake_fcntl), \
             mock.patch.multiple(r2.os, MFD_CLOEXEC=64, MFD_ALLOW_SEALING=128, memfd_create=created, create=True), \
             mock.patch.object(r2.os, "write", side_effect=(2, 2)) as write, \
             mock.patch.object(r2.os, "fchmod") as chmod, mock.patch.object(r2.os, "lseek") as seek, \
             mock.patch.object(r2.os, "close") as closed:
            self.assertEqual(71, r2._create_sealed_sort_fd(b"abcd"))
        self.assertEqual(flags, created.call_args.args[1])
        self.assertEqual([mock.call(71, b"abcd"), mock.call(71, b"cd")], write.call_args_list)
        chmod.assert_called_once_with(71, 0o500)
        seek.assert_called_once_with(71, 0, r2.os.SEEK_SET)
        self.assertEqual([mock.call(71, 10, 15), mock.call(71, 11)], fake_fcntl.fcntl.call_args_list)
        closed.assert_not_called()

    def test_memfd_missing_primitive_and_digest_mismatch_refuse_before_memfd_or_subprocess(self):
        with mock.patch.object(r2, "_secure_primitives_available", return_value=True), \
             mock.patch.object(r2, "_fcntl", None):
            with self.assertRaisesRegex(r2.Refusal, "^SECURE_DESCRIPTOR_IO_UNAVAILABLE$"):
                r2._create_sealed_sort_fd(b"x")
        executable = self.record(stat.S_IFREG | stat.S_IXUSR)
        with mock.patch.object(r2, "_secure_primitives_available", return_value=True), \
             mock.patch.multiple(r2.os, O_NOFOLLOW=1, O_CLOEXEC=2, O_NONBLOCK=4, create=True), \
             mock.patch.object(r2, "_open_root", return_value=10), mock.patch.object(r2.os, "stat", side_effect=(executable, executable)), \
             mock.patch.object(r2.os, "open", return_value=11), mock.patch.object(r2.os, "fstat", side_effect=(executable, executable)), \
             mock.patch.object(r2, "_read_and_hash_fd", return_value=("f" * 64, b"source")), \
             mock.patch.object(r2, "_create_sealed_sort_fd") as sealed, mock.patch.object(r2.os, "close"):
            with self.assertRaisesRegex(r2.Refusal, "^SORT_DIGEST_MISMATCH$"):
                r2._verified_sort_fd(self.control)
            sealed.assert_not_called()

    def test_verified_source_is_closed_and_only_sealed_fd_can_reach_exec(self):
        executable = self.record(stat.S_IFREG | stat.S_IXUSR)
        source_digest = "a" * 64
        control = r2._issue_test_control(self.circuits, "/frozen/sort", source_digest, "sort (GNU coreutils) 8.22")
        try:
            with mock.patch.object(r2, "_secure_primitives_available", return_value=True), \
                 mock.patch.multiple(r2.os, O_NOFOLLOW=1, O_CLOEXEC=2, O_NONBLOCK=4, create=True), \
                 mock.patch.object(r2, "_open_root", return_value=10), mock.patch.object(r2.os, "stat", side_effect=(executable, executable)), \
                 mock.patch.object(r2.os, "fstat", side_effect=(executable, executable)), \
                 mock.patch.object(r2, "_read_and_hash_fd", return_value=(source_digest, b"sealed-copy")), \
                 mock.patch.object(r2, "_create_sealed_sort_fd", return_value=22) as sealed, \
                 mock.patch.object(r2.os, "close") as closed, \
                 mock.patch.object(r2.os, "open", return_value=11) as opened:
                self.assertEqual(22, r2._verified_sort_fd(control))
            sealed.assert_called_once_with(b"sealed-copy")
            self.assertEqual(4, opened.call_args.args[1] & 4)
            self.assertEqual([mock.call(11), mock.call(10)], closed.call_args_list)
        finally:
            r2._close_test_control(control)

    def test_single_lane_mismatch_refuses_and_never_opens_candidate_data(self):
        observed = {"driver_log_count": 1, "historical_locale_ordered_sha256": "a" * 64,
                    "bytewise_ordered_sha256": "b" * 64}
        self.circuits["s9234"]["expected"] = dict(observed)
        for lane in ("historical_locale_ordered_sha256", "bytewise_ordered_sha256"):
            mutated = dict(observed)
            mutated[lane] = "c" * 64
            self.circuits["s9234"]["expected"] = mutated
            with mock.patch.object(r2, "_open_root", return_value=17), mock.patch.object(r2, "_walk_logs", return_value={"a.driver.log": "x"}), \
                 mock.patch.object(r2, "_run_verified_sort", return_value=["a.driver.log"]), mock.patch.object(r2, "_digest_lines", side_effect=(observed["historical_locale_ordered_sha256"], observed["bytewise_ordered_sha256"])), \
                 mock.patch.object(r2.os, "close"):
                with self.assertRaisesRegex(r2.Refusal, "^DUAL_INPUT_INVENTORY_DRIFT$"):
                    r2.verify_dual_log_inventory(self.control, "s9234")

    def test_direct_entrypoint_is_design_only(self):
        self.assertEqual(2, r2.main([]))

    def test_linux_gate_decision_refuses_skips_and_empty_runs(self):
        class Result(object):
            def __init__(self, tests_run, skipped=0, failures=0, errors=0, successful=True):
                self.testsRun = tests_run
                self.skipped = [None] * skipped
                self.failures = [None] * failures
                self.errors = [None] * errors
                self._successful = successful

            def wasSuccessful(self):
                return self._successful

        skipped = linux_r2._gate_decision(Result(6, skipped=6), True)
        self.assertFalse(skipped["gate_pass"])
        self.assertEqual(2, skipped["exit_code"])
        empty = linux_r2._gate_decision(Result(0), True)
        self.assertFalse(empty["gate_pass"])
        self.assertEqual(2, empty["exit_code"])
        passed = linux_r2._gate_decision(Result(1), True)
        self.assertTrue(passed["gate_pass"])
        self.assertEqual(0, passed["exit_code"])
        for result in (Result(1, failures=1, successful=False), Result(1, errors=1, successful=False)):
            with self.subTest(kind="failure" if result.failures else "error"):
                decision = linux_r2._gate_decision(result, True)
                self.assertFalse(decision["gate_pass"])
                self.assertEqual("FAIL_LOCAL_SYNTHETIC", decision["platform_positive_integration"])
                self.assertEqual(1, decision["exit_code"])


if __name__ == "__main__":
    unittest.main()
