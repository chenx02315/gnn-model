import hashlib
import json
import os
import pathlib
import stat
import tempfile
import unittest
from unittest import mock

from src.data import blind_join_core_v12_r3 as core
from src.data import run_blind_join_v12_r5 as runner


def aggregate(circuit):
    return {"circuit": circuit, "executed_stage_reference_count": 2, "unique_runtime_join_count": 2,
            "missing_runtime_join_count": 0, "ambiguous_runtime_join_count": 0, "coverage_rate": 1.0,
            "distinct_runtime_attempt_count": 2, "cross_stage_reference_count": 0, "eligible_action_count": 1,
            "all_unique_action_count": 1, "frozen_runtime_eligible_action_space_sha256": "a" * 64,
            "source_artifact_set_sha256": "b" * 64}


class RunBlindJoinV12R5Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.output = str(pathlib.Path(self.tmp.name) / "out")
        self.output_patch = mock.patch.object(runner, "OUTPUT_ROOT", self.output)
        self.bundle_patch = mock.patch.object(runner, "validate_bundle", return_value=("c" * 64, "i" * 64))
        self.platform_patch = mock.patch.object(runner, "_validate_runtime_platform")
        self.output_patch.start(); self.bundle_patch.start(); self.platform_patch.start()

    def tearDown(self):
        for name in ("platform_patch", "bundle_patch", "output_patch"):
            patcher = getattr(self, name)
            if patcher is not None:
                patcher.stop()
        self.tmp.cleanup()

    def test_verified_fd_is_hashed_then_reused_for_both_execs(self):
        fd = 71
        control = mock.Mock(_sort_path="/usr/bin/sort", _sort_sha256="d" * 64,
                            _sort_version="sort (GNU coreutils) 8.22")
        identity = mock.Mock(st_mode=0o100755, st_uid=0)
        calls = []
        def invoke(opened, argv, payload):
            calls.append((opened, argv, payload))
            if argv[1] == "--version":
                return mock.Mock(stdout=b"sort (GNU coreutils) 8.22\n")
            return mock.Mock(stdout=b"./a\x00./z\x00")
        with mock.patch.object(runner.os, "O_NOFOLLOW", 0x20000, create=True), \
             mock.patch.object(runner.os, "O_CLOEXEC", 0x80000, create=True), \
             mock.patch.object(runner.os, "O_NONBLOCK", 0x4000, create=True), \
             mock.patch.object(runner.os, "open", return_value=fd) as opened, \
             mock.patch.object(runner.os, "fstat", return_value=identity), \
             mock.patch.object(runner, "_sha256_fd", return_value="d" * 64) as hashed, \
             mock.patch.object(runner, "_run_sort_fd", side_effect=invoke), \
             mock.patch.object(runner.os, "close") as closed:
            self.assertEqual(["a", "z"], runner._verified_sort_fd(control, ["z", "a"]))
        self.assertEqual(mock.call("/usr/bin/sort", os.O_RDONLY | 0x20000 | 0x80000 | 0x4000), opened.call_args)
        hashed.assert_called_once_with(fd)
        self.assertEqual([(fd, ["/proc/self/fd/71", "--version"]), (fd, ["/proc/self/fd/71", "-z"])],
                         [(item[0], item[1]) for item in calls])
        closed.assert_called_once_with(fd)

    def test_empty_or_wrong_banner_refuses_and_closes_fd(self):
        control = mock.Mock(_sort_path="/usr/bin/sort", _sort_sha256="d" * 64, _sort_version="expected")
        for stdout in (b"", b"other\n"):
            with self.subTest(stdout=stdout), \
                 mock.patch.object(runner, "_open_verified_sort", return_value=9), \
                 mock.patch.object(runner, "_run_sort_fd", return_value=mock.Mock(stdout=stdout)), \
                 mock.patch.object(runner.os, "close") as closed:
                with self.assertRaisesRegex(runner.secure.Refusal, "SORT_VERSION_DRIFT"):
                    runner._verified_sort_fd(control, ["a"])
                closed.assert_called_once_with(9)

    def test_path_replacement_cannot_change_descriptor_exec_target(self):
        control = mock.Mock(_sort_path="/usr/bin/sort", _sort_sha256="d" * 64,
                            _sort_version="sort (GNU coreutils) 8.22")
        seen = []
        def invoke(fd, argv, payload):
            seen.append(argv[0])
            return mock.Mock(stdout=(b"sort (GNU coreutils) 8.22\n" if argv[1] == "--version" else b"./a\x00"))
        with mock.patch.object(runner, "_open_verified_sort", return_value=44), \
             mock.patch.object(runner, "_run_sort_fd", side_effect=invoke), \
             mock.patch.object(runner.os, "close"):
            self.assertEqual(["a"], runner._verified_sort_fd(control, ["a"]))
        self.assertEqual(["/proc/self/fd/44", "/proc/self/fd/44"], seen)
        self.assertNotIn(control._sort_path, seen)

    def test_sort_identity_rejects_nonroot_or_writable(self):
        control = mock.Mock(_sort_path="/usr/bin/sort", _sort_sha256="d" * 64)
        for mode, uid in ((0o100777, 0), (0o100755, 1000)):
            with self.subTest(mode=mode, uid=uid), \
                 mock.patch.object(runner.os, "O_NOFOLLOW", 0x20000, create=True), \
                 mock.patch.object(runner.os, "O_CLOEXEC", 0x80000, create=True), \
                 mock.patch.object(runner.os, "O_NONBLOCK", 0x4000, create=True), \
                 mock.patch.object(runner.os, "open", return_value=8), \
                 mock.patch.object(runner.os, "fstat", return_value=mock.Mock(st_mode=mode, st_uid=uid)), \
                 mock.patch.object(runner.os, "close") as closed:
                with self.assertRaisesRegex(runner.secure.Refusal, "SORT_IDENTITY_DRIFT"):
                    runner._open_verified_sort(control)
                closed.assert_called_once_with(8)

    def test_fifo_sort_refuses_immediately_with_nonblocking_open(self):
        control = mock.Mock(_sort_path="/usr/bin/sort", _sort_sha256="d" * 64)
        with mock.patch.object(runner.os, "O_NOFOLLOW", 0x20000, create=True), \
             mock.patch.object(runner.os, "O_CLOEXEC", 0x80000, create=True), \
             mock.patch.object(runner.os, "O_NONBLOCK", 0x4000, create=True), \
             mock.patch.object(runner.os, "open", return_value=8) as opened, \
             mock.patch.object(runner.os, "fstat", return_value=mock.Mock(st_mode=stat.S_IFIFO | 0o644, st_uid=0)), \
             mock.patch.object(runner, "_sha256_fd") as hashed, \
             mock.patch.object(runner.os, "close") as closed:
            with self.assertRaisesRegex(runner.secure.Refusal, "SORT_IDENTITY_DRIFT"):
                runner._open_verified_sort(control)
        self.assertEqual(mock.call("/usr/bin/sort", os.O_RDONLY | 0x20000 | 0x80000 | 0x4000), opened.call_args)
        hashed.assert_not_called()
        closed.assert_called_once_with(8)

    def test_runtime_platform_mismatch_refuses_before_snapshot(self):
        self.platform_patch.stop()
        self.platform_patch = None
        expected = runner.PLATFORM_ANCHORS
        for key, bad in (("host", "wrong-host"), ("linux", "wrong-kernel"), ("python", "3.6.7")):
            with self.subTest(key=key), \
                 mock.patch.object(runner.os, "uname", return_value=mock.Mock(
                     nodename=bad if key == "host" else expected["host"],
                     release=bad if key == "linux" else expected["linux"]), create=True), \
                 mock.patch.object(runner.sys, "version_info", (3, 6, 7) if key == "python" else (3, 6, 8)), \
                 mock.patch.object(runner.impl, "snapshot_circuit") as snapshot:
                with self.assertRaisesRegex(runner.Refusal, "RUNTIME_PLATFORM_DRIFT"):
                    runner.run()
                snapshot.assert_not_called()
            self.assertFalse(pathlib.Path(self.output).exists())

    def test_failure_envelope_and_fixed_argv(self):
        bad = aggregate("s9234"); bad["missing_runtime_join_count"] = 1; bad["unique_runtime_join_count"] = 1
        with mock.patch.object(runner.impl, "snapshot_circuit", return_value=({}, {})), \
             mock.patch.object(runner.core, "audit_circuit", return_value=bad):
            self.assertEqual(1, runner.run())
        receipt = json.loads((pathlib.Path(self.output) / "receipt.json").read_text(encoding="utf-8"))
        self.assertEqual(("FAIL", "R06_R07_FAILED", []), (receipt["status"], receipt["failure_code"], receipt["circuits"]))
        with mock.patch.object(runner, "run") as run:
            self.assertEqual(2, runner.main(["--attacker"]))
            run.assert_not_called()

    def test_contract_mutation_of_inventory_or_anchor_is_rejected(self):
        self.bundle_patch.stop()
        self.bundle_patch = None
        root = pathlib.Path(self.tmp.name) / "bundle"; (root / "contracts").mkdir(parents=True)
        required = {"src/data/blind_inventory_v12_r2.py", "src/data/blind_join_core_v12_r3.py",
                    "src/data/run_blind_join_v12_r3.py", "src/data/run_blind_join_v12_r5.py",
                    "src/data/build_blind_method_binding_v12_r3.py", "tests/test_blind_join_core_v12_r3.py",
                    "tests/test_run_blind_join_v12_r3.py", "tests/test_run_blind_join_v12_r5.py",
                    "tests/test_build_blind_method_binding_v12_r3.py"}
        artifacts = {}
        for relative in required:
            path = root.joinpath(*relative.split("/")); path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b"x")
            artifacts[relative] = hashlib.sha256(b"x").hexdigest()
        inventory = root.joinpath(*runner.INVENTORY_FREEZE["path"].split("/"))
        inventory.parent.mkdir(parents=True, exist_ok=True); inventory.write_bytes(b"inventory")
        contract = {"schema_version": "blind-runtime-join-v12-r5", "status": "AUTHORIZED_EXECUTION_REVIEWED",
                    "circuits": list(runner.CIRCUIT_ORDER), "output_root": runner.OUTPUT_ROOT, "training_allowed": False,
                    "inventory_freeze": dict(runner.INVENTORY_FREEZE), "platform_anchors": dict(runner.PLATFORM_ANCHORS),
                    "implementation": {"artifact_sha256": artifacts}}
        path = root / runner.CONTRACT_RELATIVE; path.write_text(json.dumps(contract), encoding="utf-8")
        original_hash = runner._sha256_file
        def inventory_hash(path):
            return runner.INVENTORY_FREEZE["sha256"] if str(path) == str(inventory) else original_hash(path)
        with mock.patch.object(runner, "BUNDLE_ROOT", str(root)), \
             mock.patch.object(runner, "_sha256_file", side_effect=inventory_hash):
            runner.validate_bundle()
            contract["inventory_freeze"]["sha256"] = "0" * 64; path.write_text(json.dumps(contract), encoding="utf-8")
            with self.assertRaisesRegex(runner.Refusal, "CONTRACT_INVENTORY"):
                runner.validate_bundle()
            contract["inventory_freeze"] = dict(runner.INVENTORY_FREEZE); contract["platform_anchors"]["python"] = "3.6.7"
            path.write_text(json.dumps(contract), encoding="utf-8")
            with self.assertRaisesRegex(runner.Refusal, "CONTRACT_PLATFORM"):
                runner.validate_bundle()


if __name__ == "__main__":
    unittest.main()
