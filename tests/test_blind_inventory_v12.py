import hashlib
import json
import pathlib
import tempfile
import unittest
from unittest import mock

from src.data import blind_inventory_v12 as v12


class BlindInventoryV12Tests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.logs = self.root / "logs"
        self.logs.mkdir()
        self.marker = self.root / "CONSUMED"
        self.marker.write_text(json.dumps({
            "schema_version": "blind-runtime-unseal-consumed-v12",
            "status": "CONSUMED",
            "contract_sha256": "c",
            "tool_set_sha256": "t",
        }), encoding="utf-8")
        self.capability = object()
        v12._ACTIVE_SOURCE_CAPABILITY = self.capability
        self.guard = (str(self.marker), "c", "t", self.capability)

    def tearDown(self):
        v12._ACTIVE_SOURCE_CAPABILITY = None
        self.temporary.cleanup()

    def write_log(self, name, payload):
        path = self.logs / name
        path.write_bytes(payload)
        return path

    @staticmethod
    def digest(order, payloads):
        lines = []
        for name in order:
            lines.append(hashlib.sha256(payloads[name]).hexdigest() + "  ./" + name + "\n")
        return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()

    def test_dual_order_digests_are_computed_from_one_file_set(self):
        payloads = {"a_2.driver.log": b"two", "a10.driver.log": b"ten", "a_1.driver.log": b"one"}
        for name, payload in payloads.items():
            self.write_log(name, payload)
        historical = ["a_1.driver.log", "a10.driver.log", "a_2.driver.log"]
        with mock.patch.object(v12, "_historical_locale_order", return_value=historical):
            observed = v12.dual_log_inventory(str(self.logs), self.guard)
        bytewise = sorted(payloads, key=lambda item: ("./" + item).encode("utf-8"))
        self.assertEqual(observed, {
            "driver_log_count": 3,
            "historical_locale_ordered_sha256": self.digest(historical, payloads),
            "bytewise_ordered_sha256": self.digest(bytewise, payloads),
        })

    def test_each_single_lane_mismatch_refuses(self):
        payloads = {"a_2.driver.log": b"two", "a10.driver.log": b"ten"}
        for name, payload in payloads.items():
            self.write_log(name, payload)
        historical = ["a10.driver.log", "a_2.driver.log"]
        with mock.patch.object(v12, "_historical_locale_order", return_value=historical):
            expected = v12.dual_log_inventory(str(self.logs), self.guard)
        for field in ("historical_locale_ordered_sha256", "bytewise_ordered_sha256"):
            mutated = dict(expected)
            mutated[field] = "0" * 64
            with self.subTest(field=field), mock.patch.object(v12, "_historical_locale_order", return_value=historical), self.assertRaisesRegex(v12.Refusal, "^DUAL_INPUT_INVENTORY_DRIFT$"):
                v12.verify_dual_log_inventory(str(self.logs), mutated, self.guard)

    def test_source_access_refuses_before_any_walk_open_or_sort(self):
        with mock.patch.object(v12.os, "walk") as walked, mock.patch("builtins.open") as opened, mock.patch.object(v12.subprocess, "run") as run:
            with self.assertRaisesRegex(v12.Refusal, "^SOURCE_ACCESS_BEFORE_CONSUMED$"):
                v12.dual_log_inventory(str(self.logs), None)
            walked.assert_not_called()
            opened.assert_not_called()
            run.assert_not_called()

    def test_historical_sort_command_is_fixed_and_permutation_checked(self):
        version = mock.Mock(stdout=(v12.SORT_VERSION + "\n").encode("utf-8"), stderr=b"")
        ordered = mock.Mock(stdout=b"./a10.driver.log\0./a_2.driver.log\0", stderr=b"")
        with mock.patch.object(v12.subprocess, "run", side_effect=(version, ordered)) as run:
            result = v12._historical_locale_order(["a_2.driver.log", "a10.driver.log"])
        self.assertEqual(result, ["a10.driver.log", "a_2.driver.log"])
        self.assertEqual(run.call_args_list[0].args[0], ["sort", "--version"])
        self.assertEqual(run.call_args_list[1].args[0], ["sort", "-z"])
        self.assertEqual(run.call_args_list[1].kwargs["env"]["LANG"], "en_US.UTF-8")
        self.assertNotIn("LC_ALL", run.call_args_list[1].kwargs["env"])
        self.assertNotIn("LC_COLLATE", run.call_args_list[1].kwargs["env"])

    def test_wrong_sort_version_and_nonpermutation_refuse(self):
        wrong = mock.Mock(stdout=b"sort (GNU coreutils) 9.0\n", stderr=b"")
        with mock.patch.object(v12.subprocess, "run", return_value=wrong):
            with self.assertRaisesRegex(v12.Refusal, "^HISTORICAL_SORT_VERSION$"):
                v12._historical_locale_order(["a.driver.log"])
        version = mock.Mock(stdout=(v12.SORT_VERSION + "\n").encode("utf-8"), stderr=b"")
        duplicate = mock.Mock(stdout=b"./a.driver.log\0./a.driver.log\0", stderr=b"")
        with mock.patch.object(v12.subprocess, "run", side_effect=(version, duplicate)):
            with self.assertRaisesRegex(v12.Refusal, "^HISTORICAL_SORT_PERMUTATION$"):
                v12._historical_locale_order(["a.driver.log", "b.driver.log"])

    def test_symlinked_root_and_nonportable_path_are_rejected(self):
        linked = self.root / "linked"
        try:
            linked.symlink_to(self.logs, target_is_directory=True)
        except (OSError, NotImplementedError):
            linked = None
        if linked is not None:
            with self.assertRaisesRegex(ValueError, "^LOG_ROOT_INVALID$"):
                v12.dual_log_inventory(str(linked), self.guard)
        self.write_log("nonascii_é.driver.log", b"bad")
        with self.assertRaisesRegex(ValueError, "^LOG_PATH_ENCODING$"):
            v12.dual_log_inventory(str(self.logs), self.guard)

    def test_direct_entrypoint_is_design_only(self):
        with mock.patch.object(v12, "dual_log_inventory") as inventory:
            self.assertEqual(v12.main([]), 2)
            inventory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
