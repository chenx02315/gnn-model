import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from src.models import ranking_v5_execution_boundary as boundary
from src.models import ranking_v5_package_binding as binding
from src.models.runtime_ranking_v3 import FAMILIES


def sha(number):
    return ("%064x" % number)


def receipt():
    return {"schema_version":"ranking-v3-real-input-export-receipt-v1", "scope":"REAL_TRAIN_ONLY_RELEASED_SIX_FOLD",
      "release_sha256":sha(1), "source_sha256":boundary.SOURCE_SHA256,
      "source_input_sha256":{"features.tsv":sha(2),"train_outcomes.tsv":sha(3),"graph_manifest.tsv":sha(4)},
      "graph_sha256":{circuit:sha(10+i) for i,circuit in enumerate(FAMILIES)}, "family_metadata_sha256":sha(20),
      "train_action_count":1706, "train_outcome_count":1706, "graph_count":6,
      "fold_manifest_sha256":{family:sha(30+i) for i,family in enumerate(sorted(FAMILIES.values()))}}


class PackageBindingTests(unittest.TestCase):
    def bind(self, value=None, **kwargs):
        options = {"package_root":next(iter(binding.PACKAGE_ROOT_ALLOWLIST)), "roles":["TRAIN"], "seed":boundary.SEEDS[0]}
        options.update(kwargs)
        # A synthetic object cannot hash to the production receipt pin.  Tests
        # replace only this local constant; production always uses boundary's.
        with patch.object(binding, "PACKAGE_SHA256", sha(99)):
            return binding.bind_v3_package_receipt(value or receipt(), sha(99), **options)

    def test_exact_receipt_returns_six_pins_without_authorization(self):
        result = self.bind()
        self.assertEqual(binding.STATUS, result["status"]); self.assertEqual(6, len(result["fold_manifest_sha256"]))
        self.assertEqual(boundary.SOURCE_SHA256, result["source_sha256"])

    def test_raw_receipt_sha_is_fixed_not_a_caller_choice(self):
        with self.assertRaisesRegex(ValueError, "RECEIPT_SHA"):
            binding.bind_v3_package_receipt(receipt(), sha(99), next(iter(binding.PACKAGE_ROOT_ALLOWLIST)), ["TRAIN"], boundary.SEEDS[0])

    def test_extra_missing_roles_and_float_seed_rejected(self):
        extra = receipt(); extra["roles"] = ["TRAIN"]
        missing = receipt(); del missing["graph_count"]
        for value in (extra, missing):
            with self.assertRaisesRegex(ValueError, "RECEIPT_SCHEMA"): self.bind(value)
        for roles in (["TRAIN", "VALIDATION"], ["VALIDATION"], "TRAIN"):
            with self.assertRaisesRegex(ValueError, "ROLES"): self.bind(roles=roles)
        with self.assertRaisesRegex(ValueError, "SEED"): self.bind(seed=float(boundary.SEEDS[0]))

    def test_missing_family_duplicate_pin_and_source_drift_rejected(self):
        value = receipt(); del value["fold_manifest_sha256"][next(iter(value["fold_manifest_sha256"]))]
        with self.assertRaisesRegex(ValueError, "MEMBERSHIP"): self.bind(value)
        value = receipt(); first = next(iter(value["fold_manifest_sha256"])); second = list(value["fold_manifest_sha256"])[1]
        value["fold_manifest_sha256"][second] = value["fold_manifest_sha256"][first]
        with self.assertRaisesRegex(ValueError, "DIGESTS"): self.bind(value)
        value = receipt(); value["source_sha256"] = sha(88)
        with self.assertRaisesRegex(ValueError, "BINDING"): self.bind(value)

    def test_package_root_is_exact_lexical_allowlist(self):
        for root in ("/ssd/cjc/multimode_ate_gnn_v1/train_folds", next(iter(binding.PACKAGE_ROOT_ALLOWLIST)) + "/", " C:/bad"):
            with self.assertRaisesRegex(ValueError, "PACKAGE_ROOT"): self.bind(package_root=root)

    def test_counts_and_sha_shape_rejected(self):
        value = receipt(); value["train_action_count"] = True
        with self.assertRaisesRegex(ValueError, "COUNTS"): self.bind(value)
        value = receipt(); value["graph_sha256"][next(iter(value["graph_sha256"]))] = "bad"
        with self.assertRaisesRegex(ValueError, "DIGESTS"): self.bind(value)

    def test_bytes_entry_binds_one_raw_buffer_to_the_parsed_receipt(self):
        raw = json.dumps(receipt(), sort_keys=True, separators=(",", ":")).encode()
        raw_sha = hashlib.sha256(raw).hexdigest(); captured = []
        original = binding.bind_v3_package_receipt
        def observe(value, supplied_sha, package_root, roles, seed):
            captured.append((value, supplied_sha))
            return original(value, supplied_sha, package_root, roles, seed)
        with patch.object(binding, "PACKAGE_SHA256", raw_sha), patch.object(binding, "bind_v3_package_receipt", side_effect=observe):
            result = binding.bind_v3_package_bytes(raw, next(iter(binding.PACKAGE_ROOT_ALLOWLIST)), ["TRAIN"], boundary.SEEDS[0])
        self.assertEqual(binding.STATUS, result["status"])
        self.assertEqual(receipt(), captured[0][0]); self.assertEqual(raw_sha, captured[0][1])

    def test_bytes_tamper_duplicates_and_bounds_rejected(self):
        raw = json.dumps(receipt(), sort_keys=True, separators=(",", ":")).encode()
        raw_sha = hashlib.sha256(raw).hexdigest(); root = next(iter(binding.PACKAGE_ROOT_ALLOWLIST))
        with patch.object(binding, "PACKAGE_SHA256", raw_sha):
            with self.assertRaisesRegex(ValueError, "RECEIPT_SHA"):
                binding.bind_v3_package_bytes(raw + b" ", root, ["TRAIN"], boundary.SEEDS[0])
        duplicate = b'{"schema_version":"a","schema_version":"b"}'
        duplicate_sha = hashlib.sha256(duplicate).hexdigest()
        with patch.object(binding, "PACKAGE_SHA256", duplicate_sha):
            with self.assertRaisesRegex(ValueError, "BYTES_JSON"):
                binding.bind_v3_package_bytes(duplicate, root, ["TRAIN"], boundary.SEEDS[0])
        with self.assertRaisesRegex(ValueError, "BYTES_BOUND"):
            binding.bind_v3_package_bytes(b"x" * (binding.MAX_RECEIPT_BYTES + 1), root, ["TRAIN"], boundary.SEEDS[0])


if __name__ == "__main__":
    unittest.main()
