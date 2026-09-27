#!/usr/bin/env python3
"""Seal R13 by binding every registered method to the exact r9 action hashes."""
from __future__ import print_function

import argparse
import hashlib
import json
import os
import re


EXPECTED_RECEIPT_SHA256 = "ead0b90ba5822d80ad9c46bbf0123f1f0349465d83d5656a1c7b65a0494ac00e"
EXPECTED_SIDECAR_SHA256 = "38484f8838ef73217d5c2913ecae13b2092df9b94c69e360dfa9e11523c1b1c6"
EXPECTED_RELEASED_SHA256 = "6bbf394aa2df80b6fa7793347a21b1803ae9218586500af0618d843098461d0f"
EXPECTED_CONTRACT_SHA256 = "e1aa77af8b1e28683b9a9ac6a7bf2b342438b3a7d9df8eb53160508c62421d38"
EXPECTED_IMPLEMENTATION_SHA256 = "29b960b4a87d305462dbffbc56f538a3821fb76a1a71ce243ab03f5e14e8810e"
EXPECTED_REGISTRY_SHA256 = "8fb8d4a90981c2479e3e6ea3a8a4669286080e921ad0c2ff8d82e8a2a5c4191f"
EXPECTED_METHODS = [
    "fixed_heuristic",
    "d95_safe_then_predicted_cycles",
    "d95_safe_cost_aware_topk",
]
EXPECTED_CIRCUITS = ["s9234", "s38584", "wb_dma"]
EXPECTED_FORMAL_MEMBERSHIP_SHA256 = "c8f589d67d80470dcf49ffbcab51da763162e9ae82af0308b36d6771cbd97cac"
EXPECTED_SPLIT_SHA256 = "ffecd5093453f69c11263501b822ad7bb8f7eefd5da60dd7863331088f6fbcda"
EXPECTED_OUTPUT_ROOT = "/temp/jiangchuanc/multimode_ate_phase4_20260825_A/21_blind_runtime_join_v12_r9"
EXPECTED_RECOVERY = {
    "recovery_job_id": "388797",
    "recovery_closeout_sha256": "671410d9687a725a0a1ac610bbac7c5247dd4ab4ebe918738c9ea5e9309806a5",
    "recovery_execution_audit_sha256": "38f2f99dd50da71ddfc20445edd40dfa6a82bb2177e195a38900620de4c56de9",
    "recovery_plan_sha256": "b5cf0525b635fd4832fb1b1d7cc9f88f61c2d13cedbe77b9ce0d7b0d5dd2d4e1",
    "recovery_source_manifest_sha256": "06e6160ccacc3adbcb844751ccc56e2d0f9ab745ec81a7bac3493f9c6a3ad867",
    "recovery_copy_verification_sha256": "dbd3691085f740aa3589541fc61c57aebe6d8220e1485e4be11237f72901bbfd",
    "recovery_receipt_set_sha256": "87955e9abc32970a8af2febdec7856734b9ee1d59e11098240f66fa816f39f19",
}
EXPECTED_ROWS = {
    "s9234": (1908, 1282, 22, 736, "cc628ba991f9566dfa2ad735bc7a4fc350083de5dc58df0c819c4231f0b70cfa", "c3fe4162e3d32286a4ebf7b215283ef3c80398a7db8d6611118e8e025dc93127"),
    "s38584": (164, 147, 0, 64, "bfa5acd1c06445a9b83327cbb8308ed45ed9979b642e4606d3d5818ff7c09da3", "035a2cebb473b6f09a00c01a13e0b13fca260a1ff3837123ca68d6adcf06ac57"),
    "wb_dma": (1521, 960, 22, 651, "9d1f6d4620a444c35d777d5b8c8eb5d09324d6c7a1d789c20dd267e9efbd0ee8", "7b550cce6f8b0dc2a4cda7cd91cf9f4694dd38277624e5aaad29c254ecfda403"),
}
EXPECTED_ARTIFACTS = {
    "src/data/blind_inventory_v12_r2.py",
    "src/data/blind_join_core_v12_r3.py",
    "src/data/run_blind_join_v12_r3.py",
    "src/data/run_blind_join_v12_r5.py",
    "src/data/run_blind_join_v12_r6.py",
    "src/data/run_blind_join_v12_r7.py",
    "src/data/run_blind_join_v12_r8.py",
    "src/data/run_blind_join_v12_r9.py",
    "tests/test_run_blind_join_v12_r9.py",
    "data/manifests/blind_runtime_recovery_execution_v3_audit_20260927.json",
    "data/manifests/blind_runtime_join_v12_r8_failure_closeout_20260927.json",
}
EXPECTED_R13_ARTIFACTS = {
    "src/data/build_blind_method_binding_v12_r9.py",
    "tests/test_build_blind_method_binding_v12_r9.py",
    "data/manifests/blind_runtime_join_v12_r9_receipt_20260927.json",
    "data/manifests/blind_runtime_join_v12_r9_receipt_20260927.json.sha256",
    "data/manifests/blind_runtime_join_v12_r9_RELEASED_20260927.json",
}
REQUIRED_ROW_KEYS = {
    "circuit", "executed_stage_reference_count", "unique_runtime_join_count",
    "missing_runtime_join_count", "ambiguous_runtime_join_count", "coverage_rate",
    "distinct_runtime_attempt_count", "cross_stage_reference_count",
    "eligible_action_count", "all_unique_action_count",
    "frozen_runtime_eligible_action_space_sha256", "source_artifact_set_sha256",
}
BUNDLE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def implementation_set_sha256(contract):
    artifacts = contract.get("implementation", {}).get("artifact_sha256")
    if not isinstance(artifacts, dict) or not artifacts:
        raise ValueError("IMPLEMENTATION_SET_INVALID")
    lines = sorted(path + ":" + digest for path, digest in artifacts.items())
    return hashlib.sha256(("".join(line + "\n" for line in lines)).encode("utf-8")).hexdigest()


def validate_contract(contract, contract_sha256, bundle_root=BUNDLE_ROOT):
    artifacts = contract.get("implementation", {}).get("artifact_sha256")
    recovery = contract.get("recovery", {})
    if (
        contract_sha256 != EXPECTED_CONTRACT_SHA256
        or contract.get("schema_version") != "blind-runtime-join-v12-r9"
        or contract.get("status") != "AUTHORIZED_EXECUTION_REVIEWED"
        or contract.get("circuits") != EXPECTED_CIRCUITS
        or contract.get("output_root") != EXPECTED_OUTPUT_ROOT
        or contract.get("training_allowed") is not False
        or recovery.get("job_id") != EXPECTED_RECOVERY["recovery_job_id"]
        or recovery.get("closeout_sha256") != EXPECTED_RECOVERY["recovery_closeout_sha256"]
        or recovery.get("execution_audit_sha256") != EXPECTED_RECOVERY["recovery_execution_audit_sha256"]
        or recovery.get("plan_sha256") != EXPECTED_RECOVERY["recovery_plan_sha256"]
        or recovery.get("source_manifest_sha256") != EXPECTED_RECOVERY["recovery_source_manifest_sha256"]
        or recovery.get("copy_verification_sha256") != EXPECTED_RECOVERY["recovery_copy_verification_sha256"]
        or recovery.get("receipt_set_sha256") != EXPECTED_RECOVERY["recovery_receipt_set_sha256"]
        or not isinstance(artifacts, dict)
        or set(artifacts) != EXPECTED_ARTIFACTS
    ):
        raise ValueError("AUTHORIZED_R9_CONTRACT_REQUIRED")
    root = os.path.abspath(bundle_root)
    for relative, digest in artifacts.items():
        if SHA256.match(digest or "") is None:
            raise ValueError("CONTRACT_ARTIFACT_DIGEST_INVALID")
        path = os.path.abspath(os.path.join(root, *relative.split("/")))
        if os.path.commonpath((root, path)) != root or os.path.islink(path):
            raise ValueError("CONTRACT_ARTIFACT_PATH_INVALID")
        if sha256_file(path) != digest:
            raise ValueError("CONTRACT_ARTIFACT_DIGEST_MISMATCH")
    result = implementation_set_sha256(contract)
    if result != EXPECTED_IMPLEMENTATION_SHA256:
        raise ValueError("IMPLEMENTATION_SET_INVALID")
    return result


def validate_receipt(receipt, receipt_sha256, contract_sha256, implementation_sha256):
    if receipt_sha256 != EXPECTED_RECEIPT_SHA256:
        raise ValueError("R9_RECEIPT_DIGEST_MISMATCH")
    if (
        receipt.get("schema_version") != "blind-runtime-join-receipt-v12-r9"
        or receipt.get("status") != "PASS_R06_R07_AUDIT_PENDING"
        or receipt.get("failure_code") is not None
        or receipt.get("training_allowed") is not False
    ):
        raise ValueError("R9_RECEIPT_REQUIRED")
    if (
        receipt.get("contract_sha256") != contract_sha256
        or receipt.get("implementation_set_sha256") != implementation_sha256
        or receipt.get("formal_runtime_membership_sha256") != EXPECTED_FORMAL_MEMBERSHIP_SHA256
        or receipt.get("split_contract_sha256") != EXPECTED_SPLIT_SHA256
        or receipt.get("method_registry_sha256") != EXPECTED_REGISTRY_SHA256
    ):
        raise ValueError("R9_RECEIPT_ANCHOR_MISMATCH")
    for key, expected in EXPECTED_RECOVERY.items():
        if receipt.get(key) != expected:
            raise ValueError("R9_RECOVERY_ANCHOR_MISMATCH")
    rows = receipt.get("circuits")
    if not isinstance(rows, list) or [row.get("circuit") for row in rows] != EXPECTED_CIRCUITS:
        raise ValueError("R9_CIRCUITS")
    for row in rows:
        if set(row) != REQUIRED_ROW_KEYS:
            raise ValueError("R9_ROW_SCHEMA")
        expected = EXPECTED_ROWS[row["circuit"]]
        observed = (
            row["executed_stage_reference_count"],
            row["distinct_runtime_attempt_count"],
            row["cross_stage_reference_count"],
            row["eligible_action_count"],
            row["frozen_runtime_eligible_action_space_sha256"],
            row["source_artifact_set_sha256"],
        )
        if observed != expected:
            raise ValueError("R9_AGGREGATE_DRIFT")
        if (
            row["unique_runtime_join_count"] != row["executed_stage_reference_count"]
            or row["missing_runtime_join_count"] != 0
            or row["ambiguous_runtime_join_count"] != 0
            or row["coverage_rate"] != 1.0
            or row["all_unique_action_count"] != row["eligible_action_count"]
        ):
            raise ValueError("R9_R06_R07_INVALID")
        if SHA256.match(row["frozen_runtime_eligible_action_space_sha256"]) is None:
            raise ValueError("R9_ACTION_HASH_INVALID")
    return rows


def validate_toolchain_manifest(manifest, manifest_sha256, bundle_root=BUNDLE_ROOT):
    if SHA256.match(manifest_sha256 or "") is None:
        raise ValueError("R13_TOOLCHAIN_MANIFEST_DIGEST_INVALID")
    artifacts = manifest.get("artifact_sha256")
    if (
        manifest.get("schema_version") != "blind-runtime-method-binding-v12-r9-toolchain"
        or manifest.get("status") != "AUTHORIZED_R13_BINDING_REVIEW_PENDING"
        or manifest.get("join_contract_sha256") != EXPECTED_CONTRACT_SHA256
        or manifest.get("method_registry_sha256") != EXPECTED_REGISTRY_SHA256
        or manifest.get("join_receipt_sha256") != EXPECTED_RECEIPT_SHA256
        or manifest.get("receipt_sidecar_sha256") != EXPECTED_SIDECAR_SHA256
        or manifest.get("released_sha256") != EXPECTED_RELEASED_SHA256
        or manifest.get("released_status") != "RELEASED_AUDIT_PENDING"
        or manifest.get("released_receipt_sha256") != EXPECTED_RECEIPT_SHA256
        or manifest.get("lsf_or_tessent_allowed") is not False
        or manifest.get("training_allowed") is not False
        or not isinstance(artifacts, dict)
        or set(artifacts) != EXPECTED_R13_ARTIFACTS
    ):
        raise ValueError("R13_TOOLCHAIN_MANIFEST_INVALID")
    root = os.path.abspath(bundle_root)
    for relative, digest in artifacts.items():
        if SHA256.match(digest or "") is None:
            raise ValueError("R13_ARTIFACT_DIGEST_INVALID")
        path = os.path.abspath(os.path.join(root, *relative.split("/")))
        if os.path.commonpath((root, path)) != root or os.path.islink(path):
            raise ValueError("R13_ARTIFACT_PATH_INVALID")
        if sha256_file(path) != digest:
            raise ValueError("R13_ARTIFACT_DIGEST_MISMATCH")
    sidecar_path = os.path.join(root, "data", "manifests", "blind_runtime_join_v12_r9_receipt_20260927.json.sha256")
    with open(sidecar_path, "rb") as stream:
        if stream.read() != (EXPECTED_RECEIPT_SHA256 + "  receipt.json\n").encode("ascii"):
            raise ValueError("R13_RECEIPT_SIDECAR_INVALID")
    released_path = os.path.join(root, "data", "manifests", "blind_runtime_join_v12_r9_RELEASED_20260927.json")
    with open(released_path, encoding="utf-8") as stream:
        released = json.load(stream)
    if released != {
        "receipt_sha256": EXPECTED_RECEIPT_SHA256,
        "schema_version": "blind-runtime-join-release-v12-r9",
        "status": "RELEASED_AUDIT_PENDING",
    }:
        raise ValueError("R13_RELEASED_INVALID")
    return manifest_sha256


def build(receipt, registry, receipt_sha256, registry_sha256, contract_sha256,
          implementation_sha256, contract, toolchain_manifest,
          toolchain_manifest_sha256, bundle_root=BUNDLE_ROOT):
    if registry_sha256 != EXPECTED_REGISTRY_SHA256:
        raise ValueError("METHOD_REGISTRY_DIGEST_MISMATCH")
    if (
        registry.get("schema_version") != "recommendation-method-registry-v1"
        or registry.get("methods") != EXPECTED_METHODS
        or registry.get("method_count") != len(EXPECTED_METHODS)
        or registry.get("blind_circuits") != EXPECTED_CIRCUITS
        or registry.get("formal_runtime_membership_sha256") != EXPECTED_FORMAL_MEMBERSHIP_SHA256
        or registry.get("binding_policy", {}).get("all_methods_must_use_identical_hash") is not True
        or registry.get("binding_policy", {}).get("method_specific_exclusion_allowed") is not False
        or registry.get("training_allowed") is not False
    ):
        raise ValueError("METHOD_REGISTRY_INVALID")
    if validate_contract(contract, contract_sha256, bundle_root) != implementation_sha256:
        raise ValueError("IMPLEMENTATION_SET_INVALID")
    validate_toolchain_manifest(toolchain_manifest, toolchain_manifest_sha256, bundle_root)
    rows = validate_receipt(receipt, receipt_sha256, contract_sha256, implementation_sha256)
    return {
        "schema_version": "blind-runtime-method-binding-v12-r9",
        "status": "PASS_R13_INDEPENDENT_AUDIT_PENDING",
        "join_receipt_sha256": receipt_sha256,
        "contract_sha256": contract_sha256,
        "implementation_set_sha256": implementation_sha256,
        "method_registry_sha256": registry_sha256,
        "r13_toolchain_manifest_sha256": toolchain_manifest_sha256,
        "methods": EXPECTED_METHODS,
        "circuits": [
            {
                "circuit": row["circuit"],
                "eligible_action_count": row["eligible_action_count"],
                "frozen_runtime_eligible_action_space_sha256": row["frozen_runtime_eligible_action_space_sha256"],
                "method_bindings": [
                    {"method": method, "action_space_sha256": row["frozen_runtime_eligible_action_space_sha256"]}
                    for method in EXPECTED_METHODS
                ],
            }
            for row in rows
        ],
        "all_methods_identical_per_circuit": True,
        "method_specific_exclusion_allowed": False,
        "training_allowed": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("receipt")
    parser.add_argument("registry")
    parser.add_argument("contract")
    parser.add_argument("toolchain_manifest")
    parser.add_argument("output")
    args = parser.parse_args(argv)
    with open(args.receipt, encoding="utf-8") as stream:
        receipt = json.load(stream)
    with open(args.registry, encoding="utf-8") as stream:
        registry = json.load(stream)
    with open(args.contract, encoding="utf-8") as stream:
        contract = json.load(stream)
    with open(args.toolchain_manifest, encoding="utf-8") as stream:
        toolchain_manifest = json.load(stream)
    contract_sha256 = sha256_file(args.contract)
    implementation_sha256 = validate_contract(contract, contract_sha256)
    result = build(
        receipt, registry, sha256_file(args.receipt), sha256_file(args.registry),
        contract_sha256, implementation_sha256, contract, toolchain_manifest,
        sha256_file(args.toolchain_manifest),
    )
    with open(args.output, "x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write("\n")
    print("BLIND_METHOD_BINDING_V12_R9=R13_AUDIT_PENDING")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
