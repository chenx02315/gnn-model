#!/usr/bin/env python3
"""Bind every registered method to the same audited BLIND action hashes."""
from __future__ import print_function

import argparse
import hashlib
import json

EXPECTED_REGISTRY_SHA256 = "8fb8d4a90981c2479e3e6ea3a8a4669286080e921ad0c2ff8d82e8a2a5c4191f"
EXPECTED_METHODS = ["fixed_heuristic", "d95_safe_then_predicted_cycles", "d95_safe_cost_aware_topk"]
EXPECTED_CIRCUITS = ["s9234", "s38584", "wb_dma"]


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
    payload = "".join(item + "\n" for item in sorted(set(
        path + ":" + digest for path, digest in artifacts.items())))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build(receipt, registry, receipt_sha256, registry_sha256, contract_sha256, implementation_sha256):
    if receipt.get("schema_version") != "blind-runtime-join-receipt-v12-r3" or receipt.get("status") != "PASS_R06_R07_AUDIT_PENDING":
        raise ValueError("R06_R07_PASS_RECEIPT_REQUIRED")
    if receipt.get("contract_sha256") != contract_sha256 or receipt.get("implementation_set_sha256") != implementation_sha256:
        raise ValueError("RECEIPT_IMPLEMENTATION_BINDING_MISMATCH")
    methods = registry.get("methods")
    circuits = registry.get("blind_circuits")
    rows = receipt.get("circuits")
    if registry_sha256 != EXPECTED_REGISTRY_SHA256 or receipt.get("method_registry_sha256") != EXPECTED_REGISTRY_SHA256:
        raise ValueError("METHOD_REGISTRY_DIGEST_MISMATCH")
    if methods != EXPECTED_METHODS:
        raise ValueError("METHOD_REGISTRY_INVALID")
    if circuits != EXPECTED_CIRCUITS or [row.get("circuit") for row in rows or []] != circuits:
        raise ValueError("BLIND_CIRCUIT_ORDER_MISMATCH")
    required = {"circuit", "executed_stage_reference_count", "unique_runtime_join_count",
                "missing_runtime_join_count", "ambiguous_runtime_join_count", "coverage_rate",
                "distinct_runtime_attempt_count", "cross_stage_reference_count", "eligible_action_count",
                "all_unique_action_count", "frozen_runtime_eligible_action_space_sha256",
                "source_artifact_set_sha256"}
    for row in rows:
        if (set(row) != required or row["executed_stage_reference_count"] <= 0 or
                row["unique_runtime_join_count"] != row["executed_stage_reference_count"] or
                row["missing_runtime_join_count"] != 0 or row["ambiguous_runtime_join_count"] != 0 or
                row["coverage_rate"] != 1.0 or row["eligible_action_count"] <= 0 or
                row["all_unique_action_count"] != row["eligible_action_count"]):
            raise ValueError("R06_R07_AGGREGATE_INVALID")
    bindings = []
    for row in rows:
        action_hash = row.get("frozen_runtime_eligible_action_space_sha256")
        if not isinstance(action_hash, str) or len(action_hash) != 64:
            raise ValueError("ACTION_HASH_INVALID")
        bindings.append({
            "circuit": row["circuit"],
            "eligible_action_count": row["eligible_action_count"],
            "frozen_runtime_eligible_action_space_sha256": action_hash,
            "method_bindings": [{"method": method, "action_space_sha256": action_hash} for method in methods],
        })
    return {
        "schema_version": "blind-runtime-method-binding-v12-r3",
        "status": "PASS_R13_INDEPENDENT_AUDIT_PENDING",
        "join_receipt_sha256": receipt_sha256,
        "contract_sha256": contract_sha256,
        "implementation_set_sha256": implementation_sha256,
        "method_registry_sha256": registry_sha256,
        "methods": methods,
        "circuits": bindings,
        "all_methods_identical_per_circuit": True,
        "method_specific_exclusion_allowed": False,
        "training_allowed": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("receipt")
    parser.add_argument("registry")
    parser.add_argument("contract")
    parser.add_argument("output")
    args = parser.parse_args(argv)
    with open(args.receipt, encoding="utf-8") as stream:
        receipt = json.load(stream)
    with open(args.registry, encoding="utf-8") as stream:
        registry = json.load(stream)
    with open(args.contract, encoding="utf-8") as stream:
        contract = json.load(stream)
    result = build(receipt, registry, sha256_file(args.receipt), sha256_file(args.registry),
                   sha256_file(args.contract), implementation_set_sha256(contract))
    with open(args.output, "x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write("\n")
    print("BLIND_METHOD_BINDING_V12_R3=R13_AUDIT_PENDING")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
