#!/usr/bin/env python3
"""Bind all registered methods to exact r6 aggregate action hashes."""
from __future__ import print_function
import argparse, hashlib, json, os, re

EXPECTED_REGISTRY_SHA256 = "8fb8d4a90981c2479e3e6ea3a8a4669286080e921ad0c2ff8d82e8a2a5c4191f"
EXPECTED_METHODS = ["fixed_heuristic", "d95_safe_then_predicted_cycles", "d95_safe_cost_aware_topk"]
EXPECTED_CIRCUITS = ["s9234", "s38584", "wb_dma"]
EXPECTED_FORMAL_MEMBERSHIP_SHA256 = "c8f589d67d80470dcf49ffbcab51da763162e9ae82af0308b36d6771cbd97cac"
EXPECTED_SPLIT_SHA256 = "ffecd5093453f69c11263501b822ad7bb8f7eefd5da60dd7863331088f6fbcda"
EXPECTED_HISTORICAL_INVENTORY_SHA256 = "cf7b37773516b39b1e3001e43aba1d4157f577a1906fe81605e37b10cb5645c9"
EXPECTED_CLOSEOUT_SHA256 = "671410d9687a725a0a1ac610bbac7c5247dd4ab4ebe918738c9ea5e9309806a5"
EXPECTED_OUTPUT_ROOT = "/temp/jiangchuanc/multimode_ate_phase4_20260825_A/18_blind_runtime_join_v12_r6"
EXPECTED_ARTIFACTS = {"src/data/blind_inventory_v12_r2.py", "src/data/blind_join_core_v12_r3.py",
                      "src/data/run_blind_join_v12_r3.py", "src/data/run_blind_join_v12_r5.py",
                      "src/data/run_blind_join_v12_r6.py", "src/data/build_blind_method_binding_v12_r6.py",
                      "tests/test_run_blind_join_v12_r6.py", "tests/test_build_blind_method_binding_v12_r6.py"}
BUNDLE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
REQUIRED = {"circuit", "executed_stage_reference_count", "unique_runtime_join_count", "missing_runtime_join_count", "ambiguous_runtime_join_count", "coverage_rate", "distinct_runtime_attempt_count", "cross_stage_reference_count", "eligible_action_count", "all_unique_action_count", "frozen_runtime_eligible_action_space_sha256", "source_artifact_set_sha256"}
SHA256 = re.compile(r"^[0-9a-f]{64}$")

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""): h.update(block)
    return h.hexdigest()

def implementation_set_sha256(contract):
    artifacts = contract.get("implementation", {}).get("artifact_sha256")
    if not isinstance(artifacts, dict) or not artifacts: raise ValueError("IMPLEMENTATION_SET_INVALID")
    return hashlib.sha256(("".join(x + "\n" for x in sorted(path + ":" + digest for path, digest in artifacts.items()))).encode("utf-8")).hexdigest()

def validate_contract(contract, contract_sha256, bundle_root=BUNDLE_ROOT):
    artifacts = contract.get("implementation", {}).get("artifact_sha256")
    if (contract.get("schema_version") != "blind-runtime-join-v12-r6" or
        contract.get("status") != "AUTHORIZED_EXECUTION_REVIEWED" or
        contract.get("circuits") != EXPECTED_CIRCUITS or
        contract.get("output_root") != EXPECTED_OUTPUT_ROOT or
        contract.get("training_allowed") is not False or
        contract.get("historical_inventory_sha256") != EXPECTED_HISTORICAL_INVENTORY_SHA256 or
        contract.get("recovery", {}).get("closeout_sha256") != EXPECTED_CLOSEOUT_SHA256 or
        not isinstance(artifacts, dict) or set(artifacts) != EXPECTED_ARTIFACTS):
        raise ValueError("AUTHORIZED_R6_CONTRACT_REQUIRED")
    if SHA256.match(contract_sha256 or "") is None:
        raise ValueError("DIGEST_INVALID")
    root = os.path.abspath(bundle_root)
    for relative, digest in artifacts.items():
        if SHA256.match(digest or "") is None:
            raise ValueError("CONTRACT_ARTIFACT_DIGEST_INVALID")
        path = os.path.abspath(os.path.join(root, *relative.split("/")))
        if os.path.commonpath((root, path)) != root or os.path.islink(path) or sha256_file(path) != digest:
            raise ValueError("CONTRACT_ARTIFACT_DIGEST_MISMATCH")
    return implementation_set_sha256(contract)

def build(receipt, registry, receipt_sha256, registry_sha256, contract_sha256,
          implementation_sha256, contract, bundle_root=BUNDLE_ROOT):
    if any(SHA256.match(value or "") is None for value in
           (receipt_sha256, registry_sha256, contract_sha256, implementation_sha256)):
        raise ValueError("DIGEST_INVALID")
    if validate_contract(contract, contract_sha256, bundle_root) != implementation_sha256:
        raise ValueError("IMPLEMENTATION_SET_INVALID")
    if (receipt.get("schema_version") != "blind-runtime-join-receipt-v12-r6" or receipt.get("status") != "PASS_R06_R07_AUDIT_PENDING" or receipt.get("training_allowed") is not False): raise ValueError("R6_RECEIPT_REQUIRED")
    if (receipt.get("contract_sha256") != contract_sha256 or
        receipt.get("implementation_set_sha256") != implementation_sha256):
        raise ValueError("RECEIPT_IMPLEMENTATION_BINDING_MISMATCH")
    if (receipt.get("formal_runtime_membership_sha256") != EXPECTED_FORMAL_MEMBERSHIP_SHA256 or
        receipt.get("split_contract_sha256") != EXPECTED_SPLIT_SHA256):
        raise ValueError("FORMAL_SPLIT_BINDING_MISMATCH")
    if (registry_sha256 != EXPECTED_REGISTRY_SHA256 or receipt.get("method_registry_sha256") != EXPECTED_REGISTRY_SHA256 or
        registry.get("methods") != EXPECTED_METHODS or registry.get("blind_circuits") != EXPECTED_CIRCUITS): raise ValueError("METHOD_REGISTRY_INVALID")
    rows = receipt.get("circuits")
    if not isinstance(rows, list) or [row.get("circuit") for row in rows] != EXPECTED_CIRCUITS: raise ValueError("R6_CIRCUITS")
    for row in rows:
        if (set(row) != REQUIRED or row["executed_stage_reference_count"] <= 0 or row["unique_runtime_join_count"] != row["executed_stage_reference_count"] or row["missing_runtime_join_count"] != 0 or row["ambiguous_runtime_join_count"] != 0 or row["coverage_rate"] != 1.0 or row["eligible_action_count"] <= 0 or row["all_unique_action_count"] != row["eligible_action_count"]): raise ValueError("R6_R06_R07_INVALID")
        if (SHA256.match(row.get("frozen_runtime_eligible_action_space_sha256") or "") is None or
            SHA256.match(row.get("source_artifact_set_sha256") or "") is None): raise ValueError("R6_ACTION_HASH")
    return {"schema_version":"blind-runtime-method-binding-v12-r6","status":"PASS_R13_INDEPENDENT_AUDIT_PENDING","join_receipt_sha256":receipt_sha256,"contract_sha256":contract_sha256,"implementation_set_sha256":implementation_sha256,"method_registry_sha256":registry_sha256,"methods":EXPECTED_METHODS,"circuits":[{"circuit":row["circuit"],"eligible_action_count":row["eligible_action_count"],"frozen_runtime_eligible_action_space_sha256":row["frozen_runtime_eligible_action_space_sha256"],"method_bindings":[{"method":method,"action_space_sha256":row["frozen_runtime_eligible_action_space_sha256"]} for method in EXPECTED_METHODS]} for row in rows],"all_methods_identical_per_circuit":True,"method_specific_exclusion_allowed":False,"training_allowed":False}

def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument("receipt"); parser.add_argument("registry"); parser.add_argument("contract"); parser.add_argument("output"); args = parser.parse_args(argv)
    with open(args.receipt, encoding="utf-8") as stream: receipt = json.load(stream)
    with open(args.registry, encoding="utf-8") as stream: registry = json.load(stream)
    with open(args.contract, encoding="utf-8") as stream: contract = json.load(stream)
    contract_sha256 = sha256_file(args.contract)
    implementation_sha256 = validate_contract(contract, contract_sha256)
    result = build(receipt, registry, sha256_file(args.receipt), sha256_file(args.registry),
                   contract_sha256, implementation_sha256, contract)
    with open(args.output, "x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, ensure_ascii=False, sort_keys=True, indent=2); stream.write("\n")
    print("BLIND_METHOD_BINDING_V12_R6=R13_AUDIT_PENDING"); return 0

if __name__ == "__main__": raise SystemExit(main())
