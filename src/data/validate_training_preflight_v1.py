#!/usr/bin/env python3
"""Fail-closed validation for the formal runtime-training implementation preflight."""
from __future__ import print_function

import argparse
import hashlib
import json
import os


BUNDLE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
EXPECTED_ROLES = {
    "TRAIN": ["s13207", "s15850", "s35932", "s38417", "aes_core", "spi"],
    "VALIDATION": ["s5378", "tv80"],
    "PILOT": ["b18", "b20", "b21", "b22"],
    "BLIND_TEST": ["s9234", "s38584", "wb_dma"],
}
EXPECTED_METHODS = [
    "fixed_heuristic",
    "d95_safe_then_predicted_cycles",
    "d95_safe_cost_aware_topk",
]
EXPECTED_GATES = ["R%02d" % index for index in range(1, 15)]


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def validate_sources(contract, bundle_root=BUNDLE_ROOT):
    sources = contract.get("source_sha256")
    if not isinstance(sources, dict) or len(sources) != 12:
        raise ValueError("PREFLIGHT_SOURCE_SET_INVALID")
    root = os.path.abspath(bundle_root)
    loaded = {}
    for relative, expected in sources.items():
        path = os.path.abspath(os.path.join(root, *relative.split("/")))
        if os.path.commonpath((root, path)) != root or os.path.islink(path):
            raise ValueError("PREFLIGHT_SOURCE_PATH_INVALID")
        if sha256_file(path) != expected:
            raise ValueError("PREFLIGHT_SOURCE_DIGEST_MISMATCH")
        loaded[relative] = read_json(path)
    return loaded


def validate_split(split_contract, declared_roles):
    membership = split_contract.get("formal_runtime_membership")
    if not isinstance(membership, dict):
        raise ValueError("SPLIT_INVALID")
    observed = {role: [row.get("circuit") for row in membership.get(role, [])] for role in EXPECTED_ROLES}
    if observed != EXPECTED_ROLES or declared_roles != EXPECTED_ROLES:
        raise ValueError("SPLIT_MEMBERSHIP_DRIFT")
    circuits = set()
    family_roles = {}
    for role in ("TRAIN", "VALIDATION", "PILOT", "BLIND_TEST"):
        for row in membership[role]:
            circuit, family = row.get("circuit"), row.get("family")
            if circuit in circuits or (family in family_roles and family_roles[family] != role):
                raise ValueError("FAMILY_LEAKAGE")
            circuits.add(circuit)
            family_roles[family] = role
    if len(circuits) != 15 or len(family_roles) != 12 or split_contract.get("sealed_blind_test") is not True:
        raise ValueError("SPLIT_CARDINALITY_INVALID")


def validate(contract, bundle_root=BUNDLE_ROOT):
    if (
        contract.get("schema_version") != "runtime-training-preflight-v1"
        or contract.get("status") != "AUTHORIZED_TRAINING_IMPLEMENTATION_PREFLIGHT_ONLY"
        or contract.get("lsf_or_tessent_allowed") is not False
        or contract.get("blind_candidate_rows_allowed") is not False
        or contract.get("training_execution_allowed") is not False
    ):
        raise ValueError("PREFLIGHT_AUTHORITY_INVALID")
    sources = validate_sources(contract, bundle_root)
    p0 = sources["contracts/p0_contract_v1.json"]
    split = sources["contracts/data_split_v1.json"]
    policy_v1 = sources["contracts/runtime_policy_v1.json"]
    policy_v2 = sources["contracts/runtime_policy_v2.json"]
    registry = sources["contracts/recommendation_method_registry_v1.json"]
    assessment = sources["contracts/runtime_recovery_gate_assessment_v2.json"]
    r13_toolchain = sources["contracts/blind_method_binding_v12_r9.json"]
    nonblind = sources["data/manifests/runtime_nonblind_join_audit_v2.json"]
    phase4 = sources["data/manifests/phase4_runtime_nonblind_v2_r6/summary_r6.json"]
    blind = sources["data/manifests/blind_runtime_join_r13_v12_r9_independent_review_20260928.json"]
    blind_receipt = sources["data/manifests/blind_runtime_join_v12_r9_receipt_20260927.json"]
    r13_binding = sources["data/manifests/blind_runtime_method_binding_v12_r9_20260927.json"]

    validate_split(split, contract.get("roles"))
    objective = contract.get("objective", {})
    if (
        p0.get("fixed_modes") != ["H64", "M16", "F4"]
        or p0.get("primary_epsilon") != 0.01
        or p0.get("primary_k") != 10
        or p0.get("primary_method") != "d95_safe_cost_aware_topk"
        or objective.get("primary_endpoint") != "cumulative_tessent_process_elapsed_s_to_epsilon_hit"
        or objective.get("epsilon") != p0.get("primary_epsilon")
        or objective.get("top_k") != p0.get("primary_k")
        or objective.get("d95_is_hard_constraint") is not True
        or objective.get("ate_cycles_are_not_runtime_labels") is not True
        or objective.get("pattern_count_is_not_runtime_label") is not True
    ):
        raise ValueError("OBJECTIVE_INVALID")
    accounting = contract.get("runtime_accounting", {})
    if (
        policy_v2.get("base_policy_sha256") != sha256_file(os.path.join(bundle_root, "contracts", "runtime_policy_v1.json"))
        or policy_v2.get("training_allowed") is not False
        or policy_v1.get("primary_endpoint") != objective["primary_endpoint"]
        or policy_v1.get("retry", {}).get("charge_all_attempts") is not True
        or policy_v1.get("retry", {}).get("select_fastest_success") is not False
        or policy_v1.get("timing", {}).get("failed_attempt_elapsed_in_primary") is not True
        or policy_v1.get("timing", {}).get("retry_elapsed_in_primary") is not True
        or policy_v1.get("timeouts", {}).get("timeout_retry_allowed") is not False
        or policy_v1.get("timeouts", {}).get("timeout_cost_if_elapsed_available") != "observed_process_elapsed_s"
        or policy_v1.get("timeouts", {}).get("timeout_cost_if_elapsed_missing") != "configured_stage_timeout_s"
        or policy_v1.get("timeouts", {}).get("timeout_is_candidate_failure") is not True
        or policy_v1.get("missing_historical_timing", {}).get("policy") != "missing_label_no_imputation"
        or policy_v1.get("missing_historical_timing", {}).get("zero_cost_precompute_forbidden") is not True
        or policy_v2.get("replacements", {}).get("missing_historical_timing", {}).get("zero_cost_precompute_forbidden") is not True
        or policy_v2.get("replacements", {}).get("missing_historical_timing", {}).get("accounting_rule") != "charge each unique attempt once even when multiple measurements reference it"
        or accounting != {
            "charge_all_attempts": True,
            "select_fastest_success": False,
            "timeout_retry_allowed": False,
            "missing_runtime_imputation_allowed": False,
            "failed_attempt_elapsed_is_charged": True,
            "retry_elapsed_is_charged": True,
        }
    ):
        raise ValueError("RUNTIME_ACCOUNTING_INVALID")
    if (
        registry.get("methods") != EXPECTED_METHODS
        or registry.get("blind_circuits") != EXPECTED_ROLES["BLIND_TEST"]
        or registry.get("binding_policy", {}).get("method_specific_exclusion_allowed") is not False
    ):
        raise ValueError("METHOD_REGISTRY_INVALID")
    checks = assessment.get("checks")
    if (
        assessment.get("assessment_status") != "PASS_R01_R14"
        or not isinstance(checks, dict)
        or list(checks) != EXPECTED_GATES
        or any(checks[gate] != "PASS" for gate in EXPECTED_GATES)
        or assessment.get("data_gate_completed") is not True
        or assessment.get("training_implementation_preflight_allowed") is not True
        or assessment.get("training_execution_allowed") is not False
    ):
        raise ValueError("R01_R14_NOT_SEALED")
    if (
        nonblind.get("status") != "PASS_NONBLIND_JOIN_AUDIT_PARTIAL_FORMAL_SPLIT"
        or nonblind.get("aggregate", {}).get("circuit_count") != 6
        or nonblind.get("aggregate", {}).get("missing_count") != 0
        or nonblind.get("aggregate", {}).get("ambiguity_count") != 0
        or set(nonblind.get("circuits", {})) != {"b18", "s35932", "s38417", "s13207", "s15850", "s5378"}
    ):
        raise ValueError("NONBLIND_PHASE23_INVALID")
    phase4_circuits = phase4.get("circuits", {})
    if (
        phase4.get("aggregate", {}).get("circuit_count") != 6
        or phase4.get("aggregate", {}).get("attempt", {}).get("missing_wall_count") != 0
        or set(phase4_circuits) != {"b20", "b21", "b22", "aes_core", "spi", "tv80"}
        or any(row.get("join", {}).get("join_status_counts", {}).get("MISSING", 0) != 0 for row in phase4_circuits.values())
    ):
        raise ValueError("NONBLIND_PHASE4_INVALID")
    if (
        blind.get("status") != "PASS_R06_R07_R13_DATA_GATE_SEALED"
        or blind.get("data_gate_completed") is not True
        or blind.get("independent_review") != "PASS"
        or blind.get("high_findings") != 0
        or blind.get("medium_findings") != 0
        or any(blind.get(gate, {}).get("pass") is not True for gate in ("r06", "r07", "r13"))
        or blind.get("candidate_level_data_persisted") is not False
        or blind.get("training_execution_allowed") is not False
    ):
        raise ValueError("BLIND_DATA_GATE_INVALID")
    if (
        assessment.get("blind_evidence", {}).get("r06_r07_r13_review_sha256")
        != sha256_file(os.path.join(bundle_root, "data", "manifests", "blind_runtime_join_r13_v12_r9_independent_review_20260928.json"))
        or assessment.get("blind_evidence", {}).get("join_receipt_sha256") != blind.get("join_receipt_sha256")
        or assessment.get("blind_evidence", {}).get("r13_binding_sha256") != blind.get("r13_binding_sha256")
        or blind.get("join_receipt_sha256") != sha256_file(os.path.join(bundle_root, "data", "manifests", "blind_runtime_join_v12_r9_receipt_20260927.json"))
        or blind.get("r13_binding_sha256") != sha256_file(os.path.join(bundle_root, "data", "manifests", "blind_runtime_method_binding_v12_r9_20260927.json"))
        or blind.get("r13_toolchain_manifest_sha256") != sha256_file(os.path.join(bundle_root, "contracts", "blind_method_binding_v12_r9.json"))
        or blind_receipt.get("schema_version") != "blind-runtime-join-receipt-v12-r9"
        or blind_receipt.get("status") != "PASS_R06_R07_AUDIT_PENDING"
        or blind_receipt.get("training_allowed") is not False
        or r13_binding.get("schema_version") != "blind-runtime-method-binding-v12-r9"
        or r13_binding.get("status") != "PASS_R13_INDEPENDENT_AUDIT_PENDING"
        or r13_binding.get("join_receipt_sha256") != blind.get("join_receipt_sha256")
        or r13_binding.get("r13_toolchain_manifest_sha256") != blind.get("r13_toolchain_manifest_sha256")
        or r13_binding.get("training_allowed") is not False
        or r13_toolchain.get("schema_version") != "blind-runtime-method-binding-v12-r9-toolchain"
        or r13_toolchain.get("status") != "AUTHORIZED_R13_BINDING_REVIEW_PENDING"
        or r13_toolchain.get("join_receipt_sha256") != blind.get("join_receipt_sha256")
        or r13_toolchain.get("training_allowed") is not False
        or r13_toolchain.get("lsf_or_tessent_allowed") is not False
    ):
        raise ValueError("BLIND_EVIDENCE_CHAIN_MISMATCH")
    required = contract.get("required_training_contract_fields")
    if not isinstance(required, list) or len(required) != 9 or len(set(required)) != 9:
        raise ValueError("TRAINING_CONTRACT_REQUIREMENTS_INVALID")
    source_lines = [path + ":" + digest for path, digest in sorted(contract["source_sha256"].items())]
    source_set_sha256 = hashlib.sha256(("\n".join(source_lines) + "\n").encode("utf-8")).hexdigest()
    return {
        "schema_version": "runtime-training-preflight-receipt-v1",
        "status": "PASS_TRAINING_IMPLEMENTATION_PREFLIGHT",
        "source_set_sha256": source_set_sha256,
        "formal_runtime_membership_sha256": split["formal_runtime_membership_sha256"],
        "method_registry_sha256": sha256_file(os.path.join(bundle_root, "contracts", "recommendation_method_registry_v1.json")),
        "r01_r14_pass": True,
        "family_isolated": True,
        "blind_data_gate_sealed": True,
        "training_contract_requirements_complete": True,
        "lsf_or_tessent_allowed": False,
        "training_execution_allowed": False,
        "allowed_next_action": "implement_and_independently_review_runtime_training_chain",
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("contract")
    parser.add_argument("output")
    args = parser.parse_args(argv)
    result = validate(read_json(args.contract))
    with open(args.output, "x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print("RUNTIME_TRAINING_PREFLIGHT=PASS_IMPLEMENTATION_ONLY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
