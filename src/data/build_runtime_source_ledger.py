#!/usr/bin/env python3
"""Build the aggregate-only R03 runtime-source ledger.

The ledger recomputes hashes only for checked-in files.  SHA-256 values found
inside recovery inventories describe A-side artifacts and are deliberately
labelled external_attested: this script never claims to reread those artifacts.
"""
from __future__ import print_function

import argparse
import hashlib
import json
import os
import re
import sys


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
LOGICAL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

LOCAL_INPUTS = (
    "contracts/data_split_v1.json",
    "contracts/runtime_policy_v1.json",
    "contracts/runtime_policy_v2.json",
    "contracts/runtime_recovery_gate_v1.json",
    "data/manifests/runtime_recovery_inventory_v1.json",
    "data/manifests/runtime_nonblind_join_audit_v2.json",
    "data/manifests/phase2_wall_time_semantics_v1.json",
    "src/data/audit_phase2_wall_time_semantics.py",
    "src/data/audit_runtime_log_inventory.py",
    "src/data/build_runtime_join_v2.py",
    "src/data/recover_runtime_attempts.py",
    "src/data/runtime_schema.py",
    "src/data/summarize_runtime_recovery.py",
)

R6_TOOL_TARGETS = {
    "audit_runtime_log_inventory.py": "src/data/audit_runtime_log_inventory.py",
    "recover_runtime_attempts.py": "src/data/recover_runtime_attempts.py",
    "build_runtime_join_v2.py": "src/data/build_runtime_join_v2.py",
    "summarize_runtime_recovery.py": "src/data/summarize_runtime_recovery.py",
    "runtime_schema.py": "src/data/runtime_schema.py",
    "data_split_v1.json": "contracts/data_split_v1.json",
}


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path):
    with open(path, "r") as handle:
        return json.load(handle)


def iter_sha_fields(value, prefix=""):
    if isinstance(value, dict):
        for key in sorted(value):
            child = prefix + "." + key if prefix else key
            for found in iter_sha_fields(value[key], child):
                yield found
    elif isinstance(value, list):
        for index, item in enumerate(value):
            child = "%s[%d]" % (prefix, index)
            for found in iter_sha_fields(item, child):
                yield found
    elif prefix.endswith("sha256") or "sha256" in prefix.split(".")[-1]:
        yield prefix, value


def artifact_inputs(root):
    inputs = list(LOCAL_INPUTS)
    for version in ("r2", "r3", "r6"):
        relative_root = "data/manifests/phase4_runtime_nonblind_v2_%s" % version
        absolute_root = os.path.join(root, relative_root.replace("/", os.sep))
        for directory, _, names in os.walk(absolute_root):
            for name in sorted(names):
                if name.endswith((".json", ".sha256", ".md")):
                    absolute = os.path.join(directory, name)
                    relative = os.path.relpath(absolute, root).replace(os.sep, "/")
                    inputs.append(relative)
    readback = "data/manifests/runtime_source_readback_v1.json"
    if os.path.isfile(os.path.join(root, readback.replace("/", os.sep))):
        inputs.append(readback)
    return tuple(sorted(set(inputs)))


def checked_in_hashes(root, inputs):
    result = {}
    for relative in inputs:
        absolute = os.path.join(root, relative.replace("/", os.sep))
        if not os.path.isfile(absolute):
            raise ValueError("missing checked-in ledger input: %s" % relative)
        result[relative] = sha256_file(absolute)
    return result


def validate_sha_files(root, inputs):
    field_count = 0
    for relative in inputs:
        if not relative.endswith(".sha256"):
            continue
        with open(os.path.join(root, relative.replace("/", os.sep)), "r") as handle:
            for line_number, line in enumerate(handle, 1):
                stripped = line.strip()
                if not stripped:
                    continue
                field_count += 1
                token = stripped.split()[0]
                if not SHA256_RE.match(token):
                    raise ValueError("invalid SHA-256 token: %s:%d" % (relative, line_number))
    return field_count


def parse_sha_file(path):
    result = {}
    with open(path, "r") as handle:
        for line_number, line in enumerate(handle, 1):
            stripped = line.strip()
            if not stripped:
                continue
            parts = stripped.split(None, 1)
            if len(parts) != 2 or not SHA256_RE.match(parts[0]):
                raise ValueError("invalid SHA-256 entry: %s:%d" % (path, line_number))
            name = parts[1].strip()
            if name in result:
                raise ValueError("duplicate SHA-256 target: %s" % name)
            result[name] = parts[0]
    return result


def validate_r6_local_bindings(root, r6, local_hashes):
    verified = 0
    for circuit, detail in sorted(r6.get("circuits", {}).items()):
        bindings = {
            "inventory_json": "data/manifests/phase4_runtime_nonblind_v2_r6/%s_inventory_r6.json" % circuit,
            "join_audit_json": "data/manifests/phase4_runtime_nonblind_v2_r6/%s_audit_r6.json" % circuit,
        }
        for field, relative in sorted(bindings.items()):
            if detail["file_sha256"][field] != local_hashes[relative]:
                raise ValueError("r6 local file binding mismatch: %s.%s" % (circuit, field))
            verified += 1
    sha_path = os.path.join(root, "data", "manifests", "phase4_runtime_nonblind_v2_r6", "tools_r6.sha256")
    tool_entries = parse_sha_file(sha_path)
    if set(tool_entries) != set(R6_TOOL_TARGETS):
        raise ValueError("r6 tool receipt target set mismatch")
    for name, relative in sorted(R6_TOOL_TARGETS.items()):
        if tool_entries[name] != local_hashes[relative]:
            raise ValueError("r6 tool binding mismatch: %s" % name)
        verified += 1
    return verified


def validate_sha_fields(documents):
    invalid = []
    total = 0
    for relative, document in documents.items():
        for field, value in iter_sha_fields(document):
            total += 1
            if not isinstance(value, str) or not SHA256_RE.match(value):
                invalid.append("%s:%s" % (relative, field))
    if invalid:
        raise ValueError("invalid nested SHA-256 fields: %s" % ", ".join(invalid))
    return total


def phase2_audit_status(audit):
    if audit.get("validation_status") != "PASS":
        raise ValueError("Phase2 wall-time semantics audit is not PASS")
    failures = []
    for circuit, detail in sorted(audit.get("circuits", {}).items()):
        if detail.get("validation_status") != "PASS":
            failures.append(circuit)
        for key, value in detail.get("checks", {}).items():
            if key != "row_count" and value != 0:
                failures.append("%s.%s" % (circuit, key))
    if failures:
        raise ValueError("Phase2 aggregate checks failed: %s" % ", ".join(failures))
    return {
        "validation_status": "PASS",
        "circuit_count": len(audit.get("circuits", {})),
        "row_count": sum(item["source_row_count"] for item in audit["circuits"].values()),
        "local_manifest_recomputed": True,
    }


def external_attestations(inventory):
    attestations = []
    for phase in ("phase2", "phase3", "phase4"):
        for circuit, item in sorted(inventory.get(phase, {}).get("circuits", {}).items()):
            hashes = {}
            for key, value in sorted(item.items()):
                if "sha256" in key:
                    hashes[key] = value
            if hashes:
                attestations.append({
                    "phase": phase,
                    "circuit": circuit,
                    "role": item.get("role"),
                    "hashes": hashes,
                    "verification": "external_attested_not_reread_locally",
                })
    return attestations


def expected_external_hashes(inventory, join_audit, r6):
    """Logical IDs bound by existing checked-in inventories, never raw paths."""
    expected = {}

    def add(logical_id, value):
        if logical_id in expected:
            raise ValueError("duplicate expected logical ID: %s" % logical_id)
        if not isinstance(value, str) or not SHA256_RE.match(value):
            raise ValueError("invalid expected SHA-256: %s" % logical_id)
        expected[logical_id] = value

    for phase in ("phase2", "phase3", "phase4"):
        for circuit, item in sorted(inventory.get(phase, {}).get("circuits", {}).items()):
            for key, value in sorted(item.items()):
                if "sha256" not in key:
                    continue
                suffix = key[:-7] if key.endswith("_sha256") else key
                logical_id = "%s.%s.%s" % (phase, circuit, suffix)
                add(logical_id, value)
    for circuit, item in sorted(join_audit.get("circuits", {}).items()):
        phase = "phase2" if circuit in ("b18", "s35932", "s38417") else "phase3"
        for key, value in sorted(item.items()):
            if not key.endswith("_sha256"):
                continue
            suffix = key[:-7]
            add("%s.%s.join_%s" % (phase, circuit, suffix), value)
    for circuit, item in sorted(r6.get("circuits", {}).items()):
        for key, value in sorted(item.get("file_sha256", {}).items()):
            add("phase4_r6.%s.%s" % (circuit, key), value)
        provenance = item.get("inventory_provenance", {})
        if "inventory_manifest_sha256" in provenance:
            # This is a digest of a raw-log inventory manifest, not the
            # digest of the checked-in aggregate inventory JSON.
            add("phase4_r6.%s.raw_inventory_manifest" % circuit,
                provenance["inventory_manifest_sha256"])
    return expected


def compare_readback(receipt, expected):
    if receipt.get("schema_version") != "runtime-source-readback-v1":
        raise ValueError("unsupported runtime source readback schema")
    artifacts = receipt.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError("invalid runtime source readback artifacts")
    matched = []
    mismatched = []
    unbound = []
    for logical_id, observed in sorted(artifacts.items()):
        if not LOGICAL_ID_RE.match(logical_id):
            raise ValueError("unsafe logical ID in readback receipt")
        if not isinstance(observed, str) or not SHA256_RE.match(observed):
            raise ValueError("invalid SHA-256 in readback receipt: %s" % logical_id)
        if logical_id not in expected:
            unbound.append(logical_id)
        elif observed == expected[logical_id]:
            matched.append(logical_id)
        else:
            mismatched.append(logical_id)
    missing = sorted(set(expected) - set(artifacts))
    return {
        "status": "MATCHED" if (len(matched) == len(expected) and not mismatched and
                                   not unbound and not missing) else "PARTIAL",
        "receipt_present": True,
        "expected_bindable_count": len(expected),
        "receipt_artifact_count": len(artifacts),
        "matched_count": len(matched),
        "mismatched_count": len(mismatched),
        "unbound_count": len(unbound),
        "missing_expected_count": len(missing),
        "mismatched_logical_ids": mismatched,
        "unbound_logical_ids": unbound,
        "missing_expected_logical_ids": missing,
    }


def readback_status(root, documents, inventory, join_audit, r6):
    relative = "data/manifests/runtime_source_readback_v1.json"
    expected = expected_external_hashes(inventory, join_audit, r6)
    if relative not in documents:
        return {
            "status": "ABSENT",
            "receipt_present": False,
            "expected_bindable_count": len(expected),
            "matched_count": 0,
            "mismatched_count": 0,
            "unbound_count": 0,
            "missing_expected_count": len(expected),
            "mismatched_logical_ids": [],
            "unbound_logical_ids": [],
            "missing_expected_logical_ids": sorted(expected),
        }
    return compare_readback(documents[relative], expected)


def build_ledger(root):
    documents = {}
    inputs = artifact_inputs(root)
    for relative in inputs:
        if relative.endswith(".json"):
            documents[relative] = load_json(os.path.join(root, relative.replace("/", os.sep)))
    local_hashes = checked_in_hashes(root, inputs)
    nested_sha_field_count = validate_sha_fields(documents) + validate_sha_files(root, inputs)

    split = documents["contracts/data_split_v1.json"]
    inventory = documents["data/manifests/runtime_recovery_inventory_v1.json"]
    phase2 = documents["data/manifests/phase2_wall_time_semantics_v1.json"]
    join_audit = documents["data/manifests/runtime_nonblind_join_audit_v2.json"]
    r6 = documents["data/manifests/phase4_runtime_nonblind_v2_r6/summary_r6.json"]
    determinism = documents["data/manifests/phase4_runtime_nonblind_v2_r6/determinism_r6.json"]
    r6_summary_hash = local_hashes["data/manifests/phase4_runtime_nonblind_v2_r6/summary_r6.json"]
    if determinism.get("first_run_sha256") != r6_summary_hash:
        raise ValueError("r6 determinism receipt does not bind the checked-in r6 summary")
    if determinism.get("repeat_run_sha256") != r6_summary_hash or not determinism.get("byte_identical"):
        raise ValueError("r6 repeat receipt is not byte-identical")
    if determinism.get("blind_data_accessed") is not False:
        raise ValueError("r6 determinism receipt reports BLIND access")
    local_binding_count = validate_r6_local_bindings(root, r6, local_hashes)
    r3_summary_path = "data/manifests/phase4_runtime_nonblind_v2_r3/provenance/summary_r3.json"
    policy_v2 = documents["contracts/runtime_policy_v2.json"]
    if policy_v2["replacements"]["missing_historical_timing"]["phase4_nonblind_r3_summary_sha256"] != local_hashes[r3_summary_path]:
        raise ValueError("runtime policy v2 does not bind checked-in historical r3 summary")
    local_binding_count += 1
    if r6.get("split_contract_sha256") != local_hashes["contracts/data_split_v1.json"]:
        raise ValueError("r6 summary split contract binding mismatch")
    local_binding_count += 1

    return {
        "schema_version": "runtime-source-ledger-v1",
        "status": "PARTIAL_LOCAL_HASHES_AND_EXTERNAL_ATTESTATIONS",
        "scope": "aggregate-only source provenance for R03; no runtime eligibility or P0 decision",
        "blind_policy": "No BLIND candidate, run_id, result path, or elapsed value is present. BLIND source hashes remain sealed external attestations only.",
        "verification_boundary": {
            "local_recomputed": "SHA-256 of checked-in files listed in local_artifacts",
            "external_attested": "SHA-256 values transcribed from checked-in recovery inventories; raw A-side tables, logs, and manifests were not reread locally",
            "not_a_pass_claim": "This ledger does not by itself satisfy R03 or unblock P0.",
        },
        "phase4_version_policy": {
            "authoritative": {
                "version": "r6",
                "status": "AUTHORITATIVE_NONBLIND",
                "summary": "data/manifests/phase4_runtime_nonblind_v2_r6/summary_r6.json",
                "summary_sha256": r6_summary_hash,
                "aggregate_attempt_row_count": r6["aggregate"]["attempt"]["row_count"],
                "aggregate_join_unique_count": r6["aggregate"]["join"]["unique_join_count"],
                "determinism_receipt": "data/manifests/phase4_runtime_nonblind_v2_r6/determinism_r6.json",
            },
            "historical_only": [
                {"version": "r2", "reason": "pre-cross-stage repair; never current PASS authority"},
                {"version": "r3", "reason": "pre-mode-aware r6 semantics; never current PASS authority"},
            ],
        },
        "formal_split": {
            "formal_runtime_membership_sha256": split["formal_runtime_membership_sha256"],
            "sealed_blind_test": split["sealed_blind_test"],
        },
        "phase2_wall_time_semantics": phase2_audit_status(phase2),
        "external_readback": readback_status(root, documents, inventory, join_audit, r6),
        "local_artifacts": local_hashes,
        "external_attestations": external_attestations(inventory),
        "validation": {
            "nested_referenced_sha256_field_count": nested_sha_field_count,
            "all_nested_referenced_sha256_lowercase_hex": True,
            "local_inputs_recomputed": True,
            "local_cross_reference_binding_count": local_binding_count,
            "all_local_cross_references_match": True,
            "external_artifacts_reread_locally": False,
        },
    }


def write_json(path, value):
    with open(path, "w") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
    parser.add_argument("--output", default="data/manifests/runtime_source_ledger_v1.json")
    args = parser.parse_args(argv)
    root = os.path.abspath(args.repo_root)
    output = args.output if os.path.isabs(args.output) else os.path.join(root, args.output.replace("/", os.sep))
    ledger = build_ledger(root)
    write_json(output, ledger)
    print("RUNTIME_SOURCE_LEDGER=PARTIAL local_artifacts=%d external_attestations=%d" %
          (len(ledger["local_artifacts"]), len(ledger["external_attestations"])))


if __name__ == "__main__":
    main()
