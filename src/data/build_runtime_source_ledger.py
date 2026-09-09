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
    "contracts/phase2_manifest_recovery_v1.json",
    "contracts/runtime_source_digest_recheck_v2.json",
    "data/manifests/runtime_recovery_inventory_v1.json",
    "data/manifests/runtime_nonblind_join_audit_v2.json",
    "data/manifests/runtime_authority_package_audit_v1.json",
    "data/manifests/runtime_source_reconciliation_v1.json",
    "data/manifests/runtime_source_digest_recheck_receipt_v2.json",
    "data/manifests/runtime_source_digest_recheck_verification_v2.json",
    "data/manifests/phase2_manifest_recovery_receipt_v1.json",
    "data/manifests/phase2_wall_time_semantics_v1.json",
    "src/data/audit_phase2_wall_time_semantics.py",
    "src/data/audit_phase2_manifest_recovery.py",
    "src/data/audit_runtime_log_inventory.py",
    "src/data/audit_runtime_authority_package.py",
    "src/data/build_runtime_join_v2.py",
    "src/data/recheck_runtime_source_digests.py",
    "src/data/recover_runtime_attempts.py",
    "src/data/runtime_schema.py",
    "src/data/summarize_runtime_recovery.py",
    "src/data/verify_runtime_source_digest_receipt.py",
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
    delta = "data/manifests/runtime_source_readback_delta_v1.json"
    if os.path.isfile(os.path.join(root, delta.replace("/", os.sep))):
        inputs.append(delta)
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


def merge_readback_delta(base, delta, expected):
    """Overlay a versioned corrective receipt without hiding prior evidence."""
    for receipt in (base, delta):
        if receipt.get("schema_version") != "runtime-source-readback-v1":
            raise ValueError("unsupported runtime source readback schema")
        if not isinstance(receipt.get("artifacts"), dict):
            raise ValueError("invalid runtime source readback artifacts")
    merged = dict(base["artifacts"])
    replaced = []
    confirmed = []
    for logical_id, observed in sorted(delta["artifacts"].items()):
        if logical_id not in expected:
            raise ValueError("delta contains unbound logical ID: %s" % logical_id)
        if observed != expected[logical_id]:
            raise ValueError("delta does not match authority: %s" % logical_id)
        if logical_id in merged and merged[logical_id] == expected[logical_id]:
            confirmed.append(logical_id)
            continue
        if logical_id in merged:
            replaced.append(logical_id)
        merged[logical_id] = observed
    return ({
        "schema_version": "runtime-source-readback-v1",
        "artifacts": merged,
    }, replaced, confirmed)


def merge_digest_recheck(receipt, supplement, contract, verification,
                         expected, local_hashes):
    """Fill only still-missing IDs from the independently verified v2 receipt."""
    contract_fields = {
        "schema_version", "receipt_version", "expected_entry_count",
        "trusted_raw_spec_sha256", "canonical_specification_sha256",
        "trusted_recheck_tool_sha256", "trusted_audit_tool_sha256",
        "trusted_receipt_sha256", "scope", "remaining_unresolved_logical_ids",
        "gate_result",
    }
    if not isinstance(contract, dict) or set(contract) != contract_fields:
        raise ValueError("digest recheck contract fields are invalid")
    if contract["schema_version"] != "runtime-source-digest-recheck-contract-v2":
        raise ValueError("digest recheck contract schema is invalid")
    if contract["receipt_version"] != "r03-canonical-18-v2":
        raise ValueError("digest recheck contract version is invalid")
    receipt_relative = "data/manifests/runtime_source_digest_recheck_receipt_v2.json"
    if contract["trusted_receipt_sha256"] != local_hashes[receipt_relative]:
        raise ValueError("digest recheck contract does not bind the receipt")
    if contract["trusted_recheck_tool_sha256"] != local_hashes[
            "src/data/recheck_runtime_source_digests.py"]:
        raise ValueError("digest recheck contract does not bind the recheck tool")
    if contract["trusted_audit_tool_sha256"] != local_hashes[
            "src/data/audit_runtime_log_inventory.py"]:
        raise ValueError("digest recheck contract does not bind the audit tool")

    receipt_fields = {
        "schema_version", "receipt_version", "specification_sha256",
        "audit_tool_sha256", "recheck_tool_sha256", "artifacts", "counts",
        "field_policy",
    }
    if not isinstance(supplement, dict) or set(supplement) != receipt_fields:
        raise ValueError("digest recheck receipt fields are invalid")
    if supplement["schema_version"] != "canonical-digest-recheck-receipt-v1":
        raise ValueError("digest recheck receipt schema is invalid")
    if supplement["receipt_version"] != contract["receipt_version"]:
        raise ValueError("digest recheck receipt version is invalid")
    if supplement["specification_sha256"] != contract["canonical_specification_sha256"]:
        raise ValueError("digest recheck canonical specification is unbound")
    if supplement["audit_tool_sha256"] != contract["trusted_audit_tool_sha256"]:
        raise ValueError("digest recheck receipt audit tool is unbound")
    if supplement["recheck_tool_sha256"] != contract["trusted_recheck_tool_sha256"]:
        raise ValueError("digest recheck receipt tool is unbound")
    if supplement["counts"] != {"entry_count": 18, "file_count": 1,
                                "inventory_count": 17}:
        raise ValueError("digest recheck receipt counts are invalid")
    if supplement["field_policy"] != "logical IDs, SHA-256 values, and aggregate counts only":
        raise ValueError("digest recheck field policy is invalid")
    if contract["expected_entry_count"] != 18:
        raise ValueError("digest recheck expected entry count is invalid")

    verification_fields = {
        "receipt_sha256", "receipt_version", "schema_version", "status",
        "trusted_raw_spec_sha256", "trusted_recheck_tool_sha256",
        "verified_entry_count",
    }
    if not isinstance(verification, dict) or set(verification) != verification_fields:
        raise ValueError("digest recheck verification fields are invalid")
    if (verification["schema_version"] != "canonical-digest-receipt-verification-v1" or
            verification["status"] != "VERIFIED" or
            verification["receipt_version"] != contract["receipt_version"] or
            verification["receipt_sha256"] != contract["trusted_receipt_sha256"] or
            verification["trusted_raw_spec_sha256"] != contract["trusted_raw_spec_sha256"] or
            verification["trusted_recheck_tool_sha256"] != contract["trusted_recheck_tool_sha256"] or
            verification["verified_entry_count"] != contract["expected_entry_count"]):
        raise ValueError("digest recheck verification is not bound to the contract")

    artifacts = supplement.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError("digest recheck artifacts are invalid")
    prior = compare_readback(receipt, expected)
    remaining = contract["remaining_unresolved_logical_ids"]
    if (not isinstance(remaining, list) or len(remaining) != len(set(remaining)) or
            any(item not in expected for item in remaining)):
        raise ValueError("digest recheck unresolved ID list is invalid")
    expected_supplement = set(prior["missing_expected_logical_ids"]) - set(remaining)
    if set(artifacts) != expected_supplement or len(artifacts) != 18:
        raise ValueError("digest recheck must fill exactly 18 previously missing IDs")
    merged = dict(receipt["artifacts"])
    for logical_id, observed in sorted(artifacts.items()):
        if logical_id in merged:
            raise ValueError("digest recheck may not overwrite an existing readback")
        if observed != expected[logical_id]:
            raise ValueError("digest recheck does not match authority: %s" % logical_id)
        merged[logical_id] = observed
    result = {"schema_version": "runtime-source-readback-v1", "artifacts": merged}
    post = compare_readback(result, expected)
    if (post["status"] != "PARTIAL" or post["matched_count"] != 70 or
            post["receipt_artifact_count"] != 70 or
            post["mismatched_count"] != 0 or post["unbound_count"] != 0 or
            post["missing_expected_logical_ids"] != remaining or
            contract["gate_result"] != "R03_PARTIAL_70_OF_73"):
        raise ValueError("digest recheck post-merge gate state is invalid")
    return result


def merge_phase2_manifest_recovery(receipt, supplement, contract,
                                   expected, local_hashes):
    """Fill the final three R03 IDs from the locally reread Phase2 manifests."""
    contract_fields = {
        "schema_version", "receipt_version", "expected_entry_count",
        "expected_logical_ids", "trusted_audit_tool_sha256",
        "trusted_receipt_sha256", "source_boundary", "gate_result",
    }
    if not isinstance(contract, dict) or set(contract) != contract_fields:
        raise ValueError("Phase2 manifest recovery contract fields are invalid")
    if contract["schema_version"] != "phase2-historical-manifest-recovery-contract-v1":
        raise ValueError("Phase2 manifest recovery contract schema is invalid")
    receipt_relative = "data/manifests/phase2_manifest_recovery_receipt_v1.json"
    tool_relative = "src/data/audit_phase2_manifest_recovery.py"
    if contract["trusted_receipt_sha256"] != local_hashes[receipt_relative]:
        raise ValueError("Phase2 manifest recovery contract does not bind receipt")
    if contract["trusted_audit_tool_sha256"] != local_hashes[tool_relative]:
        raise ValueError("Phase2 manifest recovery contract does not bind audit tool")

    receipt_fields = {
        "schema_version", "receipt_version", "scope", "source_boundary",
        "field_policy", "artifacts", "counts", "validation",
    }
    if not isinstance(supplement, dict) or set(supplement) != receipt_fields:
        raise ValueError("Phase2 manifest recovery receipt fields are invalid")
    if (supplement["schema_version"] !=
            "phase2-historical-manifest-recovery-receipt-v1" or
            supplement["receipt_version"] != contract["receipt_version"]):
        raise ValueError("Phase2 manifest recovery receipt version is invalid")
    expected_ids = contract["expected_logical_ids"]
    if (contract["expected_entry_count"] != 3 or
            not isinstance(expected_ids, list) or
            len(expected_ids) != len(set(expected_ids)) or
            set(supplement["artifacts"]) != set(expected_ids)):
        raise ValueError("Phase2 manifest recovery logical IDs are invalid")
    if supplement["counts"] != {
            "artifact_count": 3, "byte_count": 2325666,
            "data_row_count": 4609}:
        raise ValueError("Phase2 manifest recovery counts are invalid")
    required_validation = {
        "all_attempt_ids_unique_per_manifest": True,
        "all_forbidden_outcome_fields_absent": True,
        "all_rows_collected_success_only": True,
        "all_rows_have_wall_time": True,
        "all_source_table_digests_match": True,
        "all_target_digests_match": True,
        "blind_data_accessed": False,
    }
    if supplement["validation"] != required_validation:
        raise ValueError("Phase2 manifest recovery validation is invalid")

    merged = dict(receipt["artifacts"])
    for logical_id in sorted(expected_ids):
        if logical_id in merged:
            raise ValueError("Phase2 manifest recovery may not overwrite existing ID")
        artifact = supplement["artifacts"][logical_id]
        allowed = {
            "byte_count", "data_row_count", "manifest_sha256",
            "source_table_sha256", "unique_attempt_id_count",
        }
        if set(artifact) != allowed:
            raise ValueError("Phase2 manifest recovery artifact fields are invalid")
        if artifact["manifest_sha256"] != expected[logical_id]:
            raise ValueError("Phase2 manifest recovery digest does not match authority")
        source_logical_id = logical_id[:-len(".manifest")] + ".source"
        if artifact["source_table_sha256"] != expected[source_logical_id]:
            raise ValueError("Phase2 manifest recovery source digest does not match authority")
        if artifact["data_row_count"] != artifact["unique_attempt_id_count"]:
            raise ValueError("Phase2 manifest recovery attempt IDs are incomplete")
        merged[logical_id] = artifact["manifest_sha256"]
    result = {"schema_version": "runtime-source-readback-v1", "artifacts": merged}
    post = compare_readback(result, expected)
    if (post["status"] != "MATCHED" or post["matched_count"] != 73 or
            post["receipt_artifact_count"] != 73 or
            post["missing_expected_count"] != 0 or
            post["mismatched_count"] != 0 or post["unbound_count"] != 0 or
            contract["gate_result"] != "R03_MATCHED_73_OF_73"):
        raise ValueError("Phase2 manifest recovery post-merge gate is invalid")
    return result


def validate_reconciliation(reconciliation, base, delta, package_receipt,
                            expected, local_hashes):
    if reconciliation.get("schema_version") != "runtime-source-reconciliation-v1":
        raise ValueError("unsupported runtime source reconciliation schema")
    if reconciliation["delta_receipt_sha256"] != local_hashes[
            "data/manifests/runtime_source_readback_delta_v1.json"]:
        raise ValueError("reconciliation does not bind delta receipt")
    phase2 = reconciliation["phase2"]
    package = phase2["versioned_a_side_package"]
    if package["audit_receipt_sha256"] != local_hashes[
            "data/manifests/runtime_authority_package_audit_v1.json"]:
        raise ValueError("reconciliation does not bind package receipt")
    for field in ("archive_sha256", "manifest_sha256", "payload_file_count",
                  "bounded_extract_status"):
        if package[field] != package_receipt[field]:
            raise ValueError("package receipt mismatch: %s" % field)
    if package_receipt.get("archive_entry_count") != 8:
        raise ValueError("package archive entry count mismatch")
    if package_receipt.get("audit_tool_sha256") != local_hashes[
            "src/data/audit_runtime_authority_package.py"]:
        raise ValueError("package audit tool binding mismatch")
    if phase2["corrected_generation_epoch"] <= phase2["historical_generation_epoch"]:
        raise ValueError("reconciliation generation order is invalid")
    s5378 = reconciliation["phase3_s5378"]
    declared_delta = set(phase2["authority_artifacts"]) | set([s5378["logical_id"]])
    if set(delta["artifacts"]) != declared_delta:
        raise ValueError("reconciliation delta logical-ID set mismatch")
    for logical_id, authority_hash in sorted(phase2["authority_artifacts"].items()):
        if expected.get(logical_id) != authority_hash:
            raise ValueError("reconciliation authority mismatch: %s" % logical_id)
        if delta["artifacts"].get(logical_id) != authority_hash:
            raise ValueError("reconciliation delta mismatch: %s" % logical_id)
        if base["artifacts"].get(logical_id) != phase2["historical_artifacts"].get(logical_id):
            raise ValueError("reconciliation historical mismatch: %s" % logical_id)
        if authority_hash == phase2["historical_artifacts"].get(logical_id):
            raise ValueError("reconciliation did not preserve distinct historical evidence")
    expected_payload = {
        "b18_audit_v2.json": phase2["authority_artifacts"]["phase2.b18.join_audit_json"],
        "b18_join_v2.tsv": phase2["authority_artifacts"]["phase2.b18.join_join_tsv"],
        "s35932_audit_v2.json": phase2["authority_artifacts"]["phase2.s35932.join_audit_json"],
        "s35932_join_v2.tsv": phase2["authority_artifacts"]["phase2.s35932.join_join_tsv"],
        "s38417_audit_v2.json": phase2["authority_artifacts"]["phase2.s38417.join_audit_json"],
        "s38417_join_v2.tsv": phase2["authority_artifacts"]["phase2.s38417.join_join_tsv"],
    }
    if package_receipt.get("payload_sha256") != expected_payload:
        raise ValueError("package payload receipt mismatch")
    logical_id = s5378["logical_id"]
    if s5378["transcription_error_sha256"] == s5378["reread_sha256"]:
        raise ValueError("s5378 transcription correction is not distinct")
    if expected.get(logical_id) != s5378["reread_sha256"]:
        raise ValueError("s5378 corrected inventory does not match reread")
    if base["artifacts"].get(logical_id) != s5378["reread_sha256"]:
        raise ValueError("s5378 base receipt does not match reread")
    if delta["artifacts"].get(logical_id) != s5378["reread_sha256"]:
        raise ValueError("s5378 delta receipt does not confirm reread")
    inventory_authority = reconciliation["phase3_s5378"]["authority_attempt_manifest_sha256"]
    if inventory_authority != expected["phase3.s5378.authority_attempt_manifest"]:
        raise ValueError("s5378 authority manifest binding mismatch")
    if inventory_authority == s5378["reread_sha256"]:
        raise ValueError("s5378 raw and authority manifests must remain distinct")
    return len(phase2["authority_artifacts"]) + 1


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
    receipt = documents[relative]
    delta_relative = "data/manifests/runtime_source_readback_delta_v1.json"
    replaced = []
    confirmed = []
    if delta_relative in documents:
        receipt, replaced, confirmed = merge_readback_delta(
            receipt, documents[delta_relative], expected)
    supplement_relative = "data/manifests/runtime_source_digest_recheck_receipt_v2.json"
    supplement_present = supplement_relative in documents
    if supplement_present:
        receipt = merge_digest_recheck(
            receipt, documents[supplement_relative],
            documents["contracts/runtime_source_digest_recheck_v2.json"],
            documents["data/manifests/runtime_source_digest_recheck_verification_v2.json"],
            expected, checked_in_hashes(root, artifact_inputs(root)))
    phase2_relative = "data/manifests/phase2_manifest_recovery_receipt_v1.json"
    phase2_present = phase2_relative in documents
    if phase2_present:
        receipt = merge_phase2_manifest_recovery(
            receipt, documents[phase2_relative],
            documents["contracts/phase2_manifest_recovery_v1.json"],
            expected, checked_in_hashes(root, artifact_inputs(root)))
    result = compare_readback(receipt, expected)
    result["delta_receipt_present"] = delta_relative in documents
    result["delta_replaced_count"] = len(replaced)
    result["delta_replaced_logical_ids"] = replaced
    result["delta_confirmed_count"] = len(confirmed)
    result["delta_confirmed_logical_ids"] = confirmed
    result["digest_recheck_receipt_present"] = supplement_present
    result["digest_recheck_added_count"] = 18 if supplement_present else 0
    result["phase2_manifest_recovery_receipt_present"] = phase2_present
    result["phase2_manifest_recovery_added_count"] = 3 if phase2_present else 0
    return result


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
    reconciliation = documents["data/manifests/runtime_source_reconciliation_v1.json"]
    package_receipt = documents["data/manifests/runtime_authority_package_audit_v1.json"]
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
    readback = documents["data/manifests/runtime_source_readback_v1.json"]
    delta = documents["data/manifests/runtime_source_readback_delta_v1.json"]
    local_binding_count += validate_reconciliation(
        reconciliation, readback, delta, package_receipt,
        expected_external_hashes(inventory, join_audit, r6), local_hashes)
    if r6.get("split_contract_sha256") != local_hashes["contracts/data_split_v1.json"]:
        raise ValueError("r6 summary split contract binding mismatch")
    local_binding_count += 1

    return {
        "schema_version": "runtime-source-ledger-v1",
        "status": "MATCHED_ALL_EXPECTED_SOURCE_DIGESTS",
        "scope": "aggregate-only source provenance for R03; no runtime eligibility or P0 decision",
        "blind_policy": "No BLIND candidate, run_id, result path, or elapsed value is present. BLIND source hashes remain sealed external attestations only.",
        "verification_boundary": {
            "local_recomputed": "SHA-256 of checked-in files listed in local_artifacts",
            "external_attested": "SHA-256 values transcribed from checked-in recovery inventories; three historical Phase2 manifests were separately reread locally",
            "not_a_pass_claim": "This ledger closes R03 digest completeness only; it does not unblock P0 or satisfy other recovery gates.",
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
            "phase2_historical_manifests_reread_locally": True,
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
    print("RUNTIME_SOURCE_LEDGER=%s local_artifacts=%d external_attestations=%d" %
          (ledger["external_readback"]["status"], len(ledger["local_artifacts"]),
           len(ledger["external_attestations"])))


if __name__ == "__main__":
    main()
