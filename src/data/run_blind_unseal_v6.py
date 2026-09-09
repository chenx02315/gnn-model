#!/usr/bin/env python3
"""Bootstrap-only v6 sealed BLIND auditor; direct execution is forbidden."""
from __future__ import print_function

import hashlib
import json
import os


class BootstrapAttestationError(Exception):
    pass


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def release_marker_payload(contract_sha, receipt_sha):
    return (json.dumps({
        "schema_version": "blind-runtime-unseal-release-v6",
        "status": "RELEASED",
        "contract_sha256": contract_sha,
        "receipt_sha256": receipt_sha
    }, sort_keys=True).encode("utf-8") + b"\n")


def release(core, output_root, receipt):
    receipt_path = os.path.join(output_root, "receipt.json")
    sidecar_path = os.path.join(output_root, "receipt.json.sha256")
    released_path = os.path.join(output_root, "RELEASED")
    if any(os.path.lexists(path) for path in (receipt_path, sidecar_path, released_path)):
        raise RuntimeError("RELEASE_PATH_ALREADY_EXISTS")
    payload = json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    receipt_sha = hashlib.sha256(payload).hexdigest()
    core.durable_atomic_write(receipt_path, payload)
    core.durable_atomic_write(sidecar_path, (receipt_sha + "  receipt.json\n").encode("ascii"))
    core.durable_exclusive_write(released_path,
                                 release_marker_payload(receipt["contract_sha256"], receipt_sha))


def verify_release(output_root, contract, contract_sha, tool_set_sha):
    names = ("CONSUMED", "receipt.json", "receipt.json.sha256", "RELEASED")
    paths = dict((name, os.path.join(output_root, name)) for name in names)
    if not all(os.path.isfile(path) and not os.path.islink(path) for path in paths.values()):
        return False
    try:
        with open(paths["CONSUMED"], "r", encoding="utf-8") as stream:
            consumed = json.load(stream)
        with open(paths["receipt.json"], "r", encoding="utf-8") as stream:
            receipt = json.load(stream)
        with open(paths["receipt.json.sha256"], "r", encoding="ascii") as stream:
            sidecar = stream.read().strip().split()
        with open(paths["RELEASED"], "r", encoding="utf-8") as stream:
            released = json.load(stream)
    except (OSError, ValueError):
        return False
    if len(sidecar) != 2 or sidecar[1] != "receipt.json":
        return False
    receipt_sha = sha256_file(paths["receipt.json"])
    if sidecar[0] != receipt_sha:
        return False
    if consumed != {
            "schema_version": "blind-runtime-unseal-consumed-v6",
            "status": "CONSUMED", "contract_sha256": contract_sha,
            "tool_set_sha256": tool_set_sha}:
        return False
    if released != {
            "schema_version": "blind-runtime-unseal-release-v6",
            "status": "RELEASED", "contract_sha256": contract_sha,
            "receipt_sha256": receipt_sha}:
        return False
    allowed_envelope = set(contract["allowed_receipt"]["envelope_fields"])
    required_envelope = set(("schema_version", "status", "formal_runtime_membership_sha256",
                             "method_registry_sha256", "tool_set_sha256", "contract_sha256", "circuits"))
    if not required_envelope.issubset(receipt) or not set(receipt).issubset(allowed_envelope):
        return False
    if (receipt.get("schema_version") != "blind-runtime-unseal-receipt-v6" or
            receipt.get("status") not in ("PASS", "FAIL") or
            receipt.get("contract_sha256") != contract_sha or
            receipt.get("tool_set_sha256") != tool_set_sha or
            receipt.get("formal_runtime_membership_sha256") != contract["scope"]["formal_runtime_membership_sha256"] or
            receipt.get("method_registry_sha256") != contract["scope"]["method_registry_sha256"]):
        return False
    rows = receipt.get("circuits")
    if not isinstance(rows, list):
        return False
    allowed_row = set(contract["allowed_receipt"]["circuit_row_fields"])
    if receipt["status"] == "PASS":
        if [row.get("circuit") for row in rows] != contract["scope"]["blind_circuits"]:
            return False
        if any(set(row) != allowed_row for row in rows):
            return False
        if "failure_code" in receipt:
            return False
    else:
        if rows or receipt.get("failure_code") != "SEALED_AUDIT_FAILED":
            return False
    return True


def execute_from_bootstrap(bundle_root, contract, job, split, attestation):
    contract_path = os.path.join(bundle_root, "contracts", "blind_runtime_unseal_v6.json")
    contract_sha = sha256_file(contract_path)
    artifacts = contract["bootstrap"]["reviewed_artifact_sha256"]
    review_path = os.path.join(bundle_root, *contract["review_gate"]["receipt"].split("/"))
    with open(review_path, "r", encoding="utf-8") as stream:
        review = json.load(stream)
    if (review.get("status") != "PASS" or not review.get("execution_allowed") or
            review.get("contract_sha256") != contract_sha or
            review.get("reviewed_artifacts") != artifacts):
        raise BootstrapAttestationError("REVIEW_ATTESTATION")
    expected_attestation = {
            "status": "BOOTSTRAP_VERIFIED",
            "contract_sha256": contract_sha,
            "reviewed_commit": review.get("reviewed_commit"),
            "reviewed_artifacts": artifacts}
    if attestation != expected_attestation:
        raise BootstrapAttestationError("BOOTSTRAP_ATTESTATION")

    import run_blind_unseal_v5 as core

    tool_set_sha = core.tool_set_sha256(artifacts)
    output_root = core.prepare_output_directory(job["output_root"])
    consumed_path = os.path.join(output_root, "CONSUMED")
    consumed_payload = (json.dumps({
        "schema_version": "blind-runtime-unseal-consumed-v6",
        "status": "CONSUMED", "contract_sha256": contract_sha,
        "tool_set_sha256": tool_set_sha
    }, sort_keys=True).encode("utf-8") + b"\n")
    core.durable_exclusive_write(consumed_path, consumed_payload)

    try:
        circuits = []
        for entry in job["circuits"]:
            for root_field in ("measurements_root", "log_root", "evidence_root"):
                root = entry[root_field]
                if (not os.path.isdir(root) or os.path.islink(root) or
                        os.path.realpath(root) != os.path.abspath(root)):
                    raise ValueError("INPUT_ROOT_INVALID")
            if core.inventory_digest(entry["measurements_root"], job["measurement_files"], "") != entry["measurement_file_set_sha256"]:
                raise ValueError("MEASUREMENT_SOURCE_SET_CHANGED")
            log_sha, log_count = core.driver_log_inventory(entry["log_root"])
            if log_sha != entry["driver_log_file_set_sha256"] or log_count != entry["expected_driver_log_count"]:
                raise ValueError("DRIVER_SOURCE_SET_CHANGED")

            meta = dict((key, entry[key]) for key in
                        ("circuit", "family", "phase", "cohort", "environment_cohort"))
            meta.update({"role": "BLIND_TEST",
                         "inventory_manifest_sha256": entry["source_inventory_manifest_sha256"]})
            attempts = core.gnu_rows(entry["log_root"], entry["evidence_root"], meta, [])
            if (len(attempts) != entry["expected_driver_log_count"] or
                    len(attempts) != len(set(row.get("attempt_id") for row in attempts))):
                raise ValueError("ATTEMPT_SET_MISMATCH")
            joins = core.build_blind_join_statuses(entry["circuit"], entry["measurements_root"], attempts, split)
            summary = core.summarize_join_rows(joins)
            action_sha, measurement_artifacts = core.canonical_action_space(entry["measurements_root"], entry["circuit"])
            source_lines = measurement_artifacts + [
                "attempt:" + row.get("source_artifact_sha256", "") for row in attempts]
            if any(line.endswith(":") for line in source_lines):
                raise ValueError("MISSING_SOURCE_DIGEST")
            summary.update({
                "circuit": entry["circuit"],
                "frozen_runtime_eligible_action_space_sha256": action_sha,
                "source_artifact_set_sha256": core.sha256_lines(source_lines)
            })
            if (summary["missing_runtime_join_count"] or summary["ambiguous_runtime_join_count"] or
                    summary["unique_runtime_join_count"] != summary["executed_stage_reference_count"] or
                    summary["coverage_rate"] != 1.0):
                raise ValueError("R06_R07_FAILED")
            circuits.append(summary)

        receipt = {
            "schema_version": "blind-runtime-unseal-receipt-v6", "status": "PASS",
            "formal_runtime_membership_sha256": contract["scope"]["formal_runtime_membership_sha256"],
            "method_registry_sha256": contract["scope"]["method_registry_sha256"],
            "tool_set_sha256": tool_set_sha, "contract_sha256": contract_sha,
            "circuits": circuits
        }
        release(core, output_root, receipt)
        return 0
    except Exception:
        failure = {
            "schema_version": "blind-runtime-unseal-receipt-v6", "status": "FAIL",
            "formal_runtime_membership_sha256": contract["scope"]["formal_runtime_membership_sha256"],
            "method_registry_sha256": contract["scope"]["method_registry_sha256"],
            "tool_set_sha256": tool_set_sha, "contract_sha256": contract_sha,
            "failure_code": "SEALED_AUDIT_FAILED", "circuits": []
        }
        try:
            release(core, output_root, failure)
        except Exception:
            pass
        return 1


def main():
    print("BLIND_UNSEAL=REFUSED_USE_BOOTSTRAP_V6")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
