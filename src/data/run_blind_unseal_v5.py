#!/usr/bin/env python3
"""Durable one-shot, aggregate-only BLIND runtime coverage auditor."""
from __future__ import print_function

import argparse
import csv
import hashlib
import json
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from build_runtime_join_v2 import (basename, is_not_run, role_for, source_rows,
                                   table_paths, value)
from recover_runtime_attempts import gnu_rows
from validate_blind_unseal_preflight_v5 import validate as validate_preflight


FORMAL_STAGES = set(("02_hf_coarse", "03_hmf_coarse", "04_integer_refine"))
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class PreflightError(Exception):
    pass


def read_json(path):
    with open(path, "r", encoding="utf-8") as stream:
        return json.load(stream)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_lines(lines):
    payload = "".join(item + "\n" for item in sorted(set(lines)))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def resolve(root, relative_path):
    root_real = os.path.realpath(root)
    path = os.path.realpath(os.path.join(root_real, *relative_path.replace("\\", "/").split("/")))
    if os.path.commonpath((root_real, path)) != root_real:
        raise PreflightError("BUNDLE_PATH_ESCAPE")
    return path


def fsync_directory(path):
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def durable_atomic_write(path, payload):
    directory = os.path.dirname(os.path.abspath(path))
    descriptor, temporary = tempfile.mkstemp(prefix=".blind-unseal-v5-", suffix=".tmp",
                                              dir=directory)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        fsync_directory(directory)
    except Exception:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def durable_exclusive_write(path, payload):
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    fsync_directory(os.path.dirname(os.path.abspath(path)))


def prepare_output_directory(path):
    absolute = os.path.abspath(path)
    if os.path.lexists(absolute):
        if os.path.islink(absolute) or not os.path.isdir(absolute):
            raise PreflightError("OUTPUT_ROOT_NOT_DEDICATED_DIRECTORY")
        if os.listdir(absolute):
            raise PreflightError("OUTPUT_ROOT_NOT_EMPTY")
    else:
        parent = os.path.dirname(absolute)
        if not os.path.isdir(parent) or os.path.islink(parent):
            raise PreflightError("OUTPUT_PARENT_INVALID")
        os.mkdir(absolute, 0o700)
        fsync_directory(parent)
    if os.path.realpath(absolute) != absolute:
        raise PreflightError("OUTPUT_ROOT_SYMLINKED")
    return absolute


def inventory_digest(root, relative_paths, prefix):
    lines = []
    for relative_path in relative_paths:
        path = os.path.join(root, *relative_path.split("/"))
        if not os.path.isfile(path) or os.path.islink(path):
            raise ValueError("INPUT_FILE_MISSING_OR_SYMLINK")
        lines.append(sha256_file(path) + "  " + prefix + relative_path + "\n")
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def driver_log_inventory(root):
    relative_paths = []
    for parent, directories, files in os.walk(root):
        directories.sort()
        for filename in sorted(files):
            if filename.endswith(".driver.log"):
                path = os.path.join(parent, filename)
                relative_paths.append(os.path.relpath(path, root).replace(os.sep, "/"))
    relative_paths.sort()
    return inventory_digest(root, relative_paths, "./"), len(relative_paths)


def canonical_action_space(measurements_root, circuit):
    keys = []
    artifacts = []
    for stage, _filename, kind, path in table_paths(measurements_root):
        artifacts.append(stage + ":" + sha256_file(path))
        if kind not in ("hf", "hmf"):
            continue
        scheme = "HF" if kind == "hf" else "HMF"
        with open(path, "r", encoding="utf-8", newline="") as stream:
            for row in csv.DictReader(stream, delimiter="\t"):
                h_patterns = value(row, "h_patterns")
                m_patterns = value(row, "m_patterns") if scheme == "HMF" else ""
                if not h_patterns or (scheme == "HMF" and not m_patterns):
                    raise ValueError("INVALID_ACTION_KEY")
                keys.append("|".join((circuit, scheme, h_patterns, m_patterns)))
    if not keys:
        raise ValueError("EMPTY_ACTION_SPACE")
    return sha256_lines(keys), artifacts


def build_blind_join_statuses(circuit, measurements_root, attempt_rows, split):
    role, _family = role_for(circuit, split)
    if role != "BLIND_TEST":
        raise ValueError("NOT_REGISTERED_BLIND")
    source_index = {}
    run_index = {}
    for attempt in attempt_rows:
        if value(attempt, "circuit") != circuit:
            continue
        key = (circuit, value(attempt, "mode"))
        marker = basename(value(attempt, "source_log_path") or value(attempt, "source_log"))
        if marker:
            source_index.setdefault(key + (marker,), []).append(attempt)
        run_id = value(attempt, "run_id")
        if run_id:
            run_index.setdefault(key + (run_id,), []).append(attempt)

    output = []
    for stage, _filename, kind, path in table_paths(measurements_root):
        with open(path, "r", encoding="utf-8", newline="") as stream:
            for row in csv.DictReader(stream, delimiter="\t"):
                for mode, result_path in source_rows(kind, row):
                    marker = basename(result_path)
                    if kind != "repeatability" and is_not_run(row, mode, marker):
                        status = "NOT_RUN"
                    elif not marker:
                        status = "NO_RESULT_PATH" if kind == "repeatability" else "MISSING_RESULT_PATH"
                    else:
                        matches = source_index.get((circuit, mode, marker), [])
                        if not matches:
                            matches = run_index.get((circuit, mode, marker), [])
                        status = "UNIQUE" if len(matches) == 1 else ("MISSING" if not matches else "AMBIGUOUS")
                    output.append({"stage": stage, "join_status": status})
    return output


def summarize_join_rows(rows):
    selected = [row for row in rows if row.get("stage") in FORMAL_STAGES and
                row.get("join_status") not in ("NOT_RUN", "NO_RESULT_PATH")]
    unique = sum(row.get("join_status") == "UNIQUE" for row in selected)
    missing = sum(row.get("join_status") in ("MISSING", "MISSING_RESULT_PATH") for row in selected)
    ambiguous = sum(row.get("join_status") == "AMBIGUOUS" for row in selected)
    if unique + missing + ambiguous != len(selected):
        raise ValueError("UNCLASSIFIED_JOIN_STATUS")
    return {
        "executed_stage_reference_count": len(selected),
        "unique_runtime_join_count": unique,
        "missing_runtime_join_count": missing,
        "ambiguous_runtime_join_count": ambiguous,
        "coverage_rate": 0.0 if not selected else float(unique) / float(len(selected))
    }


def validate_review(review, contract_sha, expected_artifacts):
    if review.get("status") != "PASS" or not review.get("execution_allowed"):
        raise PreflightError("INDEPENDENT_REVIEW_NOT_PASS")
    if review.get("contract_sha256") != contract_sha:
        raise PreflightError("REVIEW_CONTRACT_DIGEST")
    if not re.match(r"^[0-9a-f]{40}$", review.get("reviewed_commit", "")):
        raise PreflightError("REVIEW_COMMIT")
    if review.get("reviewed_artifacts") != expected_artifacts:
        raise PreflightError("REVIEW_ARTIFACT_DIGESTS")
    if review.get("blind_data_read") or review.get("real_unseal_executed"):
        raise PreflightError("REVIEW_SCOPE_VIOLATION")


def validate_before_consumption(bundle_root):
    contract_path = resolve(bundle_root, "contracts/blind_runtime_unseal_v5.json")
    contract = read_json(contract_path)
    if contract.get("schema_version") != "blind-runtime-unseal-v5":
        raise PreflightError("CONTRACT_VERSION")
    contract_sha = sha256_file(contract_path)
    preflight = validate_preflight(bundle_root)
    if preflight.get("status") != "PASS" or preflight.get("contract_sha256") != contract_sha:
        raise PreflightError("CURRENT_PREFLIGHT_FAIL")

    expected_artifacts = dict(contract["toolchain"]["artifact_sha256"])
    for relative_path, expected_sha in expected_artifacts.items():
        if sha256_file(resolve(bundle_root, relative_path)) != expected_sha:
            raise PreflightError("TOOLCHAIN_DIGEST_MISMATCH")

    job_path = resolve(bundle_root, contract["inputs"]["job_spec"])
    if sha256_file(job_path) != contract["inputs"]["job_spec_sha256"]:
        raise PreflightError("JOB_SPEC_DIGEST")
    job = read_json(job_path)
    split = read_json(resolve(bundle_root, contract["scope"]["split_contract"]))
    review_path = resolve(bundle_root, contract["review_gate"]["receipt"])
    if not os.path.isfile(review_path) or os.path.islink(review_path):
        raise PreflightError("INDEPENDENT_REVIEW_RECEIPT_MISSING")
    review = read_json(review_path)
    validate_review(review, contract_sha, expected_artifacts)

    for entry in job.get("circuits", []):
        receipt_path = resolve(bundle_root, entry["aggregate_precondition_receipt"])
        if sha256_file(receipt_path) != entry["aggregate_precondition_receipt_sha256"]:
            raise PreflightError("AGGREGATE_PRECONDITION_DIGEST")
        receipt = read_json(receipt_path)
        if (receipt.get("circuit") != entry.get("circuit") or
                receipt.get("source_inventory_manifest_sha256") != entry.get("source_inventory_manifest_sha256") or
                receipt.get("counts", {}).get("recovered_attempt_count") != entry.get("expected_driver_log_count")):
            raise PreflightError("AGGREGATE_PRECONDITION_CONTENT")

    expected_scope = [(item["circuit"], item["family"])
                      for item in split["formal_runtime_membership"]["BLIND_TEST"]]
    supplied_scope = [(item.get("circuit"), item.get("family")) for item in job.get("circuits", [])]
    if supplied_scope != expected_scope:
        raise PreflightError("JOB_SCOPE")
    return contract, contract_sha, job, split, expected_artifacts


def marker_payload(schema, status, contract_sha, tool_sha):
    return (json.dumps({"schema_version": schema, "status": status,
                        "contract_sha256": contract_sha, "tool_set_sha256": tool_sha},
                       sort_keys=True).encode("utf-8") + b"\n")


def release_marker_payload(contract_sha, receipt_sha):
    return (json.dumps({
        "schema_version": "blind-runtime-unseal-release-v5",
        "status": "RELEASED",
        "contract_sha256": contract_sha,
        "receipt_sha256": receipt_sha
    }, sort_keys=True).encode("utf-8") + b"\n")


def tool_set_sha256(artifact_sha256):
    return sha256_lines(path + ":" + digest for path, digest in artifact_sha256.items())


def release(output_root, receipt):
    receipt_path = os.path.join(output_root, "receipt.json")
    sidecar_path = os.path.join(output_root, "receipt.json.sha256")
    released_path = os.path.join(output_root, "RELEASED")
    if any(os.path.lexists(path) for path in (receipt_path, sidecar_path, released_path)):
        raise RuntimeError("RELEASE_PATH_ALREADY_EXISTS")
    payload = json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    digest = hashlib.sha256(payload).hexdigest()
    durable_atomic_write(receipt_path, payload)
    durable_atomic_write(sidecar_path, (digest + "  receipt.json\n").encode("ascii"))
    durable_exclusive_write(released_path, release_marker_payload(
        receipt["contract_sha256"], digest))


def verify_release(output_root):
    required = [os.path.join(output_root, name) for name in
                ("CONSUMED", "receipt.json", "receipt.json.sha256", "RELEASED")]
    if not all(os.path.isfile(path) and not os.path.islink(path) for path in required):
        return False
    receipt_path = required[1]
    with open(required[2], "r", encoding="ascii") as stream:
        fields = stream.read().strip().split()
    if len(fields) != 2 or fields[1] != "receipt.json" or SHA256_RE.match(fields[0]) is None:
        return False
    expected = fields[0]
    released = read_json(required[3])
    return (sha256_file(receipt_path) == expected and
            released.get("schema_version") == "blind-runtime-unseal-release-v5" and
            released.get("status") == "RELEASED" and
            released.get("receipt_sha256") == expected)


def execute(bundle_root):
    contract, contract_sha, job, split, artifacts = validate_before_consumption(bundle_root)
    output_root = prepare_output_directory(job["output_root"])
    consumed_path = os.path.join(output_root, "CONSUMED")
    tool_sha = tool_set_sha256(artifacts)
    durable_exclusive_write(consumed_path, marker_payload(
        "blind-runtime-unseal-consumed-v5", "CONSUMED", contract_sha, tool_sha))

    try:
        circuits = []
        measurement_files = job["measurement_files"]
        for entry in job["circuits"]:
            for root_field in ("measurements_root", "log_root", "evidence_root"):
                root = entry[root_field]
                if (not os.path.isdir(root) or os.path.islink(root) or
                        os.path.realpath(root) != os.path.abspath(root)):
                    raise ValueError("INPUT_ROOT_INVALID")
            if inventory_digest(entry["measurements_root"], measurement_files, "") != entry["measurement_file_set_sha256"]:
                raise ValueError("MEASUREMENT_SOURCE_SET_CHANGED")
            log_sha, log_count = driver_log_inventory(entry["log_root"])
            if (log_sha != entry["driver_log_file_set_sha256"] or
                    log_count != entry["expected_driver_log_count"]):
                raise ValueError("DRIVER_SOURCE_SET_CHANGED")

            meta = {key: entry[key] for key in
                    ("circuit", "family", "phase", "cohort", "environment_cohort")}
            meta.update({"role": "BLIND_TEST",
                         "inventory_manifest_sha256": entry["source_inventory_manifest_sha256"]})
            attempts = gnu_rows(entry["log_root"], entry["evidence_root"], meta, [])
            if (len(attempts) != entry["expected_driver_log_count"] or
                    len(attempts) != len(set(row.get("attempt_id") for row in attempts))):
                raise ValueError("ATTEMPT_SET_MISMATCH")
            joins = build_blind_join_statuses(entry["circuit"], entry["measurements_root"], attempts, split)
            summary = summarize_join_rows(joins)
            action_sha, measurement_artifacts = canonical_action_space(entry["measurements_root"], entry["circuit"])
            source_lines = measurement_artifacts + [
                "attempt:" + row.get("source_artifact_sha256", "") for row in attempts]
            if any(line.endswith(":") for line in source_lines):
                raise ValueError("MISSING_SOURCE_DIGEST")
            summary.update({
                "circuit": entry["circuit"],
                "frozen_runtime_eligible_action_space_sha256": action_sha,
                "source_artifact_set_sha256": sha256_lines(source_lines)
            })
            if (summary["missing_runtime_join_count"] or summary["ambiguous_runtime_join_count"] or
                    summary["unique_runtime_join_count"] != summary["executed_stage_reference_count"] or
                    summary["coverage_rate"] != 1.0):
                raise ValueError("R06_R07_FAILED")
            circuits.append(summary)

        receipt = {
            "schema_version": "blind-runtime-unseal-receipt-v5",
            "status": "PASS",
            "formal_runtime_membership_sha256": contract["scope"]["formal_runtime_membership_sha256"],
            "method_registry_sha256": contract["scope"]["method_registry_sha256"],
            "tool_set_sha256": tool_sha,
            "contract_sha256": contract_sha,
            "circuits": circuits
        }
        release(output_root, receipt)
        return 0
    except Exception:
        failure = {
            "schema_version": "blind-runtime-unseal-receipt-v5",
            "status": "FAIL",
            "formal_runtime_membership_sha256": contract["scope"]["formal_runtime_membership_sha256"],
            "method_registry_sha256": contract["scope"]["method_registry_sha256"],
            "tool_set_sha256": tool_sha,
            "contract_sha256": contract_sha,
            "failure_code": "SEALED_AUDIT_FAILED",
            "circuits": []
        }
        try:
            release(output_root, failure)
        except Exception:
            pass
        return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-root", required=True)
    args = parser.parse_args()
    try:
        status = execute(os.path.abspath(args.bundle_root))
    except PreflightError:
        print("BLIND_UNSEAL=REFUSED_PRECONDITION")
        return 2
    print("BLIND_UNSEAL=%s" % ("PASS" if status == 0 else "FAIL"))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
