#!/usr/bin/env python3
"""One-shot, aggregate-only BLIND runtime coverage auditor (Python 3.6+)."""
from __future__ import print_function

import argparse
import csv
import hashlib
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from build_runtime_join_v2 import (basename, is_not_run, role_for, source_rows,
                                   table_paths, value)
from recover_runtime_attempts import gnu_rows


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


def tool_set_sha256():
    names = ("run_blind_unseal_v4.py", "build_runtime_join_v2.py",
             "recover_runtime_attempts.py", "runtime_schema.py")
    return sha256_lines(name + ":" + sha256_file(os.path.join(HERE, name))
                        for name in names)


def atomic_write(path, payload):
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory):
        os.makedirs(directory)
    handle, temporary = tempfile.mkstemp(prefix=".blind-unseal-", suffix=".tmp",
                                         dir=directory)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
        os.replace(temporary, path)
    except Exception:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


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
        marker = basename(value(attempt, "source_log_path") or
                          value(attempt, "source_log"))
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
                        status = ("NO_RESULT_PATH" if kind == "repeatability"
                                  else "MISSING_RESULT_PATH")
                    else:
                        key = (circuit, mode, marker)
                        matches = source_index.get(key, [])
                        if not matches:
                            matches = run_index.get(key, [])
                        if len(matches) == 1:
                            status = "UNIQUE"
                        elif not matches:
                            status = "MISSING"
                        else:
                            status = "AMBIGUOUS"
                    output.append({"stage": stage, "join_status": status})
    return output


def summarize_join_rows(rows):
    formal_stages = set(("02_hf_coarse", "03_hmf_coarse", "04_integer_refine"))
    selected = [row for row in rows if row.get("stage") in formal_stages and
                row.get("join_status") not in ("NOT_RUN", "NO_RESULT_PATH")]
    unique = sum(row.get("join_status") == "UNIQUE" for row in selected)
    missing = sum(row.get("join_status") in ("MISSING", "MISSING_RESULT_PATH")
                  for row in selected)
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


def validate_before_consumption(args, contract, job, preflight, split, registry):
    if contract.get("schema_version") != "blind-runtime-unseal-v4":
        raise PreflightError("CONTRACT_VERSION")
    contract_sha = sha256_file(args.contract)
    if preflight.get("status") != "PASS" or preflight.get("contract_sha256") != contract_sha:
        raise PreflightError("PREFLIGHT_RECEIPT")
    if sha256_file(args.method_registry) != contract["scope"]["method_registry_sha256"]:
        raise PreflightError("METHOD_REGISTRY_DIGEST")
    if registry.get("methods") is None or len(registry["methods"]) != registry.get("method_count"):
        raise PreflightError("METHOD_REGISTRY_CONTENT")
    if split.get("formal_runtime_membership_sha256") != contract["scope"]["formal_runtime_membership_sha256"]:
        raise PreflightError("SPLIT_DIGEST")
    expected = contract["scope"]["blind_circuits"]
    supplied = [entry.get("circuit") for entry in job.get("circuits", [])]
    if supplied != expected or len(supplied) != len(set(supplied)):
        raise PreflightError("JOB_CIRCUIT_SCOPE")
    if job.get("contract_sha256") != contract_sha:
        raise PreflightError("JOB_CONTRACT_DIGEST")
    for path in (args.receipt, args.sidecar, args.consumed_marker):
        if os.path.exists(path):
            raise PreflightError("ONE_SHOT_ALREADY_CONSUMED_OR_OUTPUT_EXISTS")
    required = ("measurements_root", "log_root", "evidence_root", "family", "phase",
                "cohort", "environment_cohort", "inventory_manifest_sha256")
    for entry in job["circuits"]:
        if any(not entry.get(field) for field in required):
            raise PreflightError("JOB_FIELD_MISSING")
        if not os.path.isdir(entry["measurements_root"]) or not os.path.isdir(entry["log_root"]):
            raise PreflightError("JOB_INPUT_MISSING")
    return contract_sha


def create_consumed_marker(path, contract_sha, tool_sha):
    payload = json.dumps({
        "schema_version": "blind-runtime-unseal-consumed-v4",
        "status": "CONSUMED",
        "contract_sha256": contract_sha,
        "tool_sha256": tool_sha
    }, sort_keys=True).encode("utf-8") + b"\n"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)


def write_receipt_and_sidecar(receipt_path, sidecar_path, receipt):
    payload = json.dumps(receipt, ensure_ascii=False, indent=2,
                         sort_keys=True).encode("utf-8") + b"\n"
    atomic_write(receipt_path, payload)
    digest = hashlib.sha256(payload).hexdigest()
    sidecar = (digest + "  " + os.path.basename(receipt_path) + "\n").encode("ascii")
    atomic_write(sidecar_path, sidecar)


def execute(args):
    contract = read_json(args.contract)
    job = read_json(args.job_spec)
    preflight = read_json(args.preflight_receipt)
    split = read_json(args.split_contract)
    registry = read_json(args.method_registry)
    contract_sha = validate_before_consumption(args, contract, job, preflight,
                                               split, registry)
    tool_sha = tool_set_sha256()
    create_consumed_marker(args.consumed_marker, contract_sha, tool_sha)
    try:
        circuits = []
        for entry in job["circuits"]:
            meta = {
                "circuit": entry["circuit"], "family": entry["family"],
                "role": "BLIND_TEST", "phase": entry["phase"],
                "cohort": entry["cohort"],
                "environment_cohort": entry["environment_cohort"],
                "inventory_manifest_sha256": entry["inventory_manifest_sha256"]
            }
            attempts = gnu_rows(entry["log_root"], entry["evidence_root"], meta, [])
            if len(attempts) != len(set(row.get("attempt_id") for row in attempts)):
                raise ValueError("DUPLICATE_ATTEMPT_ID")
            joins = build_blind_join_statuses(entry["circuit"],
                                              entry["measurements_root"],
                                              attempts, split)
            summary = summarize_join_rows(joins)
            action_sha, measurement_artifacts = canonical_action_space(
                entry["measurements_root"], entry["circuit"])
            source_lines = measurement_artifacts + [
                "attempt:" + row.get("source_artifact_sha256", "") for row in attempts]
            if any(line.endswith(":") for line in source_lines):
                raise ValueError("MISSING_SOURCE_DIGEST")
            summary.update({
                "circuit": entry["circuit"],
                "frozen_runtime_eligible_action_space_sha256": action_sha,
                "source_artifact_set_sha256": sha256_lines(source_lines)
            })
            if (summary["missing_runtime_join_count"] or
                    summary["ambiguous_runtime_join_count"] or
                    summary["unique_runtime_join_count"] != summary["executed_stage_reference_count"] or
                    summary["coverage_rate"] != 1.0):
                raise ValueError("R06_R07_FAILED")
            circuits.append(summary)
        receipt = {
            "schema_version": "blind-runtime-unseal-receipt-v4",
            "status": "PASS",
            "formal_runtime_membership_sha256": contract["scope"]["formal_runtime_membership_sha256"],
            "method_registry_sha256": contract["scope"]["method_registry_sha256"],
            "tool_sha256": tool_sha,
            "contract_sha256": contract_sha,
            "circuits": circuits
        }
        write_receipt_and_sidecar(args.receipt, args.sidecar, receipt)
        return 0
    except Exception:
        failure = {
            "schema_version": "blind-runtime-unseal-receipt-v4",
            "status": "FAIL",
            "formal_runtime_membership_sha256": contract["scope"]["formal_runtime_membership_sha256"],
            "method_registry_sha256": contract["scope"]["method_registry_sha256"],
            "tool_sha256": tool_sha,
            "contract_sha256": contract_sha,
            "failure_code": "SEALED_AUDIT_FAILED",
            "circuits": []
        }
        write_receipt_and_sidecar(args.receipt, args.sidecar, failure)
        return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--preflight-receipt", required=True)
    parser.add_argument("--split-contract", required=True)
    parser.add_argument("--method-registry", required=True)
    parser.add_argument("--job-spec", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--sidecar", required=True)
    parser.add_argument("--consumed-marker", required=True)
    args = parser.parse_args()
    try:
        status = execute(args)
    except PreflightError:
        print("BLIND_UNSEAL=REFUSED_PRECONDITION")
        return 2
    print("BLIND_UNSEAL=%s" % ("PASS" if status == 0 else "FAIL"))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
