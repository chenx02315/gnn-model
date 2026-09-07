#!/usr/bin/env python3
"""Summarize checked non-blind runtime-recovery evidence (Python 3.6+)."""
from __future__ import print_function
import argparse
import collections
import csv
import hashlib
import json
import os
import sys


def text(row, key):
    return (row.get(key) or "").strip()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def membership(circuit, contract):
    for role, entries in contract.get("formal_runtime_membership", {}).items():
        for entry in entries:
            if entry.get("circuit") == circuit:
                return role, entry.get("family", "")
    return "UNREGISTERED", ""


def parse_circuit_spec(spec):
    try:
        circuit, paths = spec.split("=", 1)
        inventory, attempt, join, audit = paths.split(",")
    except ValueError:
        raise ValueError("--circuit must be name=inventory_json,attempt_tsv,join_tsv,join_audit_json")
    if not circuit or not all((inventory, attempt, join, audit)):
        raise ValueError("--circuit has an empty name or path")
    return circuit, (inventory, attempt, join, audit)


def locate_inventory_entry(value, circuit):
    found = []
    if isinstance(value, dict):
        if value.get("circuit") == circuit:
            found.append(value)
        for child in value.values():
            found.extend(locate_inventory_entry(child, circuit))
    elif isinstance(value, list):
        for child in value:
            found.extend(locate_inventory_entry(child, circuit))
    return found


def count_rows(path, required, circuit):
    with open(path, "r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        if not reader.fieldnames or not set(required).issubset(set(reader.fieldnames)):
            raise ValueError("schema mismatch in %s" % path)
        rows = list(reader)
    if any(text(row, "circuit") != circuit for row in rows):
        raise ValueError("circuit mismatch in %s" % path)
    return rows


def counter(rows, key):
    return dict(sorted(collections.Counter(text(row, key) or "<EMPTY>" for row in rows).items()))


def attempt_summary(path, circuit, role, family, inventory_manifest_sha256):
    required = ("circuit", "role", "family", "cohort", "environment_cohort", "parse_status", "attempt_outcome_class",
                "wall_s", "exit_status", "retry_order_status", "semantics_status", "timeout_status", "inventory_manifest_sha256")
    rows = count_rows(path, required, circuit)
    for row in rows:
        if text(row, "role") != role or text(row, "family") != family:
            raise ValueError("attempt split membership mismatch in %s" % path)
        if text(row, "inventory_manifest_sha256") != inventory_manifest_sha256:
            raise ValueError("attempt inventory_manifest_sha256 mismatch in %s" % path)
    nonzero = 0
    for row in rows:
        exit_status = text(row, "exit_status")
        if exit_status:
            try:
                nonzero += int(exit_status) != 0
            except ValueError:
                raise ValueError("non-numeric exit_status in %s" % path)
    return {"row_count": len(rows), "parse_status_counts": counter(rows, "parse_status"),
            "outcome_counts": counter(rows, "attempt_outcome_class"),
            "missing_wall_count": sum(not text(row, "wall_s") for row in rows),
            "nonzero_exit_count": nonzero, "retry_order_status_counts": counter(rows, "retry_order_status"),
            "cohort_counts": counter(rows, "cohort"), "environment_cohort_counts": counter(rows, "environment_cohort"),
            "role_counts": counter(rows, "role"), "family_counts": counter(rows, "family"),
            "semantics_status_counts": counter(rows, "semantics_status"), "timeout_status_counts": counter(rows, "timeout_status")}


def join_summary(path, circuit, role, family):
    required = ("attempt_id", "circuit", "role", "family", "join_status", "atpg_status", "parse_status", "attempt_outcome_class", "stage_relation", "marker_run_id_mismatch")
    rows = count_rows(path, required, circuit)
    if any(text(row, "role") != role or text(row, "family") != family for row in rows):
        raise ValueError("join split membership mismatch in %s" % path)
    statuses = counter(rows, "join_status")
    unique = [row for row in rows if text(row, "join_status") == "UNIQUE"]
    explicit = [row for row in unique if text(row, "atpg_status") == "PASS"]
    unknown = [row for row in unique if text(row, "atpg_status") == "" and text(row, "parse_status") == "PASS_RUNTIME_OUTCOME_PENDING" and text(row, "attempt_outcome_class") == "UNKNOWN_LEGACY_STATUS"]
    if len(unique) != len(explicit) + len(unknown):
        raise ValueError("unexpected UNIQUE runtime status in %s" % path)
    cross_stage = [row for row in unique if text(row, "stage_relation") == "CROSS_STAGE"]
    return {"row_count": len(rows), "join_status_counts": statuses, "unique_join_count": len(unique),
            "explicit_pass_unique_count": len(explicit), "unknown_legacy_status_unique_count": len(unknown),
            "cross_stage_unique_count": len(cross_stage),
            "distinct_cross_stage_attempt_count": len(set(text(row, "attempt_id") for row in cross_stage)),
            "marker_run_id_mismatch_count": sum(text(row, "marker_run_id_mismatch").lower() == "true" for row in rows)}


def checked_circuit(circuit, paths, role, family):
    inventory_path, attempt_path, join_path, audit_path = paths
    with open(inventory_path, "r", encoding="utf-8") as stream:
        inventory = json.load(stream)
    if not isinstance(inventory, dict) or not inventory.get("schema_version"):
        raise ValueError("schema mismatch in %s" % inventory_path)
    entries = locate_inventory_entry(inventory, circuit)
    if len(entries) != 1:
        raise ValueError("inventory circuit entry must occur exactly once for %s" % circuit)
    entry = entries[0]
    if entry.get("role") and entry["role"] != role:
        raise ValueError("inventory role mismatch for %s" % circuit)
    if entry.get("family") and entry["family"] != family:
        raise ValueError("inventory family mismatch for %s" % circuit)
    provenance = dict(inventory)
    provenance.update(entry)
    inventory_manifest_sha256 = provenance.get("inventory_manifest_sha256", "")
    if not inventory_manifest_sha256:
        raise ValueError("inventory_manifest_sha256 missing for %s" % circuit)
    inventory_counts = {key: value for key, value in sorted(entry.items())
                        if key.endswith("_count") or key.endswith("footers") or key in ("driver_logs", "raw_driver_logs", "atpg_status_markers", "raw_atpg_status_markers", "nonpass_atpg_status", "raw_nonpass_atpg_status", "outcome_pending", "raw_outcome_pending", "nonzero_exit", "raw_nonzero_exit")}
    attempts = attempt_summary(attempt_path, circuit, role, family, inventory_manifest_sha256)
    joins = join_summary(join_path, circuit, role, family)
    with open(audit_path, "r", encoding="utf-8") as stream:
        audit = json.load(stream)
    required = ("row_count", "ambiguity_count", "cross_stage_unique_count", "distinct_cross_stage_attempt_count", "source_basename_marker_run_id_mismatch_count")
    if not isinstance(audit, dict) or not set(required).issubset(set(audit)):
        raise ValueError("schema mismatch in %s" % audit_path)
    expected = {"row_count": joins["row_count"], "ambiguity_count": joins["join_status_counts"].get("AMBIGUOUS", 0),
                "cross_stage_unique_count": joins["cross_stage_unique_count"],
                "distinct_cross_stage_attempt_count": joins["distinct_cross_stage_attempt_count"],
                "source_basename_marker_run_id_mismatch_count": joins["marker_run_id_mismatch_count"]}
    for key, value in expected.items():
        if audit[key] != value:
            raise ValueError("join audit mismatch for %s: %s" % (circuit, key))
    return {"role": role, "family": family,
            "inventory_provenance": {key: provenance.get(key, "") for key in ("inventory_manifest_sha256", "cohort", "field_policy")},
            "file_sha256": {"inventory_json": sha256_file(inventory_path), "attempt_tsv": sha256_file(attempt_path),
                            "join_tsv": sha256_file(join_path), "join_audit_json": sha256_file(audit_path)},
            "inventory_counts": inventory_counts, "attempt": attempts, "join": joins}


def add_counts(target, source):
    for key, value in source.items():
        if isinstance(value, int):
            target[key] = target.get(key, 0) + value
        elif isinstance(value, dict):
            child = target.setdefault(key, {})
            add_counts(child, value)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--circuit", action="append", required=True)
    parser.add_argument("--split-contract", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        specs = [parse_circuit_spec(spec) for spec in args.circuit]
        if len(set(name for name, unused in specs)) != len(specs):
            raise ValueError("duplicate --circuit name")
        # The contract is intentionally the only file opened before eligibility is settled.
        with open(args.split_contract, "r", encoding="utf-8") as stream:
            contract = json.load(stream)
        classified = []
        for circuit, paths in specs:
            role, family = membership(circuit, contract)
            if role in ("BLIND_TEST", "UNREGISTERED"):
                raise ValueError("%s circuit %s is not eligible for runtime recovery summary" % (role, circuit))
            classified.append((circuit, paths, role, family))
        circuits = {}
        aggregate = {"circuit_count": len(classified), "inventory_counts": {}, "attempt": {}, "join": {}}
        for circuit, paths, role, family in classified:
            summary = checked_circuit(circuit, paths, role, family)
            circuits[circuit] = summary
            add_counts(aggregate["inventory_counts"], summary["inventory_counts"])
            add_counts(aggregate["attempt"], summary["attempt"])
            add_counts(aggregate["join"], summary["join"])
        result = {"schema_version": "runtime_recovery_summary_v1", "split_contract_sha256": sha256_file(args.split_contract),
                  "aggregate": aggregate, "circuits": circuits}
        with open(args.output, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
        print("circuits=%d join_rows=%d" % (aggregate["circuit_count"], aggregate["join"].get("row_count", 0)))
        return 0
    except (IOError, OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    sys.exit(main())
