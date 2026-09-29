#!/usr/bin/env python3
"""Aggregate-only, fail-closed audit for runtime-training source readiness."""
from __future__ import print_function

import argparse
import csv
import hashlib
import json
import os
import re
import stat
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from runtime_schema import MANIFEST_V2_FIELDS


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
JOIN_REQUIRED_FIELDS = frozenset((
    "role", "family", "circuit", "join_status", "attempt_id",
    "retry_group_id", "retry_order", "retry_order_status",
    "timeout_status", "attempt_outcome_class",
))
KNOWN_TIMEOUT = frozenset((
    "NO_TIMEOUT", "NOT_TIMEOUT", "TIMEOUT", "TIMED_OUT", "TIMEOUT_KILLED",
))
KNOWN_OUTCOME = frozenset(("SUCCESS", "FAILURE", "TIMEOUT"))
GLOB_RE = re.compile(r"[*?\[\]]")


class AuditError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise AuditError(code)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("utf-8")


def read_regular_bytes(path, label):
    require(os.path.isfile(path) and not os.path.islink(path), label + "_MISSING")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode), label + "_NOT_REGULAR")
        return stream.read()


def load_json(path, label):
    data = read_regular_bytes(path, label)
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, TypeError, ValueError):
        raise AuditError(label + "_INVALID_JSON")
    require(isinstance(value, dict), label + "_NOT_OBJECT")
    return value, data


def read_tsv_bytes(data, label, exact_fields=None):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise AuditError(label + "_INVALID_UTF8")
    reader = csv.DictReader(text.splitlines(), delimiter="\t")
    fields = tuple(reader.fieldnames or ())
    if exact_fields is not None:
        require(fields == tuple(exact_fields), label + "_FIELDS")
    else:
        require(JOIN_REQUIRED_FIELDS.issubset(fields), label + "_FIELDS")
    rows = list(reader)
    require(rows, label + "_EMPTY")
    return rows


def is_reparse(path):
    info = os.stat(path, follow_symlinks=False)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(info, "st_file_attributes", 0)
    return os.path.islink(path) or bool(flag and attributes & flag)


def validate_local_root(root):
    require(isinstance(root, str) and root and os.path.isabs(root), "BINDING_ROOT_NOT_ABSOLUTE")
    normalized_slashes = root.replace("\\", "/")
    require(not normalized_slashes.startswith("//"), "BINDING_REMOTE_ROOT")
    require(not GLOB_RE.search(root), "BINDING_ROOT_GLOB")
    absolute = os.path.abspath(root)
    require(os.path.isdir(absolute), "BINDING_ROOT_MISSING")
    drive, tail = os.path.splitdrive(absolute)
    cursor = drive + os.sep if drive else os.sep
    for component in [item for item in tail.split(os.sep) if item]:
        cursor = os.path.join(cursor, component)
        require(not is_reparse(cursor), "BINDING_ROOT_REPARSE")
    return absolute


def read_bound_artifact(artifact):
    require(isinstance(artifact, dict) and set(artifact) == set(("root", "path", "sha256")),
            "BINDING_ARTIFACT_FIELDS")
    root = validate_local_root(artifact.get("root"))
    relative = artifact.get("path")
    require(isinstance(relative, str) and relative and not os.path.isabs(relative),
            "BINDING_PATH_NOT_RELATIVE")
    drive, _tail = os.path.splitdrive(relative)
    require(not drive and not GLOB_RE.search(relative), "BINDING_PATH_INVALID")
    normalized = os.path.normpath(relative)
    require(normalized not in ("", ".", "..") and
            not normalized.startswith(".." + os.sep), "BINDING_PATH_ESCAPE")
    path = os.path.abspath(os.path.join(root, normalized))
    try:
        inside = os.path.commonpath((root, path)) == root
    except ValueError:
        inside = False
    require(inside, "BINDING_PATH_ESCAPE")
    cursor = root
    for component in normalized.split(os.sep):
        cursor = os.path.join(cursor, component)
        require(os.path.exists(cursor), "BINDING_ARTIFACT_MISSING")
        require(not is_reparse(cursor), "BINDING_ARTIFACT_REPARSE")
    require(SHA256_RE.match(artifact.get("sha256", "")) is not None,
            "BINDING_SHA_FORMAT")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode), "BINDING_ARTIFACT_NOT_REGULAR")
        data = stream.read()
    require(hashlib.sha256(data).hexdigest() == artifact["sha256"],
            "BINDING_SHA_MISMATCH")
    return {"sha256": artifact["sha256"], "data": data}


def validate_contract(contract):
    require(contract.get("schema_version") == "runtime-training-source-readiness-v1",
            "CONTRACT_SCHEMA")
    require(contract.get("status") == "DESIGN_FROZEN_AUDIT_ONLY", "CONTRACT_STATUS")
    roster = contract.get("required_roster")
    require(isinstance(roster, list) and len(roster) == 8, "CONTRACT_ROSTER")
    require(all(isinstance(item, dict) and
                set(item) == set(("circuit", "family", "role"))
                for item in roster), "CONTRACT_ROSTER_FIELDS")
    require(len(set(item["circuit"] for item in roster)) == len(roster),
            "CONTRACT_ROSTER_DUPLICATE")
    rules = contract.get("source_rules", {})
    require(rules.get("roles_allowed") == ["TRAIN", "VALIDATION"] and
            rules.get("blind_or_pilot_rows_allowed") is False and
            rules.get("retry_order_status_required") == "KNOWN_ORDER" and
            rules.get("attempt_outcome_class_allowed") == ["SUCCESS", "FAILURE", "TIMEOUT"] and
            rules.get("fastest_success_selection_allowed") is False and
            rules.get("unknown_status_inference_allowed") is False and
            rules.get("missing_attempt_omission_allowed") is False,
            "CONTRACT_RULES")
    boundary = contract.get("execution_boundary", {})
    require(all(boundary.get(key) is False for key in (
        "training_allowed", "blind_access_allowed", "lsf_or_tessent_allowed",
        "remote_access_allowed", "package_release_allowed")), "CONTRACT_BOUNDARY")


def validate_bindings(bindings, roster):
    require(bindings.get("schema_version") == "runtime-training-source-readiness-bindings-v1",
            "BINDINGS_SCHEMA")
    circuits = bindings.get("circuits")
    require(isinstance(circuits, list) and len(circuits) == len(roster),
            "BINDINGS_CIRCUITS")
    expected = dict((item["circuit"], (item["role"], item["family"])) for item in roster)
    observed = {}
    for item in circuits:
        require(isinstance(item, dict) and set(item) == set((
            "circuit", "family", "role", "attempt_manifest", "join")),
            "BINDING_FIELDS")
        circuit = item.get("circuit")
        require(circuit in expected and circuit not in observed, "BINDING_ROSTER")
        require((item.get("role"), item.get("family")) == expected[circuit],
                "BINDING_MEMBERSHIP")
        for key in ("attempt_manifest", "join"):
            item[key] = read_bound_artifact(item.get(key))
        observed[circuit] = item
    require(set(observed) == set(expected), "BINDING_ROSTER")
    return observed


def count_values(rows, field):
    answer = {}
    for row in rows:
        value = (row.get(field) or "").strip() or "<BLANK>"
        answer[value] = answer.get(value, 0) + 1
    return dict(sorted(answer.items()))


def audit_one(item):
    circuit, role, family = item["circuit"], item["role"], item["family"]
    attempts = read_tsv_bytes(item["attempt_manifest"]["data"], "ATTEMPTS", MANIFEST_V2_FIELDS)
    joins = read_tsv_bytes(item["join"]["data"], "JOIN")
    attempt_ids = set()
    retry_groups = {}
    for row in attempts:
        require(row["circuit"] == circuit and row["role"] == role and row["family"] == family,
                "ATTEMPT_MEMBERSHIP")
        attempt_id = row["attempt_id"].strip()
        require(attempt_id and attempt_id not in attempt_ids, "ATTEMPT_ID_NOT_UNIQUE")
        attempt_ids.add(attempt_id)
        retry_group = row["retry_group_id"].strip()
        require(retry_group, "RETRY_GROUP_MISSING")
        retry_groups[retry_group] = retry_groups.get(retry_group, 0) + 1

    join_attempt_ids = set()
    for row in joins:
        require(row["circuit"] == circuit and row["role"] == role and row["family"] == family,
                "JOIN_MEMBERSHIP")
        attempt_id = row["attempt_id"].strip()
        if attempt_id:
            require(attempt_id in attempt_ids, "JOIN_FOREIGN_ATTEMPT")
            join_attempt_ids.add(attempt_id)

    retry_status = count_values(attempts, "retry_order_status")
    timeout_status = count_values(attempts, "timeout_status")
    outcomes = count_values(attempts, "attempt_outcome_class")
    retry_order_unknown = sum(count for value, count in retry_status.items()
                              if value != "KNOWN_ORDER")
    retry_order_invalid = 0
    for row in attempts:
        raw = row["retry_order"].strip()
        if not raw.isdigit() or int(raw) < 1:
            retry_order_invalid += 1
    timeout_unknown = sum(count for value, count in timeout_status.items()
                          if value.upper() not in KNOWN_TIMEOUT)
    outcome_unknown = sum(count for value, count in outcomes.items()
                          if value.upper() not in KNOWN_OUTCOME)
    duplicate_groups = sum(1 for count in retry_groups.values() if count > 1)
    max_group = max(retry_groups.values())
    blockers = []
    if retry_order_unknown:
        blockers.append("UNKNOWN_RETRY_ORDER")
    if retry_order_invalid:
        blockers.append("INVALID_RETRY_ORDER")
    if timeout_unknown:
        blockers.append("UNKNOWN_TIMEOUT_STATUS")
    if outcome_unknown:
        blockers.append("UNKNOWN_ATTEMPT_OUTCOME")
    if attempt_ids - join_attempt_ids:
        blockers.append("ATTEMPTS_NOT_REFERENCED_BY_CURRENT_JOIN")
    return {
        "circuit": circuit,
        "family": family,
        "role": role,
        "attempt_manifest_sha256": item["attempt_manifest"]["sha256"],
        "join_sha256": item["join"]["sha256"],
        "attempt_count": len(attempts),
        "join_row_count": len(joins),
        "joined_unique_attempt_count": len(join_attempt_ids),
        "attempts_not_referenced_by_current_join": len(attempt_ids - join_attempt_ids),
        "retry_order_status_counts": retry_status,
        "invalid_retry_order_count": retry_order_invalid,
        "timeout_status_counts": timeout_status,
        "unknown_timeout_status_count": timeout_unknown,
        "attempt_outcome_class_counts": outcomes,
        "unknown_attempt_outcome_count": outcome_unknown,
        "retry_group_count": len(retry_groups),
        "multi_attempt_retry_group_count": duplicate_groups,
        "max_retry_group_size": max_group,
        "blockers": blockers,
    }


def run(contract_path, bindings_path):
    contract, contract_bytes = load_json(contract_path, "CONTRACT")
    validate_contract(contract)
    bindings, bindings_bytes = load_json(bindings_path, "BINDINGS")
    bound = validate_bindings(bindings, contract["required_roster"])
    circuits = [audit_one(bound[item["circuit"]]) for item in contract["required_roster"]]
    blockers = sorted(set(code for item in circuits for code in item["blockers"]))
    status = (contract["pass_status"] if not blockers else contract["blocked_status"])
    totals = {
        "attempt_count": sum(item["attempt_count"] for item in circuits),
        "join_row_count": sum(item["join_row_count"] for item in circuits),
        "joined_unique_attempt_count": sum(item["joined_unique_attempt_count"] for item in circuits),
        "attempts_not_referenced_by_current_join": sum(
            item["attempts_not_referenced_by_current_join"] for item in circuits),
        "unknown_retry_order_count": sum(
            sum(count for value, count in item["retry_order_status_counts"].items()
                if value != "KNOWN_ORDER") for item in circuits),
        "invalid_retry_order_count": sum(item["invalid_retry_order_count"] for item in circuits),
        "unknown_timeout_status_count": sum(item["unknown_timeout_status_count"] for item in circuits),
        "unknown_attempt_outcome_count": sum(item["unknown_attempt_outcome_count"] for item in circuits),
        "multi_attempt_retry_group_count": sum(
            item["multi_attempt_retry_group_count"] for item in circuits),
    }
    return {
        "schema_version": "runtime-training-source-readiness-receipt-v1",
        "status": status,
        "contract_sha256": hashlib.sha256(contract_bytes).hexdigest(),
        "bindings_sha256": hashlib.sha256(bindings_bytes).hexdigest(),
        "circuits": circuits,
        "totals": totals,
        "blockers": blockers,
        "boundaries": {
            "training_execution_allowed": False,
            "package_release_allowed": False,
            "blind_rows_read": False,
            "lsf_or_tessent_submitted": False,
            "remote_access_performed": False,
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", required=True)
    parser.add_argument("--bindings", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        receipt = run(os.path.abspath(args.contract), os.path.abspath(args.bindings))
        payload = canonical_json(receipt)
        parent = os.path.dirname(os.path.abspath(args.output))
        if parent and not os.path.isdir(parent):
            os.makedirs(parent)
        with open(args.output, "wb") as stream:
            stream.write(payload)
        print("status=%s circuits=%d attempts=%d" % (
            receipt["status"], len(receipt["circuits"]), receipt["totals"]["attempt_count"]))
        return 0 if not receipt["blockers"] else 2
    except (AuditError, OSError, ValueError) as exc:
        print("AUDIT_ERROR: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
