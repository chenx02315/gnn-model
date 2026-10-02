#!/usr/bin/env python3
"""Read-only audit of runtime driver-log session structure.

The input manifests remain authoritative for file identity only.  This audit
does not rewrite attempts or infer outcomes.  It verifies each source digest
and records whether a log contains multiple GNU-time footers, both legacy
status-marker dialects, explicit timeout/error markers, and embedded Tessent
start timestamps.
"""
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
ELAPSED_RE = re.compile(r"^\s*Elapsed \(wall clock\) time \(h:mm:ss or m:ss\):\s*(\S+)", re.M)
EXIT_RE = re.compile(r"^\s*Exit status:\s*(\S+)", re.M)
COMMON_STATUS_RE = re.compile(r"^MAPPED_COMMON_ATPG_STATUS=(\S+)", re.M)
INCREMENTAL_STATUS_RE = re.compile(r"^MAPPED_INCREMENTAL_ATPG_STATUS=(\S+)", re.M)
START_RE = re.compile(r"^//\s+Siemens software executing .*? on (.+?)\.\s*$", re.M)
TIMEOUT_RE = re.compile(r"(?:^|\n)(?:TIMEOUT|TIMED_OUT|KILLED_FOR_TIMEOUT)(?:\b|=)", re.I)
ERROR_RE = re.compile(r"(?:^|\n)(?:ERROR:|//\s+(?:Error|Fatal):|Command exited with non-zero status)", re.I)
GLOB_RE = re.compile(r"[*?\[\]]")


class AuditError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise AuditError(code)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


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


def is_reparse(path):
    info = os.stat(path, follow_symlinks=False)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(info, "st_file_attributes", 0)
    return os.path.islink(path) or bool(flag and attributes & flag)


def validate_root(root):
    require(isinstance(root, str) and root and os.path.isabs(root), "ROOT_NOT_ABSOLUTE")
    require(not root.replace("\\", "/").startswith("//"), "REMOTE_ROOT_FORBIDDEN")
    require(not GLOB_RE.search(root), "ROOT_GLOB_FORBIDDEN")
    absolute = os.path.abspath(root)
    require(os.path.isdir(absolute), "ROOT_MISSING")
    drive, tail = os.path.splitdrive(absolute)
    cursor = drive + os.sep if drive else os.sep
    for component in [item for item in tail.split(os.sep) if item]:
        cursor = os.path.join(cursor, component)
        require(not is_reparse(cursor), "ROOT_REPARSE_FORBIDDEN")
    return absolute


def bound_path(root, relative):
    require(isinstance(relative, str) and relative and not os.path.isabs(relative),
            "SOURCE_PATH_NOT_RELATIVE")
    require(not GLOB_RE.search(relative), "SOURCE_PATH_GLOB_FORBIDDEN")
    normalized = os.path.normpath(relative)
    require(normalized not in ("", ".", "..") and
            not normalized.startswith(".." + os.sep), "SOURCE_PATH_ESCAPE")
    candidate = os.path.abspath(os.path.join(root, normalized))
    try:
        inside = os.path.commonpath((root, candidate)) == root
    except ValueError:
        inside = False
    require(inside, "SOURCE_PATH_ESCAPE")
    cursor = root
    for component in normalized.split(os.sep):
        cursor = os.path.join(cursor, component)
        require(os.path.exists(cursor), "SOURCE_PATH_MISSING")
        require(not is_reparse(cursor), "SOURCE_PATH_REPARSE_FORBIDDEN")
    return candidate


def read_manifest(path):
    data = read_regular_bytes(path, "MANIFEST")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise AuditError("MANIFEST_INVALID_UTF8")
    reader = csv.DictReader(text.splitlines(), delimiter="\t")
    require(tuple(reader.fieldnames or ()) == tuple(MANIFEST_V2_FIELDS), "MANIFEST_FIELDS")
    rows = list(reader)
    require(rows, "MANIFEST_EMPTY")
    return rows, sha256_bytes(data)


def inspect_log(data):
    text = data.decode("utf-8", "replace")
    elapsed = ELAPSED_RE.findall(text)
    exits = EXIT_RE.findall(text)
    common = COMMON_STATUS_RE.findall(text)
    incremental = INCREMENTAL_STATUS_RE.findall(text)
    starts = START_RE.findall(text)
    return {
        "elapsed_footer_count": len(elapsed),
        "exit_footer_count": len(exits),
        "common_status_count": len(common),
        "incremental_status_count": len(incremental),
        "pass_marker_count": sum(value.upper() == "PASS" for value in common + incremental),
        "nonpass_status_count": sum(value.upper() != "PASS" for value in common + incremental),
        "embedded_start_count": len(starts),
        "timeout_marker_count": len(TIMEOUT_RE.findall(text)),
        "error_marker_count": len(ERROR_RE.findall(text)),
        "first_embedded_start": starts[0] if starts else "",
    }


def add_counts(target, evidence):
    for key in (
            "elapsed_footer_count", "exit_footer_count", "common_status_count",
            "incremental_status_count", "pass_marker_count", "nonpass_status_count",
            "embedded_start_count", "timeout_marker_count", "error_marker_count"):
        target[key] = target.get(key, 0) + evidence[key]


def audit(bindings):
    require(bindings.get("schema_version") == "runtime-attempt-session-bindings-v1",
            "BINDINGS_SCHEMA")
    items = bindings.get("circuits")
    require(isinstance(items, list) and len(items) == 8, "BINDINGS_CIRCUITS")
    allowed = {"s13207", "s15850", "s35932", "s38417", "aes_core", "spi", "s5378", "tv80"}
    observed = set()
    details = []
    circuits = []
    for item in items:
        require(isinstance(item, dict) and set(item) == {
            "circuit", "role", "family", "manifest", "evidence_roots"
        }, "BINDING_FIELDS")
        circuit = item.get("circuit")
        require(circuit in allowed and circuit not in observed, "BINDING_ROSTER")
        require(item.get("role") in ("TRAIN", "VALIDATION"), "BINDING_ROLE")
        observed.add(circuit)
        raw_roots = item.get("evidence_roots")
        require(isinstance(raw_roots, list) and raw_roots, "EVIDENCE_ROOTS_EMPTY")
        roots = [validate_root(value) for value in raw_roots]
        require(len(roots) == len(set(roots)), "EVIDENCE_ROOTS_DUPLICATE")
        manifest_path = item.get("manifest")
        require(isinstance(manifest_path, str) and os.path.isabs(manifest_path),
                "MANIFEST_PATH_NOT_ABSOLUTE")
        rows, manifest_sha = read_manifest(manifest_path)
        attempt_ids = set()
        groups = {}
        totals = {"log_count": 0, "hash_verified_count": 0,
                  "multi_elapsed_log_count": 0, "multi_exit_log_count": 0,
                  "no_explicit_status_log_count": 0,
                  "elapsed_exit_count_mismatch_log_count": 0}
        for row in rows:
            require(row.get("circuit") == circuit and row.get("role") == item["role"] and
                    row.get("family") == item["family"], "MANIFEST_MEMBERSHIP")
            attempt_id = (row.get("attempt_id") or "").strip()
            require(attempt_id and attempt_id not in attempt_ids, "ATTEMPT_ID_NOT_UNIQUE")
            attempt_ids.add(attempt_id)
            relative = (row.get("source_log_path") or "").strip()
            expected_sha = (row.get("source_log_sha256") or "").strip()
            require(SHA256_RE.match(expected_sha) is not None, "SOURCE_SHA_FORMAT")
            matches = []
            for root in roots:
                try:
                    path = bound_path(root, relative)
                except AuditError as exc:
                    if str(exc) == "SOURCE_PATH_MISSING":
                        continue
                    raise AuditError("%s:%s:%s" % (exc, circuit, attempt_id))
                data = read_regular_bytes(path, "SOURCE_LOG")
                if sha256_bytes(data) == expected_sha:
                    matches.append((path, data))
            require(len(matches) == 1,
                    "SOURCE_BINDING_MATCH_COUNT_%d:%s:%s" %
                    (len(matches), circuit, attempt_id))
            _path, data = matches[0]
            evidence = inspect_log(data)
            totals["log_count"] += 1
            totals["hash_verified_count"] += 1
            add_counts(totals, evidence)
            if evidence["elapsed_footer_count"] > 1:
                totals["multi_elapsed_log_count"] += 1
            if evidence["exit_footer_count"] > 1:
                totals["multi_exit_log_count"] += 1
            if evidence["common_status_count"] + evidence["incremental_status_count"] == 0:
                totals["no_explicit_status_log_count"] += 1
            if evidence["elapsed_footer_count"] != evidence["exit_footer_count"]:
                totals["elapsed_exit_count_mismatch_log_count"] += 1
            retry_group = (row.get("retry_group_id") or "").strip()
            require(retry_group, "RETRY_GROUP_MISSING")
            groups[retry_group] = groups.get(retry_group, 0) + evidence["elapsed_footer_count"]
            detail = {
                "circuit": circuit,
                "attempt_id": attempt_id,
                "retry_group_id": retry_group,
                "source_log_path": relative,
                "source_log_sha256": expected_sha,
            }
            detail.update(evidence)
            details.append(detail)
        totals["manifest_sha256"] = manifest_sha
        totals["manifest_row_count"] = len(rows)
        totals["effective_session_count"] = totals.get("elapsed_footer_count", 0)
        totals["multi_session_retry_group_count"] = sum(1 for value in groups.values() if value > 1)
        totals["max_sessions_per_retry_group"] = max(groups.values())
        totals["all_hashes_verified"] = totals["hash_verified_count"] == totals["log_count"]
        circuits.append({"circuit": circuit, "role": item["role"], "family": item["family"],
                         "counts": totals})
    require(observed == allowed, "BINDING_ROSTER")
    aggregate = {
        "schema_version": "runtime-attempt-session-audit-receipt-v1",
        "status": "PASS_READ_ONLY_INVENTORY",
        "circuits": circuits,
        "totals": {
            "manifest_row_count": sum(item["counts"]["manifest_row_count"] for item in circuits),
            "effective_session_count": sum(item["counts"]["effective_session_count"] for item in circuits),
            "multi_elapsed_log_count": sum(item["counts"]["multi_elapsed_log_count"] for item in circuits),
            "multi_exit_log_count": sum(item["counts"]["multi_exit_log_count"] for item in circuits),
            "no_explicit_status_log_count": sum(item["counts"]["no_explicit_status_log_count"] for item in circuits),
            "incremental_status_count": sum(item["counts"].get("incremental_status_count", 0) for item in circuits),
            "common_status_count": sum(item["counts"].get("common_status_count", 0) for item in circuits),
            "timeout_marker_count": sum(item["counts"].get("timeout_marker_count", 0) for item in circuits),
            "error_marker_count": sum(item["counts"].get("error_marker_count", 0) for item in circuits),
        },
        "boundaries": {"blind_rows_read": False, "source_mutated": False,
                       "lsf_or_tessent_submitted": False, "training_allowed": False},
    }
    return aggregate, details


DETAIL_FIELDS = (
    "circuit", "attempt_id", "retry_group_id", "source_log_path", "source_log_sha256",
    "elapsed_footer_count", "exit_footer_count", "common_status_count",
    "incremental_status_count", "pass_marker_count", "nonpass_status_count",
    "embedded_start_count", "timeout_marker_count", "error_marker_count",
    "first_embedded_start",
)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--bindings", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--details", required=True)
    args = parser.parse_args(argv)
    try:
        bindings, _raw = load_json(args.bindings, "BINDINGS")
        receipt, details = audit(bindings)
        with open(args.details, "w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=DETAIL_FIELDS, delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerows({key: row.get(key, "") for key in DETAIL_FIELDS} for row in details)
        receipt["detailed_evidence_sha256"] = hashlib.sha256(
            read_regular_bytes(args.details, "DETAILS")).hexdigest()
        with open(args.receipt, "w", encoding="utf-8") as stream:
            json.dump(receipt, stream, indent=2, sort_keys=True)
            stream.write("\n")
    except (AuditError, OSError) as exc:
        print("FAIL:%s" % exc, file=sys.stderr)
        return 2
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
