#!/usr/bin/env python3
"""Session-aware, fail-closed remediation of non-BLIND runtime attempts."""
from __future__ import print_function

import argparse
import csv
import datetime
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
USER_RE = re.compile(r"^\s*User time \(seconds\):\s*(\S+)", re.M)
SYSTEM_RE = re.compile(r"^\s*System time \(seconds\):\s*(\S+)", re.M)
RSS_RE = re.compile(r"^\s*Maximum resident set size \(kbytes\):\s*(\S+)", re.M)
STATUS_RE = re.compile(r"^MAPPED_(?:COMMON|INCREMENTAL)_ATPG_STATUS=(\S+)", re.M)
START_RE = re.compile(r"^//\s+Siemens software executing .*? on (.+?)\.\s*$", re.M)
TIMEOUT_RE = re.compile(r"(?:^|\n)(?:TIMEOUT|TIMED_OUT|KILLED_FOR_TIMEOUT)(?:\b|=)", re.I)
NON_TIMEOUT_ERRORS = (
    re.compile(r"(?:^|\n)ERROR: refusing to overwrite(?:\s|$)", re.I),
    re.compile(r"(?:^|\n)//\s+Error: Incorrect argument(?:\s|$)", re.I),
    re.compile(r"(?:^|\n)//\s+Error: Unable to open \(or close\) file(?:\s|$)", re.I),
)
GLOB_RE = re.compile(r"[*?\[\]]")


class RemediationError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise RemediationError(code)


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


def read_json(path, label):
    data = read_regular_bytes(path, label)
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, TypeError, ValueError):
        raise RemediationError(label + "_INVALID_JSON")
    require(isinstance(value, dict), label + "_NOT_OBJECT")
    return value


def read_manifest(path):
    data = read_regular_bytes(path, "MANIFEST")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise RemediationError("MANIFEST_INVALID_UTF8")
    reader = csv.DictReader(text.splitlines(), delimiter="\t")
    require(tuple(reader.fieldnames or ()) == tuple(MANIFEST_V2_FIELDS), "MANIFEST_FIELDS")
    rows = list(reader)
    require(rows, "MANIFEST_EMPTY")
    return rows, sha256_bytes(data)


def parse_wall(raw):
    parts = raw.split(":")
    try:
        if len(parts) == 2:
            value = float(parts[0]) * 60.0 + float(parts[1])
        elif len(parts) == 3:
            value = float(parts[0]) * 3600.0 + float(parts[1]) * 60.0 + float(parts[2])
        else:
            raise ValueError
    except ValueError:
        raise RemediationError("ELAPSED_INVALID")
    require(value > 0, "ELAPSED_INVALID")
    return "%.3f" % value


def one(pattern, text, label, required=False):
    values = pattern.findall(text)
    require(len(values) <= 1, label + "_MULTIPLE")
    if required:
        require(len(values) == 1, label + "_MISSING")
    return values[0] if values else ""


def timestamp_key(raw):
    if not raw:
        return None
    normalized = re.sub(r"\s+[A-Z]{2,5}\s+(\d{4})$", r" \1", raw)
    try:
        return datetime.datetime.strptime(normalized, "%a %b %d %H:%M:%S %Y")
    except ValueError:
        raise RemediationError("EMBEDDED_START_INVALID")


def split_sessions(data):
    text = data.decode("utf-8", "replace")
    exits = list(EXIT_RE.finditer(text))
    require(exits, "EXIT_FOOTER_MISSING")
    sessions = []
    start = 0
    for index, match in enumerate(exits, 1):
        segment = text[start:match.end()]
        start = match.end()
        elapsed = one(ELAPSED_RE, segment, "ELAPSED", required=True)
        exit_status = match.group(1)
        status = one(STATUS_RE, segment, "ATPG_STATUS")
        embedded = one(START_RE, segment, "EMBEDDED_START")
        timeout = bool(TIMEOUT_RE.search(segment))
        deterministic_error = any(pattern.search(segment) for pattern in NON_TIMEOUT_ERRORS)
        if timeout:
            timeout_status, outcome, parse_status = "TIMEOUT", "TIMEOUT", "TIMEOUT"
        elif status.upper() == "PASS" and exit_status == "0":
            timeout_status, outcome, parse_status = "NO_TIMEOUT", "SUCCESS", "PASS"
        elif status and status.upper() != "PASS":
            timeout_status, outcome, parse_status = "NOT_TIMEOUT", "FAILURE", "ATPG_STATUS_FAIL"
        elif exit_status != "0" and deterministic_error:
            timeout_status, outcome, parse_status = "NOT_TIMEOUT", "FAILURE", "NONZERO_EXIT"
        else:
            raise RemediationError("SESSION_OUTCOME_UNRESOLVED_%d" % index)
        sessions.append({
            "session_index": index,
            "wall_s": parse_wall(elapsed),
            "user_s": one(USER_RE, segment, "USER"),
            "system_s": one(SYSTEM_RE, segment, "SYSTEM"),
            "rss_kb": one(RSS_RE, segment, "RSS"),
            "exit_status": exit_status,
            "atpg_status": status,
            "timeout_status": timeout_status,
            "attempt_outcome_class": outcome,
            "parse_status": parse_status,
            "embedded_start": embedded,
            "start_key": timestamp_key(embedded),
            "order_evidence": "",
        })
    require(not text[start:].strip(), "TRAILING_CONTENT_AFTER_LAST_EXIT")
    return sessions


def resolve_log(roots, relative, expected_sha, circuit, attempt_id):
    matches = []
    for root in roots:
        try:
            path = bound_path(root, relative)
        except RemediationError as exc:
            if str(exc) == "SOURCE_PATH_MISSING":
                continue
            raise RemediationError("%s:%s:%s" % (exc, circuit, attempt_id))
        data = read_regular_bytes(path, "SOURCE_LOG")
        if sha256_bytes(data) == expected_sha:
            matches.append(data)
    require(len(matches) == 1, "SOURCE_BINDING_MATCH_COUNT_%d:%s:%s" %
            (len(matches), circuit, attempt_id))
    return matches[0]


def remediate(bindings):
    require(bindings.get("schema_version") == "runtime-attempt-remediation-bindings-v2",
            "BINDINGS_SCHEMA")
    items = bindings.get("circuits")
    require(isinstance(items, list) and len(items) == 8, "BINDINGS_CIRCUITS")
    allowed = {"s13207", "s15850", "s35932", "s38417", "aes_core", "spi", "s5378", "tv80"}
    outputs = {}
    aggregate = []
    observed = set()
    for item in items:
        require(isinstance(item, dict) and set(item) == {
            "circuit", "role", "family", "manifest", "evidence_roots"
        }, "BINDING_FIELDS")
        circuit = item["circuit"]
        require(circuit in allowed and circuit not in observed, "BINDING_ROSTER")
        observed.add(circuit)
        roots = [validate_root(value) for value in item["evidence_roots"]]
        require(roots and len(roots) == len(set(roots)), "EVIDENCE_ROOTS_INVALID")
        parents, manifest_sha = read_manifest(item["manifest"])
        entries = []
        lineage = []
        parent_ids = set()
        for parent in parents:
            require(parent["circuit"] == circuit and parent["role"] == item["role"] and
                    parent["family"] == item["family"], "MANIFEST_MEMBERSHIP")
            parent_id = parent["attempt_id"].strip()
            require(parent_id and parent_id not in parent_ids, "PARENT_ATTEMPT_ID_NOT_UNIQUE")
            parent_ids.add(parent_id)
            expected_sha = parent["source_log_sha256"].strip()
            require(SHA256_RE.match(expected_sha) is not None, "SOURCE_SHA_FORMAT")
            data = resolve_log(roots, parent["source_log_path"].strip(), expected_sha,
                               circuit, parent_id)
            sessions = split_sessions(data)
            for session in sessions:
                row = dict(parent)
                terminal = session["session_index"] == len(sessions)
                if len(sessions) == 1 or terminal:
                    attempt_id = parent_id
                else:
                    identity = "%s|%d|%s" % (parent_id, session["session_index"], expected_sha)
                    attempt_id = "attempt_" + hashlib.sha256(
                        identity.encode("utf-8")).hexdigest()[:20]
                row.update({
                    "attempt_id": attempt_id,
                    "wall_s": session["wall_s"],
                    "user_s": session["user_s"],
                    "system_s": session["system_s"],
                    "rss_kb": session["rss_kb"],
                    "exit_status": session["exit_status"],
                    "atpg_status": session["atpg_status"],
                    "timeout_status": session["timeout_status"],
                    "parse_status": session["parse_status"],
                    "attempt_outcome_class": session["attempt_outcome_class"],
                    "source_row_number": ("session:%d" % session["session_index"]
                                          if len(sessions) > 1 else parent["source_row_number"]),
                })
                entries.append({"row": row, "parent_id": parent_id,
                                "session_index": session["session_index"],
                                "session_count": len(sessions),
                                "source_sha": expected_sha,
                                "start_key": session["start_key"],
                                "order_evidence": session["order_evidence"]})
        groups = {}
        for entry in entries:
            groups.setdefault(entry["row"]["retry_group_id"], []).append(entry)
        for group_id, group in groups.items():
            if len(group) == 1:
                ordered = group
                evidence = "STRUCTURAL_SINGLETON"
            elif len({entry["source_sha"] for entry in group}) == 1:
                require(len({entry["session_index"] for entry in group}) == len(group),
                        "SAME_FILE_SESSION_ORDER_AMBIGUOUS")
                ordered = sorted(group, key=lambda entry: entry["session_index"])
                evidence = "GNU_TIME_FOOTER_EMISSION_ORDER"
            else:
                require(all(entry["start_key"] is not None for entry in group),
                        "EMBEDDED_START_MISSING_FOR_MULTI_FILE_GROUP")
                require(len({entry["start_key"] for entry in group}) == len(group),
                        "EMBEDDED_START_TIED_FOR_MULTI_FILE_GROUP")
                ordered = sorted(group, key=lambda entry: entry["start_key"])
                evidence = "EMBEDDED_SIEMENS_START_ORDER"
            for order, entry in enumerate(ordered, 1):
                entry["row"]["retry_order"] = str(order)
                entry["row"]["retry_order_status"] = "KNOWN_ORDER"
                lineage.append({
                    "circuit": circuit,
                    "parent_attempt_id": entry["parent_id"],
                    "attempt_id": entry["row"]["attempt_id"],
                    "retry_group_id": group_id,
                    "retry_order": str(order),
                    "order_evidence": evidence,
                    "session_index": str(entry["session_index"]),
                    "session_count": str(entry["session_count"]),
                    "attempt_outcome_class": entry["row"]["attempt_outcome_class"],
                    "timeout_status": entry["row"]["timeout_status"],
                })
        rows = [entry["row"] for entry in entries]
        require(len({row["attempt_id"] for row in rows}) == len(rows),
                "REMEDIATED_ATTEMPT_ID_NOT_UNIQUE")
        rows.sort(key=lambda row: (row["retry_group_id"], int(row["retry_order"]), row["attempt_id"]))
        lineage.sort(key=lambda row: (row["retry_group_id"], int(row["retry_order"]), row["attempt_id"]))
        outputs[circuit] = {"rows": rows, "lineage": lineage}
        outcomes = {}
        for row in rows:
            value = row["attempt_outcome_class"]
            outcomes[value] = outcomes.get(value, 0) + 1
        aggregate.append({
            "circuit": circuit,
            "role": item["role"],
            "family": item["family"],
            "input_manifest_sha256": manifest_sha,
            "input_log_count": len(parents),
            "output_attempt_count": len(rows),
            "split_session_count": len(rows) - len(parents),
            "retry_group_count": len(groups),
            "multi_attempt_retry_group_count": sum(len(group) > 1 for group in groups.values()),
            "max_retry_group_size": max(len(group) for group in groups.values()),
            "outcome_counts": dict(sorted(outcomes.items())),
            "unknown_retry_order_count": sum(row["retry_order_status"] != "KNOWN_ORDER" for row in rows),
            "unknown_timeout_status_count": sum(row["timeout_status"] not in
                                                ("NO_TIMEOUT", "NOT_TIMEOUT", "TIMEOUT")
                                                for row in rows),
        })
    require(observed == allowed, "BINDING_ROSTER")
    return outputs, aggregate


LINEAGE_FIELDS = (
    "circuit", "parent_attempt_id", "attempt_id", "retry_group_id", "retry_order",
    "order_evidence", "session_index", "session_count", "attempt_outcome_class",
    "timeout_status",
)


def write_tsv(path, fields, rows):
    with open(path, "w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows({key: row.get(key, "") for key in fields} for row in rows)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--bindings", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)
    try:
        bindings = read_json(args.bindings, "BINDINGS")
        require(not os.path.exists(args.output_dir), "OUTPUT_DIR_MUST_NOT_EXIST")
        outputs, aggregate = remediate(bindings)
        os.mkdir(args.output_dir)
        file_hashes = {}
        for circuit, payload in sorted(outputs.items()):
            manifest_name = circuit + "_attempt_manifest_v2_remediated.tsv"
            lineage_name = circuit + "_lineage_v2.tsv"
            manifest_path = os.path.join(args.output_dir, manifest_name)
            lineage_path = os.path.join(args.output_dir, lineage_name)
            write_tsv(manifest_path, MANIFEST_V2_FIELDS, payload["rows"])
            write_tsv(lineage_path, LINEAGE_FIELDS, payload["lineage"])
            file_hashes[manifest_name] = sha256_bytes(read_regular_bytes(manifest_path, "OUTPUT"))
            file_hashes[lineage_name] = sha256_bytes(read_regular_bytes(lineage_path, "OUTPUT"))
        receipt = {
            "schema_version": "runtime-attempt-remediation-receipt-v2",
            "status": "PASS_REMEDIATED_ATTEMPTS_TRAINING_STILL_BLOCKED",
            "circuits": aggregate,
            "totals": {
                "input_log_count": sum(item["input_log_count"] for item in aggregate),
                "output_attempt_count": sum(item["output_attempt_count"] for item in aggregate),
                "split_session_count": sum(item["split_session_count"] for item in aggregate),
                "success_count": sum(item["outcome_counts"].get("SUCCESS", 0) for item in aggregate),
                "failure_count": sum(item["outcome_counts"].get("FAILURE", 0) for item in aggregate),
                "timeout_count": sum(item["outcome_counts"].get("TIMEOUT", 0) for item in aggregate),
                "unknown_retry_order_count": sum(item["unknown_retry_order_count"] for item in aggregate),
                "unknown_timeout_status_count": sum(item["unknown_timeout_status_count"] for item in aggregate),
            },
            "files": file_hashes,
            "boundaries": {"blind_rows_read": False, "source_mutated": False,
                           "lsf_or_tessent_submitted": False, "training_allowed": False},
        }
        receipt_path = os.path.join(args.output_dir, "receipt_v2.json")
        with open(receipt_path, "w", encoding="utf-8") as stream:
            json.dump(receipt, stream, indent=2, sort_keys=True)
            stream.write("\n")
        print(json.dumps(receipt, sort_keys=True))
        return 0
    except (RemediationError, OSError) as exc:
        print("FAIL:%s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
