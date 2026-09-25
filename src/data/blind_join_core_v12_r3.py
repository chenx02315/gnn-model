#!/usr/bin/env python3
"""Pure, in-memory BLIND runtime join core for v12-r3.

This module never opens files and never serializes row-level BLIND data.  The
caller supplies immutable byte snapshots obtained by the descriptor-only
reader.  Only aggregate gate evidence is returned.
"""
from __future__ import print_function

import csv
import hashlib
import io
import re


LAYOUTS = (
    ("01_single_boundaries/measurements.tsv", "01_single_boundaries", "single"),
    ("02_hf_coarse/measurements.tsv", "02_hf_coarse", "hf"),
    ("03_hmf_coarse/measurements.tsv", "03_hmf_coarse", "hmf"),
    ("04_integer_refine/hf_measurements.tsv", "04_integer_refine", "hf"),
    ("04_integer_refine/hmf_measurements.tsv", "04_integer_refine", "hmf"),
    ("05_repeatability/measurements.tsv", "05_repeatability", "repeatability"),
)
FORMAL_STAGES = frozenset(("02_hf_coarse", "03_hmf_coarse", "04_integer_refine"))
MARKERS = {
    "run_id": re.compile(r"^MAPPED_COMMON_ATPG_RUN_ID=(.+)$", re.M),
    "mode": re.compile(r"^MAPPED_COMMON_ATPG_MODE=(.+)$", re.M),
    "atpg_status": re.compile(r"^MAPPED_COMMON_ATPG_STATUS=(.+)$", re.M),
    "elapsed": re.compile(r"^\s*Elapsed \(wall clock\) time \(h:mm:ss or m:ss\):\s*(\S+)", re.M),
    "exit_status": re.compile(r"^\s*Exit status:\s*(\S+)", re.M),
}
TIMEOUT = re.compile(r"(?:^|\n)(?:TIMEOUT|TIMED_OUT|KILLED_FOR_TIMEOUT)(?:\b|=)", re.I)
CANONICAL_COUNT = re.compile(r"^(?:0|[1-9][0-9]*)$")


class JoinFailure(Exception):
    def __init__(self, stage, code):
        super(JoinFailure, self).__init__(stage + ":" + code)
        self.stage = stage
        self.code = code


def _value(row, key):
    return (row.get(key) or "").strip()


def _basename(path):
    name = (path or "").replace("\\", "/").rstrip("/").split("/")[-1]
    for suffix in (".driver.log", ".log", ".tsv", ".csv"):
        if name.endswith(suffix):
            return name[:-len(suffix)]
    return name


def _source_state(row):
    return _value(row, "result_status") or _value(row, "status")


def _source_rows(kind, row):
    if kind == "single":
        return [(_value(row, "mode"), _value(row, "result_directory") or _value(row, "result"))]
    if kind == "repeatability":
        modes = {"FullScan-F4": ("F",), "ComScan-H64": ("H",),
                 "H64-F4": ("H", "F"), "H64-M16-F4": ("H", "M", "F")}.get(_value(row, "scheme"), ())
        return [(mode, "") for mode in modes]
    modes = ("H", "F") if kind == "hf" else ("H", "M", "F")
    return [(mode, _value(row, mode.lower() + "_result")) for mode in modes]


def _is_not_run(row, mode, marker):
    state = _source_state(row)
    if "TARGET_BEFORE_F" in state or "INFEASIBLE_AT_D95" in state:
        return mode == "F"
    return not marker and ("NOT_RUN" in state or "PRUNED_OR_UNREACHED" in state)


def canonical_action_uid(circuit, kind, row):
    if kind not in ("hf", "hmf"):
        return ""
    h = _value(row, "h_patterns")
    m = _value(row, "m_patterns") if kind == "hmf" else ""
    if not CANONICAL_COUNT.match(h) or (kind == "hmf" and not CANONICAL_COUNT.match(m)):
        raise JoinFailure("MEASUREMENT_PARSE", "MEASUREMENT_SCHEMA_FAILURE")
    return "%s:%s:h%s%s" % (circuit, "HF" if kind == "hf" else "HMF", h,
                              (":m" + m) if kind == "hmf" else "")


def _wall_seconds(text):
    try:
        parts = text.split(":")
        if len(parts) == 2:
            return "%.3f" % (float(parts[0]) * 60 + float(parts[1]))
        if len(parts) == 3:
            return "%.3f" % (float(parts[0]) * 3600 + float(parts[1]) * 60 + float(parts[2]))
    except (TypeError, ValueError):
        pass
    return ""


def _parse_log(relative, payload, digest):
    text = payload.decode("utf-8", "replace")
    found = {}
    for key, pattern in MARKERS.items():
        match = pattern.search(text)
        found[key] = match.group(1).strip() if match else ""
    filename = relative.split("/")[-1]
    run_id = found["run_id"] or (filename[:-11] if filename.endswith(".driver.log") else filename)
    mode = found["mode"] or (run_id[0] if run_id[:2] in ("H_", "M_", "F_") else "")
    stage = relative.split("/")[-2] if "/" in relative else ""
    identity = "|".join((digest, relative, run_id))
    return {
        "attempt_id": "attempt_" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20],
        "run_id": run_id,
        "mode": mode,
        "stage": stage,
        "source_marker": _basename(relative),
        "source_digest": digest,
        "wall_s": _wall_seconds(found["elapsed"]),
        "exit_status": found["exit_status"],
        "atpg_status": found["atpg_status"],
        "timed_out": bool(TIMEOUT.search(text)),
    }


def _decode_table(payload):
    try:
        text = payload.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise JoinFailure("MEASUREMENT_PARSE", "MEASUREMENT_SCHEMA_FAILURE")
    try:
        return list(csv.DictReader(io.StringIO(text, newline=""), delimiter="\t"))
    except (csv.Error, TypeError):
        raise JoinFailure("MEASUREMENT_PARSE", "MEASUREMENT_SCHEMA_FAILURE")


def _sha_lines(lines):
    payload = "".join(item + "\n" for item in sorted(set(lines)))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def audit_circuit(circuit, log_snapshots, measurement_snapshots):
    """Return aggregate R06/R07 evidence; never return row-level values."""
    attempts = [_parse_log(relative, payload, digest)
                for relative, (digest, payload) in sorted(log_snapshots.items())]
    if len(attempts) != len(set(item["attempt_id"] for item in attempts)):
        raise JoinFailure("ATTEMPT_PARSE", "ATTEMPT_INTEGRITY_FAILURE")
    by_source, by_run = {}, {}
    for item in attempts:
        by_source.setdefault((item["mode"], item["source_marker"]), []).append(item)
        by_run.setdefault((item["mode"], item["run_id"]), []).append(item)

    refs, actions, action_refs, matched, artifacts = [], [], {}, [], []
    cross_stage = 0
    for relative, stage, kind in LAYOUTS:
        if relative not in measurement_snapshots:
            raise JoinFailure("SOURCE_INVENTORY", "INPUT_INVENTORY_DRIFT")
        digest, payload = measurement_snapshots[relative]
        artifacts.append(relative + ":" + digest)
        for row in _decode_table(payload):
            action = canonical_action_uid(circuit, kind, row)
            if action:
                actions.append(action)
            for mode, result in _source_rows(kind, row):
                marker = _basename(result)
                matches = []
                if kind != "repeatability" and _is_not_run(row, mode, marker):
                    status = "NOT_RUN"
                elif not marker:
                    status = "NO_RESULT_PATH" if kind == "repeatability" else "MISSING_RESULT_PATH"
                else:
                    matches = by_source.get((mode, marker), []) or by_run.get((mode, marker), [])
                    if len(matches) == 1 and matches[0]["wall_s"]:
                        status = "UNIQUE"
                    elif len(matches) == 1:
                        status = "MISSING_RUNTIME"
                    elif not matches:
                        status = "MISSING"
                    else:
                        status = "AMBIGUOUS"
                if stage in FORMAL_STAGES and status not in ("NOT_RUN", "NO_RESULT_PATH"):
                    refs.append(status)
                    if action:
                        action_refs.setdefault(action, []).append(status)
                    if status == "UNIQUE":
                        attempt = matches[0]
                        matched.append(attempt["attempt_id"])
                        if attempt["stage"] and attempt["stage"] != stage:
                            cross_stage += 1

    unique = refs.count("UNIQUE")
    missing = sum(item in ("MISSING", "MISSING_RUNTIME", "MISSING_RESULT_PATH") for item in refs)
    ambiguous = refs.count("AMBIGUOUS")
    if unique + missing + ambiguous != len(refs):
        raise JoinFailure("JOIN_CLASSIFICATION", "JOIN_CLASSIFICATION_FAILURE")
    eligible = sorted(set(actions))
    if not eligible:
        raise JoinFailure("MEASUREMENT_PARSE", "MEASUREMENT_SCHEMA_FAILURE")
    all_unique = sum(bool(action_refs.get(action)) and
                     all(status == "UNIQUE" for status in action_refs[action]) for action in eligible)
    source_hash = _sha_lines(artifacts + ["attempt:" + item["source_digest"] for item in attempts])
    return {
        "circuit": circuit,
        "executed_stage_reference_count": len(refs),
        "unique_runtime_join_count": unique,
        "missing_runtime_join_count": missing,
        "ambiguous_runtime_join_count": ambiguous,
        "coverage_rate": 0.0 if not refs else float(unique) / len(refs),
        "distinct_runtime_attempt_count": len(set(matched)),
        "cross_stage_reference_count": cross_stage,
        "eligible_action_count": len(eligible),
        "all_unique_action_count": all_unique,
        "frozen_runtime_eligible_action_space_sha256": _sha_lines(eligible),
        "source_artifact_set_sha256": source_hash,
    }


def gates_pass(rows):
    return bool(rows) and all(
        row["executed_stage_reference_count"] > 0 and
        row["unique_runtime_join_count"] == row["executed_stage_reference_count"] and
        row["missing_runtime_join_count"] == 0 and
        row["ambiguous_runtime_join_count"] == 0 and
        row["coverage_rate"] == 1.0 and
        row["eligible_action_count"] > 0 and
        row["all_unique_action_count"] == row["eligible_action_count"]
        for row in rows
    )
