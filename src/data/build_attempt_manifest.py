#!/usr/bin/env python3
"""Build an auditable, one-row-per-driver-log ATPG attempt manifest.

Input is the TSV from recover_phase4_atpg_timing.py.  Pass --log-root as the
evidence root used for recovery so source logs can be hashed and their markers
rechecked. All input rows are retained; this tool never chooses a fastest run.
Python 3.6+; standard library only.
"""
from __future__ import print_function

import argparse
import csv
import hashlib
import json
import os
import re

LOG_PATTERNS = {
    "run_id": re.compile(r"^MAPPED_COMMON_ATPG_RUN_ID=(.+)$", re.M),
    "mode": re.compile(r"^MAPPED_COMMON_ATPG_MODE=(.+)$", re.M),
    "config_key": re.compile(r"^MAPPED_COMMON_ATPG_CONFIG_KEY=(.+)$", re.M),
    "wall_s": re.compile(r"^\s*Elapsed \(wall clock\) time \(h:mm:ss or m:ss\):\s*(\S+)", re.M),
    "user_s": re.compile(r"^\s*User time \(seconds\):\s*(\S+)", re.M),
    "system_s": re.compile(r"^\s*System time \(seconds\):\s*(\S+)", re.M),
    "rss_kb": re.compile(r"^\s*Maximum resident set size \(kbytes\):\s*(\S+)", re.M),
    "exit": re.compile(r"^\s*Exit status:\s*(\S+)", re.M),
}
OUTPUT_FIELDS = [
    "attempt_id", "circuit", "stage", "run_id", "run_id_source", "mode",
    "wall_s", "user_s", "system_s", "rss_kb", "exit", "source_log",
    "source_log_sha256", "config_key", "config_key_source", "retry_index",
    "parse_status", "duplicate_run_id", "ambiguity_reason",
]


def value(row, *names):
    for name in names:
        if row.get(name, "").strip():
            return row[name].strip()
    return ""


def elapsed_seconds(text):
    if not text:
        return ""
    parts = text.split(":")
    try:
        if len(parts) == 2:
            return "%.3f" % (float(parts[0]) * 60 + float(parts[1]))
        if len(parts) == 3:
            return "%.3f" % (float(parts[0]) * 3600 + float(parts[1]) * 60 + float(parts[2]))
    except ValueError:
        pass
    return ""


def read_log(path):
    result = {key: "" for key in LOG_PATTERNS}
    try:
        with open(path, "rb") as stream:
            data = stream.read()
    except (IOError, OSError):
        return result, "", False
    text = data.decode("utf-8", "replace")
    for key, pattern in LOG_PATTERNS.items():
        match = pattern.search(text)
        if match:
            result[key] = match.group(1).strip()
    return result, hashlib.sha256(data).hexdigest(), True


def filename_run_id(source_log):
    name = os.path.basename(source_log)
    return name[:-len(".driver.log")] if name.endswith(".driver.log") else os.path.splitext(name)[0]


def config_from_run_id(run_id):
    # Do not strip ordinary integer suffixes: they may be actual ATPG limits.
    return re.sub(r"(?:[_-](?:retry|rerun|attempt)[_-]?\d+)$", "", run_id, flags=re.I)


def build_rows(timing_tsv, log_root, circuits=None):
    with open(timing_tsv, "r", encoding="utf-8", newline="") as stream:
        sources = list(csv.DictReader(stream, delimiter="\t"))
    source_row_count = len(sources)
    selected = set(circuits or [])
    if selected:
        sources = [source for source in sources if value(source, "circuit") in selected]
    rows = []
    for index, source in enumerate(sources, 1):
        source_log = value(source, "source_log")
        path = source_log if os.path.isabs(source_log) else os.path.join(log_root, source_log)
        parsed, log_hash, present = read_log(path) if source_log and log_root else ({}, "", False)
        run_id = parsed.get("run_id", "") or value(source, "run_id")
        run_source = "log_marker" if parsed.get("run_id") else value(source, "run_id_source")
        if not run_id:
            run_id, run_source = filename_run_id(source_log), "filename"
        mode = parsed.get("mode", "") or value(source, "mode")
        if not mode and run_id[:2] in ("H_", "M_", "F_"):
            mode = run_id[0]
        config_key = parsed.get("config_key", "")
        config_source = "log_marker" if config_key else ""
        if not config_key:
            config_key = config_from_run_id(run_id) if run_id else ""
            config_source = "run_id" if config_key else "missing"
        log_wall = elapsed_seconds(parsed.get("wall_s", ""))
        row = {
            "circuit": value(source, "circuit"), "stage": value(source, "stage"),
            "run_id": run_id, "run_id_source": run_source or "missing", "mode": mode,
            "wall_s": log_wall or value(source, "elapsed_wall_s", "wall_s"),
            "user_s": parsed.get("user_s", "") or value(source, "user_time_s", "user_s"),
            "system_s": parsed.get("system_s", "") or value(source, "system_time_s", "system_s"),
            "rss_kb": parsed.get("rss_kb", "") or value(source, "max_rss_kb", "rss_kb"),
            "exit": parsed.get("exit", "") or value(source, "exit_status", "exit"),
            "source_log": source_log.replace("\\", "/"), "source_log_sha256": log_hash,
            "config_key": config_key, "config_key_source": config_source,
            "retry_index": "", "duplicate_run_id": "", "ambiguity_reason": "", "_index": index,
        }
        missing = [key for key in ("run_id", "wall_s", "source_log_sha256") if not row[key]]
        row["parse_status"] = "PASS" if not missing else "INCOMPLETE:" + ",".join(missing)
        rows.append(row)

    # Stable path ordering, rather than timing, defines retry lineage.
    rows.sort(key=lambda r: (r["circuit"], r["stage"], r["config_key"], r["source_log"], r["_index"]))
    config_counts, run_counts = {}, {}
    for row in rows:
        key = (row["circuit"], row["stage"], row["config_key"])
        config_counts[key] = config_counts.get(key, 0) + 1
        key = (row["circuit"], row["stage"], row["run_id"])
        run_counts[key] = run_counts.get(key, 0) + 1
    seen = {}
    for row in rows:
        config_id = (row["circuit"], row["stage"], row["config_key"])
        seen[config_id] = seen.get(config_id, 0) + 1
        row["retry_index"] = str(seen[config_id] - 1)
        run_id = (row["circuit"], row["stage"], row["run_id"])
        if run_counts[run_id] > 1:
            row["duplicate_run_id"] = "true"
            row["ambiguity_reason"] = "duplicate_run_id"
        elif config_counts[config_id] > 1:
            row["ambiguity_reason"] = "multiple_attempts_same_config"
        identity = "|".join((row["circuit"], row["stage"], row["source_log"], row["source_log_sha256"], str(row["_index"])))
        row["attempt_id"] = "attempt_" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
    return rows, source_row_count


def write_outputs(rows, output_tsv, audit_json, source_row_count, circuit_filter):
    parent = os.path.dirname(os.path.abspath(output_tsv))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)
    with open(output_tsv, "w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=OUTPUT_FIELDS, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows({key: row.get(key, "") for key in OUTPUT_FIELDS} for row in rows)
    status = {}
    for row in rows:
        status[row["parse_status"]] = status.get(row["parse_status"], 0) + 1
    audit = {
        "schema_version": "attempt_manifest_v1", "attempt_count": len(rows),
        "source_row_count": source_row_count,
        "selected_row_count": len(rows),
        "circuit_filter": sorted(circuit_filter or []),
        "selected_circuits": sorted(set(row["circuit"] for row in rows)),
        "parse_status_counts": status,
        "run_id_source_counts": {key: sum(r["run_id_source"] == key for r in rows) for key in sorted(set(r["run_id_source"] for r in rows))},
        "duplicate_run_ids": sorted(set(r["run_id"] for r in rows if r["duplicate_run_id"] == "true")),
        "ambiguous_attempt_ids": [r["attempt_id"] for r in rows if r["ambiguity_reason"]],
        "selection_policy": "all input rows retained; no fastest-result deduplication",
    }
    with open(audit_json, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(audit, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")
    return audit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("timing_tsv")
    parser.add_argument("output_tsv")
    parser.add_argument("audit_json")
    parser.add_argument("--log-root", required=True, help="root that source_log paths are relative to")
    parser.add_argument("--circuit", action="append", default=[], help="include one circuit; repeat option for a b20/b21 pilot")
    args = parser.parse_args()
    rows, source_row_count = build_rows(args.timing_tsv, args.log_root, args.circuit)
    audit = write_outputs(rows, args.output_tsv, args.audit_json, source_row_count, args.circuit)
    incomplete = sum(count for state, count in audit["parse_status_counts"].items() if state != "PASS")
    print("attempts=%d duplicate_run_ids=%d incomplete=%d" % (audit["attempt_count"], len(audit["duplicate_run_ids"]), incomplete))


if __name__ == "__main__":
    main()
