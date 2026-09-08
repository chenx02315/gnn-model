#!/usr/bin/env python3
"""Audit Phase2 CSV wall_time values against GNU-time driver footers."""
from __future__ import print_function

import argparse
import csv
import hashlib
import json
import os
import re


WALL = re.compile(r"Elapsed \(wall clock\) time \(h:mm:ss or m:ss\):\s+(.+)$", re.M)
WALL_VALUE = re.compile(r"^(?:(\d+):)?(\d+):(\d+(?:\.\d+)?)$")
REQUIRED = ("circuit", "phase", "mode", "run_id", "wall_time")


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def wall_seconds(value):
    match = WALL_VALUE.match(value.strip())
    if not match:
        raise ValueError("unsupported GNU elapsed format")
    hours = int(match.group(1) or 0)
    minutes = int(match.group(2))
    seconds = float(match.group(3))
    if match.group(1) is not None and minutes >= 60:
        raise ValueError("invalid GNU elapsed minute")
    if seconds >= 60:
        raise ValueError("invalid GNU elapsed minute or second")
    return hours * 3600 + minutes * 60 + seconds


def audit_circuit(circuit, csv_path, circuit_root):
    counts = {
        "row_count": 0,
        "duplicate_run_id_count": 0,
        "circuit_mismatch_count": 0,
        "missing_driver_count": 0,
        "missing_footer_count": 0,
        "invalid_footer_wall_count": 0,
        "missing_csv_wall_count": 0,
        "invalid_wall_count": 0,
        "footer_mismatch_count": 0,
    }
    seen = set()
    with open(csv_path, "r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        if not set(REQUIRED).issubset(set(reader.fieldnames or ())):
            raise ValueError("Phase2 CSV schema mismatch for %s" % circuit)
        for row in reader:
            counts["row_count"] += 1
            run_id = (row.get("run_id") or "").strip()
            mode = (row.get("mode") or "").strip()
            key = (mode, run_id)
            if key in seen:
                counts["duplicate_run_id_count"] += 1
            seen.add(key)
            if (row.get("circuit") or "").strip() != circuit:
                counts["circuit_mismatch_count"] += 1
            csv_wall = (row.get("wall_time") or "").strip()
            if not csv_wall:
                counts["missing_csv_wall_count"] += 1
            try:
                wall_seconds(csv_wall)
            except (TypeError, ValueError):
                counts["invalid_wall_count"] += 1
            driver = os.path.join(circuit_root, "logs", "%s_%s.driver.log" % (mode, run_id))
            if not os.path.isfile(driver):
                counts["missing_driver_count"] += 1
                continue
            with open(driver, "r", encoding="utf-8", errors="replace") as log:
                match = WALL.search(log.read())
            if not match:
                counts["missing_footer_count"] += 1
            else:
                footer_wall = match.group(1).strip()
                try:
                    wall_seconds(footer_wall)
                except (TypeError, ValueError):
                    counts["invalid_footer_wall_count"] += 1
                if footer_wall != csv_wall:
                    counts["footer_mismatch_count"] += 1
    failures = sum(value for key, value in counts.items() if key != "row_count")
    return {
        "source_csv_sha256": sha256(csv_path),
        "source_row_count": counts["row_count"],
        "checks": counts,
        "validation_status": "PASS" if failures == 0 else "FAIL",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--collector-script", required=True)
    parser.add_argument("--runtime-policy", required=True)
    parser.add_argument("--circuit", action="append", required=True,
                        help="CIRCUIT=CSV_PATH,CIRCUIT_ROOT")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    circuits = {}
    for spec in args.circuit:
        name, payload = spec.split("=", 1)
        csv_path, circuit_root = payload.split(",", 1)
        if name in circuits:
            raise ValueError("duplicate circuit %s" % name)
        circuits[name] = audit_circuit(name, csv_path, circuit_root)
    output = {
        "schema_version": "phase2-wall-time-semantics-audit-v1",
        "semantics_contract": "tessent_process_wall_seconds",
        "source_field": "GNU time Elapsed (wall clock) time (h:mm:ss or m:ss)",
        "start_event": "timed_tessent_process_exec",
        "stop_event": "timed_tessent_process_exit_or_kill",
        "included_wait_classes": ["internal_license_wait", "internal_io_wait"],
        "excluded_wait_classes": ["external_scheduler_queue"],
        "failed_attempt_policy": "include_observed_elapsed",
        "retry_attempt_policy": "include_each_attempt_elapsed",
        "missing_elapsed_policy": "never_impute",
        "collector_script_sha256": sha256(args.collector_script),
        "runtime_policy_sha256": sha256(args.runtime_policy),
        "circuits": circuits,
        "validation_status": "PASS" if all(row["validation_status"] == "PASS" for row in circuits.values()) else "FAIL",
    }
    with open(args.output, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(output, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")
    print("PHASE2_WALL_TIME_SEMANTICS=%s circuits=%d rows=%d" % (
        output["validation_status"], len(circuits),
        sum(row["source_row_count"] for row in circuits.values())))
    return 0 if output["validation_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
