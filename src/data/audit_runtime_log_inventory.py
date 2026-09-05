#!/usr/bin/env python3
"""Produce a blind-safe aggregate inventory of GNU-time driver logs.

The output intentionally contains no paths, run IDs, timing values, candidates,
patterns, cycles, or outcomes. Python 3.6+; standard library only.
"""
from __future__ import print_function

import argparse
import hashlib
import json
import os
import re


PATTERNS = {
    "elapsed": re.compile(r"^\s*Elapsed \(wall clock\) time .*:\s*\S+", re.M),
    "user": re.compile(r"^\s*User time \(seconds\):\s*\S+", re.M),
    "system": re.compile(r"^\s*System time \(seconds\):\s*\S+", re.M),
    "exit": re.compile(r"^\s*Exit status:\s*(\S+)", re.M),
    "atpg_status": re.compile(r"^MAPPED_COMMON_ATPG_STATUS=(\S+)", re.M),
}


def scan_file(path):
    digest = hashlib.sha256()
    found = dict((key, "") for key in PATTERNS)
    with open(path, "rb") as stream:
        for raw in stream:
            digest.update(raw)
            line = raw.decode("utf-8", "replace")
            for key, pattern in PATTERNS.items():
                if not found[key]:
                    match = pattern.search(line)
                    if match:
                        found[key] = match.group(1) if match.groups() else "PRESENT"
    return digest.hexdigest(), found


def audit(input_path, circuit, cohort, evidence_root="", extra_logs=None):
    paths = []
    for parent, _directories, files in os.walk(input_path):
        for name in files:
            if name.endswith(".driver.log"):
                paths.append(os.path.join(parent, name))
    root = evidence_root or input_path
    root_real = os.path.realpath(root)
    scanned_real = set(os.path.realpath(path) for path in paths)
    extra_real = set()
    for path in extra_logs or []:
        real = os.path.realpath(path)
        if not os.path.exists(path):
            raise ValueError("--extra-log does not exist: %s" % path)
        if not os.path.isfile(path):
            raise ValueError("--extra-log is not a file: %s" % path)
        if not path.endswith(".driver.log"):
            raise ValueError("--extra-log must end in .driver.log: %s" % path)
        if os.path.commonpath((root_real, real)) != root_real:
            raise ValueError("--extra-log is outside --evidence-root: %s" % path)
        if real in scanned_real or real in extra_real:
            raise ValueError("--extra-log duplicates a scanned or extra log: %s" % path)
        extra_real.add(real)
    paths.extend(extra_logs or [])
    paths.sort(key=lambda path: os.path.relpath(os.path.realpath(path), root_real).replace(os.sep, "/"))
    counts = dict((key, 0) for key in PATTERNS)
    nonzero_exit = 0
    nonpass_atpg_status = 0
    inventory = hashlib.sha256()
    for path in paths:
        digest, found = scan_file(path)
        relative = os.path.relpath(os.path.realpath(path), root_real).replace(os.sep, "/")
        inventory.update((relative + "\t" + digest + "\n").encode("utf-8"))
        for key in PATTERNS:
            if found[key]:
                counts[key] += 1
                if key == "exit" and found[key] != "0":
                    nonzero_exit += 1
                if key == "atpg_status" and found[key] != "PASS":
                    nonpass_atpg_status += 1
    total = len(paths)
    result = {
        "schema_version": "runtime_log_inventory_aggregate_v1",
        "circuit": circuit,
        "cohort": cohort,
        "driver_log_count": total,
        "elapsed_footer_count": counts["elapsed"],
        "user_footer_count": counts["user"],
        "system_footer_count": counts["system"],
        "exit_footer_count": counts["exit"],
        "nonzero_exit_count": nonzero_exit,
        "atpg_status_marker_count": counts["atpg_status"],
        "nonpass_atpg_status_count": nonpass_atpg_status,
        "missing_elapsed_count": total - counts["elapsed"],
        "missing_exit_count": total - counts["exit"],
        "missing_atpg_status_count": total - counts["atpg_status"],
        "inventory_manifest_sha256": inventory.hexdigest(),
        "field_policy": "aggregate-only; no path, run_id, elapsed value, candidate, pattern, cycle, or outcome fields",
    }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--evidence-root", default="")
    parser.add_argument("--extra-log", action="append", default=[])
    parser.add_argument("--circuit", required=True)
    parser.add_argument("--cohort", required=True)
    args = parser.parse_args()
    try:
        result = audit(args.input, args.circuit, args.cohort, args.evidence_root, args.extra_log)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
