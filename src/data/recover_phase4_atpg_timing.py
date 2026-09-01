#!/usr/bin/env python3
"""Recover GNU time metrics from immutable Phase4 driver logs."""

from __future__ import print_function

import argparse
import csv
import glob
import os
import re


FIELD_PATTERNS = {
    "run_id": re.compile(r"^MAPPED_COMMON_ATPG_RUN_ID=(.+)$", re.M),
    "mode": re.compile(r"^MAPPED_COMMON_ATPG_MODE=(.+)$", re.M),
    "user_time_s": re.compile(r"^\s*User time \(seconds\):\s*(\S+)", re.M),
    "system_time_s": re.compile(r"^\s*System time \(seconds\):\s*(\S+)", re.M),
    "elapsed_text": re.compile(
        r"^\s*Elapsed \(wall clock\) time \(h:mm:ss or m:ss\):\s*(\S+)", re.M
    ),
    "max_rss_kb": re.compile(r"^\s*Maximum resident set size \(kbytes\):\s*(\S+)", re.M),
    "exit_status": re.compile(r"^\s*Exit status:\s*(\S+)", re.M),
}


def elapsed_seconds(value):
    if not value:
        return ""
    parts = value.split(":")
    try:
        if len(parts) == 2:
            return "%.3f" % (float(parts[0]) * 60.0 + float(parts[1]))
        if len(parts) == 3:
            return "%.3f" % (
                float(parts[0]) * 3600.0 + float(parts[1]) * 60.0 + float(parts[2])
            )
    except ValueError:
        return ""
    return ""


def parse_log(path, evidence_root):
    with open(path, "rb") as stream:
        stream.seek(0, os.SEEK_END)
        size = stream.tell()
        stream.seek(max(0, size - 65536), os.SEEK_SET)
        text = stream.read().decode("utf-8", "replace")
    row = {}
    for key, pattern in FIELD_PATTERNS.items():
        match = pattern.search(text)
        row[key] = match.group(1).strip() if match else ""
    relative = os.path.relpath(path, evidence_root)
    pieces = relative.split(os.sep)
    row["circuit"] = pieces[1] if len(pieces) > 1 and pieces[0] == "10_circuits" else ""
    row["stage"] = pieces[-2] if len(pieces) > 1 else ""
    if not row["run_id"]:
        row["run_id"] = os.path.basename(path)[:-len(".driver.log")]
        row["run_id_source"] = "filename"
    else:
        row["run_id_source"] = "log_marker"
    if not row["mode"] and row["run_id"][:2] in ("F_", "H_", "M_"):
        row["mode"] = row["run_id"][0]
    row["elapsed_wall_s"] = elapsed_seconds(row.pop("elapsed_text"))
    row["source_log"] = relative.replace(os.sep, "/")
    row["parse_status"] = "PASS" if row["run_id"] and row["elapsed_wall_s"] else "INCOMPLETE"
    return row


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence_root")
    parser.add_argument("output_tsv")
    args = parser.parse_args()

    audit_roots = sorted(glob.glob(os.path.join(
        args.evidence_root, "10_circuits", "*", "10_coverage95_phase4_v2"
    )))
    if not audit_roots:
        audit_roots = [args.evidence_root]

    rows = []
    for audit_root in audit_roots:
        for directory, subdirs, files in os.walk(audit_root):
            subdirs[:] = [name for name in subdirs if name != "_translated_fault_state"]
            for name in files:
                if name.endswith(".driver.log"):
                    rows.append(parse_log(os.path.join(directory, name), args.evidence_root))
    rows.sort(key=lambda row: (row["circuit"], row["stage"], row["run_id"], row["source_log"]))

    fields = [
        "circuit", "stage", "run_id", "run_id_source", "mode", "elapsed_wall_s", "user_time_s",
        "system_time_s", "max_rss_kb", "exit_status", "parse_status", "source_log",
    ]
    parent = os.path.dirname(os.path.abspath(args.output_tsv))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)
    with open(args.output_tsv, "w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    complete = sum(row["parse_status"] == "PASS" for row in rows)
    print("rows=%d complete=%d incomplete=%d" % (len(rows), complete, len(rows) - complete))


if __name__ == "__main__":
    main()
