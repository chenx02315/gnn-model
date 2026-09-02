#!/usr/bin/env python3
"""Build the pre-deployment HF/HMF action space without selecting outcomes."""
from __future__ import print_function
import argparse
import csv
import hashlib
import json
import os

OUTCOME_FIELDS = ("f_patterns", "detected_faults", "total_cycles", "tester_cycles", "feasible_at_d95")
OUTPUT_FIELDS = ("action_uid", "circuit", "action_scheme", "mode_stack", "h_patterns", "m_patterns", "repeat_measurement_count", "source_candidate_uids", "source_stages", "outcome_conflict", "outcome_conflict_fields")

def val(row, name):
    return (row.get(name) or "").strip()

def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

def build(input_tsv):
    groups, input_count, eligible_count, skipped = {}, 0, 0, {}
    with open(input_tsv, "r", encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream, delimiter="\t"):
            input_count += 1
            if val(row, "eligible_regression") != "1":
                skipped["eligible_regression_not_1"] = skipped.get("eligible_regression_not_1", 0) + 1
                continue
            if val(row, "formal_scheme") != "1":
                skipped["formal_scheme_not_1"] = skipped.get("formal_scheme_not_1", 0) + 1
                continue
            stage = val(row, "stage")
            if stage.startswith("hf_"):
                scheme = "HF"
            elif stage.startswith("hmf_"):
                scheme = "HMF"
            else:
                skipped["stage_not_hf_or_hmf"] = skipped.get("stage_not_hf_or_hmf", 0) + 1
                continue
            eligible_count += 1
            circuit, h, m = val(row, "circuit"), val(row, "h_patterns"), val(row, "m_patterns")
            # F is an observed outcome, never part of a deployable action key.
            key = (circuit, scheme, h, "" if scheme == "HF" else m)
            group = groups.setdefault(key, {"rows": [], "outcomes": {field: set() for field in OUTCOME_FIELDS}})
            group["rows"].append(row)
            for field in OUTCOME_FIELDS:
                observed = val(row, field)
                if observed:
                    group["outcomes"][field].add(observed)
    actions = []
    for key in sorted(groups):
        circuit, scheme, h, m = key
        group = groups[key]
        conflicts = sorted(field for field, values in group["outcomes"].items() if len(values) > 1)
        actions.append({"action_uid": "%s:%s:h%s%s" % (circuit, scheme, h, (":m" + m) if scheme == "HMF" else ""), "circuit": circuit, "action_scheme": scheme, "mode_stack": "|".join(sorted(set(val(row, "scheme") for row in group["rows"] if val(row, "scheme")))), "h_patterns": h, "m_patterns": m, "repeat_measurement_count": str(len(group["rows"])), "source_candidate_uids": "|".join(sorted(set(val(row, "candidate_uid") for row in group["rows"] if val(row, "candidate_uid")))), "source_stages": "|".join(sorted(set(val(row, "stage") for row in group["rows"] if val(row, "stage")))), "outcome_conflict": "true" if conflicts else "false", "outcome_conflict_fields": "|".join(conflicts)})
    return actions, input_count, eligible_count, skipped

def write(input_tsv, actions, input_count, eligible_count, skipped, output_tsv, audit_json):
    with open(output_tsv, "w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=OUTPUT_FIELDS, delimiter="\t", lineterminator="\n")
        writer.writeheader(); writer.writerows(actions)
    by_circuit_scheme = {}
    for action in actions:
        key = action["circuit"] + ":" + action["action_scheme"]
        by_circuit_scheme[key] = by_circuit_scheme.get(key, 0) + 1
    audit = {"input_sha256": sha256_file(input_tsv), "output_sha256": sha256_file(output_tsv), "input_row_count": input_count, "eligible_measurement_count": eligible_count, "action_count": len(actions), "counts_by_circuit_scheme": by_circuit_scheme, "skipped_reason_counts": skipped, "duplicate_action_count": sum(int(row["repeat_measurement_count"]) > 1 for row in actions), "outcome_conflict_action_count": sum(row["outcome_conflict"] == "true" for row in actions), "deduplication_policy": "group deployable actions only; retain repeat counts and all sorted source identifiers; never select an outcome"}
    with open(audit_json, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(audit, stream, ensure_ascii=False, indent=2, sort_keys=True); stream.write("\n")
    return audit

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input_tsv"); parser.add_argument("output_tsv"); parser.add_argument("audit_json")
    args = parser.parse_args()
    actions, total, eligible, skipped = build(args.input_tsv)
    audit = write(args.input_tsv, actions, total, eligible, skipped, args.output_tsv, args.audit_json)
    print("actions=%d eligible_measurements=%d" % (audit["action_count"], eligible))
if __name__ == "__main__": main()
