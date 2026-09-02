#!/usr/bin/env python3
"""Join non-blind measurement result paths to runtime attempts (Python 3.6+)."""
from __future__ import print_function
import argparse
import csv
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from runtime_schema import MANIFEST_V2_FIELDS, FORBIDDEN_OUTCOME_FIELDS

LAYOUTS = (
    ("01_single_boundaries", "measurements.tsv", "single"),
    ("02_hf_coarse", "measurements.tsv", "hf"),
    ("03_hmf_coarse", "measurements.tsv", "hmf"),
    ("04_integer_refine", "hf_measurements.tsv", "hf"),
    ("04_integer_refine", "hmf_measurements.tsv", "hmf"),
    ("05_repeatability", "measurements.tsv", "repeatability"),
)
JOIN_FIELDS = ("role", "family", "circuit", "stage", "mode", "normalized_result_basename",
               "source_file", "source_row", "attempt_stage", "stage_relation", "marker_run_id_mismatch",
               "join_status", "join_reason", "join_key_source")
FIELDS = JOIN_FIELDS + tuple(x for x in MANIFEST_V2_FIELDS if x not in JOIN_FIELDS)
if set(FIELDS).intersection(FORBIDDEN_OUTCOME_FIELDS):
    raise RuntimeError("runtime join output must not contain candidate outcome fields")


def value(row, key):
    return (row.get(key) or "").strip()


def basename(path):
    """Canonical result/log marker, independent of host path separators."""
    name = os.path.basename((path or "").replace("\\", "/").rstrip("/"))
    for suffix in (".driver.log", ".log", ".tsv", ".csv"):
        if name.endswith(suffix):
            return name[:-len(suffix)]
    return name


def role_for(circuit, contract):
    membership = contract.get("formal_runtime_membership", {})
    for role, entries in membership.items():
        for entry in entries:
            if entry.get("circuit") == circuit:
                return role, entry.get("family", "")
    return "UNREGISTERED", ""


def source_rows(kind, row):
    if kind == "single":
        mode = value(row, "mode")
        path = value(row, "result_directory") or value(row, "result")
        return [(mode, path)]
    if kind == "repeatability":
        scheme = value(row, "scheme")
        modes = {"FullScan-F4": ("F",), "ComScan-H64": ("H",),
                 "H64-F4": ("H", "F"), "H64-M16-F4": ("H", "M", "F")}.get(scheme, ())
        return [(mode, "") for mode in modes]
    modes = ("H", "F") if kind == "hf" else ("H", "M", "F")
    return [(mode, value(row, mode.lower() + "_result")) for mode in modes]


def is_not_run(row):
    state = source_state(row)
    return ("TARGET_BEFORE_F" in state or "NOT_RUN" in state or
            "PRUNED_OR_UNREACHED" in state)


def source_state(row):
    """The raw table's primary execution state, retained in the audit reason."""
    return value(row, "result_status") or value(row, "status")


def table_paths(root):
    for directory, filename, kind in LAYOUTS:
        path = os.path.join(root, directory, filename)
        if os.path.isfile(path):
            yield directory, filename, kind, path


def load_attempts(path, circuit):
    source_index, run_index = {}, {}
    with open(path, "r", encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream, delimiter="\t"):
            if value(row, "circuit") != circuit:
                continue
            stage, mode = value(row, "stage"), value(row, "mode")
            key = (circuit, mode)
            marker = basename(value(row, "source_log_path") or value(row, "source_log"))
            if marker:
                source_index.setdefault(key + (marker,), []).append(row)
            run = value(row, "run_id")
            if run:
                run_index.setdefault(key + (run,), []).append(row)
    return source_index, run_index


def build(circuit, measurements_root, attempt_manifest, contract):
    role, family = role_for(circuit, contract)
    if role in ("BLIND_TEST", "UNREGISTERED"):
        raise ValueError("%s circuit %s is not eligible for runtime join" % (role, circuit))
    source_index, run_index = load_attempts(attempt_manifest, circuit)
    output = []
    for stage, filename, kind, path in table_paths(measurements_root):
        with open(path, "r", encoding="utf-8", newline="") as stream:
            for row_number, row in enumerate(csv.DictReader(stream, delimiter="\t"), 2):
                for mode, result_path in source_rows(kind, row):
                    marker = basename(result_path)
                    result = {field: "" for field in FIELDS}
                    result.update({"role": role, "family": family, "circuit": circuit,
                                   "stage": stage, "mode": mode,
                                   "normalized_result_basename": marker,
                                   "source_file": os.path.relpath(path, measurements_root).replace("\\", "/"),
                                   "source_row": str(row_number)})
                    if not marker:
                        if kind == "repeatability":
                            result.update(join_status="NO_RESULT_PATH", join_reason="repeatability_has_no_result_path")
                        elif is_not_run(row):
                            result.update(join_status="NOT_RUN", join_reason=source_state(row))
                        else:
                            result.update(join_status="MISSING_RESULT_PATH", join_reason="empty_result_path")
                    else:
                        key = (circuit, mode, marker)
                        matches = source_index.get(key, [])
                        key_source = "source_log_basename" if matches else ""
                        if not matches:
                            matches = run_index.get(key, [])
                            key_source = "run_id_exact" if matches else ""
                        result["join_key_source"] = key_source
                        if len(matches) == 1:
                            attempt = matches[0]
                            result.update({field: value(attempt, field) for field in MANIFEST_V2_FIELDS
                                           if field in result and field not in ("role", "family", "circuit", "stage", "mode")})
                            # Contract-derived split membership is authoritative.
                            result["role"], result["family"] = role, family
                            result["attempt_stage"] = value(attempt, "stage")
                            result["stage_relation"] = "SAME_STAGE" if result["attempt_stage"] == stage else "CROSS_STAGE"
                            result["marker_run_id_mismatch"] = "true" if key_source == "source_log_basename" and marker != value(attempt, "run_id") else "false"
                            result.update(join_status="UNIQUE", join_reason=key_source)
                        elif not matches:
                            result.update(join_status="MISSING", join_reason="no_attempt_same_circuit_stage_mode")
                        else:
                            result.update(join_status="AMBIGUOUS", join_reason="multiple_attempts_same_circuit_stage_mode")
                    output.append(result)
    output.sort(key=lambda r: (r["stage"], r["source_file"], int(r["source_row"]), r["mode"]))
    return output


def write(rows, output_tsv, output_audit):
    with open(output_tsv, "w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    by_key = {}
    for row in rows:
        key = "/".join((row["role"], row["circuit"], row["stage"], row["mode"]))
        by_key.setdefault(key, {}).setdefault(row["join_status"], 0)
        by_key[key][row["join_status"]] += 1
    ambiguity_count = sum(row["join_status"] == "AMBIGUOUS" for row in rows)
    cross_stage = sum(row["join_status"] == "UNIQUE" and row["stage_relation"] == "CROSS_STAGE" for row in rows)
    marker_mismatches = sum(row["marker_run_id_mismatch"] == "true" for row in rows)
    audit = {"row_count": len(rows), "by_role_circuit_stage_mode": by_key,
             "ambiguity_count": ambiguity_count, "ambiguity_zero": ambiguity_count == 0,
             "cross_stage_unique_count": cross_stage,
             "source_basename_marker_run_id_mismatch_count": marker_mismatches}
    with open(output_audit, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(audit, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")
    return audit


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--circuit", required=True)
    parser.add_argument("--measurements-root", required=True)
    parser.add_argument("--attempt-manifest", required=True)
    parser.add_argument("--split-contract", default=os.path.join(HERE, "..", "..", "contracts", "data_split_v1.json"))
    parser.add_argument("output_join_tsv")
    parser.add_argument("output_audit_json")
    args = parser.parse_args()
    # Read the contract before raw measurements or runtime attempts, to seal blind data.
    with open(args.split_contract, "r", encoding="utf-8") as stream:
        contract = json.load(stream)
    try:
        rows = build(args.circuit, args.measurements_root, args.attempt_manifest, contract)
    except ValueError as exc:
        parser.error(str(exc))
    audit = write(rows, args.output_join_tsv, args.output_audit_json)
    print("rows=%d ambiguity_count=%d" % (audit["row_count"], audit["ambiguity_count"]))
    return 1 if audit["ambiguity_count"] else 0


if __name__ == "__main__":
    sys.exit(main())
