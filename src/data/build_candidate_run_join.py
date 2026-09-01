#!/usr/bin/env python3
"""Directly join Phase4 candidate result paths to ATPG attempts (Python 3.6+)."""
from __future__ import print_function
import argparse, csv, json, os

TABLES = ("single_boundary", "hf_coarse", "hmf_coarse", "hf_refine", "hmf_refine", "repeatability")
FIELDS = ("candidate_uid", "circuit", "stage", "scheme", "candidate", "repeat", "mode", "run_id", "attempt_id", "join_key_source", "patterns", "fault_sha", "source_file", "source_row", "join_status", "join_reason")

def v(row, key):
    return (row.get(key) or "").strip()

def rows_for(table, circuit, source_file, row, number):
    if table == "single_boundary":
        mode = v(row, "mode")
        return [(mode, v(row, "result"), v(row, "actual_patterns"), "", "SINGLE", v(row, "requested_limit"), "")]
    if table == "repeatability":
        scheme = v(row, "scheme")
        modes = {"FullScan-F4": ("F",), "ComScan-H64": ("H",), "H64-F4": ("H", "F"), "H64-M16-F4": ("H", "M", "F")}.get(scheme, ())
        return [(mode, "", v(row, mode.lower() + "_patterns"), v(row, mode.lower() + "_fault_sha256"), scheme, scheme, v(row, "repeat")) for mode in modes]
    scheme = "HF" if table.startswith("hf_") else "HMF"
    result_status = v(row, "result_status")
    result = []
    for mode in ("H", "M", "F"):
        if mode == "M" and scheme == "HF":
            continue
        path = v(row, mode.lower() + "_result")
        result.append((mode, path, v(row, mode.lower() + "_patterns"), v(row, mode.lower() + "_fault_sha256"), scheme, v(row, "candidate"), ""))
    return result

def load_attempts(path, circuit):
    source_index, run_index = {}, {}
    with open(path, "r", encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream, delimiter="\t"):
            if v(row, "circuit") == circuit:
                run_index.setdefault(v(row, "run_id"), []).append(row)
                source = os.path.basename(v(row, "source_log"))
                if source.endswith(".driver.log"):
                    source = source[:-len(".driver.log")]
                if source:
                    source_index.setdefault(source, []).append(row)
    return source_index, run_index

def build(circuit, raw_dir, attempt_manifest):
    source_attempts, run_attempts = load_attempts(attempt_manifest, circuit)
    output = []
    for table in TABLES:
        path = os.path.join(raw_dir, table + ".tsv")
        if not os.path.isfile(path):
            continue
        with open(path, "r", encoding="utf-8", newline="") as stream:
            for number, source in enumerate(csv.DictReader(stream, delimiter="\t"), 2):
                for mode, result_path, patterns, fault_sha, scheme, candidate, repeat in rows_for(table, circuit, path, source, number):
                    run_id = os.path.basename(result_path) if result_path else ""
                    status, reason, attempt_id, key_source, marker_mismatch = "", "", "", "", False
                    state = v(source, "result_status") or v(source, "status")
                    if not result_path:
                        if "TARGET_BEFORE_F" in state or "NOT_RUN" in state:
                            status, reason = "NOT_RUN", "TARGET_BEFORE_F"
                        elif table == "repeatability":
                            status, reason = "NO_RESULT_PATH", "repeatability_has_no_result_path"
                        else:
                            status, reason = "MISSING_RESULT_PATH", "empty_%s_result" % mode.lower()
                    else:
                        matches = source_attempts.get(run_id, [])
                        key_source = "source_log_basename" if matches else ""
                        if not matches:
                            matches = run_attempts.get(run_id, [])
                            key_source = "run_id_fallback" if matches else ""
                        if len(matches) == 1:
                            status, reason, attempt_id = "UNIQUE", key_source, v(matches[0], "attempt_id")
                            marker_mismatch = key_source == "source_log_basename" and run_id != v(matches[0], "run_id")
                        elif not matches:
                            status, reason = "MISSING", "no_attempt_for_source_basename_or_run_id"
                        else:
                            status, reason = "AMBIGUOUS", "multiple_attempts_for_basename"
                    uid = "%s:%s:%s:%s:%s" % (circuit, table, scheme, candidate, repeat or "0")
                    output.append({"candidate_uid": uid, "circuit": circuit, "stage": table, "scheme": scheme, "candidate": candidate, "repeat": repeat, "mode": mode, "run_id": run_id, "attempt_id": attempt_id, "join_key_source": key_source, "patterns": patterns, "fault_sha": fault_sha, "source_file": os.path.basename(path), "source_row": str(number), "join_status": status, "join_reason": reason, "_source_marker_mismatch": marker_mismatch})
    output.sort(key=lambda x: (x["stage"], x["candidate_uid"], x["mode"], x["source_row"]))
    return output

def write(rows, output_tsv, output_audit):
    with open(output_tsv, "w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS, delimiter="\t", lineterminator="\n")
        writer.writeheader(); writer.writerows({key: row.get(key, "") for key in FIELDS} for row in rows)
    by_stage_mode = {}
    for row in rows:
        key = row["stage"] + ":" + row["mode"]
        by_stage_mode.setdefault(key, {}).setdefault(row["join_status"], 0)
        by_stage_mode[key][row["join_status"]] += 1
    path_backed = [row for row in rows if row["stage"] != "repeatability"]
    ambiguous = sum(row["join_status"] == "AMBIGUOUS" for row in path_backed)
    repeat_rows = [row for row in rows if row["stage"] == "repeatability"]
    key_source_counts = {}
    mismatches = 0
    for row in rows:
        key = row["join_key_source"] or "not_joined"
        key_source_counts[key] = key_source_counts.get(key, 0) + 1
        if row.get("_source_marker_mismatch"):
            mismatches += 1
    audit = {"row_count": len(rows), "path_backed_row_count": len(path_backed), "by_stage_mode": by_stage_mode, "join_key_source_counts": key_source_counts, "source_basename_marker_run_id_mismatch_count": mismatches, "final_direct_join_ambiguity_count": ambiguous, "final_direct_join_ambiguity_zero": ambiguous == 0, "repeatability_not_joined_count": len(repeat_rows), "repeatability_policy": "NO_RESULT_PATH/NOT_JOINED; excluded from path-backed direct-join completeness", "auxiliary_boundary_search_attempts": "future incidence task; not included in candidate search cost"}
    with open(output_audit, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(audit, stream, ensure_ascii=False, indent=2, sort_keys=True); stream.write("\n")
    return audit

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--circuit", required=True); parser.add_argument("--raw-tables-dir", required=True)
    parser.add_argument("--attempt-manifest", required=True); parser.add_argument("output_join_tsv"); parser.add_argument("output_audit_json")
    args = parser.parse_args()
    audit = write(build(args.circuit, args.raw_tables_dir, args.attempt_manifest), args.output_join_tsv, args.output_audit_json)
    print("rows=%d ambiguous=%d" % (audit["row_count"], audit["final_direct_join_ambiguity_count"]))
if __name__ == "__main__": main()
