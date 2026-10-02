#!/usr/bin/env python3
"""Build an eight-circuit formal candidate space from historical measurements."""
from __future__ import print_function

import argparse
import csv
import hashlib
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import build_candidate_space


ROSTER = ("s13207", "s15850", "s35932", "s38417",
          "aes_core", "spi", "s5378", "tv80")
PHASE3 = frozenset(("s13207", "s15850", "s5378"))
PHASE4 = frozenset(("aes_core", "spi", "tv80"))
LAYOUT = (
    ("hf_coarse", "HF", "H64-F4", "02_hf_coarse__measurements.tsv",
     os.path.join("02_hf_coarse", "measurements.tsv")),
    ("hmf_coarse", "HMF", "H64-M16-F4", "03_hmf_coarse__measurements.tsv",
     os.path.join("03_hmf_coarse", "measurements.tsv")),
    ("hf_refine", "HF", "H64-F4", "04_integer_refine__hf_measurements.tsv",
     os.path.join("04_integer_refine", "hf_measurements.tsv")),
    ("hmf_refine", "HMF", "H64-M16-F4", "04_integer_refine__hmf_measurements.tsv",
     os.path.join("04_integer_refine", "hmf_measurements.tsv")),
)
NORMALIZED_FIELDS = (
    "candidate_uid", "circuit", "scheme", "formal_scheme", "stage",
    "candidate", "common_fault_count", "d95", "h_full_patterns",
    "m_full_patterns", "f_full_patterns", "h_patterns", "m_patterns",
    "f_patterns", "h_ratio", "m_ratio", "f_ratio", "h_cycles",
    "m_cycles", "f_cycles", "total_cycles", "detected_faults",
    "feasible_at_d95", "f_minus_one_patterns", "f_minus_one_detected",
    "result_status", "eligible_regression", "source_version", "source_file",
    "source_row",
)


class BuildError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise BuildError(code)


def value(row, key):
    return (row.get(key) or "").strip()


def sha256_file(path):
    answer = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            answer.update(block)
    return answer.hexdigest()


def read_tsv(path):
    require(os.path.isfile(path) and not os.path.islink(path), "SOURCE_MISSING")
    with open(path, "r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        fields = tuple(reader.fieldnames or ())
        rows = list(reader)
    require(rows and "result_status" in fields and "h_patterns" in fields,
            "SOURCE_SCHEMA_INVALID")
    return fields, rows


def write_tsv(path, fields, rows):
    with open(path, "w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, delimiter="\t",
                                lineterminator="\n", extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def source_path(circuit, alias, phase3_root, phase4_root, phase2_root):
    for item in LAYOUT:
        if item[0] == alias:
            flat_name, phase2_name = item[3], item[4]
            break
    if circuit in PHASE3:
        return os.path.join(phase3_root, circuit, flat_name)
    if circuit in PHASE4:
        return os.path.join(phase4_root, circuit, flat_name)
    return os.path.join(phase2_root, circuit, phase2_name)


def normalized_row(circuit, alias, scheme, mode_stack, candidate, row,
                   source_name, source_row):
    answer = dict((field, "") for field in NORMALIZED_FIELDS)
    answer.update({
        "candidate_uid": "%s:%s:%s:%s" % (circuit, alias, mode_stack, candidate),
        "circuit": circuit,
        "scheme": mode_stack,
        "formal_scheme": "1",
        "stage": alias,
        "candidate": candidate,
        "h_patterns": value(row, "h_patterns"),
        "m_patterns": value(row, "m_patterns") or "0",
        "f_patterns": value(row, "f_patterns"),
        "h_cycles": value(row, "h_cycles"),
        "m_cycles": value(row, "m_cycles") or "0",
        "f_cycles": value(row, "f_cycles"),
        "total_cycles": value(row, "total_cycles"),
        "detected_faults": value(row, "detected_faults"),
        "f_minus_one_patterns": value(row, "f_minus_one_patterns"),
        "f_minus_one_detected": value(row, "f_minus_one_detected"),
        "result_status": value(row, "result_status"),
        "eligible_regression": "1" if value(row, "result_status") == "PASS" else "0",
        "source_version": "formal_candidate_space_v2",
        "source_file": source_name.replace("\\", "/"),
        "source_row": str(source_row),
    })
    require(answer["h_patterns"].isdigit(), "H_PATTERNS_INVALID")
    require(scheme == "HF" or answer["m_patterns"].isdigit(), "M_PATTERNS_INVALID")
    return answer


def phase4_expected_rows(path):
    fields, rows = read_tsv(path)
    require(tuple(fields) == NORMALIZED_FIELDS, "PHASE4_NORMALIZED_FIELDS")
    return dict((value(row, "candidate_uid"), row) for row in rows
                if value(row, "circuit") in PHASE4 and
                value(row, "stage") in dict((item[0], item) for item in LAYOUT) and
                value(row, "result_status") == "PASS" and
                value(row, "formal_scheme") == "1")


def comparable_source(row):
    fields = ("candidate_uid", "circuit", "scheme", "stage", "candidate",
              "h_patterns", "m_patterns", "f_patterns", "h_cycles", "m_cycles",
              "f_cycles", "total_cycles", "detected_faults", "f_minus_one_patterns",
              "f_minus_one_detected", "result_status", "eligible_regression")
    return tuple(value(row, field) for field in fields)


def read_actions(path, circuits):
    with open(path, "r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        require(tuple(reader.fieldnames or ()) == build_candidate_space.OUTPUT_FIELDS,
                "ACTION_FIELDS_INVALID")
        return dict((value(row, "action_uid"), row) for row in reader
                    if value(row, "circuit") in circuits)


def build(args):
    output_root = os.path.abspath(args.output_root)
    require(not os.path.exists(output_root), "OUTPUT_ROOT_EXISTS")
    parent = os.path.dirname(output_root)
    require(os.path.isdir(parent), "OUTPUT_PARENT_MISSING")
    temporary = tempfile.mkdtemp(prefix=os.path.basename(output_root) + ".tmp-", dir=parent)
    provenance, normalized, candidate_uids = [], [], set()
    try:
        measurement_root = os.path.join(temporary, "measurements")
        os.mkdir(measurement_root)
        for circuit in ROSTER:
            circuit_dir = os.path.join(measurement_root, circuit)
            os.mkdir(circuit_dir)
            for alias, scheme, mode_stack, flat_name, unused in LAYOUT:
                path = source_path(circuit, alias, args.phase3_root,
                                   args.phase4_root, args.phase2_root)
                fields, rows = read_tsv(path)
                output_fields = fields if "candidate" in fields else ("candidate",) + fields
                output_rows = []
                seen_candidates = set()
                for index, row in enumerate(rows, 1):
                    candidate = value(row, "candidate") or str(index)
                    require(candidate.isdigit() and candidate not in seen_candidates,
                            "CANDIDATE_INVALID_OR_DUPLICATE")
                    seen_candidates.add(candidate)
                    copied = dict(row)
                    copied["candidate"] = candidate
                    output_rows.append(copied)
                    item = normalized_row(circuit, alias, scheme, mode_stack,
                                          candidate, row,
                                          "%s/%s" % (circuit, flat_name), index + 1)
                    require(item["candidate_uid"] not in candidate_uids,
                            "SOURCE_CANDIDATE_UID_DUPLICATE")
                    candidate_uids.add(item["candidate_uid"])
                    normalized.append(item)
                destination = os.path.join(circuit_dir, flat_name)
                write_tsv(destination, output_fields, output_rows)
                provenance.append({
                    "circuit": circuit, "stage": alias,
                    "source_sha256": sha256_file(path),
                    "normalized_sha256": sha256_file(destination),
                    "row_count": len(rows), "source_basename": os.path.basename(path),
                })

        normalized_path = os.path.join(temporary, "formal_candidate_measurements_v2.tsv")
        write_tsv(normalized_path, NORMALIZED_FIELDS, normalized)
        expected = phase4_expected_rows(args.phase4_normalized_v1)
        actual = dict((row["candidate_uid"], row) for row in normalized
                      if row["circuit"] in PHASE4 and row["eligible_regression"] == "1")
        require(set(actual) == set(expected), "PHASE4_SOURCE_UID_REPRODUCTION_MISMATCH")
        require(all(comparable_source(actual[uid]) == comparable_source(expected[uid])
                    for uid in actual), "PHASE4_SOURCE_VALUE_REPRODUCTION_MISMATCH")

        actions, total, eligible, skipped = build_candidate_space.build(normalized_path)
        action_path = os.path.join(temporary, "candidate_space_v2.tsv")
        action_audit_path = os.path.join(temporary, "candidate_space_v2_audit.json")
        action_audit = build_candidate_space.write(
            normalized_path, actions, total, eligible, skipped,
            action_path, action_audit_path)
        require(action_audit["outcome_conflict_action_count"] == 0,
                "ACTION_OUTCOME_CONFLICT")
        require(set(row["circuit"] for row in actions) == set(ROSTER),
                "CIRCUIT_ROSTER_MISMATCH")
        old_actions = read_actions(args.phase4_candidate_space_v1, PHASE4)
        new_actions = read_actions(action_path, PHASE4)
        require(old_actions == new_actions, "PHASE4_ACTION_REPRODUCTION_MISMATCH")

        provenance_path = os.path.join(temporary, "source_provenance_v2.tsv")
        write_tsv(provenance_path,
                  ("circuit", "stage", "source_sha256", "normalized_sha256",
                   "row_count", "source_basename"), provenance)
        receipt = {
            "schema_version": "formal-candidate-space-v2-receipt",
            "status": "PASS_BUILD_REPEAT_AGGREGATION_PENDING",
            "required_circuits": list(ROSTER),
            "counts": {
                "input_measurement_count": len(normalized),
                "eligible_source_invocation_count": action_audit["eligible_measurement_count"],
                "action_count": action_audit["action_count"],
                "duplicate_action_count": action_audit["duplicate_action_count"],
                "outcome_conflict_action_count": action_audit["outcome_conflict_action_count"],
                "phase4_reproduced_source_invocation_count": len(actual),
                "phase4_reproduced_action_count": len(new_actions),
            },
            "sha256": {
                "normalized_measurements": sha256_file(normalized_path),
                "candidate_space": sha256_file(action_path),
                "candidate_space_audit": sha256_file(action_audit_path),
                "source_provenance": sha256_file(provenance_path),
            },
            "gates": {
                "phase4_source_reproduction_exact": True,
                "phase4_action_reproduction_exact": True,
                "circuit_roster_exact": True,
                "source_candidate_uid_unique": True,
                "action_uid_unique": True,
                "outcome_conflict_count_zero": True,
            },
            "boundaries": {"training_allowed": False, "blind_rows_read": False,
                           "lsf_or_tessent_submitted": False,
                           "repeat_aggregation_allowed": False},
        }
        receipt_path = os.path.join(temporary, "receipt_v2.json")
        with open(receipt_path, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(receipt, stream, sort_keys=True, indent=2)
            stream.write("\n")
        os.rename(temporary, output_root)
        print(json.dumps(receipt, sort_keys=True))
        return 0
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase3-root", required=True)
    parser.add_argument("--phase4-root", required=True)
    parser.add_argument("--phase2-root", required=True)
    parser.add_argument("--phase4-normalized-v1", required=True)
    parser.add_argument("--phase4-candidate-space-v1", required=True)
    parser.add_argument("--output-root", required=True)
    args = parser.parse_args(argv)
    try:
        return build(args)
    except (BuildError, OSError, ValueError) as exc:
        print("FAIL:%s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
