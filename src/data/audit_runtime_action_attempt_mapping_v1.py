#!/usr/bin/env python3
"""Fail-closed action-invocation to runtime-attempt mapping audit."""
from __future__ import print_function

import argparse
import collections
import csv
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from runtime_schema import MANIFEST_V2_FIELDS


ACTION_FIELDS = (
    "action_uid", "circuit", "action_scheme", "mode_stack", "h_patterns",
    "m_patterns", "repeat_measurement_count", "source_candidate_uids",
    "source_stages", "outcome_conflict", "outcome_conflict_fields",
)
EDGE_FIELDS = (
    "action_uid", "source_candidate_uid", "circuit", "stage", "action_scheme",
    "h_patterns", "m_patterns", "mode", "retry_group_id", "retry_order",
    "attempt_id", "mapping_rule",
)
EXCLUSION_FIELDS = (
    "circuit", "stage", "mode", "attempt_id", "exclusion_reason",
)
SOURCE_UID_RE = re.compile(
    r"^([^:]+):(hf_coarse|hmf_coarse|hf_refine|hmf_refine):([^:]+):(\d+)$")
HF_F_RE = re.compile(r"_HF(?:_c\d+)?(?:_refine)?_h(\d+)_", re.I)
HMF_F_RE = re.compile(r"_HMF(?:_c\d+)?(?:_refine)?_h(\d+)_m(\d+)_", re.I)
FORMAL_STAGES = frozenset(("02_hf_coarse", "03_hmf_coarse", "04_integer_refine"))
FORMAL_CIRCUITS = frozenset((
    "s13207", "s15850", "s35932", "s38417",
    "aes_core", "spi", "s5378", "tv80",
))
SOURCE_LAYOUT = {
    "hf_coarse": ("02_hf_coarse", "02_hf_coarse__measurements.tsv", "HF"),
    "hmf_coarse": ("03_hmf_coarse", "03_hmf_coarse__measurements.tsv", "HMF"),
    "hf_refine": ("04_integer_refine", "04_integer_refine__hf_measurements.tsv", "HF"),
    "hmf_refine": ("04_integer_refine", "04_integer_refine__hmf_measurements.tsv", "HMF"),
}


class MappingError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise MappingError(code)


def value(row, key):
    return (row.get(key) or "").strip()


def digest(path):
    answer = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            answer.update(block)
    return answer.hexdigest()


def basename(path):
    name = os.path.basename((path or "").replace("\\", "/").rstrip("/"))
    for suffix in (".driver.log", ".log", ".tsv", ".csv"):
        if name.endswith(suffix):
            return name[:-len(suffix)]
    return name


def evidence_root(path, circuit):
    parts = [part for part in (path or "").replace("\\", "/").split("/") if part]
    if "10_circuits" in parts:
        index = parts.index("10_circuits")
        if index + 2 < len(parts) and parts[index + 1] == circuit:
            return parts[index + 2]
    return parts[0] if len(parts) > 1 else ""


def read_tsv(path, expected, label):
    require(os.path.isfile(path) and not os.path.islink(path), label + "_MISSING")
    with open(path, "r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        require(tuple(reader.fieldnames or ()) == tuple(expected), label + "_FIELDS")
        rows = list(reader)
    require(rows, label + "_EMPTY")
    return rows


def measurement_rows(path):
    require(os.path.isfile(path) and not os.path.islink(path), "MEASUREMENT_MISSING")
    with open(path, "r", encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream, delimiter="\t"))
    require(rows, "MEASUREMENT_EMPTY")
    by_candidate = {}
    for row in rows:
        candidate = value(row, "candidate")
        require(candidate.isdigit() and candidate not in by_candidate,
                "MEASUREMENT_CANDIDATE_INVALID")
        by_candidate[candidate] = row
    return by_candidate


def write_tsv(path, fields, rows):
    with open(path, "x", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def parse_f_key(run_id, scheme):
    match = (HF_F_RE if scheme == "HF" else HMF_F_RE).search(run_id)
    if not match:
        return None
    h = str(int(match.group(1)))
    m = "" if scheme == "HF" else str(int(match.group(2)))
    return h, m


def audit(candidate_space, measurement_root, manifest_root, output_dir):
    actions = read_tsv(candidate_space, ACTION_FIELDS, "CANDIDATE_SPACE")
    action_map, invocations, measurement_cache = {}, [], {}
    actions = [action for action in actions if value(action, "circuit") in FORMAL_CIRCUITS]
    require(set(value(action, "circuit") for action in actions) == FORMAL_CIRCUITS,
            "FORMAL_CIRCUIT_ROSTER_MISMATCH")
    for action in actions:
        uid = value(action, "action_uid")
        require(uid and uid not in action_map, "ACTION_UID_NOT_UNIQUE")
        require(value(action, "outcome_conflict") == "false", "ACTION_OUTCOME_CONFLICT")
        sources = value(action, "source_candidate_uids").split("|")
        require(len(sources) == int(value(action, "repeat_measurement_count")),
                "ACTION_REPEAT_COUNT_MISMATCH")
        action_map[uid] = action
        for source_uid in sources:
            match = SOURCE_UID_RE.match(source_uid)
            require(match is not None and match.group(1) == value(action, "circuit"),
                    "SOURCE_UID_INVALID")
            alias, candidate = match.group(2), match.group(4)
            stage, filename, scheme = SOURCE_LAYOUT[alias]
            require(scheme == value(action, "action_scheme"), "SOURCE_SCHEME_MISMATCH")
            cache_key = (match.group(1), alias)
            if cache_key not in measurement_cache:
                measurement_cache[cache_key] = measurement_rows(
                    os.path.join(measurement_root, match.group(1), filename))
            table = measurement_cache[cache_key]
            require(candidate in table, "SOURCE_CANDIDATE_MISSING")
            row = table[candidate]
            h = str(int(value(row, "h_patterns")))
            m = "" if scheme == "HF" else str(int(value(row, "m_patterns")))
            values_match = (
                h == str(int(value(action, "h_patterns"))) and
                (scheme == "HF" or m == str(int(value(action, "m_patterns"))))
            )
            require(values_match, "SOURCE_ACTION_VALUE_MISMATCH")
            invocations.append({
                "action_uid": uid, "source_candidate_uid": source_uid,
                "circuit": match.group(1), "stage": stage, "scheme": scheme,
                "h": h, "m": m, "measurement": row,
            })

    # Index every historical formal source row, including non-PASS rows.  This
    # proves that excluded search work belongs to a real non-eligible source
    # invocation instead of silently discarding an unexplained attempt.
    all_invocation_index, all_marker_index, allowed_evidence_roots = {}, {}, {}
    for circuit in sorted(FORMAL_CIRCUITS):
        for alias, layout in sorted(SOURCE_LAYOUT.items()):
            stage, filename, scheme = layout
            cache_key = (circuit, alias)
            if cache_key not in measurement_cache:
                measurement_cache[cache_key] = measurement_rows(
                    os.path.join(measurement_root, circuit, filename))
            for candidate, row in measurement_cache[cache_key].items():
                h = str(int(value(row, "h_patterns")))
                m = "" if scheme == "HF" else str(int(value(row, "m_patterns")))
                item = {"circuit": circuit, "stage": stage, "scheme": scheme,
                        "h": h, "m": m, "candidate": candidate,
                        "status": value(row, "result_status"), "measurement": row}
                all_invocation_index.setdefault((circuit, stage, scheme, h, m), []).append(item)
                for mode in (("H", "F") if scheme == "HF" else ("H", "M", "F")):
                    result_path = value(row, mode.lower() + "_result")
                    marker = basename(result_path)
                    if marker:
                        all_marker_index.setdefault((circuit, stage, mode, marker), []).append(item)
                        root = evidence_root(result_path, circuit)
                        if root:
                            allowed_evidence_roots.setdefault((circuit, mode), set()).add(root)

    manifests, attempts_by_circuit, marker_index, global_marker_index = {}, {}, {}, {}
    for circuit in sorted(set(item["circuit"] for item in invocations)):
        path = os.path.join(manifest_root, circuit + "_attempt_manifest_v2_remediated.tsv")
        rows = read_tsv(path, MANIFEST_V2_FIELDS, "ATTEMPT_MANIFEST")
        manifests[circuit] = {"path": path, "sha256": digest(path), "rows": rows}
        attempts_by_circuit[circuit] = rows
        for attempt in rows:
            require(value(attempt, "circuit") == circuit, "ATTEMPT_CIRCUIT_MISMATCH")
            key = (circuit, value(attempt, "stage"), value(attempt, "mode"),
                   basename(value(attempt, "source_log_path")))
            marker_index.setdefault(key, []).append(attempt)
            global_key = (circuit, value(attempt, "mode"),
                          basename(value(attempt, "source_log_path")))
            global_marker_index.setdefault(global_key, []).append(attempt)

    invocation_index = {}
    edges, edge_keys, mapped_attempt_ids = [], set(), set()
    for item in invocations:
        key = (item["circuit"], item["stage"], item["scheme"], item["h"], item["m"])
        invocation_index.setdefault(key, []).append(item)
        modes = ("H", "F") if item["scheme"] == "HF" else ("H", "M", "F")
        for mode in modes:
            marker = basename(value(item["measurement"], mode.lower() + "_result"))
            if not marker:
                require(mode == "F" and value(item["measurement"], "result_status") in
                        ("TARGET_BEFORE_F", "INFEASIBLE_AT_D95"), "DIRECT_RESULT_MISSING")
                continue
            matches = marker_index.get((item["circuit"], item["stage"], mode, marker), [])
            mapping_rule = "DIRECT_RESULT_BASENAME"
            if not matches:
                matches = global_marker_index.get((item["circuit"], mode, marker), [])
                mapping_rule = "DIRECT_RESULT_BASENAME_CROSS_STAGE"
            require(len(matches) == 1,
                    "DIRECT_RESULT_MATCH_COUNT_%d:%s:%s:%s:%s:%s" %
                    (len(matches), item["source_candidate_uid"], item["circuit"],
                     item["stage"], mode, marker))
            attempt = matches[0]
            edge_key = (item["source_candidate_uid"], value(attempt, "attempt_id"))
            if edge_key not in edge_keys:
                edge_keys.add(edge_key)
                mapped_attempt_ids.add(value(attempt, "attempt_id"))
                edges.append({
                    "action_uid": item["action_uid"],
                    "source_candidate_uid": item["source_candidate_uid"],
                    "circuit": item["circuit"], "stage": item["stage"],
                    "action_scheme": item["scheme"], "h_patterns": item["h"],
                    "m_patterns": item["m"], "mode": mode,
                    "retry_group_id": value(attempt, "retry_group_id"),
                    "retry_order": value(attempt, "retry_order"),
                    "attempt_id": value(attempt, "attempt_id"),
                    "mapping_rule": mapping_rule,
                })

    blockers, blocker_details, exclusions = [], [], []
    def block(code, detail):
        blockers.append(code)
        if len(blocker_details) < 100:
            blocker_details.append(code + ":" + detail)
    for circuit, attempts in attempts_by_circuit.items():
        for attempt in attempts:
            stage, mode = value(attempt, "stage"), value(attempt, "mode")
            attempt_id, run_id = value(attempt, "attempt_id"), value(attempt, "run_id")
            if attempt_id in mapped_attempt_ids:
                continue
            if stage not in FORMAL_STAGES:
                exclusions.append({"circuit": circuit, "stage": stage, "mode": mode,
                                   "attempt_id": attempt_id,
                                   "exclusion_reason": "OUT_OF_SCOPE_STAGE"})
                continue
            if mode == "M" and run_id.endswith("_Mfull"):
                exclusions.append({"circuit": circuit, "stage": stage, "mode": mode,
                                   "attempt_id": attempt_id,
                                   "exclusion_reason": "COARSE_M_FULL_PROBE"})
                continue
            if mode == "F":
                scheme = "HMF" if "_HMF" in run_id.upper() else "HF" if "_HF" in run_id.upper() else ""
                parsed = parse_f_key(run_id, scheme) if scheme else None
                if parsed is None:
                    block("F_RUN_ID_UNPARSED", "%s:%s:%s" %
                          (circuit, stage, run_id))
                    continue
                key = (circuit, stage, scheme, parsed[0], parsed[1])
                targets = invocation_index.get(key, [])
                all_targets = all_invocation_index.get(key, [])
                if not targets and all_targets and all(
                        item["status"] != "PASS" for item in all_targets):
                    exclusions.append({"circuit": circuit, "stage": stage, "mode": mode,
                                       "attempt_id": attempt_id,
                                       "exclusion_reason": "NON_ELIGIBLE_SOURCE_INVOCATION"})
                    continue
                attempt_root = evidence_root(value(attempt, "source_log_path"), circuit)
                allowed_roots = allowed_evidence_roots.get((circuit, mode), set())
                if not targets and attempt_root and allowed_roots and attempt_root not in allowed_roots:
                    exclusions.append({"circuit": circuit, "stage": stage, "mode": mode,
                                       "attempt_id": attempt_id,
                                       "exclusion_reason": "OUT_OF_SCOPE_EVIDENCE_VERSION"})
                    continue
                if not targets and not all_targets and attempt_root in allowed_roots:
                    exclusions.append({"circuit": circuit, "stage": stage, "mode": mode,
                                       "attempt_id": attempt_id,
                                       "exclusion_reason": "NON_TERMINAL_SEARCH_PROBE"})
                    continue
                if len(targets) != 1:
                    block("F_INVOCATION_MATCH_COUNT_%d" % len(targets),
                          "%s:%s:%s:%s:%s" %
                          (circuit, stage, scheme, parsed[0], parsed[1]))
                    continue
                item = targets[0]
                edge_key = (item["source_candidate_uid"], attempt_id)
                if edge_key not in edge_keys:
                    edge_keys.add(edge_key)
                    mapped_attempt_ids.add(attempt_id)
                    edges.append({
                        "action_uid": item["action_uid"],
                        "source_candidate_uid": item["source_candidate_uid"],
                        "circuit": circuit, "stage": stage, "action_scheme": scheme,
                        "h_patterns": parsed[0], "m_patterns": parsed[1], "mode": mode,
                        "retry_group_id": value(attempt, "retry_group_id"),
                        "retry_order": value(attempt, "retry_order"),
                        "attempt_id": attempt_id, "mapping_rule": "F_SEARCH_RUN_ID",
                    })
                continue
            marker = basename(value(attempt, "source_log_path"))
            all_targets = all_marker_index.get((circuit, stage, mode, marker), [])
            if all_targets and all(item["status"] != "PASS" for item in all_targets):
                exclusions.append({"circuit": circuit, "stage": stage, "mode": mode,
                                   "attempt_id": attempt_id,
                                   "exclusion_reason": "NON_ELIGIBLE_SOURCE_INVOCATION"})
                continue
            attempt_root = evidence_root(value(attempt, "source_log_path"), circuit)
            allowed_roots = allowed_evidence_roots.get((circuit, mode), set())
            if attempt_root and allowed_roots and attempt_root not in allowed_roots:
                exclusions.append({"circuit": circuit, "stage": stage, "mode": mode,
                                   "attempt_id": attempt_id,
                                   "exclusion_reason": "OUT_OF_SCOPE_EVIDENCE_VERSION"})
                continue
            if not all_targets and attempt_root in allowed_roots:
                exclusions.append({"circuit": circuit, "stage": stage, "mode": mode,
                                   "attempt_id": attempt_id,
                                   "exclusion_reason": "NON_TERMINAL_SEARCH_PROBE"})
                continue
            block("FORMAL_H_OR_M_UNMAPPED", "%s:%s:%s:%s:%s" %
                  (circuit, stage, mode, attempt_id, run_id))

    require(not os.path.exists(output_dir), "OUTPUT_DIR_EXISTS")
    os.mkdir(output_dir)
    edges.sort(key=lambda row: (row["source_candidate_uid"], row["mode"],
                                row["retry_group_id"], int(row["retry_order"]), row["attempt_id"]))
    exclusions.sort(key=lambda row: (row["circuit"], row["stage"], row["mode"], row["attempt_id"]))
    edge_path = os.path.join(output_dir, "invocation_attempt_edges_v1.tsv")
    exclusion_path = os.path.join(output_dir, "excluded_attempts_v1.tsv")
    write_tsv(edge_path, EDGE_FIELDS, edges)
    write_tsv(exclusion_path, EXCLUSION_FIELDS, exclusions)
    duplicate_actions = sum(int(value(action, "repeat_measurement_count")) > 1 for action in actions)
    receipt = {
        "schema_version": "runtime-action-attempt-mapping-receipt-v1",
        "status": ("PASS_MAPPING_REPEAT_AGGREGATION_PENDING" if not blockers
                   else "BLOCKED_ACTION_ATTEMPT_MAPPING"),
        "candidate_space_sha256": digest(candidate_space),
        "counts": {
            "action_count": len(actions), "source_invocation_count": len(invocations),
            "duplicate_action_count": duplicate_actions, "edge_count": len(edges),
            "distinct_mapped_attempt_count": len(set(row["attempt_id"] for row in edges)),
            "excluded_attempt_count": len(exclusions),
            "out_of_scope_stage_count": sum(row["exclusion_reason"] == "OUT_OF_SCOPE_STAGE" for row in exclusions),
            "coarse_m_full_probe_count": sum(row["exclusion_reason"] == "COARSE_M_FULL_PROBE" for row in exclusions),
            "non_eligible_source_invocation_count": sum(
                row["exclusion_reason"] == "NON_ELIGIBLE_SOURCE_INVOCATION" for row in exclusions),
            "out_of_scope_evidence_version_count": sum(
                row["exclusion_reason"] == "OUT_OF_SCOPE_EVIDENCE_VERSION" for row in exclusions),
            "non_terminal_search_probe_count": sum(
                row["exclusion_reason"] == "NON_TERMINAL_SEARCH_PROBE" for row in exclusions),
        },
        "manifest_sha256": dict((circuit, item["sha256"]) for circuit, item in sorted(manifests.items())),
        "output_sha256": {"invocation_attempt_edges_v1.tsv": digest(edge_path),
                          "excluded_attempts_v1.tsv": digest(exclusion_path)},
        "blockers": sorted(set(blockers)),
        "blocker_counts": dict(sorted(collections.Counter(blockers).items())),
        "blocker_samples": blocker_details,
        "boundaries": {"training_allowed": False, "blind_rows_read": False,
                       "lsf_or_tessent_submitted": False, "repeat_aggregation_allowed": False},
    }
    receipt_path = os.path.join(output_dir, "receipt_v1.json")
    with open(receipt_path, "x", encoding="utf-8", newline="\n") as stream:
        json.dump(receipt, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(json.dumps(receipt, sort_keys=True))
    return 0 if not blockers else 2


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-space", required=True)
    parser.add_argument("--measurement-root", required=True)
    parser.add_argument("--manifest-root", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)
    try:
        return audit(os.path.abspath(args.candidate_space), os.path.abspath(args.measurement_root),
                     os.path.abspath(args.manifest_root), os.path.abspath(args.output_dir))
    except (MappingError, OSError, ValueError) as exc:
        print("FAIL:%s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
