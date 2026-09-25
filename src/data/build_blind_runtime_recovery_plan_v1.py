#!/usr/bin/env python3
"""Pure, Python-3.6-compatible focused BLIND runtime recovery planning.

This module accepts only in-memory snapshots.  It never opens evidence,
serializes a plan, invokes Tessent, or submits LSF.  A caller that is later
authorized to persist the returned records must use the contract's A-private
output root and a separate execution gate.
"""
from __future__ import print_function

import re

from src.data import blind_join_core_v12_r3 as core


FIXED_CIRCUITS = ("s9234", "s38584", "wb_dma")
FORMAL_STAGES = frozenset(("02_hf_coarse", "03_hmf_coarse", "04_integer_refine"))

# Every accepted form is historical and exact.  The output mode is supplied by
# the measurement column; run-id parsing checks that it agrees with the form.
_V2_HF_H = re.compile(r"^(?P<circuit>[A-Za-z0-9_]+)_cov95v2_HF_c(?P<coordinate>[0-9]+)_H_p(?P<limit>[1-9][0-9]*)$")
_V2_HMF_H = re.compile(r"^(?P<circuit>[A-Za-z0-9_]+)_cov95v2_HMF_h(?P<coordinate>[0-9]+)_H_p(?P<limit>[1-9][0-9]*)$")
_V2_HMF_MFULL = re.compile(r"^(?P<circuit>[A-Za-z0-9_]+)_cov95v2_HMF_h(?P<coordinate>[0-9]+)_Mfull$")
_V2_HMF_MLIMIT = re.compile(r"^(?P<circuit>[A-Za-z0-9_]+)_cov95v2_HMF_h(?P<coordinate>[0-9]+)_m[0-9]+_p(?P<limit>[1-9][0-9]*)$")
_P2_HF_H = re.compile(r"^s38584_HF_src_H_(?P<h_pct>[1-9][0-9]*)pct_p(?P<limit>[1-9][0-9]*)_v0_1$")
_P2_HMF_H = re.compile(r"^s38584_HMF_src_H_(?P<h_pct>[1-9][0-9]*)pct_p(?P<limit>[1-9][0-9]*)_v0_1$")
_P2_HMF_MFULL = re.compile(r"^s38584_HMF_H_(?P<h_pct>[1-9][0-9]*)pct_p(?P<h_limit>[1-9][0-9]*)_Mfull_v0_1$")
_P2_HMF_MLIMIT = re.compile(r"^s38584_HMF_H_(?P<h_pct>[1-9][0-9]*)pct_p(?P<h_limit>[1-9][0-9]*)_M_(?P<m_pct>[1-9][0-9]*)pct_p(?P<limit>[1-9][0-9]*)_v0_1$")
_POSITIVE_COUNT = re.compile(r"^[1-9][0-9]*$")


class RecoveryPlanFailure(Exception):
    def __init__(self, stage, code):
        Exception.__init__(self, stage + ":" + code)
        self.stage = stage
        self.code = code


def _basename(path):
    return core._basename(path)


def _value(row, key):
    return core._value(row, key)


def _parse_attempts(log_snapshots):
    attempts = []
    for relative, snapshot in sorted(log_snapshots.items()):
        try:
            digest, payload = snapshot
        except (TypeError, ValueError):
            raise RecoveryPlanFailure("SOURCE_INVENTORY", "LOG_SNAPSHOT_SCHEMA")
        if not isinstance(digest, str) or not isinstance(payload, bytes):
            raise RecoveryPlanFailure("SOURCE_INVENTORY", "LOG_SNAPSHOT_SCHEMA")
        attempts.append(core._parse_log(relative, payload, digest))
    return attempts


def _run_id_fields(circuit, stage, mode, marker, depends_on_h_marker, measured_m_patterns):
    """Validate only a recovery-safe subset of historical run-id grammar."""
    if stage == "04_integer_refine":
        raise RecoveryPlanFailure("RUN_ID", "RECOVERY_STAGE_UNSUPPORTED")
    if mode not in ("H", "M"):
        raise RecoveryPlanFailure("RUN_ID", "RECOVERY_MODE_UNSUPPORTED")
    if stage == "02_hf_coarse" and mode == "H":
        match = _P2_HF_H.match(marker) if circuit == "s38584" else _V2_HF_H.match(marker)
        if not match:
            raise RecoveryPlanFailure("RUN_ID", "ILLEGAL_RUN_ID")
        if circuit != "s38584" and match.group("circuit") != circuit:
            raise RecoveryPlanFailure("RUN_ID", "RUN_ID_SCOPE_MISMATCH")
        return int(match.group("limit")), "", ""
    if stage != "03_hmf_coarse":
        raise RecoveryPlanFailure("RUN_ID", "RUN_ID_STAGE_MISMATCH")
    if mode == "H":
        match = _P2_HMF_H.match(marker) if circuit == "s38584" else _V2_HMF_H.match(marker)
        if not match:
            raise RecoveryPlanFailure("RUN_ID", "ILLEGAL_RUN_ID")
        if circuit != "s38584" and match.group("circuit") != circuit:
            raise RecoveryPlanFailure("RUN_ID", "RUN_ID_SCOPE_MISMATCH")
        return int(match.group("limit")), "", ""
    if not depends_on_h_marker:
        raise RecoveryPlanFailure("DEPENDENCY", "MISSING_H_DEPENDENCY")
    if circuit == "s38584":
        match = _P2_HMF_MFULL.match(marker) or _P2_HMF_MLIMIT.match(marker)
        expected = _P2_HMF_H.match(depends_on_h_marker)
        if not match or not expected:
            raise RecoveryPlanFailure("RUN_ID", "ILLEGAL_RUN_ID")
        # Phase2's M run embeds the H limit; require the same H source limit.
        if (match.group("h_pct") != expected.group("h_pct") or
                int(match.group("h_limit")) != int(expected.group("limit"))):
            raise RecoveryPlanFailure("DEPENDENCY", "H_DEPENDENCY_MISMATCH")
        if match.groupdict().get("limit"):
            limit = int(match.group("limit"))
            if limit != int(measured_m_patterns):
                raise RecoveryPlanFailure("RUN_ID", "M_PATTERN_LIMIT_MISMATCH")
            return limit, depends_on_h_marker, "limited"
        if not _POSITIVE_COUNT.match(measured_m_patterns):
            raise RecoveryPlanFailure("RUN_ID", "MFULL_M_PATTERN_INVALID")
        return int(measured_m_patterns), depends_on_h_marker, "full"
    match = _V2_HMF_MFULL.match(marker) or _V2_HMF_MLIMIT.match(marker)
    expected = _V2_HMF_H.match(depends_on_h_marker)
    if not match or not expected:
        raise RecoveryPlanFailure("RUN_ID", "ILLEGAL_RUN_ID")
    if match.group("circuit") != circuit or expected.group("circuit") != circuit:
        raise RecoveryPlanFailure("RUN_ID", "RUN_ID_SCOPE_MISMATCH")
    # V2 HMF M encodes the actual H pattern count while the H source encodes
    # the checkpoint index.  Their only safe equality is M.h == H.p_limit.
    if int(match.group("coordinate")) != int(expected.group("limit")):
        raise RecoveryPlanFailure("DEPENDENCY", "H_DEPENDENCY_MISMATCH")
    if match.groupdict().get("limit"):
        limit = int(match.group("limit"))
        if limit != int(measured_m_patterns):
            raise RecoveryPlanFailure("RUN_ID", "M_PATTERN_LIMIT_MISMATCH")
        return limit, depends_on_h_marker, "limited"
    if not _POSITIVE_COUNT.match(measured_m_patterns):
        raise RecoveryPlanFailure("RUN_ID", "MFULL_M_PATTERN_INVALID")
    return int(measured_m_patterns), depends_on_h_marker, "full"


def _all_marker_matches(attempts, marker):
    return [item for item in attempts
            if item["source_marker"] == marker or item["run_id"] == marker]


def _bare_run_id(mode, source_marker):
    """Accept only the exact measurement-result prefix for the declared mode."""
    expected = mode + "_"
    if not source_marker.startswith(expected) or source_marker == expected:
        raise RecoveryPlanFailure("RUN_ID", "SOURCE_MARKER_PREFIX_MISMATCH")
    return source_marker[len(expected):]


def _reference_state(attempts, mode, marker):
    """Classify without treating a wall-less existing log as recoverable."""
    matches = _all_marker_matches(attempts, marker)
    if not matches:
        return "MISSING"
    if len(matches) != 1:
        raise RecoveryPlanFailure("JOIN", "AMBIGUOUS_LOG_MATCH")
    item = matches[0]
    if item["mode"] != mode:
        raise RecoveryPlanFailure("JOIN", "LOG_MODE_CONFLICT")
    if not item["wall_s"]:
        raise RecoveryPlanFailure("JOIN", "EXISTS_MISSING_WALL")
    return "UNIQUE"


def _iter_formal_references(circuit, measurement_snapshots):
    seen_tables = set()
    for relative, stage, kind in core.LAYOUTS:
        if stage not in FORMAL_STAGES:
            continue
        if relative not in measurement_snapshots:
            raise RecoveryPlanFailure("SOURCE_INVENTORY", "MEASUREMENT_SNAPSHOT_MISSING")
        if relative in seen_tables:
            raise RecoveryPlanFailure("SOURCE_INVENTORY", "MEASUREMENT_LAYOUT_DUPLICATE")
        seen_tables.add(relative)
        digest, payload = measurement_snapshots[relative]
        if not isinstance(digest, str) or not isinstance(payload, bytes):
            raise RecoveryPlanFailure("SOURCE_INVENTORY", "MEASUREMENT_SNAPSHOT_SCHEMA")
        try:
            rows = core._decode_table(payload)
        except core.JoinFailure:
            raise RecoveryPlanFailure("MEASUREMENT_PARSE", "MEASUREMENT_SCHEMA_FAILURE")
        for row in rows:
            # This also rejects malformed H/M counts before emitting a plan.
            try:
                core.canonical_action_uid(circuit, kind, row)
            except core.JoinFailure:
                raise RecoveryPlanFailure("MEASUREMENT_PARSE", "MEASUREMENT_SCHEMA_FAILURE")
            for mode, result in core._source_rows(kind, row):
                marker = _basename(result)
                if core._is_not_run(row, mode, marker):
                    continue
                if not marker:
                    raise RecoveryPlanFailure("MEASUREMENT_PARSE", "MISSING_RESULT_MARKER")
                depends_on_h_marker = ""
                measured_m_patterns = ""
                if kind == "hmf" and mode == "M":
                    depends_on_h_marker = _basename(_value(row, "h_result"))
                    measured_m_patterns = _value(row, "m_patterns")
                    if not depends_on_h_marker:
                        raise RecoveryPlanFailure("DEPENDENCY", "MISSING_H_DEPENDENCY")
                yield stage, mode, marker, depends_on_h_marker, measured_m_patterns


def build_recovery_plan(circuit, log_snapshots, measurement_snapshots):
    """Return a minimal, deduplicated plan for *one* fixed BLIND circuit.

    Each returned dictionary contains no result path, measurement values,
    coverage, log text, or runtime.  It is intentionally not an executable
    job specification.
    """
    if circuit not in FIXED_CIRCUITS:
        raise RecoveryPlanFailure("SCOPE", "CIRCUIT_NOT_AUTHORIZED")
    if not isinstance(log_snapshots, dict) or not isinstance(measurement_snapshots, dict):
        raise RecoveryPlanFailure("SOURCE_INVENTORY", "SNAPSHOT_CONTAINER_SCHEMA")
    attempts = _parse_attempts(log_snapshots)
    planned = {}
    for stage, mode, marker, depends_on_h_marker, measured_m_patterns in _iter_formal_references(circuit, measurement_snapshots):
        state = _reference_state(attempts, mode, marker)
        if state == "UNIQUE":
            continue
        if mode == "F":
            raise RecoveryPlanFailure("SCOPE", "OUT_OF_SCOPE_MODE")
        run_id = _bare_run_id(mode, marker)
        dependency_run_id = (_bare_run_id("H", depends_on_h_marker)
                             if depends_on_h_marker else "")
        limit, unused_dependency, variant = _run_id_fields(
            circuit, stage, mode, run_id, dependency_run_id, measured_m_patterns)
        record = {"circuit": circuit, "stage": stage, "mode": mode,
                  "run_id": run_id, "source_marker": marker,
                  "pattern_limit": limit, "run_kind": variant,
                  "depends_on_h_marker": depends_on_h_marker}
        key = (record["circuit"], record["stage"], record["mode"], record["run_id"],
               record["source_marker"])
        if key in planned and planned[key] != record:
            raise RecoveryPlanFailure("PLAN", "DUPLICATE_ATTEMPT_CONFLICT")
        planned[key] = record
    return [planned[key] for key in sorted(planned)]
