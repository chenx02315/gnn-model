#!/usr/bin/env python3
"""Fail-closed BLIND runtime recovery execution design.

The checked-in contract is design-only.  The module validates the A-private
plan, derives an exact H-before-M command manifest, and refuses execution until
an independently reviewed contract explicitly enables it.  It never reads
measurement tables or candidate features.
"""
from __future__ import print_function

import argparse
import hashlib
import json
import os
import re
import sys


CONTRACT_RELATIVE = "contracts/blind_runtime_recovery_execution_v1.json"
PLAN_FIELDS = frozenset(("circuit", "stage", "mode", "run_id", "source_marker",
                         "pattern_limit", "run_kind", "depends_on_h_marker"))
PLAN_SHA256 = "b5cf0525b635fd4832fb1b1d7cc9f88f61c2d13cedbe77b9ce0d7b0d5dd2d4e1"
PLAN_COUNTS = {"s9234": 1, "s38584": 42, "wb_dma": 1}
RUN_ID = re.compile(r"^[A-Za-z0-9_]+$")


class Refusal(Exception):
    pass


def _require(condition, code):
    if not condition:
        raise Refusal(code)


def _sha256_bytes(payload):
    return hashlib.sha256(payload).hexdigest()


def _read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()


def _load_json_bytes(payload, code):
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Refusal(code)


def validate_contract(root):
    path = os.path.join(root, CONTRACT_RELATIVE)
    payload = _read_bytes(path)
    contract = _load_json_bytes(payload, "CONTRACT_JSON")
    _require(contract.get("schema_version") == "blind-runtime-recovery-execution-v1",
             "CONTRACT_SCHEMA")
    _require(contract.get("status") == "DESIGN_REVIEW_PENDING_NO_EXECUTION",
             "CONTRACT_STATUS")
    authority = contract.get("authority", {})
    _require(authority == {"execution_authorized": False,
                           "lsf_submission_allowed": False,
                           "training_allowed": False}, "CONTRACT_AUTHORITY")
    plan = contract.get("private_plan", {})
    _require(plan.get("sha256") == PLAN_SHA256, "PLAN_SHA_BINDING")
    _require(plan.get("expected_attempts") == 44, "PLAN_COUNT_BINDING")
    _require(plan.get("expected_counts") == PLAN_COUNTS, "PLAN_CIRCUIT_COUNTS")
    _require(contract.get("attempt_order") == ["H", "M"], "ATTEMPT_ORDER")
    _require(contract.get("historical_evidence", {}).get("write_policy") == "READ_ONLY",
             "HISTORICAL_WRITE_POLICY")
    _require(contract.get("output", {}).get("overwrite") == "REFUSE",
             "OUTPUT_OVERWRITE_POLICY")
    _require(contract.get("command", {}).get("time_argv") == ["/usr/bin/time", "-v"],
             "TIME_COMMAND")
    _require(contract.get("command", {}).get("tessent_argv") == [
        "/cad/mentor/tessent2021_2/bin/tessent", "-shell", "-license_wait", "5"],
        "TESSENT_COMMAND")
    command_hashes = contract.get("command", {}).get("artifact_sha256", {})
    _require(command_hashes == {
        "/usr/bin/time": "54643b2f510907c0bc0a1d13373f1d8233deb38c90dd97ebd9ecb27010e4d803",
        "/cad/mentor/tessent2021_2/bin/tessent": "d92e81eaacf0727fd18d4cafa67d7c9a066069c6d8f7fc05caaf1252c3e44905",
        "stage_mapped_common_atpg_no_tsdb.tcl": "100d58c816d7e318e81e03aae2d9436405cbb90bf629c4104f462b4c7047d529",
        "stage_mapped_incremental_atpg_no_tsdb.tcl": "c2419bac5569192bfa04987d2e71c3e0aa4dadb8d8c22e755cc08318b2aaca95",
    }, "COMMAND_DIGEST_BINDING")
    artifacts = contract.get("implementation", {}).get("artifact_sha256", {})
    expected_artifacts = {
        "src/data/run_blind_runtime_recovery_execution_v1.py",
        "tests/test_run_blind_runtime_recovery_execution_v1.py",
    }
    _require(set(artifacts) == expected_artifacts, "IMPLEMENTATION_SET")
    for relative, expected in artifacts.items():
        _require(isinstance(expected, str) and re.match(r"^[0-9a-f]{64}$", expected),
                 "IMPLEMENTATION_DIGEST_SCHEMA")
        _require(_sha256_bytes(_read_bytes(os.path.join(root, relative))) == expected,
                 "IMPLEMENTATION_DIGEST")
    return contract, _sha256_bytes(payload)


def validate_plan_bytes(payload, contract):
    _require(_sha256_bytes(payload) == PLAN_SHA256, "PLAN_DIGEST")
    document = _load_json_bytes(payload, "PLAN_JSON")
    _require(isinstance(document, dict) and set(document) == {
        "schema_version", "status", "training_allowed", "circuits"},
        "PLAN_CONTAINER")
    _require(document.get("schema_version") == "blind-runtime-recovery-plan-v1" and
             document.get("status") == "PLAN_ONLY" and
             document.get("training_allowed") is False, "PLAN_CONTROL_FIELDS")
    circuit_items = document.get("circuits")
    _require(isinstance(circuit_items, list) and len(circuit_items) == 3,
             "PLAN_CIRCUIT_CONTAINER")
    plan = []
    envelope_counts = {}
    for item in circuit_items:
        _require(isinstance(item, dict) and set(item) == {"circuit", "attempts"},
                 "PLAN_CIRCUIT_SCHEMA")
        circuit = item.get("circuit")
        attempts = item.get("attempts")
        _require(circuit in PLAN_COUNTS and circuit not in envelope_counts,
                 "PLAN_CIRCUIT_ENVELOPE")
        _require(isinstance(attempts, list), "PLAN_ATTEMPT_CONTAINER")
        envelope_counts[circuit] = len(attempts)
        plan.extend(attempts)
    _require(envelope_counts == PLAN_COUNTS, "PLAN_ENVELOPE_COUNTS")
    _require(len(plan) == 44, "PLAN_ATTEMPT_COUNT")
    seen = set()
    counts = dict((name, 0) for name in PLAN_COUNTS)
    h_markers = {}
    for row in plan:
        _require(isinstance(row, dict) and set(row) == PLAN_FIELDS, "PLAN_ROW_SCHEMA")
        circuit = row.get("circuit")
        mode = row.get("mode")
        stage = row.get("stage")
        run_id = row.get("run_id")
        marker = row.get("source_marker")
        _require(circuit in PLAN_COUNTS, "PLAN_CIRCUIT")
        _require(mode in ("H", "M"), "PLAN_MODE")
        _require(stage in ("01_single_mode_full", "02_hf_coarse", "03_hmf_coarse"),
                 "PLAN_STAGE")
        _require(isinstance(run_id, str) and RUN_ID.match(run_id), "PLAN_RUN_ID")
        _require(marker == mode + "_" + run_id, "PLAN_SOURCE_MARKER")
        _require(isinstance(row.get("pattern_limit"), int) and
                 row["pattern_limit"] > 0, "PLAN_PATTERN_LIMIT")
        key = (circuit, stage, mode, run_id)
        _require(key not in seen, "PLAN_DUPLICATE")
        seen.add(key)
        counts[circuit] += 1
        if mode == "H":
            _require(not row.get("depends_on_h_marker"), "H_HAS_DEPENDENCY")
            h_markers[(circuit, marker)] = row
        else:
            _require(stage == "03_hmf_coarse", "M_STAGE")
            dependency = row.get("depends_on_h_marker")
            _require((circuit, dependency) in h_markers, "M_DEPENDENCY_ORDER")
            _require(row.get("run_kind") in ("full", "limited"), "M_RUN_KIND")
    _require(counts == PLAN_COUNTS, "PLAN_COUNTS")
    return plan


def _circuit_binding(contract, circuit):
    bindings = contract.get("circuit_bindings", {})
    _require(set(bindings) == set(PLAN_COUNTS), "CIRCUIT_BINDING_SET")
    item = bindings[circuit]
    required = ("source_root", "framework", "common_fault_dir", "config")
    _require(all(isinstance(item.get(key), str) and item.get(key) for key in required),
             "CIRCUIT_BINDING_SCHEMA")
    return item


def build_command_manifest(plan, contract):
    """Derive non-secret command bindings; no process is executed."""
    recovery_root = contract["output"]["root"]
    manifest = []
    outputs = set()
    for index, row in enumerate(plan):
        binding = _circuit_binding(contract, row["circuit"])
        workspace = os.path.join(recovery_root, "workspaces", row["circuit"])
        output = os.path.join(workspace, row["stage"],
                              row["mode"] + "_" + row["run_id"])
        _require(output not in outputs, "OUTPUT_COLLISION")
        outputs.add(output)
        env = {
            "CIRCUIT_ROOT": workspace,
            "CIRCUIT": row["circuit"],
            "MODE": row["mode"],
            "RUN_ID": row["run_id"],
            "PHASE": row["stage"],
            "COMMON_FAULT_DIR": binding["common_fault_dir"],
            "PATTERN_LIMIT": str(row["pattern_limit"]),
        }
        dofile = "stage_mapped_common_atpg_no_tsdb.tcl"
        status_file = ""
        if row["mode"] == "M":
            dependency = row["depends_on_h_marker"][2:]
            status_file = os.path.join(workspace, "03_hmf_coarse",
                                       "H_" + dependency, "faults.mtfi")
            env["STATUS_FILE"] = status_file
            dofile = "stage_mapped_incremental_atpg_no_tsdb.tcl"
            if row["run_kind"] == "full":
                del env["PATTERN_LIMIT"]
        log_stem = "%03d_%s_%s" % (index + 1, row["mode"], row["run_id"])
        manifest.append({
            "attempt_index": index + 1,
            "circuit": row["circuit"],
            "stage": row["stage"],
            "mode": row["mode"],
            "run_id": row["run_id"],
            "source_root": binding["source_root"],
            "workspace": workspace,
            "output": output,
            "status_file": status_file,
            "environment": env,
            "argv": contract["command"]["time_argv"] +
                    contract["command"]["tessent_argv"] + [
                        "-log", os.path.join(recovery_root, "logs", row["circuit"],
                                             log_stem + ".tessent.log"),
                        "-replace", "-dofile", os.path.join(binding["framework"], dofile)],
            "driver_log": os.path.join(recovery_root, "logs", row["circuit"],
                                       log_stem + ".driver.log"),
        })
    return manifest


def preflight_sources(contract):
    """Verify immutable command/input anchors without creating output."""
    output_root = contract["output"]["root"]
    _require(not os.path.lexists(output_root), "OUTPUT_ROOT_EXISTS")
    hashes = contract["command"]["artifact_sha256"]
    for path in ("/usr/bin/time", "/cad/mentor/tessent2021_2/bin/tessent"):
        _require(os.path.isfile(path) and not os.path.islink(path), "COMMAND_PATH")
        _require(_sha256_bytes(_read_bytes(path)) == hashes[path], "COMMAND_DIGEST")
    for circuit in PLAN_COUNTS:
        binding = _circuit_binding(contract, circuit)
        root = binding["source_root"]
        _require(os.path.isdir(root) and not os.path.islink(root), "SOURCE_ROOT")
        _require(os.path.isfile(binding["config"]), "SOURCE_CONFIG")
        for mode in ("H", "M"):
            _require(os.path.isdir(os.path.join(root, "99_tmp", mode + "_mapped_tsdb")),
                     "SOURCE_TSDB")
            fault = os.path.join(root, "03_fault_universe", binding["common_fault_dir"],
                                 mode + "_common_initial_faults.basic")
            _require(os.path.isfile(fault), "SOURCE_COMMON_FAULT")
        for name in ("stage_mapped_common_atpg_no_tsdb.tcl",
                     "stage_mapped_incremental_atpg_no_tsdb.tcl"):
            path = os.path.join(binding["framework"], name)
            _require(os.path.isfile(path), "SOURCE_TCL")
            _require(_sha256_bytes(_read_bytes(path)) == hashes[name], "SOURCE_TCL_DIGEST")
    return True


def validate_only(root, plan_path, source_preflight=False):
    contract, contract_sha = validate_contract(root)
    plan_payload = _read_bytes(plan_path)
    plan = validate_plan_bytes(plan_payload, contract)
    manifest = build_command_manifest(plan, contract)
    if source_preflight:
        preflight_sources(contract)
    return {"status": "PASS_DESIGN_NO_EXECUTION", "attempts": len(manifest),
            "contract_sha256": contract_sha, "plan_sha256": PLAN_SHA256,
            "execution_authorized": False, "training_allowed": False}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--plan", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--source-preflight", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = validate_only(os.path.abspath(args.root), args.plan,
                               source_preflight=args.source_preflight)
        if args.execute:
            raise Refusal("EXECUTION_NOT_AUTHORIZED")
        print(json.dumps(result, sort_keys=True))
        return 0
    except (IOError, OSError, Refusal) as exc:
        print("BLIND_RUNTIME_RECOVERY_EXECUTION_V1=REFUSED:%s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
