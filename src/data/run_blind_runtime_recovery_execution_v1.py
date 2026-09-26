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
import shutil
import subprocess
import sys


CONTRACT_RELATIVE = "contracts/blind_runtime_recovery_execution_v1.json"
PLAN_FIELDS = frozenset(("circuit", "stage", "mode", "run_id", "source_marker",
                         "pattern_limit", "run_kind", "depends_on_h_marker"))
PLAN_SHA256 = "b5cf0525b635fd4832fb1b1d7cc9f88f61c2d13cedbe77b9ce0d7b0d5dd2d4e1"
PLAN_COUNTS = {"s9234": 1, "s38584": 42, "wb_dma": 1}
RUN_ID = re.compile(r"^[A-Za-z0-9_]+$")
JOB_TEMPLATE_RELATIVE = "contracts/blind_runtime_recovery_execution_v1_job_template.json"
BUNDLE_MANIFEST_RELATIVE = "bundle_manifest.json"
JOB_BUNDLE_ROOT = "/temp/jiangchuanc/blind_runtime_recovery_execution_v1_authorized_r1_bundle"
JOB_REGISTRATION_ROOT = ("/temp/jiangchuanc/multimode_ate_phase4_20260825_A/logs/"
                         "blind_runtime_recovery_execution_v1_registration_r1")
AUTHORIZATION_PATH = JOB_REGISTRATION_ROOT + "/authorization.json"
REGISTRATION_REVIEW_PATH = JOB_REGISTRATION_ROOT + "/independent_review.json"
BJOBS_CAPTURE_PATH = JOB_REGISTRATION_ROOT + "/bjobs.txt"
BJOBS_AL_CAPTURE_PATH = JOB_REGISTRATION_ROOT + "/bjobs_al.txt"


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


def validate_job_template(document):
    _require(isinstance(document, dict) and set(document) == {
        "schema_version", "status", "registration", "lifecycle"},
        "JOB_TEMPLATE_CONTAINER")
    _require(document.get("schema_version") ==
             "blind-runtime-recovery-execution-v1-job-template" and
             document.get("status") == "AUTHORIZED_PRE_REGISTRATION_TEMPLATE",
             "JOB_TEMPLATE_STATUS")
    registration = document.get("registration")
    _require(isinstance(registration, dict) and set(registration) == {
        "queue", "initial_scheduler_state", "job_name", "command_argv", "cwd",
        "stdout_path", "stderr_path", "array_allowed", "retry_allowed",
        "requeue_allowed", "rerun_allowed"}, "JOB_TEMPLATE_REGISTRATION")
    _require(registration == {
        "queue": "normal",
        "initial_scheduler_state": "PSUSP",
        "job_name": "blind_rt_recovery_v1_r1",
        "command_argv": [
            "/bin/bash",
            JOB_BUNDLE_ROOT + "/src/data/launch_blind_runtime_recovery_execution_v1.sh"],
        "cwd": JOB_BUNDLE_ROOT,
        "stdout_path": JOB_REGISTRATION_ROOT + "/stdout.log",
        "stderr_path": JOB_REGISTRATION_ROOT + "/stderr.log",
        "array_allowed": False,
        "retry_allowed": False,
        "requeue_allowed": False,
        "rerun_allowed": False,
    }, "JOB_TEMPLATE_EXACT_REGISTRATION")
    lifecycle = document.get("lifecycle")
    _require(isinstance(lifecycle, dict) and set(lifecycle) == {
        "register", "after_registration", "resume", "forbidden"},
        "JOB_TEMPLATE_LIFECYCLE")
    _require(lifecycle.get("register") == "bsub -H exactly once" and
             lifecycle.get("resume") ==
             "only bresume of the independently reviewed registered Job ID" and
             lifecycle.get("forbidden") == [
                 "second bsub", "bmod", "rerun", "requeue", "array submission",
                 "resume before PASS review"], "JOB_TEMPLATE_EXACT_LIFECYCLE")
    return document


def validate_bundle_manifest(root, contract):
    binding = contract.get("bundle_manifest")
    _require(isinstance(binding, dict) and set(binding) == {
        "root", "path", "sha256", "reviewed_commit"},
        "BUNDLE_MANIFEST_BINDING")
    _require(binding.get("root") == JOB_BUNDLE_ROOT and
             binding.get("path") == BUNDLE_MANIFEST_RELATIVE and
             re.match(r"^[0-9a-f]{64}$", binding.get("sha256", "")) and
             re.match(r"^[0-9a-f]{40}$", binding.get("reviewed_commit", "")),
             "BUNDLE_MANIFEST_BINDING")
    payload = _read_bytes(os.path.join(root, binding["path"]))
    _require(_sha256_bytes(payload) == binding["sha256"],
             "BUNDLE_MANIFEST_DIGEST")
    document = _load_json_bytes(payload, "BUNDLE_MANIFEST_JSON")
    _require(isinstance(document, dict) and set(document) == {
        "schema_version", "status", "reviewed_commit", "artifact_sha256"},
        "BUNDLE_MANIFEST_SCHEMA")
    _require(document.get("schema_version") ==
             "blind-runtime-recovery-execution-v1-bundle-manifest" and
             document.get("status") == "SEALED" and
             document.get("reviewed_commit") == binding["reviewed_commit"],
             "BUNDLE_MANIFEST_STATUS")
    artifacts = contract.get("implementation", {}).get("artifact_sha256", {})
    _require(document.get("artifact_sha256") == artifacts,
             "BUNDLE_MANIFEST_ARTIFACTS")
    for relative, expected in artifacts.items():
        _require(_sha256_bytes(_read_bytes(os.path.join(root, relative))) == expected,
                 "BUNDLE_MANIFEST_ARTIFACT_DIGEST")
    return document


def validate_contract(root):
    path = os.path.join(root, CONTRACT_RELATIVE)
    payload = _read_bytes(path)
    contract = _load_json_bytes(payload, "CONTRACT_JSON")
    _require(contract.get("schema_version") == "blind-runtime-recovery-execution-v1",
             "CONTRACT_SCHEMA")
    status = contract.get("status")
    authority = contract.get("authority", {})
    allowed_states = {
        "DESIGN_REVIEW_PENDING_NO_EXECUTION": {
            "execution_authorized": False, "lsf_submission_allowed": False,
            "training_allowed": False},
        "REVIEWED_EXECUTION_AUTHORIZED": {
            "execution_authorized": True, "lsf_submission_allowed": True,
            "training_allowed": False},
    }
    _require(status in allowed_states, "CONTRACT_STATUS")
    _require(authority == allowed_states[status], "CONTRACT_AUTHORITY")
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
    template_path = os.path.join(root, JOB_TEMPLATE_RELATIVE)
    validate_job_template(_load_json_bytes(_read_bytes(template_path),
                                           "JOB_TEMPLATE_JSON"))
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
        "src/data/launch_blind_runtime_recovery_execution_v1.sh",
        "contracts/blind_runtime_recovery_execution_v1_job_template.json",
        "tests/test_run_blind_runtime_recovery_execution_v1.py",
    }
    _require(set(artifacts) == expected_artifacts, "IMPLEMENTATION_SET")
    for relative, expected in artifacts.items():
        _require(isinstance(expected, str) and re.match(r"^[0-9a-f]{64}$", expected),
                 "IMPLEMENTATION_DIGEST_SCHEMA")
        _require(_sha256_bytes(_read_bytes(os.path.join(root, relative))) == expected,
                 "IMPLEMENTATION_DIGEST")
    validate_bundle_manifest(root, contract)
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
            _require((circuit, marker) not in h_markers, "H_MARKER_AMBIGUOUS")
            h_markers[(circuit, marker)] = row
        else:
            _require(stage == "03_hmf_coarse", "M_STAGE")
            dependency = row.get("depends_on_h_marker")
            _require((circuit, dependency) in h_markers, "M_DEPENDENCY_ORDER")
            _require(h_markers[(circuit, dependency)]["stage"] == "03_hmf_coarse",
                     "M_DEPENDENCY_STAGE")
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


def _refuse_symlinks(root):
    for current, directories, files in os.walk(root):
        for name in directories + files:
            _require(not os.path.islink(os.path.join(current, name)),
                     "SOURCE_SYMLINK")


def _copy_tree(source, target):
    _require(os.path.isdir(source) and not os.path.lexists(target), "COPY_TREE_BOUNDARY")
    _refuse_symlinks(source)
    shutil.copytree(source, target, symlinks=False)


def _tree_entries(root, logical_prefix):
    _require(os.path.isdir(root) and not os.path.islink(root), "MANIFEST_ROOT")
    entries = []
    for current, directories, files in os.walk(root):
        directories.sort()
        files.sort()
        for name in directories:
            _require(not os.path.islink(os.path.join(current, name)), "SOURCE_SYMLINK")
        for name in files:
            path = os.path.join(current, name)
            _require(os.path.isfile(path) and not os.path.islink(path), "MANIFEST_FILE")
            relative = os.path.relpath(path, root).replace(os.sep, "/")
            entries.append({"logical_path": logical_prefix + "/" + relative,
                            "bytes": os.path.getsize(path),
                            "sha256": _sha256_bytes(_read_bytes(path))})
    _require(entries, "MANIFEST_EMPTY")
    return entries


def _file_entry(path, logical_path):
    _require(os.path.isfile(path) and not os.path.islink(path), "MANIFEST_FILE")
    return {"logical_path": logical_path, "bytes": os.path.getsize(path),
            "sha256": _sha256_bytes(_read_bytes(path))}


def build_source_manifest(contract):
    entries = []
    for circuit in sorted(PLAN_COUNTS):
        binding = _circuit_binding(contract, circuit)
        root = binding["source_root"]
        entries.append(_file_entry(binding["config"], circuit + "/01_config/config.env"))
        for mode in ("H", "M"):
            entries.extend(_tree_entries(os.path.join(root, "99_tmp", mode + "_mapped_tsdb"),
                                         circuit + "/99_tmp/" + mode + "_mapped_tsdb"))
        entries.extend(_tree_entries(os.path.join(root, "03_fault_universe",
                                                  binding["common_fault_dir"]),
                                     circuit + "/03_fault_universe/" +
                                     binding["common_fault_dir"]))
    entries.sort(key=lambda item: item["logical_path"])
    logical_paths = [item["logical_path"] for item in entries]
    _require(len(logical_paths) == len(set(logical_paths)), "MANIFEST_DUPLICATE")
    return {"schema_version": "blind-runtime-recovery-source-manifest-v1",
            "plan_sha256": PLAN_SHA256, "entries": entries}


def build_copy_manifest(contract):
    output_root = contract["output"]["root"]
    entries = []
    for circuit in sorted(PLAN_COUNTS):
        binding = _circuit_binding(contract, circuit)
        workspace = os.path.join(output_root, "workspaces", circuit)
        entries.append(_file_entry(os.path.join(workspace, "01_config", "config.env"),
                                   circuit + "/01_config/config.env"))
        for mode in ("H", "M"):
            entries.extend(_tree_entries(os.path.join(workspace, "99_tmp",
                                                      mode + "_mapped_tsdb"),
                                         circuit + "/99_tmp/" + mode + "_mapped_tsdb"))
        entries.extend(_tree_entries(os.path.join(workspace, "03_fault_universe",
                                                  binding["common_fault_dir"]),
                                     circuit + "/03_fault_universe/" +
                                     binding["common_fault_dir"]))
    entries.sort(key=lambda item: item["logical_path"])
    return {"schema_version": "blind-runtime-recovery-copy-manifest-v1",
            "plan_sha256": PLAN_SHA256, "entries": entries}


def _parse_config(path, expected_circuit):
    values = {}
    with open(path, "r") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            _require("=" in line, "CONFIG_LINE")
            key, value = line.split("=", 1)
            _require(re.match(r"^[A-Z][A-Z0-9_]*$", key) and value, "CONFIG_FIELD")
            _require(key not in values, "CONFIG_DUPLICATE")
            values[key] = value
    _require(values.get("CIRCUIT") == expected_circuit, "CONFIG_CIRCUIT")
    _require(values.get("TOP_MODULE") and values.get("CELL_LIBRARY"), "CONFIG_REQUIRED")
    _require(os.path.isfile(values["CELL_LIBRARY"]), "CELL_LIBRARY")
    return {"TOP_MODULE": values["TOP_MODULE"], "CELL_LIBRARY": values["CELL_LIBRARY"]}


def prepare_workspaces(contract):
    """Copy only required mutable Tessent state into a new isolated root."""
    preflight_sources(contract)
    output_root = contract["output"]["root"]
    old_umask = os.umask(0o077)
    try:
        os.makedirs(output_root, 0o700)
        os.makedirs(os.path.join(output_root, "logs"), 0o700)
        os.makedirs(os.path.join(output_root, "receipts"), 0o700)
        source_manifest = build_source_manifest(contract)
        source_manifest_path = os.path.join(output_root, "source_manifest.json")
        _write_json_new(source_manifest_path, source_manifest)
        source_manifest_sha = _sha256_bytes(_read_bytes(source_manifest_path))
        config_values = {}
        for circuit in sorted(PLAN_COUNTS):
            binding = _circuit_binding(contract, circuit)
            source = binding["source_root"]
            workspace = os.path.join(output_root, "workspaces", circuit)
            os.makedirs(os.path.join(workspace, "99_tmp"), 0o700)
            os.makedirs(os.path.join(workspace, "03_fault_universe"), 0o700)
            os.makedirs(os.path.join(workspace, "01_config"), 0o700)
            os.makedirs(os.path.join(output_root, "logs", circuit), 0o700)
            _copy_tree(os.path.join(source, "99_tmp", "H_mapped_tsdb"),
                       os.path.join(workspace, "99_tmp", "H_mapped_tsdb"))
            _copy_tree(os.path.join(source, "99_tmp", "M_mapped_tsdb"),
                       os.path.join(workspace, "99_tmp", "M_mapped_tsdb"))
            _copy_tree(os.path.join(source, "03_fault_universe",
                                    binding["common_fault_dir"]),
                       os.path.join(workspace, "03_fault_universe",
                                    binding["common_fault_dir"]))
            config_target = os.path.join(workspace, "01_config", "config.env")
            shutil.copy2(binding["config"], config_target)
            config_values[circuit] = _parse_config(binding["config"], circuit)
        copy_manifest = build_copy_manifest(contract)
        _require(copy_manifest["entries"] == source_manifest["entries"],
                 "COPY_MANIFEST_MISMATCH")
        copy_document = {"schema_version": "blind-runtime-recovery-copy-verification-v1",
                         "source_manifest_sha256": source_manifest_sha,
                         "copy_matches_source": True,
                         "entries": copy_manifest["entries"]}
        _write_json_new(os.path.join(output_root, "copy_verification.json"), copy_document)
        return config_values, source_manifest_sha
    except Exception:
        # Evidence is deliberately retained.  A new versioned output root is
        # required after any preparation failure.
        raise
    finally:
        os.umask(old_umask)


def _write_json_new(path, document):
    _require(not os.path.lexists(path), "RECEIPT_EXISTS")
    tmp = path + ".tmp"
    _require(not os.path.lexists(tmp), "RECEIPT_TMP_EXISTS")
    payload = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    with open(tmp, "xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, 0o600)
    os.rename(tmp, path)


def _log_result(driver_log, mode):
    payload = _read_bytes(driver_log)
    expected = (b"MAPPED_COMMON_ATPG_STATUS=PASS" if mode == "H" else
                b"MAPPED_INCREMENTAL_ATPG_STATUS=PASS")
    _require(expected in payload, "ATPG_SUCCESS_MARKER")
    _require(b"Elapsed (wall clock) time" in payload and b"Exit status: 0" in payload,
             "GNU_TIME_FOOTER")
    elapsed = ""
    for raw in payload.splitlines():
        if b"Elapsed (wall clock) time" in raw:
            elapsed = raw.split(b": ", 1)[-1].decode("ascii", "strict").strip()
    _require(elapsed, "ELAPSED_VALUE")
    return _sha256_bytes(payload), elapsed


def execute_manifest(manifest, contract, config_values, source_manifest_sha):
    """Execute exactly once in manifest order; any failure stops the chain."""
    output_root = contract["output"]["root"]
    receipts = []
    for item in manifest:
        _require(not os.path.lexists(item["output"]), "ATTEMPT_OUTPUT_EXISTS")
        _require(not os.path.lexists(item["driver_log"]), "ATTEMPT_LOG_EXISTS")
        if item["mode"] == "M":
            _require(os.path.isfile(item["status_file"]), "M_STATUS_FILE_MISSING")
        environment = os.environ.copy()
        environment.update(item["environment"])
        environment.update(config_values[item["circuit"]])
        receipt_path = os.path.join(output_root, "receipts",
                                    "%03d_%s_%s.json" % (
                                        item["attempt_index"], item["mode"], item["run_id"]))
        document = {"schema_version": "blind-runtime-recovery-attempt-receipt-v1",
                    "attempt_index": item["attempt_index"],
                    "circuit": item["circuit"], "stage": item["stage"],
                    "mode": item["mode"], "run_id": item["run_id"],
                    "return_code": None, "retry_count": 0,
                    "output": item["output"], "driver_log": item["driver_log"],
                    "source_manifest_sha256": source_manifest_sha,
                    "status": "FAIL"}
        try:
            with open(item["driver_log"], "xb") as log_handle:
                process = subprocess.Popen(item["argv"], cwd=item["workspace"],
                                           env=environment, stdout=log_handle,
                                           stderr=subprocess.STDOUT)
                return_code = process.wait()
            document["return_code"] = return_code
            _require(return_code == 0, "ATPG_EXIT")
            _require(os.path.isdir(item["output"]), "ATPG_OUTPUT_MISSING")
            _require(os.path.isfile(os.path.join(item["output"], "faults.mtfi")),
                     "ATPG_FAULTS_MISSING")
            log_sha, elapsed = _log_result(item["driver_log"], item["mode"])
            document.update({"status": "PASS", "driver_log_sha256": log_sha,
                             "elapsed_raw": elapsed,
                             "faults_mtfi_sha256": _sha256_bytes(_read_bytes(
                                 os.path.join(item["output"], "faults.mtfi")))})
            _write_json_new(receipt_path, document)
            receipts.append(document)
        except Exception:
            document["driver_log_sha256"] = (_sha256_bytes(_read_bytes(item["driver_log"]))
                                                if os.path.isfile(item["driver_log"]) else "")
            _write_json_new(receipt_path, document)
            raise
    _require(len(receipts) == 44, "EXECUTION_RECEIPT_COUNT")
    return receipts


def validate_only(root, plan_path, source_preflight=False):
    contract, contract_sha = validate_contract(root)
    plan_payload = _read_bytes(plan_path)
    plan = validate_plan_bytes(plan_payload, contract)
    manifest = build_command_manifest(plan, contract)
    if source_preflight:
        preflight_sources(contract)
    authority = contract["authority"]
    return {"status": "PASS_DESIGN_NO_EXECUTION", "attempts": len(manifest),
            "contract_sha256": contract_sha, "plan_sha256": PLAN_SHA256,
            "execution_authorized": authority["execution_authorized"],
            "training_allowed": authority["training_allowed"]}


def validate_registration_review(path, authorization, contract_sha, runner_sha):
    payload = _read_bytes(path)
    document = _load_json_bytes(payload, "REGISTRATION_REVIEW_JSON")
    expected_fields = {
        "schema_version", "status", "lsf_job_id", "initial_scheduler_state",
        "submission_count", "contract_sha256", "plan_sha256", "runner_sha256",
        "launcher_sha256", "job_template_sha256", "bundle_manifest_sha256",
        "reviewed_commit", "no_retry", "no_requeue", "nonarray",
        "training_allowed", "bjobs_path", "bjobs_sha256", "bjobs_al_path",
        "bjobs_al_sha256"}
    _require(isinstance(document, dict) and set(document) == expected_fields,
             "REGISTRATION_REVIEW_SCHEMA")
    _require(document.get("schema_version") ==
             "blind-runtime-recovery-execution-v1-registration-review" and
             document.get("status") == "PASS" and
             document.get("initial_scheduler_state") == "PSUSP" and
             document.get("submission_count") == 1 and
             document.get("training_allowed") is False,
             "REGISTRATION_REVIEW_STATUS")
    for field in ("lsf_job_id", "launcher_sha256", "job_template_sha256",
                  "bundle_manifest_sha256", "reviewed_commit", "bjobs_path",
                  "bjobs_sha256", "bjobs_al_path", "bjobs_al_sha256"):
        _require(document.get(field) == authorization.get(field),
                 "REGISTRATION_REVIEW_BINDING")
    _require(document.get("contract_sha256") == contract_sha and
             document.get("plan_sha256") == PLAN_SHA256 and
             document.get("runner_sha256") == runner_sha,
             "REGISTRATION_REVIEW_BINDING")
    _require(document.get("no_retry") is True and
             document.get("no_requeue") is True and
             document.get("nonarray") is True,
             "REGISTRATION_REVIEW_SCHEDULER")
    _require(_sha256_bytes(payload) == authorization.get("registration_review_sha256"),
             "REGISTRATION_REVIEW_DIGEST")
    return document


def validate_authorization(path, contract_sha, runner_sha, contract,
                           environment=None):
    document = _load_json_bytes(_read_bytes(path), "AUTHORIZATION_JSON")
    expected_fields = {"schema_version", "status", "execution_allowed",
                       "contract_sha256", "plan_sha256", "runner_sha256",
                       "launcher_sha256", "job_template_sha256",
                       "bundle_manifest_sha256",
                       "reviewed_commit", "lsf_job_id", "no_retry", "no_requeue",
                       "nonarray", "training_allowed", "registration_review_path",
                       "registration_review_sha256", "bjobs_path", "bjobs_sha256",
                       "bjobs_al_path", "bjobs_al_sha256"}
    _require(isinstance(document, dict) and set(document) == expected_fields,
             "AUTHORIZATION_SCHEMA")
    _require(document.get("schema_version") ==
             "blind-runtime-recovery-execution-v1-authorization" and
             document.get("status") == "PASS" and
             document.get("execution_allowed") is True and
             document.get("training_allowed") is False, "AUTHORIZATION_STATUS")
    _require(document.get("contract_sha256") == contract_sha and
             document.get("plan_sha256") == PLAN_SHA256 and
             document.get("runner_sha256") == runner_sha, "AUTHORIZATION_BINDING")
    implementation = contract.get("implementation", {}).get("artifact_sha256", {})
    _require(document.get("launcher_sha256") == implementation.get(
                 "src/data/launch_blind_runtime_recovery_execution_v1.sh") and
             document.get("job_template_sha256") == implementation.get(
                 JOB_TEMPLATE_RELATIVE), "AUTHORIZATION_IMPLEMENTATION_BINDING")
    _require(document.get("bundle_manifest_sha256") ==
             contract.get("bundle_manifest", {}).get("sha256") and
             document.get("reviewed_commit") ==
             contract.get("bundle_manifest", {}).get("reviewed_commit"),
             "AUTHORIZATION_BUNDLE_BINDING")
    for field in ("bundle_manifest_sha256", "registration_review_sha256", "bjobs_sha256",
                  "bjobs_al_sha256"):
        _require(re.match(r"^[0-9a-f]{64}$", document.get(field, "")),
                 "AUTHORIZATION_DIGEST_SCHEMA")
    _require(re.match(r"^[0-9a-f]{40}$", document.get("reviewed_commit", "")),
             "AUTHORIZATION_COMMIT")
    _require(re.match(r"^[1-9][0-9]*$", document.get("lsf_job_id", "")),
             "AUTHORIZATION_JOB")
    _require(document.get("no_retry") is True and
             document.get("no_requeue") is True and
             document.get("nonarray") is True, "AUTHORIZATION_SCHEDULER")
    _require(document.get("registration_review_path") == REGISTRATION_REVIEW_PATH and
             document.get("bjobs_path") == BJOBS_CAPTURE_PATH and
             document.get("bjobs_al_path") == BJOBS_AL_CAPTURE_PATH,
             "AUTHORIZATION_CONTROL_PATH")
    for path_field, digest_field in (("bjobs_path", "bjobs_sha256"),
                                     ("bjobs_al_path", "bjobs_al_sha256")):
        capture = _read_bytes(document[path_field])
        _require(capture and _sha256_bytes(capture) == document[digest_field],
                 "AUTHORIZATION_CAPTURE_DIGEST")
    validate_registration_review(document["registration_review_path"], document,
                                 contract_sha, runner_sha)
    current = os.environ if environment is None else environment
    _require(current.get("LSB_JOBID") == document.get("lsf_job_id"),
             "AUTHORIZATION_CURRENT_JOB")
    for field in ("LSB_JOBINDEX", "LSB_JOBINDEX_END", "LSB_JOBINDEX_STEP"):
        _require(not current.get(field), "AUTHORIZATION_ARRAY_JOB")
    return document


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--plan", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--source-preflight", action="store_true")
    parser.add_argument("--authorization")
    args = parser.parse_args(argv)
    try:
        result = validate_only(os.path.abspath(args.root), args.plan,
                               source_preflight=args.source_preflight)
        if args.execute:
            contract, contract_sha = validate_contract(os.path.abspath(args.root))
            _require(contract["authority"]["execution_authorized"] is True and
                     contract["authority"]["lsf_submission_allowed"] is True,
                     "EXECUTION_NOT_AUTHORIZED")
            _require(args.authorization, "AUTHORIZATION_REQUIRED")
            runner_sha = contract["implementation"]["artifact_sha256"][
                "src/data/run_blind_runtime_recovery_execution_v1.py"]
            _require(os.path.realpath(args.authorization) == AUTHORIZATION_PATH,
                     "AUTHORIZATION_FIXED_PATH")
            validate_authorization(args.authorization, contract_sha, runner_sha,
                                   contract)
            plan = validate_plan_bytes(_read_bytes(args.plan), contract)
            manifest = build_command_manifest(plan, contract)
            config_values, source_manifest_sha = prepare_workspaces(contract)
            execute_manifest(manifest, contract, config_values, source_manifest_sha)
            result["status"] = "PASS_EXECUTION_COMPLETE_AUDIT_PENDING"
        print(json.dumps(result, sort_keys=True))
        return 0
    except (IOError, OSError, Refusal) as exc:
        print("BLIND_RUNTIME_RECOVERY_EXECUTION_V1=REFUSED:%s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
