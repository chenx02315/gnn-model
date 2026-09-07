#!/usr/bin/env python3
"""Deterministically rerun the Phase4 non-blind recovery in a new A-side tag."""
from __future__ import print_function

import hashlib
import json
import os
import subprocess
import sys


EVIDENCE_ROOT = "/temp/jiangchuanc/multimode_ate_phase4_20260825_A"
RECOVERY_ROOT = "/temp/jiangchuanc/multimode_atpg_runtime_recovery_v1/phase4_nonblind_v2_r1"
TOOLS = os.path.dirname(os.path.abspath(__file__))

SPECS = {
    "b20": ("PILOT", "itc99_b14_connected", "phase4_v1"),
    "b21": ("PILOT", "itc99_b14_connected", "phase4_v2"),
    "b22": ("PILOT", "itc99_b14_connected", "phase4_v2"),
    "aes_core": ("TRAIN", "iwls_aes_core", "phase4_v2"),
    "spi": ("TRAIN", "iwls_spi", "phase4_v2"),
    "tv80": ("VALIDATION", "iwls_tv80", "phase4_v2"),
}


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(command, **kwargs):
    return subprocess.check_call(command, **kwargs)


def baseline(circuit, mode):
    _role, _family, version = SPECS[circuit]
    return os.path.join(
        EVIDENCE_ROOT,
        "10_circuits",
        circuit,
        "logs",
        "%s_%s_%s_full_%s.driver.log" % (mode, circuit, mode, version),
    )


def main():
    if len(sys.argv) != 2 or not sys.argv[1].replace("_", "").isalnum():
        raise SystemExit("usage: repeat_phase4_nonblind_runtime_recovery.py TAG")
    tag = sys.argv[1]
    dirs = {
        "inventory": os.path.join(RECOVERY_ROOT, "inventory_" + tag),
        "attempt": os.path.join(RECOVERY_ROOT, "attempts_" + tag),
        "join": os.path.join(RECOVERY_ROOT, "joins_" + tag),
        "summary": os.path.join(RECOVERY_ROOT, "summaries_" + tag),
    }
    for path in dirs.values():
        if not os.path.isdir(path):
            os.makedirs(path)
    split_contract = os.path.join(TOOLS, "data_split_v1.json")
    audit_tool = os.path.join(TOOLS, "audit_runtime_log_inventory.py")
    recover_tool = os.path.join(TOOLS, "recover_runtime_attempts.py")
    join_tool = os.path.join(TOOLS, "build_runtime_join_v2.py")
    summary_tool = os.path.join(TOOLS, "summarize_runtime_recovery.py")
    for path in (split_contract, audit_tool, recover_tool, join_tool, summary_tool):
        if not os.path.isfile(path):
            raise SystemExit("missing tool: %s" % path)

    artifacts = []
    for circuit in SPECS:
        measurement_root = os.path.join(
            EVIDENCE_ROOT, "10_circuits", circuit, "10_coverage95_phase4_v2"
        )
        f_log, h_log = baseline(circuit, "F"), baseline(circuit, "H")
        if not os.path.isdir(measurement_root) or not os.path.isfile(f_log) or not os.path.isfile(h_log):
            raise SystemExit("missing source for %s" % circuit)
        inventory = os.path.join(dirs["inventory"], "%s_inventory_%s.json" % (circuit, tag))
        attempt = os.path.join(dirs["attempt"], "%s_attempt_manifest_%s.tsv" % (circuit, tag))
        join = os.path.join(dirs["join"], "%s_join_%s.tsv" % (circuit, tag))
        audit = os.path.join(dirs["join"], "%s_audit_%s.json" % (circuit, tag))
        artifacts.extend((inventory, attempt, join, audit))
        if any(os.path.exists(path) for path in artifacts[-4:]):
            raise SystemExit("refusing to overwrite existing tagged artifact for %s" % circuit)

    for circuit in SPECS:
        role, family, _version = SPECS[circuit]
        measurement_root = os.path.join(
            EVIDENCE_ROOT, "10_circuits", circuit, "10_coverage95_phase4_v2"
        )
        f_log, h_log = baseline(circuit, "F"), baseline(circuit, "H")
        inventory = os.path.join(dirs["inventory"], "%s_inventory_%s.json" % (circuit, tag))
        attempt = os.path.join(dirs["attempt"], "%s_attempt_manifest_%s.tsv" % (circuit, tag))
        join = os.path.join(dirs["join"], "%s_join_%s.tsv" % (circuit, tag))
        audit = os.path.join(dirs["join"], "%s_audit_%s.json" % (circuit, tag))
        inventory_tmp = inventory + ".tmp"
        with open(inventory_tmp, "w") as stream:
            run([
                "python3", audit_tool, "--input", measurement_root,
                "--evidence-root", EVIDENCE_ROOT, "--extra-log", f_log,
                "--extra-log", h_log, "--circuit", circuit,
                "--cohort", "phase4_v2_base_plus_full_boundaries_r6",
            ], stdout=stream)
        os.rename(inventory_tmp, inventory)
        with open(inventory) as stream:
            inventory_sha = json.load(stream)["inventory_manifest_sha256"]
        attempt_tmp = attempt + ".tmp"
        run([
            "python3", recover_tool, "--adapter", "gnu_time_log",
            "--input", measurement_root, "--evidence-root", EVIDENCE_ROOT,
            "--extra-log", f_log, "--extra-log", h_log, "--output", attempt_tmp,
            "--phase", "phase4", "--cohort", "phase4_v2_r1_full_gnu_time_plus_full_boundaries_r6",
            "--environment-cohort", "phase4_20260825_A_phase4_v2_base_environment_unverified",
            "--circuit", circuit, "--family", family, "--role", role,
            "--inventory-manifest-sha256", inventory_sha,
        ])
        os.rename(attempt_tmp, attempt)
        join_tmp, audit_tmp = join + ".tmp", audit + ".tmp"
        run([
            "python3", join_tool, "--circuit", circuit,
            "--measurements-root", measurement_root, "--attempt-manifest", attempt,
            "--split-contract", split_contract, join_tmp, audit_tmp,
        ])
        os.rename(join_tmp, join)
        os.rename(audit_tmp, audit)

    command = ["python3", summary_tool, "--split-contract", split_contract]
    for circuit in SPECS:
        command.extend([
            "--circuit",
            "%s=%s,%s,%s,%s" % (
                circuit,
                os.path.join(dirs["inventory"], "%s_inventory_%s.json" % (circuit, tag)),
                os.path.join(dirs["attempt"], "%s_attempt_manifest_%s.tsv" % (circuit, tag)),
                os.path.join(dirs["join"], "%s_join_%s.tsv" % (circuit, tag)),
                os.path.join(dirs["join"], "%s_audit_%s.json" % (circuit, tag)),
            ),
        ])
    summary = os.path.join(dirs["summary"], "summary_%s.json" % tag)
    summary_tmp = summary + ".tmp"
    command.extend(["--output", summary_tmp])
    run(command)
    os.rename(summary_tmp, summary)
    tool_hash = os.path.join(dirs["summary"], "tools_%s.sha256" % tag)
    with open(tool_hash + ".tmp", "w") as stream:
        for path in (audit_tool, recover_tool, join_tool, summary_tool,
                     os.path.join(TOOLS, "runtime_schema.py"), split_contract):
            stream.write("%s  %s\n" % (sha256(path), os.path.basename(path)))
    os.rename(tool_hash + ".tmp", tool_hash)
    print(sha256(summary))


if __name__ == "__main__":
    main()
