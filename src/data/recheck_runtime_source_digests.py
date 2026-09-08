#!/usr/bin/env python3
"""Create a versioned, aggregate-only canonical digest recheck receipt.

The input specification is local-only and may contain source locations.  Those
locations, together with all inventory details, are deliberately excluded from
the receipt.  Python 3.6+; standard library only.
"""
from __future__ import print_function

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys


LOGICAL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SPEC_SCHEMA = "canonical-digest-recheck-spec-v1"
RECEIPT_SCHEMA = "canonical-digest-recheck-receipt-v1"
AUDIT_TOOL_SHA256 = "ab1ed797e4bbd58ef9aee04a46c24a4843c63d5436f296eeb1f7a48d5e99ac61"
CANONICAL_DIGESTS = {
    "phase2.b18.manifest": "e251e482f070e2e80a6535ff1621a064cfb56e4c04b041c8d219c2505b6253e8",
    "phase2.b18.raw_inventory_manifest": "3f76c1dd798f6df721d033a18f9cb7ae4e47664c3f825fe1629a50f3cfd36239",
    "phase2.s35932.manifest": "9eeb437f12598ddc08d5539800e0faaeab2508a0285e15d49b33f348538fe45f",
    "phase2.s35932.raw_inventory_manifest": "8fc1b79ffbe4d0332a1a196f3ddd3e26cb8e94437035ee888d85032bc01f0365",
    "phase2.s38417.manifest": "416dfdbddee67964ebfbd93618d6cf63d8645553d7050804122b7b63f34f749c",
    "phase2.s38417.raw_inventory_manifest": "4382b2c5e22b867ae2bead4d83e75e4632215f04c462914c96d09bf5b2b32c00",
    "phase2.s38584.inventory_manifest": "73fc713b8d0795dec69307cf43a96d2133b5d253a0986f33761e5ffb0c152a09",
    "phase2.s38584.source": "e506507d0d1f5c9e8264307a1c9dcef4f312de7235ee3e78d1aa336003819246",
    "phase3.s13207.inventory_manifest": "895c325c23609b059b4fab0027b2d790c0d515390ad474052b20e3026ee6ec52",
    "phase3.s15850.inventory_manifest": "643215f90884023f212a2dde56cafeadb4c335461d951e0d586fb57859f604f0",
    "phase3.s5378.authority_baseline_inventory_manifest": "f624ea4c2f92e622ec4a9bf142861695423c2fbae6c811c6a350b92b912925b0",
    "phase3.s5378.coverage_subtree_inventory_manifest": "ac5ad79e96598af11301bb99c941fbd65f138feedad1631944305f176c59273a",
    "phase3.s5378.inventory_manifest": "28be4c039edab0eed7102dd8786e796840599159ace06beae8f430f8a7b103d1",
    "phase3.s9234.inventory_manifest": "cd226c86807c6e80bfe2210db46eab5d3305c322626829f7e163467d4b562826",
    "phase4.wb_dma.inventory_manifest": "4755a03a9da7eb9bf8fab2ec6f2c95e5c83919c42e236b72ccaed763786b3f4f",
    "phase4_r6.aes_core.raw_inventory_manifest": "f4fa71c48411dea2bddbb246fb3213be35fd612e5ce9ebf56b3e83c13b598fa2",
    "phase4_r6.b20.raw_inventory_manifest": "5865b6a1bd062905293295dbd0b6a4c2829a0845c37ff6c5021e6928e6000fde",
    "phase4_r6.b21.raw_inventory_manifest": "722cd495244a576ec1626858d05b2e98824ade124252f33900e3f8cc527adcd2",
    "phase4_r6.b22.raw_inventory_manifest": "39cf3b554e6d88a1c2dbdae7cc931f56c72ddc6f68ab26ec4a57efdf470aaaa7",
    "phase4_r6.spi.raw_inventory_manifest": "c3715bde2c0ba7d628ff3b60fc432962f7c920a969d4101c2fb0f46bb549df11",
    "phase4_r6.tv80.raw_inventory_manifest": "8013fae3ef791d852959ee88cd62ce619e1c6e54376c3a475008edd250d5c19a",
}
CANONICAL_VERSIONS = {
    "r03-canonical-21-v1": frozenset(CANONICAL_DIGESTS),
    "r03-canonical-18-v2": frozenset(key for key in CANONICAL_DIGESTS
                                      if key not in ("phase2.b18.manifest", "phase2.s35932.manifest", "phase2.s38417.manifest")),
}


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: %s" % key)
        result[key] = value
    return result


def strict_json_loads(value):
    return json.loads(value, object_pairs_hook=reject_duplicate_keys)


def canonical_json_sha256(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def specification_sha256(specification):
    normalized = dict(specification)
    normalized["entries"] = sorted(specification["entries"], key=lambda entry: entry.get("logical_id", ""))
    return canonical_json_sha256(normalized)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_sha256(value, label):
    if not isinstance(value, str) or not SHA256_RE.match(value):
        raise ValueError("%s must be a lowercase 64-hex SHA-256" % label)
    return value


def require_exact_keys(entry, allowed, kind):
    unknown = set(entry) - set(allowed)
    missing = set(allowed) - set(entry)
    if unknown or missing:
        raise ValueError("invalid fields for %s entry" % kind)


def parse_entry(entry):
    if not isinstance(entry, dict):
        raise ValueError("each entry must be an object")
    kind = entry.get("kind")
    common = ("logical_id", "kind", "expected_sha256")
    if kind == "file":
        require_exact_keys(entry, common + ("source_path",), kind)
        source_path = entry["source_path"]
        if not isinstance(source_path, str) or not os.path.isfile(source_path):
            raise ValueError("file entry source_path is not a regular file")
    elif kind == "inventory":
        require_exact_keys(entry, common + ("input_path", "evidence_root", "extra_logs", "circuit", "cohort"), kind)
        source_path = entry["input_path"]
        if not isinstance(source_path, str) or not os.path.isdir(source_path):
            raise ValueError("inventory entry input_path is not a directory")
        if not isinstance(entry["evidence_root"], str):
            raise ValueError("inventory entry evidence_root must be a string")
        if not isinstance(entry["extra_logs"], list) or not all(isinstance(value, str) for value in entry["extra_logs"]):
            raise ValueError("inventory entry extra_logs must be a string list")
        if not isinstance(entry["circuit"], str) or not isinstance(entry["cohort"], str):
            raise ValueError("inventory entry circuit and cohort must be strings")
    else:
        raise ValueError("entry kind must be file or inventory")
    logical_id = entry.get("logical_id")
    if not isinstance(logical_id, str) or not LOGICAL_ID_RE.match(logical_id):
        raise ValueError("unsafe logical ID")
    require_sha256(entry.get("expected_sha256"), "expected_sha256")
    return kind, logical_id


def inventory_digest(entry, audit_script, runner=subprocess.check_output):
    command = [sys.executable, audit_script, "--input", entry["input_path"],
               "--circuit", entry["circuit"], "--cohort", entry["cohort"]]
    if entry["evidence_root"]:
        command.extend(("--evidence-root", entry["evidence_root"]))
    for extra_log in entry["extra_logs"]:
        command.extend(("--extra-log", extra_log))
    try:
        raw = runner(command)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError("inventory audit subprocess failed") from exc
    try:
        result = strict_json_loads(raw.decode("utf-8"))
    except (AttributeError, UnicodeDecodeError, ValueError):
        raise ValueError("inventory audit returned invalid JSON")
    if not isinstance(result, dict):
        raise ValueError("inventory audit returned invalid receipt")
    if result.get("schema_version") != "runtime_log_inventory_aggregate_v1":
        raise ValueError("inventory audit schema mismatch")
    if result.get("circuit") != entry["circuit"] or result.get("cohort") != entry["cohort"]:
        raise ValueError("inventory audit identity echo mismatch")
    return require_sha256(result.get("inventory_manifest_sha256"), "inventory audit digest")


def build_receipt(specification, audit_script=None, runner=subprocess.check_output):
    if not isinstance(specification, dict):
        raise ValueError("specification must be an object")
    if set(specification) != set(("schema_version", "receipt_version", "entries")):
        raise ValueError("specification fields are invalid")
    if specification["schema_version"] != SPEC_SCHEMA:
        raise ValueError("unsupported specification schema")
    version = specification["receipt_version"]
    if version not in CANONICAL_VERSIONS:
        raise ValueError("receipt_version is not a frozen canonical version")
    entries = specification["entries"]
    if not isinstance(entries, list) or not entries:
        raise ValueError("entries must be a non-empty list")
    audit_script = audit_script or os.path.join(os.path.dirname(os.path.abspath(__file__)), "audit_runtime_log_inventory.py")
    if not os.path.isfile(audit_script):
        raise ValueError("inventory audit tool is unavailable")
    if sha256_file(audit_script) != AUDIT_TOOL_SHA256:
        raise ValueError("inventory audit tool hash mismatch")
    artifacts = {}
    counts = {"entry_count": 0, "file_count": 0, "inventory_count": 0}
    for entry in entries:
        kind, logical_id = parse_entry(entry)
        if logical_id in artifacts:
            raise ValueError("duplicate logical ID: %s" % logical_id)
        if logical_id not in CANONICAL_VERSIONS[version]:
            raise ValueError("logical ID is not in frozen canonical version")
        if entry["expected_sha256"] != CANONICAL_DIGESTS[logical_id]:
            raise ValueError("expected SHA-256 does not match frozen canonical digest")
        observed = sha256_file(entry["source_path"]) if kind == "file" else inventory_digest(entry, audit_script, runner)
        if observed != entry["expected_sha256"]:
            raise ValueError("canonical digest mismatch: %s" % logical_id)
        artifacts[logical_id] = observed
        counts["entry_count"] += 1
        counts["file_count" if kind == "file" else "inventory_count"] += 1
    if set(artifacts) != CANONICAL_VERSIONS[version]:
        raise ValueError("canonical version requires its exact logical ID set")
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "receipt_version": version,
        "specification_sha256": specification_sha256(specification),
        "audit_tool_sha256": sha256_file(audit_script),
        "recheck_tool_sha256": sha256_file(os.path.abspath(__file__)),
        "artifacts": dict((key, artifacts[key]) for key in sorted(artifacts)),
        "counts": counts,
        "field_policy": "logical IDs, SHA-256 values, and aggregate counts only",
    }
    serialized = json.dumps(receipt, sort_keys=True).lower()
    for forbidden in ("path", "run_id", "runtime", "candidate"):
        if forbidden in serialized:
            raise ValueError("receipt contains forbidden sensitive field")
    return receipt


def load_specification(path):
    with open(path, "r") as stream:
        return strict_json_loads(stream.read())


def write_receipt(path, receipt):
    if os.path.lexists(path):
        raise ValueError("refusing to overwrite existing output")
    parent = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(parent):
        raise ValueError("output directory does not exist")
    try:
        with open(path, "x") as stream:
            json.dump(receipt, stream, indent=2, sort_keys=True)
            stream.write("\n")
    except FileExistsError:
        raise ValueError("refusing to overwrite existing output")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        receipt = build_receipt(load_specification(args.spec))
        write_receipt(args.output, receipt)
    except (IOError, OSError, ValueError) as exc:
        parser.error(str(exc))
    print("CANONICAL_DIGEST_RECHECK=PASS entries=%d" % receipt["counts"]["entry_count"])


if __name__ == "__main__":
    main()
