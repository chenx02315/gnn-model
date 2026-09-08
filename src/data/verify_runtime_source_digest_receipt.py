#!/usr/bin/env python3
"""Verify a frozen canonical digest receipt without exposing its source locations."""
from __future__ import print_function

import argparse
import hashlib
import json
import os

import recheck_runtime_source_digests as recheck


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: %s" % key)
        result[key] = value
    return result


def load_json_strict(path):
    with open(path, "r") as stream:
        return json.load(stream, object_pairs_hook=no_duplicates)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify(receipt_path, spec_path, trusted_spec_sha256, trusted_recheck_sha256,
           expected_receipt_version, recheck_tool, audit_tool):
    recheck.require_sha256(trusted_spec_sha256, "trusted spec SHA-256")
    recheck.require_sha256(trusted_recheck_sha256, "trusted recheck tool SHA-256")
    if expected_receipt_version != "r03-canonical-18-v2":
        raise ValueError("expected receipt version must be the frozen R03 v2 version")
    if sha256_file(spec_path) != trusted_spec_sha256:
        raise ValueError("trusted specification hash mismatch")
    receipt = load_json_strict(receipt_path)
    specification = load_json_strict(spec_path)
    receipt_fields = ("schema_version", "receipt_version", "specification_sha256",
                      "audit_tool_sha256", "recheck_tool_sha256", "artifacts",
                      "counts", "field_policy")
    if not isinstance(receipt, dict) or set(receipt) != set(receipt_fields):
        raise ValueError("receipt fields are invalid")
    version = receipt.get("receipt_version")
    if (receipt.get("schema_version") != recheck.RECEIPT_SCHEMA or
            version != expected_receipt_version):
        raise ValueError("receipt schema or version is invalid")
    expected_ids = recheck.CANONICAL_VERSIONS[version]
    if not isinstance(receipt["artifacts"], dict) or set(receipt["artifacts"]) != expected_ids:
        raise ValueError("receipt logical IDs are invalid")
    if receipt["artifacts"] != dict((key, recheck.CANONICAL_DIGESTS[key]) for key in sorted(expected_ids)):
        raise ValueError("receipt canonical digest mapping is invalid")
    if sha256_file(audit_tool) != recheck.AUDIT_TOOL_SHA256:
        raise ValueError("actual inventory audit tool hash is invalid")
    if receipt["audit_tool_sha256"] != recheck.AUDIT_TOOL_SHA256:
        raise ValueError("receipt inventory audit tool hash is invalid")
    if sha256_file(recheck_tool) != trusted_recheck_sha256:
        raise ValueError("actual recheck tool hash is not trusted")
    if receipt["recheck_tool_sha256"] != trusted_recheck_sha256:
        raise ValueError("receipt recheck tool hash is invalid")
    if not isinstance(specification, dict) or set(specification) != set(("schema_version", "receipt_version", "entries")):
        raise ValueError("specification fields are invalid")
    if specification.get("schema_version") != recheck.SPEC_SCHEMA:
        raise ValueError("specification schema is invalid")
    if specification.get("receipt_version") != version:
        raise ValueError("specification version differs from receipt")
    # Re-run strict frozen ID and expected-digest validation without reading sources.
    seen = set()
    entries = specification.get("entries")
    if not isinstance(entries, list):
        raise ValueError("specification entries are invalid")
    file_count = 0
    inventory_count = 0
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("logical_id") in seen:
            raise ValueError("specification entries are invalid")
        seen.add(entry.get("logical_id"))
        logical_id = entry.get("logical_id")
        if logical_id not in expected_ids or entry.get("expected_sha256") != recheck.CANONICAL_DIGESTS[logical_id]:
            raise ValueError("specification canonical mapping is invalid")
        kind = entry.get("kind")
        common = ("logical_id", "kind", "expected_sha256")
        if kind == "file":
            expected_fields = common + ("source_path",)
            file_count += 1
        elif kind == "inventory":
            expected_fields = common + ("input_path", "evidence_root", "extra_logs", "circuit", "cohort")
            inventory_count += 1
        else:
            raise ValueError("specification entry kind is invalid")
        if set(entry) != set(expected_fields):
            raise ValueError("specification entry fields are invalid")
    if seen != expected_ids:
        raise ValueError("specification logical IDs are invalid")
    if receipt["specification_sha256"] != recheck.specification_sha256(specification):
        raise ValueError("receipt canonical specification hash is invalid")
    expected_counts = {"entry_count": len(expected_ids), "file_count": file_count,
                       "inventory_count": inventory_count}
    if (not isinstance(receipt["counts"], dict) or
            receipt["counts"] != expected_counts):
        raise ValueError("receipt aggregate counts are invalid")
    if receipt["field_policy"] != "logical IDs, SHA-256 values, and aggregate counts only":
        raise ValueError("receipt field policy is invalid")
    serialized = json.dumps(receipt, sort_keys=True).lower()
    for forbidden in ("path", "run_id", "runtime", "candidate"):
        if forbidden in serialized:
            raise ValueError("receipt contains forbidden sensitive field")
    return {
        "schema_version": "canonical-digest-receipt-verification-v1",
        "receipt_version": version,
        "trusted_raw_spec_sha256": trusted_spec_sha256,
        "trusted_recheck_tool_sha256": trusted_recheck_sha256,
        "receipt_sha256": sha256_file(receipt_path),
        "verified_entry_count": len(expected_ids),
        "status": "VERIFIED",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--spec", required=True)
    parser.add_argument("--trusted-spec-sha256", required=True)
    parser.add_argument("--trusted-recheck-sha256", required=True)
    parser.add_argument("--expected-receipt-version", required=True)
    parser.add_argument("--recheck-tool", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "recheck_runtime_source_digests.py"))
    parser.add_argument("--audit-tool", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "audit_runtime_log_inventory.py"))
    args = parser.parse_args(argv)
    try:
        result = verify(args.receipt, args.spec, args.trusted_spec_sha256,
                        args.trusted_recheck_sha256, args.expected_receipt_version,
                        args.recheck_tool, args.audit_tool)
    except (IOError, OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
