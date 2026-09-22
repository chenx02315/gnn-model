#!/usr/bin/env python3
"""Build and validate path-free synthetic v11 failure receipts.

This module has no runner integration and accepts no BLIND input paths.
"""
from __future__ import print_function

import argparse
import hashlib
import json
import os
import re

DESIGN_PATH = "contracts/blind_runtime_unseal_v11_design.json"
DESIGN_SHA256 = "db507511aad99785111ccad136c6618a7ec8a14f6ae1de1cfd2b69ef4e26a9c4"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
RECEIPT_FIELDS = {
    "schema_version", "status", "contract_sha256", "tool_set_sha256",
    "failure_stage", "failure_code", "circuits",
}


class ReceiptError(ValueError):
    pass


def _require(condition, code):
    if not condition:
        raise ReceiptError(code)


def _load_design(repo_root):
    path = os.path.join(repo_root, DESIGN_PATH)
    with open(path, "rb") as stream:
        raw = stream.read()
    _require(hashlib.sha256(raw).hexdigest() == DESIGN_SHA256, "DESIGN_DIGEST")
    design = json.loads(raw.decode("utf-8"))
    _require(design.get("status") == "DESIGN_ONLY_NO_EXECUTION", "DESIGN_STATUS")
    _require(design.get("authority") == {
        "blind_read_allowed": False,
        "execution_authorized": False,
        "lsf_registration_allowed": False,
        "training_allowed": False,
    }, "DESIGN_AUTHORITY")
    return design


def _allowed_pairs(design):
    taxonomy = design.get("failure_taxonomy")
    _require(isinstance(taxonomy, list), "TAXONOMY")
    pairs = []
    for item in taxonomy:
        _require(
            isinstance(item, dict)
            and set(item) == {"stage", "code", "after_consumed", "retryable"}
            and item.get("after_consumed") is True
            and item.get("retryable") is False,
            "TAXONOMY_ENTRY",
        )
        pairs.append((item.get("stage"), item.get("code")))
    _require(len(pairs) == 7 and len(set(pairs)) == 7, "TAXONOMY_PAIR_SET")
    return set(pairs)


def build_failure_receipt(repo_root, contract_sha256, tool_set_sha256, stage, code):
    design = _load_design(repo_root)
    _require(SHA256.match(contract_sha256 or "") is not None, "CONTRACT_DIGEST")
    _require(SHA256.match(tool_set_sha256 or "") is not None, "TOOL_SET_DIGEST")
    _require((stage, code) in _allowed_pairs(design), "STAGE_CODE_PAIR")
    receipt = {
        "schema_version": "blind-runtime-unseal-receipt-v11",
        "status": "FAIL",
        "contract_sha256": contract_sha256,
        "tool_set_sha256": tool_set_sha256,
        "failure_stage": stage,
        "failure_code": code,
        "circuits": [],
    }
    validate_failure_receipt(repo_root, receipt)
    return receipt


def validate_failure_receipt(repo_root, receipt):
    design = _load_design(repo_root)
    _require(isinstance(receipt, dict) and set(receipt) == RECEIPT_FIELDS, "RECEIPT_FIELDS")
    _require(receipt.get("schema_version") == "blind-runtime-unseal-receipt-v11", "RECEIPT_SCHEMA")
    _require(receipt.get("status") == "FAIL" and receipt.get("circuits") == [], "FAILURE_ONLY")
    _require(SHA256.match(receipt.get("contract_sha256") or "") is not None, "CONTRACT_DIGEST")
    _require(SHA256.match(receipt.get("tool_set_sha256") or "") is not None, "TOOL_SET_DIGEST")
    _require((receipt.get("failure_stage"), receipt.get("failure_code")) in _allowed_pairs(design), "STAGE_CODE_PAIR")
    return True


def build_synthetic_fixture(repo_root, contract_sha256, tool_set_sha256, stage, code):
    """Wrap the expected receipt so CLI output cannot be mistaken for a real run."""
    return {
        "schema_version": "blind-runtime-unseal-v11-synthetic-failure-fixture",
        "status": "SYNTHETIC_ONLY_NO_EXECUTION",
        "execution_authorized": False,
        "expected_public_failure_receipt": build_failure_receipt(
            repo_root, contract_sha256, tool_set_sha256, stage, code,
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--contract-sha256", required=True)
    parser.add_argument("--tool-set-sha256", required=True)
    parser.add_argument("--stage", required=True)
    parser.add_argument("--code", required=True)
    args = parser.parse_args(argv)
    try:
        fixture = build_synthetic_fixture(
            os.path.abspath(args.repo_root), args.contract_sha256,
            args.tool_set_sha256, args.stage, args.code,
        )
    except (OSError, UnicodeDecodeError, ValueError, ReceiptError) as error:
        print("BLIND_UNSEAL_V11_SYNTHETIC_RECEIPT=FAIL:%s" % error)
        return 1
    print(json.dumps(fixture, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
