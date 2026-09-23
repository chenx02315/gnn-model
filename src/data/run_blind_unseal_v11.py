#!/usr/bin/env python3
"""Non-executable v11 production draft.

The CLI is deliberately a pre-consumption refusal.  The in-memory stage helper
exists solely for shape tests and cannot open paths, create markers, or grant
BLIND/LSF/training authorization.
"""
from __future__ import print_function

import argparse
import hashlib
import json
import os

from validate_blind_unseal_v11_draft import (
    DraftError, allowed_pair, load_draft, validate_failure_receipt,
    validate_post_consumption_context,
)


class Refusal(DraftError):
    pass


def _refuse_pre_consumption(draft):
    if draft["status"] != "DRAFT_NO_EXECUTION":
        raise Refusal("DRAFT_STATUS_INVALID")
    authority = draft["authority"]
    if authority != {
        "execution_authorized": False, "blind_read_allowed": False,
        "lsf_registration_allowed": False, "training_allowed": False,
    }:
        raise Refusal("AUTHORITY_INVALID")
    if any(value is not None for value in draft["draft_bindings"].values()):
        raise Refusal("DRAFT_BINDINGS_NOT_EMPTY")
    raise Refusal("REFUSED_NOT_CONSUMED")


def _build_post_consumption_failure_shape_oracle(draft, final_contract_bytes, pre_reviewed_tool_set_bytes, stage, code):
    """Build a private receipt-shaped oracle; never serialize it by itself."""
    if draft.get("status") != "DRAFT_NO_EXECUTION":
        raise Refusal("DRAFT_STATUS_INVALID")
    if not allowed_pair(stage, code):
        raise Refusal("STAGE_CODE_INVALID")
    contract_sha256, tool_set_sha256 = validate_post_consumption_context(
        final_contract_bytes, pre_reviewed_tool_set_bytes,
    )
    receipt = {
        "schema_version": "blind-runtime-unseal-receipt-v11",
        "status": "FAIL",
        "contract_sha256": contract_sha256,
        "tool_set_sha256": tool_set_sha256,
        "failure_stage": stage,
        "failure_code": code,
        "circuits": [],
    }
    validate_failure_receipt(draft, receipt, contract_sha256, tool_set_sha256)
    return receipt


def build_synthetic_post_consumption_failure_fixture_for_test(
        draft, final_contract_bytes, pre_reviewed_tool_set_bytes, stage, code):
    """Return only a synthetic wrapper around the private shape oracle."""
    return {
        "schema_version": "blind-runtime-unseal-v11-draft-synthetic-stage-fixture",
        "status": "SYNTHETIC_ONLY_NO_EXECUTION",
        "execution_authorized": False,
        "embedded_shape_oracle_not_public_evidence":
            _build_post_consumption_failure_shape_oracle(
                draft, final_contract_bytes, pre_reviewed_tool_set_bytes,
                stage, code,
            ),
    }


def run_draft(repo_root, draft_path, output_root=None):
    """Validate only the draft and then refuse before any output-side effect."""
    del output_root  # A caller cannot nominate an output root in this state.
    draft = load_draft(repo_root, draft_path)
    _refuse_pre_consumption(draft)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--draft", required=True)
    parser.add_argument("--output-root")
    args = parser.parse_args(argv)
    try:
        run_draft(os.path.abspath(args.repo_root), os.path.abspath(args.draft), args.output_root)
    except (OSError, ValueError, DraftError, Refusal) as error:
        # Deliberately do not serialize arbitrary exception text: a later
        # finalized runner must also keep pre-consumption refusal non-public.
        print("BLIND_UNSEAL_V11=REFUSED_NOT_CONSUMED")
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
