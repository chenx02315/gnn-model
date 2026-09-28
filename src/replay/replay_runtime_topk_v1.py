#!/usr/bin/env python3
"""CLI for the v1 non-BLIND validation Top-k replay."""
from __future__ import annotations

import argparse
from pathlib import Path

from runtime_accounting_v1 import run_cli


METHODS = (
    "fixed_heuristic",
    "d95_safe_then_predicted_cycles",
    "d95_safe_cost_aware_topk",
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("package_root", type=Path)
    parser.add_argument("ranking_tsv", type=Path)
    parser.add_argument("ranking_freeze_json", type=Path)
    parser.add_argument("outcome_access_ledger_jsonl", type=Path)
    parser.add_argument("output_json", type=Path)
    args = parser.parse_args()
    run_cli(args.package_root, args.ranking_tsv, args.ranking_freeze_json, args.outcome_access_ledger_jsonl, args.output_json, METHODS)
    print("RUNTIME_TOPK_REPLAY=PASS_VALIDATION_ONLY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
