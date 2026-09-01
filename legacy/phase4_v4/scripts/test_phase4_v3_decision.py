#!/usr/bin/env python3
"""Synthetic, outcome-free tests for the Phase4 v3 selection contract."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import numpy as np
import pandas as pd


def load_module(path: Path):
    spec = importlib.util.spec_from_file_location("phase4_v3", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    module = load_module(Path(__file__).with_name("train_family_holdout_phase4_v3.py"))
    base = pd.DataFrame({
        "circuit": ["c1", "c1", "c2"],
        "candidate_uid": ["b", "a", "c"],
        "predicted_cycles": [10.0, 10.0, 0.0],
        "predicted_feasible_probability": [0.9, 0.9, 0.9],
        "safe_anchor_uid": ["anchor1", "anchor1", "anchor2"],
    })
    abstain = module.choose_actions(base, {"identifiable": False})
    assert set(abstain.selection_action) == {"single_baseline"}
    assert set(abstain.selection_reason) == {"ABSTAIN_SINGLE_CLASS"}
    assert dict(zip(abstain.circuit, abstain.selected_action_uid)) == {
        "c1": "anchor1", "c2": "anchor2"
    }

    identified = module.choose_actions(base, {"identifiable": True})
    c1 = identified[identified.circuit == "c1"].iloc[0]
    c2 = identified[identified.circuit == "c2"].iloc[0]
    assert c1.selection_action == "candidate" and c1.selected_action_uid == "a"
    assert c2.selection_action == "single_baseline"
    assert c2.selection_reason == "ABSTAIN_NO_VALID_CANDIDATE"

    nonfinite = base.copy()
    nonfinite.loc[nonfinite.circuit == "c1", "predicted_cycles"] = np.nan
    decision = module.choose_actions(nonfinite, {"identifiable": True})
    assert set(decision.selection_action) == {"single_baseline"}

    forbidden = base.assign(total_cycles=1)
    try:
        module.choose_actions(forbidden, {"identifiable": True})
    except RuntimeError as exc:
        assert "unexpected columns" in str(exc)
    else:
        raise AssertionError("Outcome-bearing selection interface was accepted")
    print("PHASE4_V3_DECISION_TEST=PASS")


if __name__ == "__main__":
    main()
