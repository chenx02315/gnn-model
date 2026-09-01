#!/usr/bin/env python3
"""Run leakage-safe LOFO regressors with an abstain-to-safe-anchor policy."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import mean_absolute_error, mean_squared_error
from xgboost import XGBClassifier, XGBRegressor
from torch import nn
from torch_geometric.nn import SAGEConv


SEED = 20260824
SCALAR_GRAPH_FEATURES = [
    "log_nodes", "log_edges", "sequential_fraction", "edge_node_ratio",
]
CANDIDATE_FEATURES = [
    # f_ratio is deliberately excluded: the F pattern count is an ATPG result
    # of a candidate, and using it would defeat pre-grid prediction.
    "h_ratio", "m_ratio", "scheme_hf", "scheme_hmf",
    "log_common_faults", "log_h_full", "log_m_full", "log_f_full",
] + SCALAR_GRAPH_FEATURES


def seed_all(seed=SEED):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    torch.use_deterministic_algorithms(True, warn_only=True)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_inputs(dataset: Path, graph_dir: Path, family_map: Path):
    candidate_path = dataset / "data/processed/candidate_points_fixed.tsv"
    dedup_manifest_path = dataset / "metadata/candidate_dedup_manifest.json"
    dedup_manifest = json.loads(dedup_manifest_path.read_text(encoding="utf-8"))
    if dedup_manifest.get("status") != "PASS":
        raise RuntimeError("Candidate fixed-source dedup manifest is not PASS")
    if dedup_manifest.get("output_sha256") != file_sha256(candidate_path):
        raise RuntimeError("Candidate table hash does not match fixed-source dedup manifest")
    expected_policy = (
        "lexicographically smallest immutable source_version, source_file, source_row; "
        "stable mergesort"
    )
    if dedup_manifest.get("dedup_policy") != expected_policy:
        raise RuntimeError("Unexpected candidate deduplication policy")
    not_used = set(dedup_manifest.get("outcome_fields_not_used_for_selection", []))
    if not {"total_cycles", "detected_faults", "feasible_at_d95", "result_status"} <= not_used:
        raise RuntimeError("Dedup manifest does not prove outcome fields were excluded")
    all_points = pd.read_csv(candidate_path, sep="\t")
    safe_anchor_rows = all_points[
        (all_points.stage == "single_boundary")
        & (all_points.scheme == "FullScan-F4")
        & (all_points.f_patterns == all_points.f_full_patterns)
    ].copy()
    if (
        safe_anchor_rows.empty
        or safe_anchor_rows.circuit.duplicated().any()
        or safe_anchor_rows.circuit.nunique() != all_points.circuit.nunique()
    ):
        raise RuntimeError("Every circuit must have one coordinate-fixed FullScan-F4 anchor")
    safe_anchor_rows = safe_anchor_rows[[
        "circuit", "candidate_uid", "scheme", "total_cycles", "detected_faults",
        "d95", "feasible_at_d95",
    ]].rename(columns={
        "candidate_uid": "safe_anchor_uid",
        "scheme": "safe_anchor_scheme",
        "total_cycles": "safe_anchor_cycles",
        "detected_faults": "safe_anchor_detected_faults",
        "d95": "safe_anchor_d95",
        "feasible_at_d95": "safe_anchor_feasible_at_d95",
    })
    baseline_rows = all_points[
        (all_points.stage == "single_boundary")
        & all_points.scheme.isin(["FullScan-F4", "ComScan-H64"])
        & (all_points.feasible_at_d95 == 1)
        & (all_points.detected_faults >= all_points.d95)
    ].copy()
    if baseline_rows.empty:
        raise RuntimeError("No feasible FullScan-F4/ComScan-H64 single-mode baselines")
    baseline_rows = baseline_rows.loc[
        baseline_rows.groupby("circuit").total_cycles.idxmin(),
        ["circuit", "candidate_uid", "scheme", "total_cycles"],
    ].rename(columns={
        "candidate_uid": "single_baseline_uid",
        "scheme": "single_baseline_scheme",
        "total_cycles": "single_baseline_cycles",
    })
    frame = all_points[all_points.scheme.isin(["H64-F4", "H64-M16-F4"])].copy()
    allowed_status = {"PASS", "TARGET_BEFORE_F", "INFEASIBLE_AT_D95"}
    if frame.result_status.isna().any() or (frame.result_status.astype(str).str.strip() == "").any():
        raise RuntimeError("HF/HMF contains an empty result_status")
    if not set(frame.result_status) <= allowed_status:
        raise RuntimeError("HF/HMF contains a non-PASS result status")
    numeric_columns = [
        "total_cycles", "h_cycles", "m_cycles", "f_cycles", "detected_faults",
        "d95", "common_fault_count", "h_full_patterns", "m_full_patterns",
        "f_full_patterns", "h_patterns", "m_patterns", "f_patterns",
    ]
    numeric = frame[numeric_columns].apply(pd.to_numeric, errors="coerce")
    if not np.isfinite(numeric.to_numpy(dtype=float)).all():
        raise RuntimeError("HF/HMF contains non-finite numeric data")
    if (frame.total_cycles <= 0).any() or (frame[numeric_columns[1:]] < 0).any().any():
        raise RuntimeError("HF/HMF contains non-positive cycles or negative measurements")
    if frame.candidate_uid.duplicated().any():
        raise RuntimeError("candidate_uid must be unique")
    coordinate = ["circuit", "scheme", "h_patterns", "m_patterns"]
    if frame.duplicated(coordinate).any():
        raise RuntimeError("Candidate coordinates are not unique before training")
    constants = [
        "common_fault_count", "d95", "h_full_patterns", "m_full_patterns", "f_full_patterns"
    ]
    if (frame.groupby("circuit")[constants].nunique(dropna=False) != 1).any().any():
        raise RuntimeError("Per-circuit fault/full-pattern constants are inconsistent")
    expected_d95 = np.ceil(0.95 * frame.common_fault_count).astype(int)
    if not np.array_equal(expected_d95.to_numpy(), frame.d95.astype(int).to_numpy()):
        raise RuntimeError("D95 is not ceil(0.95 * common_fault_count)")
    segment_sum = frame.h_cycles + frame.m_cycles + frame.f_cycles
    if not np.array_equal(segment_sum.astype(int).to_numpy(), frame.total_cycles.astype(int).to_numpy()):
        raise RuntimeError("Segment cycles do not sum to total_cycles")
    frame["is_feasible"] = (
        (frame.feasible_at_d95 == 1) & (frame.detected_faults >= frame.d95)
    ).astype(int)
    if not (frame.groupby("circuit").is_feasible.sum() > 0).all():
        raise RuntimeError("Every circuit must retain at least one measured D95-feasible candidate")
    frame["scheme_hf"] = (frame.scheme == "H64-F4").astype(float)
    frame["scheme_hmf"] = (frame.scheme == "H64-M16-F4").astype(float)
    for dst, src in [
        ("log_common_faults", "common_fault_count"), ("log_h_full", "h_full_patterns"),
        ("log_m_full", "m_full_patterns"), ("log_f_full", "f_full_patterns"),
    ]:
        frame[dst] = np.log1p(frame[src].astype(float))

    expected_circuits = set(frame.circuit)
    gm = pd.read_csv(graph_dir / "graph_manifest.tsv", sep="\t")
    if not expected_circuits <= set(gm.circuit):
        raise RuntimeError("Missing graph manifest circuits")
    gm["log_nodes"] = np.log1p(gm.nodes)
    gm["log_edges"] = np.log1p(gm.edges)
    gm["sequential_fraction"] = gm.sequential_nodes / gm.nodes
    gm["edge_node_ratio"] = gm.edges / gm.nodes
    families = pd.read_csv(family_map, sep="\t", usecols=["circuit", "effective_family"])
    if families.circuit.duplicated().any() or set(families.circuit) != expected_circuits:
        raise RuntimeError("Family map circuit set must exactly match candidate circuits")
    if set(baseline_rows.circuit) != expected_circuits:
        raise RuntimeError("Every candidate circuit must have one feasible single-mode baseline")
    row_count = len(frame)
    frame = frame.merge(gm[["circuit"] + SCALAR_GRAPH_FEATURES], on="circuit", validate="many_to_one")
    frame = frame.merge(families, on="circuit", validate="many_to_one")
    frame = frame.merge(baseline_rows, on="circuit", validate="many_to_one")
    frame = frame.merge(safe_anchor_rows, on="circuit", validate="many_to_one")
    if len(frame) != row_count or set(frame.circuit) != expected_circuits:
        raise RuntimeError("Merge changed candidate rows or silently dropped circuits")
    if frame[["effective_family", "single_baseline_cycles", "safe_anchor_uid"]].isna().any().any():
        raise RuntimeError("Missing family, evaluation baseline, or safe anchor mapping")
    graphs = {c: torch.load(graph_dir / f"{c}.pt", weights_only=False) for c in sorted(frame.circuit.unique())}
    return frame.reset_index(drop=True), graphs


class GraphCandidateRegressor(nn.Module):
    def __init__(self, node_dim: int, candidate_dim: int):
        super().__init__()
        self.conv1 = SAGEConv(node_dim, 48)
        self.conv2 = SAGEConv(48, 48)
        self.head = nn.Sequential(
            nn.Linear(48 + candidate_dim, 64), nn.ReLU(), nn.Dropout(0.10),
            nn.Linear(64, 32), nn.ReLU(), nn.Linear(32, 1),
        )

    def encode(self, graph):
        x = torch.relu(self.conv1(graph.x, graph.edge_index))
        x = torch.relu(self.conv2(x, graph.edge_index))
        return x.mean(dim=0)

    def forward(self, graphs, circuit_ids, candidate_x):
        embeddings = {name: self.encode(graph) for name, graph in graphs.items()}
        stacked = torch.stack([embeddings[name] for name in circuit_ids])
        return self.head(torch.cat([stacked, candidate_x], dim=1)).squeeze(1)


def standardize(train, other):
    mean = train.mean(axis=0)
    std = train.std(axis=0)
    std[std < 1e-9] = 1.0
    return (train - mean) / std, (other - mean) / std, mean, std


def choose_actions(decision_frame: pd.DataFrame, feasibility_meta: dict) -> pd.DataFrame:
    """Choose a candidate or abstain without receiving any test outcome column."""
    allowed = {
        "circuit", "candidate_uid", "predicted_cycles",
        "predicted_feasible_probability", "safe_anchor_uid",
    }
    if set(decision_frame.columns) != allowed:
        raise RuntimeError("Selection interface contains unexpected columns")
    rows = []
    identifiable = bool(feasibility_meta.get("identifiable", False))
    for circuit, part in decision_frame.groupby("circuit", sort=True):
        anchors = part.safe_anchor_uid.unique()
        if len(anchors) != 1:
            raise RuntimeError(f"Non-unique safe anchor for {circuit}")
        if not identifiable:
            rows.append({
                "circuit": circuit,
                "selection_action": "single_baseline",
                "selected_action_uid": anchors[0],
                "selection_reason": "ABSTAIN_SINGLE_CLASS",
            })
            continue
        eligible = part[
            (part.predicted_feasible_probability >= 0.5)
            & np.isfinite(part.predicted_cycles)
            & (part.predicted_cycles > 0)
        ].sort_values(["predicted_cycles", "candidate_uid"], kind="mergesort")
        if eligible.empty:
            rows.append({
                "circuit": circuit,
                "selection_action": "single_baseline",
                "selected_action_uid": anchors[0],
                "selection_reason": "ABSTAIN_NO_VALID_CANDIDATE",
            })
        else:
            rows.append({
                "circuit": circuit,
                "selection_action": "candidate",
                "selected_action_uid": eligible.iloc[0].candidate_uid,
                "selection_reason": "MODEL_CANDIDATE",
            })
    return pd.DataFrame(rows)


def metrics_for_predictions(
    part: pd.DataFrame,
    pred_cycles: np.ndarray,
    feasible_probability: np.ndarray,
    feasibility_meta: dict,
    model: str,
    fold_family: str,
):
    out = part.copy()
    out["predicted_cycles"] = pred_cycles
    out["predicted_feasible_probability"] = feasible_probability
    out["predicted_feasible_gate"] = (
        np.isfinite(feasible_probability) & (feasible_probability >= 0.5)
    ).astype(int)
    decisions = choose_actions(
        out[[
            "circuit", "candidate_uid", "predicted_cycles",
            "predicted_feasible_probability", "safe_anchor_uid",
        ]].copy(),
        feasibility_meta,
    )
    out = out.merge(decisions, on="circuit", validate="many_to_one")
    rows = []
    for circuit, circuit_part in out.groupby("circuit", sort=True):
        feasible_part = circuit_part[circuit_part.is_feasible == 1]
        if feasible_part.empty:
            raise RuntimeError(f"No measured D95-feasible candidate for {circuit}")
        oracle = feasible_part.loc[feasible_part.total_cycles.idxmin()]
        decision = decisions[decisions.circuit == circuit].iloc[0]
        baseline_values = circuit_part.single_baseline_cycles.unique()
        if len(baseline_values) != 1:
            raise RuntimeError(f"Non-unique evaluation single baseline for {circuit}")
        baseline = int(baseline_values[0])
        if decision.selection_action == "candidate":
            chosen = circuit_part[circuit_part.candidate_uid == decision.selected_action_uid]
            if len(chosen) != 1:
                raise RuntimeError(f"Selected candidate is not unique for {circuit}")
            chosen = chosen.iloc[0]
            actual_cycles = int(chosen.total_cycles)
            detected_faults = int(chosen.detected_faults)
            d95 = int(chosen.d95)
            d95_feasible = int(chosen.is_feasible)
            selected_scheme = chosen.scheme
            predicted_probability = float(chosen.predicted_feasible_probability)
            predicted_uid = chosen.candidate_uid
            exact_candidate = int(chosen.candidate_uid == oracle.candidate_uid)
            correct_scheme = int(chosen.scheme == oracle.scheme)
            saved_cycles = int(baseline - actual_cycles) if d95_feasible else 0
            gain = (
                float(saved_cycles / baseline * 100.0) if d95_feasible else np.nan
            )
        else:
            anchor = circuit_part.iloc[0]
            actual_cycles = int(anchor.safe_anchor_cycles)
            detected_faults = int(anchor.safe_anchor_detected_faults)
            d95 = int(anchor.safe_anchor_d95)
            d95_feasible = int(
                anchor.safe_anchor_feasible_at_d95 == 1 and detected_faults >= d95
            )
            selected_scheme = anchor.safe_anchor_scheme
            predicted_probability = np.nan
            predicted_uid = ""
            exact_candidate = 0
            correct_scheme = 0
            saved_cycles = 0
            gain = 0.0 if d95_feasible else np.nan
        beats_single = int(
            decision.selection_action == "candidate"
            and d95_feasible
            and actual_cycles < baseline
        )
        oracle_can_beat_single = int(int(oracle.total_cycles) < baseline)
        regret = (
            float((actual_cycles - oracle.total_cycles) / oracle.total_cycles * 100.0)
            if d95_feasible else np.nan
        )
        rows.append({
            "model": model,
            "test_family": fold_family,
            "test_circuit": circuit,
            "candidate_rows": len(circuit_part),
            "measured_feasible_candidate_rows": len(feasible_part),
            "mae_cycles": float(mean_absolute_error(feasible_part.total_cycles, feasible_part.predicted_cycles)),
            "rmse_cycles": float(math.sqrt(mean_squared_error(feasible_part.total_cycles, feasible_part.predicted_cycles))),
            "oracle_uid": oracle.candidate_uid,
            "oracle_scheme": oracle.scheme,
            "oracle_cycles": int(oracle.total_cycles),
            "single_baseline_cycles": baseline,
            "single_baseline_scheme": circuit_part.iloc[0].single_baseline_scheme,
            "safe_anchor_uid": circuit_part.iloc[0].safe_anchor_uid,
            "safe_anchor_scheme": circuit_part.iloc[0].safe_anchor_scheme,
            "selection_action": decision.selection_action,
            "selection_reason": decision.selection_reason,
            "selected_action_uid": decision.selected_action_uid,
            "predicted_best_uid": predicted_uid,
            "predicted_best_scheme": selected_scheme,
            "predicted_best_actual_cycles": actual_cycles,
            "predicted_best_feasible_probability": predicted_probability,
            "feasibility_gate_fallback": int(decision.selection_action != "candidate"),
            "feasibility_gate_kind": feasibility_meta["kind"],
            "feasibility_gate_identifiable": int(feasibility_meta["identifiable"]),
            "feasibility_gate_train_rows": feasibility_meta["train_rows"],
            "feasibility_gate_train_negative_rows": feasibility_meta["train_negative_rows"],
            "predicted_best_detected_faults": detected_faults,
            "d95": d95,
            "d95_feasible": d95_feasible,
            "unsafe_combo_selection": int(
                decision.selection_action == "candidate" and not d95_feasible
            ),
            "beats_single_baseline": beats_single,
            "oracle_can_beat_single": oracle_can_beat_single,
            "opportunity_captured": int(oracle_can_beat_single and beats_single),
            "saved_cycles_vs_single": saved_cycles,
            "gain_vs_single_percent": gain,
            "fallback_gain_vs_single_percent": max(gain, 0.0) if d95_feasible else 0.0,
            "regret_percent": regret,
            "exact_candidate": exact_candidate,
            "correct_scheme": correct_scheme,
        })
    return out, rows


def balanced_row_weights(frame: pd.DataFrame) -> np.ndarray:
    circuit_rows = frame.groupby("circuit").circuit.transform("size").astype(float)
    family_circuits = frame[["effective_family", "circuit"]].drop_duplicates().groupby(
        "effective_family"
    ).circuit.size()
    family_count = frame.effective_family.map(family_circuits).astype(float)
    weights = 1.0 / (family_count * circuit_rows)
    return (weights * len(weights) / weights.sum()).to_numpy(dtype=np.float32)


def run_feasibility_gate(
    train: pd.DataFrame,
    test: pd.DataFrame,
    output: Path,
    model_tag: str,
    fold: str,
    seed: int,
):
    """Fit a gate using training-family rows only; never inspect test labels."""
    labels = train.is_feasible.astype(int)
    meta = {
        "kind": "unidentifiable_single_class" if labels.nunique() < 2 else "xgboost_classifier",
        "identifiable": bool(labels.nunique() >= 2),
        "train_rows": int(len(train)),
        "train_negative_rows": int((labels == 0).sum()),
        "holdout_family": fold,
        "threshold": 0.5,
        "test_labels_not_used": True,
    }
    prefix = output / "models" / f"{model_tag}__feasibility__holdout_family_{fold}"
    if labels.nunique() < 2:
        probability = np.nan
        meta["constant_probability"] = None
        prefix.with_suffix(".json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        return np.full(len(test), probability, dtype=float), meta

    class_counts = labels.value_counts().to_dict()
    class_balance = labels.map({
        value: len(labels) / (len(class_counts) * count)
        for value, count in class_counts.items()
    }).to_numpy(dtype=np.float32)
    weights = balanced_row_weights(train) * class_balance
    gate = XGBClassifier(
        n_estimators=240,
        max_depth=4,
        learning_rate=0.04,
        subsample=0.9,
        colsample_bytree=0.9,
        reg_lambda=2.0,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=seed,
        n_jobs=16,
    )
    gate.fit(train[CANDIDATE_FEATURES], labels, sample_weight=weights)
    probability = gate.predict_proba(test[CANDIDATE_FEATURES])[:, 1]
    joblib.dump(gate, prefix.with_suffix(".joblib"))
    prefix.with_suffix(".json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return probability, meta


def run_xgb(frame, output: Path, seed: int):
    prediction_parts, fold_rows = [], []
    features = CANDIDATE_FEATURES
    for fold in sorted(frame.effective_family.unique()):
        train_all = frame[frame.effective_family != fold]
        test = frame[frame.effective_family == fold]
        feasible_probability, feasibility_meta = run_feasibility_gate(
            train_all, test, output, "xgboost_scalar", fold, seed
        )
        train = train_all[train_all.is_feasible == 1]
        model = XGBRegressor(
            n_estimators=500, max_depth=5, learning_rate=0.035, subsample=0.9,
            colsample_bytree=0.9, reg_lambda=2.0, objective="reg:squarederror",
            random_state=seed, n_jobs=16,
        )
        # Normalize by a circuit quantity known before candidate-grid search.
        target = np.log1p(train.total_cycles / train.common_fault_count)
        sample_weight = balanced_row_weights(train)
        model.fit(train[features], target, sample_weight=sample_weight)
        pred_ratio = np.expm1(model.predict(test[features])).clip(min=0)
        pred = pred_ratio * test.common_fault_count.to_numpy()
        part, rows = metrics_for_predictions(
            test, pred, feasible_probability, feasibility_meta, "xgboost_scalar", fold
        )
        prediction_parts.append(part)
        fold_rows.extend(rows)
        joblib.dump(model, output / "models" / f"xgboost_scalar__holdout_family_{fold}.joblib")
    return pd.concat(prediction_parts), pd.DataFrame(fold_rows)


def run_gnn(frame, graphs, output: Path, device: torch.device, epochs: int, seed: int):
    prediction_parts, fold_rows = [], []
    families = sorted(frame.effective_family.unique())
    for fold_i, fold in enumerate(families):
        seed_all(seed + fold_i)
        remaining = [family for family in families if family != fold]
        val_family = remaining[fold_i % len(remaining)]
        outer_train = frame[frame.effective_family != fold].copy()
        train_all = frame[
            (frame.effective_family != fold) & (frame.effective_family != val_family)
        ].copy()
        val_all = frame[frame.effective_family == val_family].copy()
        test = frame[frame.effective_family == fold].copy()
        feasible_probability, feasibility_meta = run_feasibility_gate(
            outer_train, test, output, "graphsage", fold, seed
        )
        train = train_all[train_all.is_feasible == 1].copy()
        val = val_all[val_all.is_feasible == 1].copy()
        train_families = set(train.effective_family)
        val_families = set(val.effective_family)
        test_families = set(test.effective_family)
        assert not (train_families & val_families)
        assert not (train_families & test_families)
        assert not (val_families & test_families)
        train_x = train[CANDIDATE_FEATURES].to_numpy(dtype=np.float32)
        val_x = val[CANDIDATE_FEATURES].to_numpy(dtype=np.float32)
        test_x = test[CANDIDATE_FEATURES].to_numpy(dtype=np.float32)
        train_x, val_x, mean, std = standardize(train_x, val_x)
        test_x = (test_x - mean) / std
        y_train = np.log1p(
            train.total_cycles.to_numpy(dtype=np.float32)
            / train.common_fault_count.to_numpy(dtype=np.float32)
        )
        y_val = np.log1p(
            val.total_cycles.to_numpy(dtype=np.float32)
            / val.common_fault_count.to_numpy(dtype=np.float32)
        )
        y_mean, y_std = float(y_train.mean()), float(y_train.std() or 1.0)
        y_train = (y_train - y_mean) / y_std
        y_val = (y_val - y_mean) / y_std

        fit_circuits = sorted(set(train.circuit) | set(val.circuit))
        fit_graphs = {c: graphs[c].to(device) for c in fit_circuits}
        model = GraphCandidateRegressor(next(iter(graphs.values())).x.shape[1], len(CANDIDATE_FEATURES)).to(device)
        optimizer = torch.optim.AdamW(model.parameters(), lr=0.004, weight_decay=1e-4)
        loss_fn = nn.HuberLoss(delta=1.0, reduction="none")
        tx = torch.tensor(train_x, device=device)
        vx = torch.tensor(val_x, device=device)
        ty = torch.tensor(y_train, device=device)
        vy = torch.tensor(y_val, device=device)
        train_w = torch.tensor(balanced_row_weights(train), device=device)
        val_w = torch.tensor(balanced_row_weights(val), device=device)
        best_loss, best_state, patience = float("inf"), None, 0
        for _ in range(epochs):
            model.train()
            optimizer.zero_grad(set_to_none=True)
            pred = model(fit_graphs, train.circuit.tolist(), tx)
            loss = (loss_fn(pred, ty) * train_w).mean()
            loss.backward()
            optimizer.step()
            model.eval()
            with torch.no_grad():
                val_loss = float((loss_fn(model(fit_graphs, val.circuit.tolist(), vx), vy) * val_w).mean())
            if val_loss < best_loss - 1e-6:
                best_loss = val_loss
                best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
                patience = 0
            else:
                patience += 1
            if patience >= 35:
                break
        model.load_state_dict(best_state)
        model.eval()
        test_graphs = {c: graphs[c].to(device) for c in sorted(set(test.circuit))}
        with torch.no_grad():
            raw = model(test_graphs, test.circuit.tolist(), torch.tensor(test_x, device=device)).cpu().numpy()
        pred_ratio = np.expm1(raw * y_std + y_mean).clip(min=0)
        pred_cycles = pred_ratio * test.common_fault_count.to_numpy()
        part, rows = metrics_for_predictions(
            test, pred_cycles, feasible_probability, feasibility_meta, "graphsage", fold
        )
        for row in rows:
            row["validation_family"] = val_family
            row["best_validation_loss"] = best_loss
        prediction_parts.append(part)
        fold_rows.extend(rows)
        torch.save({
            "state_dict": best_state, "feature_mean": mean, "feature_std": std,
            "target_mean": y_mean, "target_std": y_std, "holdout_family": fold,
            "validation_family": val_family,
        }, output / "models" / f"graphsage__holdout_family_{fold}.pt")
    return pd.concat(prediction_parts), pd.DataFrame(fold_rows)


def summarize(metrics: pd.DataFrame):
    summary = metrics.groupby("model").agg(
        circuits=("test_circuit", "count"),
        families=("test_family", "nunique"),
        d95_feasible_rate=("d95_feasible", "mean"),
        beats_single_baseline_rate=("beats_single_baseline", "mean"),
        opportunity_rate=("oracle_can_beat_single", "mean"),
        mean_gain_vs_single_percent=("gain_vs_single_percent", "mean"),
        mean_fallback_gain_percent=("fallback_gain_vs_single_percent", "mean"),
        mean_regret_percent=("regret_percent", "mean"),
        median_regret_percent=("regret_percent", "median"),
        max_regret_percent=("regret_percent", "max"),
        exact_candidate_rate=("exact_candidate", "mean"),
        correct_scheme_rate=("correct_scheme", "mean"),
        candidate_action_rate=("selection_action", lambda values: float((values == "candidate").mean())),
        abstain_rate=("selection_action", lambda values: float((values != "candidate").mean())),
        unsafe_combo_selection_rate=("unsafe_combo_selection", "mean"),
        mean_mae_cycles=("mae_cycles", "mean"),
        mean_rmse_cycles=("rmse_cycles", "mean"),
    ).reset_index()
    opportunities = metrics[metrics.oracle_can_beat_single == 1]
    capture = opportunities.groupby("model").beats_single_baseline.mean().rename(
        "opportunity_capture_rate"
    )
    family = metrics.groupby(["model", "test_family"]).agg(
        family_circuits=("test_circuit", "count"),
        family_win_rate=("beats_single_baseline", "mean"),
        family_d95_rate=("d95_feasible", "mean"),
        family_mean_gain_percent=("gain_vs_single_percent", "mean"),
        family_mean_regret_percent=("regret_percent", "mean"),
    ).reset_index()
    family_macro = family.groupby("model").family_win_rate.mean().rename(
        "family_macro_win_rate"
    )
    summary = summary.merge(capture, on="model", how="left").merge(
        family_macro, on="model", how="left"
    )
    return summary, family


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--graphs", required=True, type=Path)
    parser.add_argument("--family-map", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--epochs", type=int, default=220)
    parser.add_argument("--device", default="cuda")
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "models").mkdir()
    seed_all(args.seed)
    device = torch.device(args.device if args.device == "cpu" or torch.cuda.is_available() else "cpu")
    frame, graphs = load_inputs(args.dataset, args.graphs, args.family_map)
    if frame.circuit.nunique() < 8 or frame.effective_family.nunique() < 5:
        raise RuntimeError("Family-holdout V1 requires at least 8 circuits from 5 effective families")
    start = time.time()
    x_pred, x_metrics = run_xgb(frame, args.output, args.seed)
    g_pred, g_metrics = run_gnn(frame, graphs, args.output, device, args.epochs, args.seed)
    predictions = pd.concat([
        x_pred.assign(model="xgboost_scalar"), g_pred.assign(model="graphsage")
    ], ignore_index=True)
    metrics = pd.concat([x_metrics, g_metrics], ignore_index=True)
    summary, family_metrics = summarize(metrics)
    predictions.to_csv(args.output / "lofo_predictions.tsv", sep="\t", index=False)
    metrics.to_csv(args.output / "lofo_circuit_metrics.tsv", sep="\t", index=False)
    family_metrics.to_csv(args.output / "lofo_family_metrics.tsv", sep="\t", index=False)
    summary.to_csv(args.output / "lofo_summary.tsv", sep="\t", index=False)
    meta = {
        "status": "PASS", "split": "leave-one-effective-family-out",
        "candidate_rows": len(frame), "circuits": frame.circuit.nunique(),
        "measured_infeasible_candidate_rows": int((frame.is_feasible == 0).sum()),
        "effective_families": frame.effective_family.nunique(),
        "device": str(device), "seed": args.seed, "elapsed_seconds": time.time() - start,
        "input_policy": "no f_patterns/f_ratio candidate outcome leakage",
        "feasibility_policy": "shared outer-train-family gate; single-class labels are unidentifiable and force abstention",
        "decision_policy": "single-class or invalid/non-positive candidate predictions abstain to coordinate-fixed FullScan-F4 anchor",
        "target": "log1p(total_cycles/common_fault_count)",
        "primary_success": "selected candidate reaches D95 and has fewer cycles than the best feasible single-mode baseline",
        "secondary_metric": "cycle regret to the measured oracle candidate",
        "warning": "This remains a feasibility study; success does not imply oracle-optimal prediction.",
    }
    (args.output / "run_summary.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(summary.to_string(index=False))
    print(json.dumps(meta))


if __name__ == "__main__":
    main()
