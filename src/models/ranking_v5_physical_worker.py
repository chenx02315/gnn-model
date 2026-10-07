"""CPU-only, synthetic-only physical worker for the v5 boundary.

There is deliberately no request-file loader or real-fit CLI.  The only CLI
entry creates an in-memory synthetic request and writes create-once evidence.
"""
import argparse
import io
import json
import os
from pathlib import Path
import hashlib

from src.models import ranking_v5_execution_boundary as boundary
from src.models import ranking_v5_training_kernel as kernel
from src.models.ranking_v3_freeze_io import persist_freeze, read_freeze
from src.models.runtime_ranking_v3 import FEATURES, FAMILIES, digest, make_candidate_ranker

MAX_MODEL_BYTES = 1024 * 1024
MAX_LOG_RECORD_BYTES = 20 * 1024
MAX_LOG_BYTES = 3 * 1024 * 1024
MAX_FREEZE_BYTES = 20 * 1024
MAX_RECEIPT_BYTES = 20 * 1024
MAX_SOURCE_BYTES = 30 * 1024
LOG_RECORDS = 122
PHYSICAL_PREFIX = "/ssd/cjc/gnn_model_ranking_v5_worker_gate_"
SYNTHETIC_PROVENANCE = "SYNTHETIC_PHYSICAL_WORKER_ONLY"
SOURCE_SHA256 = boundary.SOURCE_SHA256
PACKAGE_SHA256 = boundary.PACKAGE_SHA256


def _sha_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def _safe_path(path, *, allow_test_path=False):
    path = Path(path)
    if not path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError("V5_WORKER_OUTPUT_PATH")
    if not allow_test_path and not path.as_posix().startswith(PHYSICAL_PREFIX):
        raise ValueError("V5_WORKER_PHYSICAL_PREFIX")
    # Check extant components before resolve so a symlink can never redirect us.
    for item in (path, *path.parents):
        if item.is_symlink():
            raise ValueError("V5_WORKER_OUTPUT_SYMLINK")
    return path


def _write_exclusive(path, raw):
    with Path(path).open("xb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def verify_source_files(root):
    """Hash exactly the source binding expected by the execution boundary."""
    root = Path(root)
    if not root.is_absolute() or any(item.is_symlink() for item in (root, *root.parents)) or not root.is_dir():
        raise ValueError("V5_WORKER_SOURCE_ROOT")
    result = {}
    for rel in sorted(boundary.REQUIRED_SOURCE_BINDINGS):
        path = root.joinpath(*rel.split("/"))
        # Each source path is constructed from the fixed allowlist, and every
        # component is checked so a linked directory cannot escape ``root``.
        relative = path.relative_to(root)
        components = [root]
        current = root
        for part in relative.parts:
            current = current / part; components.append(current)
        if any(item.is_symlink() for item in components) or not path.is_file() or path.stat().st_size > MAX_SOURCE_BYTES:
            raise ValueError("V5_WORKER_SOURCE_FILE")
        result[rel] = _sha_bytes(path.read_bytes())
    return result


class PhysicalArtifactStore:
    """Create-once bounded files, with acknowledgement only after readback."""
    def __init__(self, output, *, allow_test_path=False):
        self.output = _safe_path(output, allow_test_path=allow_test_path)
        self.output.mkdir(mode=0o700, parents=False, exist_ok=False)
        if self.output.is_symlink():
            raise ValueError("V5_WORKER_OUTPUT_SYMLINK")

    def persist_model_bytes(self, raw, expected_sha):
        if not isinstance(raw, bytes) or len(raw) > MAX_MODEL_BYTES or _sha_bytes(raw) != expected_sha:
            raise ValueError("V5_WORKER_MODEL_BYTES")
        path = self.output / "model.pt"
        _write_exclusive(path, raw)
        if path.is_symlink() or _sha_bytes(path.read_bytes()) != expected_sha:
            raise ValueError("V5_WORKER_MODEL_READBACK")
        return expected_sha

    def persist_logs(self, records):
        if not isinstance(records, list) or len(records) != LOG_RECORDS:
            raise ValueError("V5_WORKER_LOG_COUNT")
        lines = []
        for record in records:
            raw = (json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
            if len(raw) > MAX_LOG_RECORD_BYTES:
                raise ValueError("V5_WORKER_LOG_RECORD_BOUND")
            lines.append(raw)
        data = b"".join(lines)
        if len(data) > MAX_LOG_BYTES:
            raise ValueError("V5_WORKER_LOG_TOTAL_BOUND")
        path = self.output / "fitting.jsonl"; expected = _sha_bytes(data)
        _write_exclusive(path, data)
        if path.is_symlink() or _sha_bytes(path.read_bytes()) != expected:
            raise ValueError("V5_WORKER_LOG_READBACK")
        return expected

    def persist_freeze(self, payload, sha):
        envelope = (json.dumps({"payload": payload, "sha256": sha}, sort_keys=True,
                               separators=(",", ":"), allow_nan=False) + "\n").encode()
        if len(envelope) > MAX_FREEZE_BYTES:
            raise ValueError("V5_WORKER_FREEZE_BOUND")
        return persist_freeze(self.output / "freeze.json", payload, sha)

    def read_freeze(self, expected_sha):
        if (self.output / "freeze.json").stat().st_size > MAX_FREEZE_BYTES:
            raise ValueError("V5_WORKER_FREEZE_BOUND")
        payload = read_freeze(self.output / "freeze.json", expected_sha)
        return payload, expected_sha

    def write_receipt(self, receipt):
        raw = (json.dumps(receipt, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
        if len(raw) > MAX_RECEIPT_BYTES:
            raise ValueError("V5_WORKER_RECEIPT_BOUND")
        _write_exclusive(self.output / "worker_receipt.json", raw)
        if _sha_bytes((self.output / "worker_receipt.json").read_bytes()) != _sha_bytes(raw):
            raise ValueError("V5_WORKER_RECEIPT_READBACK")


def fit_prepared(torch, np, prepared, recipe, seed, emit, request_sha256):
    """The kernel's fixed 120-epoch fitting loop, on already prepared data."""
    if not callable(emit) or not boundary._sha(request_sha256):
        raise ValueError("V5_WORKER_FIT_INPUT")
    from src.models.runtime_training_v2 import seed_everything
    seed_everything(seed, torch, np)
    uids = prepared["fit_uids"]; index = {uid: i for i, uid in enumerate(uids)}
    x = torch.tensor(prepared["fit_features"], dtype=torch.float32, device="cpu")
    model = make_candidate_ranker(torch)
    optimizer = torch.optim.Adam(model.parameters(), lr=.001, weight_decay=.0001)
    def record(epoch, phase):
        with torch.no_grad(): values = model(x).detach().cpu().tolist()
        if len(values) != len(uids): raise ValueError("V5_WORKER_LOG_SCORE_SHAPE")
        emit(kernel.log_record(dict(zip(uids, values)), recipe, prepared["pairs"], epoch=epoch,
                               phase=phase, request_sha256=request_sha256))
    model.train(); record(0, "INITIAL")
    for epoch in range(1, kernel.EPOCHS + 1):
        optimizer.zero_grad(); loss = kernel.torch_loss(model(x), index, recipe, torch)
        loss.backward(); optimizer.step(); record(epoch, "EPOCH")
    model.eval(); record(kernel.EPOCHS, "FINAL")
    return model


def execute_synthetic(request, release, output, torch, np, *, root=None, allow_test_path=False):
    """Run only a synthetic request; no held labels/callback are accepted."""
    root = Path(root) if root is not None else Path(__file__).resolve().parents[2]
    sources = verify_source_files(root)
    # This worker has no caller-authorized synthetic mode: only its own exact
    # fixture and explicitly non-formal authority may proceed.
    expected_request = synthetic_request()
    expected_release = _test_release(sources)
    if (request != expected_request or release != expected_release
            or digest(request) != digest(expected_request) or digest(release) != digest(expected_release)):
        raise ValueError("V5_WORKER_GENERATED_SYNTHETIC_FIXTURE_REQUIRED")
    # Refuse malformed authority/data before provisioning any physical output.
    boundary.validate_release(release, sources)
    boundary.prepare_request(request)
    store = PhysicalArtifactStore(output, allow_test_path=allow_test_path)
    logs = []; log_bytes = [0]; request_sha = digest(request)
    def emit(record):
        raw = (json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
        if len(logs) >= LOG_RECORDS:
            raise ValueError("V5_WORKER_LOG_COUNT")
        if len(raw) > MAX_LOG_RECORD_BYTES:
            raise ValueError("V5_WORKER_LOG_RECORD_BOUND")
        if log_bytes[0] + len(raw) > MAX_LOG_BYTES:
            raise ValueError("V5_WORKER_LOG_TOTAL_BOUND")
        log_bytes[0] += len(raw); logs.append(record)
    def fit(prepared, recipe, seed):
        return fit_prepared(torch, np, prepared, recipe, seed, emit, request_sha)
    model_raw = {}
    def model_sha(model):
        buffer = io.BytesIO(); torch.save(model.state_dict(), buffer); raw = buffer.getvalue()
        if len(raw) > MAX_MODEL_BYTES: raise ValueError("V5_WORKER_MODEL_BOUND")
        model_raw["raw"] = raw; return _sha_bytes(raw)
    def persist_model(model, expected): return store.persist_model_bytes(model_raw.get("raw", b""), expected)
    def predict(model, uids, features):
        with torch.no_grad(): values = model(torch.tensor(features, dtype=torch.float32, device="cpu")).detach().cpu().tolist()
        return dict(zip(uids, values))
    receipt = boundary.execute(request, release, sources, fit=fit, predict=predict, model_sha256=model_sha,
                               persist_model=persist_model, persist_freeze=store.persist_freeze,
                               read_frozen=store.read_freeze)
    boundary_receipt_sha = digest(receipt)
    log_sha = store.persist_logs(logs)
    receipt.update({"artifact_scope": SYNTHETIC_PROVENANCE, "formal": False, "real_fits": 0,
                    "model_sha256": receipt["model_ack_sha256"], "fitting_log_sha256": log_sha,
                    "freeze_sha256": receipt["freeze_sha256"], "worker_receipt_kind": "SYNTHETIC_ONLY"})
    receipt["boundary_receipt_sha256"] = boundary_receipt_sha
    receipt["worker_receipt_sha256"] = digest({k: v for k, v in receipt.items() if k != "worker_receipt_sha256"})
    store.write_receipt(receipt)
    return receipt


def synthetic_request():
    rows = []; cycles = {}
    for circuit, family in FAMILIES.items():
        for index in range(12):
            uid = "%s:synthetic:%02d" % (circuit, index)
            rows.append(dict(action_uid=uid, circuit=circuit, family=family, role="TRAIN",
                             **{name: float(index + column + 1) for column, name in enumerate(FEATURES)}))
            cycles[uid] = 100 if index == 0 else 200 + index
    family = sorted(FAMILIES.values())[0]
    held_circuit = next(circuit for circuit, value in FAMILIES.items() if value == family)
    return {"scope": boundary.SCOPE, "source_sha256": boundary.SOURCE_SHA256, "family": family,
            "seed": boundary.SEEDS[0], "model": boundary.MODEL, "rows": rows,
            "fit_cycles": {uid: value for uid, value in cycles.items() if not uid.startswith(held_circuit + ":")}}


def _test_release(sources):
    return {"schema":"ranking-v5-train-execution-release-v1", "status":"PASS_V5_TRAIN_EXECUTION_AUTHORIZED",
      "source_sha256":boundary.SOURCE_SHA256, "package_receipt_sha256":boundary.PACKAGE_SHA256, "roles":["TRAIN"],
      "seeds":list(boundary.SEEDS), "model":boundary.MODEL, "epochs":120, "feature_count":7,
      "optimizer":{"name":"Adam","lr":.001,"weight_decay":.0001}, "K":10, "epsilon":"101/100",
      "worker_limits":{"worker_count":1,"threads":1,"as_limit_bytes":8*1024**3,"rss_limit_bytes":1024**3}, "retry_count":0,
      "user_authorization_id":"TEST_ONLY_AUTHORITY_NOT_FORMAL", "user_authorization_sha256":"0"*64,
      "independent_review":True, "independent_review_receipt_sha256":"1"*64, "source_binding":sources,
      "synthetic_gate":{"kind":"raw_log","raw_log_sha256":boundary.V5_KERNEL_RAW_LOG_SHA256}}


def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument("--synthetic-gate", action="store_true"); parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    if not args.synthetic_gate: parser.error("only --synthetic-gate is open; formal CLI is CLOSED")
    # CUDA is explicitly disabled before importing torch; no external data is read.
    os.environ["CUDA_VISIBLE_DEVICES"] = ""
    from src.models.preflight_runtime_v2 import parse_lock, validate_installed_dependencies
    validate_installed_dependencies(parse_lock(Path(__file__).resolve().parents[2] / "requirements/runtime_v2.lock.txt"))
    import numpy as np
    import torch
    torch.set_num_threads(1); torch.set_num_interop_threads(1)
    sources = verify_source_files(Path(__file__).resolve().parents[2])
    receipt = execute_synthetic(synthetic_request(), _test_release(sources), args.output, torch, np)
    print("V5_SYNTHETIC_PHYSICAL_WORKER=" + receipt["worker_receipt_sha256"])


if __name__ == "__main__":
    main()
