"""Fail-closed, callback-only v5 TRAIN execution boundary.

This module is deliberately *not* a trainer, CLI, OS sandbox, or v5 worker.
The caller owns all storage and runtime isolation through the injected
callbacks.  The boundary only validates the release/request contract and
makes held-label access occur after model and freeze acknowledgement/readback.
"""
from copy import deepcopy

from src.models import ranking_v4_training_worker as _v4
from src.models.ranking_v5_head_objective import build_recipe
from src.models.runtime_ranking_v3 import digest, feature_matrix, freeze_ranking, replay_frozen, transform


SCOPE = "RANKING_V5_TRAIN_EXECUTION_BOUNDARY"
MODEL = "candidate_mlp"
SEEDS = (20260824, 20260825, 20260826)
EPOCHS = 120
FEATURE_COUNT = 7
ADAM_LR = .001
ADAM_WEIGHT_DECAY = .0001
K = 10
EPSILON = "101/100"
WORKER_THREADS = 1
WORKER_AS_LIMIT_BYTES = 8 * 1024 ** 3
WORKER_RSS_LIMIT_BYTES = 1 * 1024 ** 3
RETRY_COUNT = 0
SOURCE_SHA256 = "b89b455ace9d545c0afd54fe9fded98e4db4abd56f58fe09a0cce28b88215d9c"
PACKAGE_SHA256 = "964703dc441fea95c3b1b301dfd6dd01a2cf38f817d82597ff00450287e43868"
V5_KERNEL_RAW_LOG_SHA256 = "647e83f7381f9a4e3434cda4435426348a1a12975c5ea50ddae89f22c72199cf"
V5_KERNEL_MANIFEST_SHA256 = "dab412fdf477870f409cb681b854297fe1dbc4a707d3f86cf68d4db26c6960e2"
REQUIRED_SOURCE_BINDINGS = frozenset((
    "src/models/runtime_ranking_v3.py", "src/models/runtime_training_v2.py", "src/models/neural_ranking_v3.py",
    "src/models/run_runtime_ranking_v3.py", "src/models/ranking_v3_freeze_io.py",
    "src/data/ranking_v3_real_fold_package.py", "scripts/ranking_v4_near_optimal_pairs.py",
    "src/models/ranking_v4_training_worker.py", "src/models/ranking_v5_head_objective.py",
    "src/models/ranking_v5_training_kernel.py", "requirements/runtime_v2.lock.txt",
    "src/models/ranking_v5_execution_boundary.py",
))

RELEASE_FIELDS = frozenset((
    "schema", "status", "source_sha256", "package_receipt_sha256", "roles", "seeds", "model",
    "epochs", "feature_count", "optimizer", "K", "epsilon", "worker_limits", "retry_count",
    "user_authorization_id", "user_authorization_sha256", "independent_review",
    "independent_review_receipt_sha256", "source_binding", "synthetic_gate",
))


def _sha(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _fail(code):
    raise ValueError(code)


def _exact_int(value, expected):
    return type(value) is int and value == expected


def _safe_source_binding(binding):
    if not isinstance(binding, dict) or set(binding) != REQUIRED_SOURCE_BINDINGS:
        return False
    for path, sha in binding.items():
        if (not isinstance(path, str) or not path or path.startswith(("/", "\\")) or "\\" in path
                or any(part in ("", ".", "..") for part in path.split("/")) or not _sha(sha)):
            return False
    return True


def _validate_synthetic_gate(gate):
    """Accept raw-kernel evidence or a separately bound manifest contract."""
    if not isinstance(gate, dict):
        _fail("V5_SYNTHETIC_GATE_SCHEMA")
    if gate.get("kind") == "raw_log":
        if set(gate) != {"kind", "raw_log_sha256"} or gate["raw_log_sha256"] != V5_KERNEL_RAW_LOG_SHA256:
            _fail("V5_SYNTHETIC_GATE_RAW")
    elif gate.get("kind") == "manifest_bound":
        if (set(gate) != {"kind", "manifest_sha256", "raw_log_sha256"} or not _sha(gate["manifest_sha256"])
                or gate["manifest_sha256"] != V5_KERNEL_MANIFEST_SHA256
                or gate["raw_log_sha256"] != V5_KERNEL_RAW_LOG_SHA256):
            _fail("V5_SYNTHETIC_GATE_MANIFEST")
    else:
        _fail("V5_SYNTHETIC_GATE_KIND")


def validate_release(release, expected_source_binding):
    """Validate the explicit v5 release; never manufacture authority locally."""
    if not isinstance(release, dict) or set(release) != RELEASE_FIELDS:
        _fail("V5_RELEASE_SCHEMA")
    if (release["schema"] != "ranking-v5-train-execution-release-v1"
            or release["status"] != "PASS_V5_TRAIN_EXECUTION_AUTHORIZED"
            or release["source_sha256"] != SOURCE_SHA256
            or release["package_receipt_sha256"] != PACKAGE_SHA256
            or release["roles"] != ["TRAIN"] or release["seeds"] != list(SEEDS)
            or release["model"] != MODEL or not _exact_int(release["epochs"], EPOCHS)
            or not _exact_int(release["feature_count"], FEATURE_COUNT) or not _exact_int(release["K"], K)
            or release["epsilon"] != EPSILON or not _exact_int(release["retry_count"], RETRY_COUNT)):
        _fail("V5_RELEASE_PROTOCOL")
    if any(type(seed) is not int for seed in release["seeds"]):
        _fail("V5_RELEASE_SEEDS")
    optimizer = release["optimizer"]
    if (not isinstance(optimizer, dict) or optimizer != {"name": "Adam", "lr": ADAM_LR, "weight_decay": ADAM_WEIGHT_DECAY}
            or type(optimizer.get("lr")) is not float or type(optimizer.get("weight_decay")) is not float):
        _fail("V5_RELEASE_OPTIMIZER")
    limits = release["worker_limits"]
    if (not isinstance(limits, dict) or limits != {"worker_count": 1, "threads": WORKER_THREADS,
                                                    "as_limit_bytes": WORKER_AS_LIMIT_BYTES, "rss_limit_bytes": WORKER_RSS_LIMIT_BYTES}
            or any(type(limits[key]) is not int for key in limits)):
        _fail("V5_RELEASE_LIMITS")
    if (not isinstance(release["user_authorization_id"], str) or not release["user_authorization_id"]
            or not _sha(release["user_authorization_sha256"])
            or release["independent_review"] is not True
            or not _sha(release["independent_review_receipt_sha256"])):
        _fail("V5_RELEASE_AUTHORITY")
    if not _safe_source_binding(expected_source_binding) or release["source_binding"] != expected_source_binding:
        _fail("V5_SOURCE_BINDING")
    _validate_synthetic_gate(release["synthetic_gate"])


def prepare_request(request):
    """Strictly validate v5 request data using v4 only as its data validator."""
    if not isinstance(request, dict) or set(request) != _v4.REQUEST_FIELDS:
        _fail("V5_REQUEST_SCHEMA")
    if not isinstance(request.get("rows"), list) or not 0 < len(request["rows"]) <= 20000:
        _fail("V5_REQUEST_ROW_BOUND")
    if (request.get("scope") != SCOPE or request.get("source_sha256") != SOURCE_SHA256
            or type(request.get("seed")) is not int):
        _fail("V5_REQUEST_PROTOCOL")
    # v4's strict parser is intentionally used only for rows/folds/fitting data.
    fold, prepared, held_rows, _ = _v4.prepare_request(dict(request, scope=_v4.SCOPE))
    # Validate every row before fit, including held-out feature values.
    feature_matrix(request["rows"])
    by_uid = {row["action_uid"]: row for row in request["rows"]}
    recipe = build_recipe([
        {"action_uid": uid, "family": by_uid[uid]["family"], "total_cycles": request["fit_cycles"][uid]}
        for uid in prepared["fit_uids"]
    ], heldout_family=fold.family)
    return fold, prepared, held_rows, recipe


def execute(request, release, expected_source_binding, *, fit, predict, model_sha256, persist_model, persist_freeze, read_frozen,
            load_held_labels=None):
    """Run one authorized fold through injected callbacks and return bounded evidence.

    ``fit`` receives exactly ``(prepared_fitting_data, head_recipe, seed)``.
    It is never given held rows/features/labels. ``load_held_labels`` is optional
    and is called only after exact model acknowledgement and freeze reread.
    """
    callbacks = (fit, predict, model_sha256, persist_model, persist_freeze, read_frozen)
    if any(not callable(callback) for callback in callbacks) or (load_held_labels is not None and not callable(load_held_labels)):
        _fail("V5_CALLBACKS")
    request_snapshot, release_snapshot, binding_snapshot = deepcopy(request), deepcopy(release), deepcopy(expected_source_binding)
    request_sha, release_sha, binding_sha = (digest(request_snapshot), digest(release_snapshot), digest(binding_snapshot))
    validate_release(release_snapshot, binding_snapshot)
    fold, prepared, held_rows, recipe = prepare_request(request_snapshot)
    recipe_sha = digest(recipe)
    # The fit callback gets its own copy: it cannot alter later held-feature
    # normalization or the recipe digest retained by this boundary.
    model = fit(deepcopy(prepared), deepcopy(recipe), request_snapshot["seed"])
    expected_model_sha = model_sha256(model)
    if not _sha(expected_model_sha):
        _fail("V5_MODEL_ACK")
    model_ack = persist_model(model, expected_model_sha)
    if model_ack != expected_model_sha:
        _fail("V5_MODEL_ACK")
    held_uids = tuple(row["action_uid"] for row in held_rows)
    held_features = transform(feature_matrix(held_rows), prepared["normalizer"])
    scores = predict(model, held_uids, held_features)
    payload, freeze_sha = freeze_ranking(scores, fold)
    if persist_freeze(payload, freeze_sha) != freeze_sha:
        _fail("V5_FREEZE_PERSIST_ACK")
    reread = read_frozen(freeze_sha)
    if (not isinstance(reread, tuple) or len(reread) != 2 or reread[0] != payload
            or reread[1] != freeze_sha or digest(reread[0]) != freeze_sha):
        _fail("V5_FREEZE_REREAD")
    result = None
    if load_held_labels is not None:
        outcomes = load_held_labels(fold.heldout, freeze_sha)
        result = replay_frozen(reread[0], freeze_sha, fold, outcomes)
    return {"scope": SCOPE, "family": fold.family, "seed": request_snapshot["seed"], "model": MODEL,
            "model_ack_sha256": model_ack, "freeze_sha256": freeze_sha,
            "expected_model_sha256": expected_model_sha, "canonical_request_sha256": request_sha,
            "release_sha256": release_sha, "source_binding_sha256": binding_sha,
            "head_recipe_sha256": recipe_sha, "held_labels_replayed": result is not None,
            "metrics": result}
