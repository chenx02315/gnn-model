"""Freeze-gated local reader for v3 TRAIN held-out outcomes.

It has no CLI, release, network, model, or training entry point.  The caller
must provide a freeze payload that was already persisted and read back.
"""
from src.data import ranking_v3_real_fold_package as v3
from src.models import ranking_v5_execution_boundary as boundary
from src.models import ranking_v5_package_binding as package_binding
from src.models import ranking_v5_real_request_loader as safe_loader
from src.models.runtime_ranking_v3 import FAMILIES, freeze_ranking

IDENTITY_FIELDS = frozenset(("package_receipt_sha256", "source_sha256", "fold_manifest_sha256", "family", "seed"))
MANIFEST_FIELDS = frozenset(("schema_version", "scope", "release", "source_sha256",
                             "family", "fitting", "heldout", "sha256"))


def _fail(code):
    raise ValueError(code)


def _validate_before_io(package_root, input_identity, fold, uids, freeze_sha, frozen_readback):
    if not package_binding._lexical_root_allowed(package_root):
        _fail("V5_HELD_ROOT")
    if (not isinstance(input_identity, dict) or set(input_identity) != IDENTITY_FIELDS
            or input_identity["package_receipt_sha256"] != package_binding.PACKAGE_SHA256
            or input_identity["source_sha256"] != boundary.SOURCE_SHA256
            or not boundary._sha(input_identity["fold_manifest_sha256"])
            or not isinstance(input_identity["family"], str) or input_identity["family"] not in FAMILIES.values()
            or type(input_identity["seed"]) is not int
            or input_identity["seed"] not in boundary.SEEDS):
        _fail("V5_HELD_IDENTITY")
    if (not hasattr(fold, "family") or not hasattr(fold, "fitting") or not hasattr(fold, "heldout")
            or type(uids) is not tuple or fold.family != input_identity["family"] or uids != fold.heldout):
        _fail("V5_HELD_MEMBERSHIP")
    if (not isinstance(frozen_readback, tuple) or len(frozen_readback) != 2
            or frozen_readback[1] != freeze_sha or not boundary._sha(freeze_sha)
            or not isinstance(frozen_readback[0], dict) or set(frozen_readback[0]) !=
            {"family", "fitting_uids_sha256", "heldout_uids_sha256", "scores", "order", "epsilon", "top_k"}):
        _fail("V5_HELD_FREEZE_READBACK")
    payload = frozen_readback[0]
    try:
        expected, expected_sha = freeze_ranking(payload["scores"], fold)
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("V5_HELD_FREEZE_READBACK") from error
    if payload != expected or freeze_sha != expected_sha:
        _fail("V5_HELD_FREEZE_READBACK")


def load_frozen_held_outcomes(package_root, input_identity, fold, uids, freeze_sha, frozen_readback):
    """Return exact held outcomes only after exact frozen-ranking readback."""
    _validate_before_io(package_root, input_identity, fold, uids, freeze_sha, frozen_readback)
    family_root = package_root + "/fold_" + input_identity["family"]
    manifest = safe_loader._read_one(safe_loader._ordinary_path(family_root, "manifest.json"),
                                     input_identity["fold_manifest_sha256"])
    if (not isinstance(manifest, dict) or set(manifest) != MANIFEST_FIELDS
            or manifest["schema_version"] != v3.SCHEMA_VERSION or manifest["scope"] != v3.SCOPE
            or manifest["source_sha256"] != boundary.SOURCE_SHA256 or manifest["family"] != fold.family
            or manifest["fitting"] != list(fold.fitting) or manifest["heldout"] != list(fold.heldout)
            or not isinstance(manifest["sha256"], dict) or set(manifest["sha256"]) != set(v3.SHARD_NAMES)):
        _fail("V5_HELD_MANIFEST")
    try:
        v3._validate_release(manifest["release"], manifest["source_sha256"])
    except (TypeError, ValueError) as error:
        raise ValueError("V5_HELD_RELEASE") from error
    if any(not v3._is_sha256(value) for value in manifest["sha256"].values()):
        _fail("V5_HELD_MANIFEST_SHA")
    outcomes = safe_loader._read_one(
        safe_loader._ordinary_path(family_root, "heldout_outcomes.json"), manifest["sha256"]["heldout_outcomes.json"])
    try:
        v3._validate_outcomes([{"action_uid": uid} for uid in uids], outcomes)
    except (TypeError, ValueError) as error:
        raise ValueError("V5_HELD_OUTCOMES") from error
    if any(type(outcome["total_cycles"]) is not int or outcome["total_cycles"] <= 0 for outcome in outcomes.values()):
        _fail("V5_HELD_OUTCOMES")
    return outcomes
