"""Implementation-only adapter from a released v3 fold to a v5 fit request.

This local reader neither validates a package-level receipt nor creates a
release.  It deliberately never touches ``heldout_outcomes.json``.
"""
import json

from src.data import ranking_v3_real_fold_package as v3
from src.models import ranking_v5_execution_boundary as boundary
from src.models import ranking_v5_real_request_loader as safe_loader
from src.models.runtime_ranking_v3 import FEATURES, plan_folds

STATUS = "IMPLEMENTATION_ONLY_PENDING_PHYSICAL_CALLER"
MAX_ROWS = 20000
READ_SHARDS = ("fit_features.json", "fit_outcomes.json", "heldout_features.json")
MANIFEST_KEYS = frozenset(("schema_version", "scope", "release", "source_sha256",
                           "family", "fitting", "heldout", "sha256"))
ROW_ALLOWED = frozenset((*v3.METADATA, *FEATURES, *v3.OPTIONAL))
ROW_REQUIRED = frozenset((*v3.METADATA, *FEATURES))


def _fail(code):
    raise ValueError(code)


def _read(root, name, expected_sha):
    return safe_loader._read_one(safe_loader._ordinary_path(root, name), expected_sha)


def _project_rows(rows):
    if not isinstance(rows, list):
        _fail("V5_V3_ADAPTER_ROWS")
    projected = []
    for row in rows:
        if (not isinstance(row, dict) or not ROW_REQUIRED <= set(row)
                or not set(row) <= ROW_ALLOWED):
            _fail("V5_V3_ADAPTER_ROW_SCHEMA")
        projected.append({field: row[field] for field in (*v3.METADATA, *FEATURES)})
    return projected


def adapt_v3_fold(root, expected_manifest_sha256, family, seed):
    """Return a boundary-compatible v5 request from one v3 released fold.

    ``expected_manifest_sha256`` and the caller-selected physical root are
    integrity inputs, not authority.  A later caller must independently bind
    the v3 package-level receipt, source set and formal release.
    """
    if not isinstance(family, str) or type(seed) is not int:
        _fail("V5_V3_ADAPTER_ARGUMENTS")
    manifest = _read(root, "manifest.json", expected_manifest_sha256)
    if not isinstance(manifest, dict) or set(manifest) != MANIFEST_KEYS:
        _fail("V5_V3_ADAPTER_MANIFEST_SCHEMA")
    if (manifest["schema_version"] != v3.SCHEMA_VERSION or manifest["scope"] != v3.SCOPE
            or manifest["source_sha256"] != boundary.SOURCE_SHA256 or manifest["family"] != family
            or not isinstance(manifest["sha256"], dict) or set(manifest["sha256"]) != set(v3.SHARD_NAMES)):
        _fail("V5_V3_ADAPTER_MANIFEST_BINDING")
    try:
        v3._validate_release(manifest["release"], manifest["source_sha256"])
    except (TypeError, ValueError) as error:
        raise ValueError("V5_V3_ADAPTER_RELEASE") from error
    if any(not v3._is_sha256(value) for value in manifest["sha256"].values()):
        _fail("V5_V3_ADAPTER_SHARD_SHA")

    # Do not add heldout_outcomes.json here: no path examination is permitted.
    fit_rows = _project_rows(_read(root, "fit_features.json", manifest["sha256"]["fit_features.json"]))
    held_rows = _project_rows(_read(root, "heldout_features.json", manifest["sha256"]["heldout_features.json"]))
    rows = fit_rows + held_rows
    if not 0 < len(rows) <= MAX_ROWS:
        _fail("V5_V3_ADAPTER_ROW_BOUND")
    try:
        folds = plan_folds(rows)
    except (TypeError, ValueError) as error:
        raise ValueError("V5_V3_ADAPTER_METADATA") from error
    matches = [fold for fold in folds if fold.family == family]
    if len(matches) != 1:
        _fail("V5_V3_ADAPTER_FAMILY")
    fold = matches[0]
    if manifest["fitting"] != list(fold.fitting) or manifest["heldout"] != list(fold.heldout):
        _fail("V5_V3_ADAPTER_MEMBERSHIP")

    outcomes = _read(root, "fit_outcomes.json", manifest["sha256"]["fit_outcomes.json"])
    try:
        v3._validate_outcomes(fit_rows, outcomes)
    except (TypeError, ValueError) as error:
        raise ValueError("V5_V3_ADAPTER_FIT_OUTCOMES") from error
    cycles = {}
    for uid, outcome in outcomes.items():
        value = outcome["total_cycles"]
        if type(value) is not int or value <= 0:
            _fail("V5_V3_ADAPTER_CYCLES")
        cycles[uid] = value
    request = {"scope": boundary.SCOPE, "source_sha256": boundary.SOURCE_SHA256,
               "family": family, "seed": seed, "model": boundary.MODEL,
               "rows": rows, "fit_cycles": cycles}
    try:
        boundary.prepare_request(request)
    except (TypeError, ValueError) as error:
        raise ValueError("V5_V3_ADAPTER_REQUEST") from error
    return request
