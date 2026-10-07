"""Pure, non-authorizing binding of the existing v3 aggregate export receipt.

The caller supplies an already-read receipt object and its independently
captured raw-file SHA-256.  This module performs no I/O and cannot establish
that the caller actually read that file, grant a release, or start training.
"""
from copy import deepcopy
import hashlib
import json

from src.models import ranking_v5_execution_boundary as boundary
from src.models.runtime_ranking_v3 import FAMILIES

STATUS = "IMPLEMENTATION_ONLY_PENDING_PHYSICAL_CALLER"
PACKAGE_ROOT_ALLOWLIST = frozenset((
    "/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/train_folds",
))
RECEIPT_FIELDS = frozenset(("schema_version", "scope", "release_sha256", "source_sha256",
                            "source_input_sha256", "graph_sha256", "family_metadata_sha256",
                            "train_action_count", "train_outcome_count", "graph_count",
                            "fold_manifest_sha256"))
SOURCE_INPUT_NAMES = frozenset(("features.tsv", "train_outcomes.tsv", "graph_manifest.tsv"))
FAMILIES_EXACT = frozenset(FAMILIES.values())
PACKAGE_SHA256 = boundary.PACKAGE_SHA256
SOURCE_SHA256 = boundary.SOURCE_SHA256
MAX_RECEIPT_BYTES = 20 * 1024


def _sha(value):
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _lexical_root_allowed(package_root):
    if not isinstance(package_root, str) or package_root != package_root.strip() or "\\" in package_root:
        return False
    return package_root in PACKAGE_ROOT_ALLOWLIST


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("V5_PACKAGE_DUPLICATE_KEY")
        value[key] = item
    return value


def bind_v3_package_bytes(raw, package_root, roles, seed):
    """Bind one bounded raw aggregate-receipt buffer, without I/O or authority.

    The SHA is calculated from ``raw`` itself before parsing.  It is therefore
    not a caller assertion, and the decoded receipt can only originate from
    that same one-shot buffer.
    """
    if type(raw) is not bytes or not raw or len(raw) > MAX_RECEIPT_BYTES:
        raise ValueError("V5_PACKAGE_BYTES_BOUND")
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    if raw_sha256 != PACKAGE_SHA256:
        raise ValueError("V5_PACKAGE_RECEIPT_SHA")
    try:
        receipt = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, TypeError, ValueError) as error:
        raise ValueError("V5_PACKAGE_BYTES_JSON") from error
    return bind_v3_package_receipt(receipt, raw_sha256, package_root, roles, seed)


def bind_v3_package_receipt(receipt, raw_receipt_sha256, package_root, roles, seed):
    """Validate six immutable v3 fold-manifest pins for one v5 caller seed.

    ``raw_receipt_sha256`` is an integrity pin that a physical caller must
    independently associate with the bytes it read; it is explicitly not an
    authorization token.  ``roles`` similarly records TRAIN-only caller input
    and cannot replace a formal release.
    """
    if not _lexical_root_allowed(package_root):
        raise ValueError("V5_PACKAGE_ROOT")
    if raw_receipt_sha256 != PACKAGE_SHA256 or not _sha(raw_receipt_sha256):
        raise ValueError("V5_PACKAGE_RECEIPT_SHA")
    if roles != ["TRAIN"]:
        raise ValueError("V5_PACKAGE_ROLES")
    if type(seed) is not int or seed not in boundary.SEEDS:
        raise ValueError("V5_PACKAGE_SEED")
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_FIELDS:
        raise ValueError("V5_PACKAGE_RECEIPT_SCHEMA")
    if (receipt["schema_version"] != "ranking-v3-real-input-export-receipt-v1"
            or receipt["scope"] != "REAL_TRAIN_ONLY_RELEASED_SIX_FOLD"
            or receipt["source_sha256"] != SOURCE_SHA256):
        raise ValueError("V5_PACKAGE_RECEIPT_BINDING")
    if (not isinstance(receipt["source_input_sha256"], dict)
            or set(receipt["source_input_sha256"]) != SOURCE_INPUT_NAMES
            or not isinstance(receipt["graph_sha256"], dict)
            or set(receipt["graph_sha256"]) != set(FAMILIES)
            or not isinstance(receipt["fold_manifest_sha256"], dict)
            or set(receipt["fold_manifest_sha256"]) != FAMILIES_EXACT):
        raise ValueError("V5_PACKAGE_RECEIPT_MEMBERSHIP")
    digests = [receipt["release_sha256"], receipt["family_metadata_sha256"]]
    digests += list(receipt["source_input_sha256"].values()) + list(receipt["graph_sha256"].values())
    pins = receipt["fold_manifest_sha256"]
    digests += list(pins.values())
    if not all(_sha(value) for value in digests) or len(set(pins.values())) != len(pins):
        raise ValueError("V5_PACKAGE_DIGESTS")
    if (type(receipt["train_action_count"]) is not int or type(receipt["train_outcome_count"]) is not int
            or type(receipt["graph_count"]) is not int or receipt["train_action_count"] != 1706
            or receipt["train_outcome_count"] != 1706 or receipt["graph_count"] != 6):
        raise ValueError("V5_PACKAGE_COUNTS")
    return {"status": STATUS, "package_root": package_root, "package_receipt_sha256": raw_receipt_sha256,
            "source_sha256": SOURCE_SHA256, "roles": ["TRAIN"], "seed": seed,
            "fold_manifest_sha256": deepcopy(pins)}
