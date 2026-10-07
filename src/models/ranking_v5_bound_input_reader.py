"""Local, non-authorizing reader binding one v3 package receipt to one fold."""
from src.models import ranking_v5_package_binding as package_binding
from src.models import ranking_v5_real_request_loader as safe_loader
from src.models import ranking_v5_v3_fold_adapter as fold_adapter
from src.models import ranking_v5_execution_boundary as boundary
from src.models.runtime_ranking_v3 import FAMILIES

STATUS = "IMPLEMENTATION_ONLY_PENDING_PHYSICAL_CALLER"
MAX_RECEIPT_BYTES = 20 * 1024


def _read_receipt_bytes(root):
    """Read the aggregate receipt once, bounded, after safe path validation."""
    path = safe_loader._ordinary_path(root, "receipt.json")
    with path.open("rb") as stream:
        raw = stream.read(MAX_RECEIPT_BYTES + 1)
    if not raw or len(raw) > MAX_RECEIPT_BYTES:
        raise ValueError("V5_BOUND_INPUT_RECEIPT_BOUND")
    return raw


def load_bound_fold_request(package_root, family, seed):
    """Return one v5 request plus non-authorizing, bounded input identity.

    A physical caller still must validate approvals, source binding and prelaunch
    evidence.  This reader has no CLI, release, writer, worker or fit path.
    """
    # These lexical/type gates intentionally precede all filesystem operations.
    if not package_binding._lexical_root_allowed(package_root):
        raise ValueError("V5_BOUND_INPUT_ROOT")
    if not isinstance(family, str) or family not in FAMILIES.values():
        raise ValueError("V5_BOUND_INPUT_FAMILY")
    if type(seed) is not int or seed not in boundary.SEEDS:
        raise ValueError("V5_BOUND_INPUT_SEED")
    raw = _read_receipt_bytes(package_root)
    pins = package_binding.bind_v3_package_bytes(raw, package_root, ["TRAIN"], seed)
    manifest_sha = pins["fold_manifest_sha256"][family]
    request = fold_adapter.adapt_v3_fold(package_root + "/fold_" + family, manifest_sha, family, seed)
    if len(request["rows"]) != 1706:
        raise ValueError("V5_BOUND_INPUT_ROW_COUNT")
    return {"status": STATUS, "request": request,
            "input_identity": {"package_receipt_sha256": pins["package_receipt_sha256"],
                               "source_sha256": pins["source_sha256"], "fold_manifest_sha256": manifest_sha,
                               "family": family, "seed": seed}}
