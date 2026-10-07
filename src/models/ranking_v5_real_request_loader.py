"""Fail-closed local loader for one sealed v5 TRAIN request.

It is intentionally only an input verifier: it creates nothing, authorizes
nothing, imports no trainer, and exposes no CLI.  A formal caller must still
validate its separate release and source bindings at the execution boundary.
"""
import hashlib
import json
import stat
from pathlib import Path

from src.models import ranking_v5_execution_boundary as boundary
from src.models.runtime_ranking_v3 import digest

SCHEMA = "ranking-v5-real-train-request-v1"
ENVELOPE_FIELDS = frozenset(("schema", "roles", "source_sha256", "package_receipt_sha256",
                             "request_sha256", "request"))
MAX_REQUEST_BYTES = 16 * 1024 * 1024
MAX_ROWS = 20000
PROTECTED_ROOT_TEXT = "/ssd/cjc/multimode_ate_gnn_v1"
FORBIDDEN_PATH_TERMS = frozenset(("blind", "validation", "pilot"))


def _sha(value):
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _under(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _protected_lexically(path):
    """Reject protected spellings without resolving or touching the filesystem."""
    text = str(path).replace("\\", "/").rstrip("/").casefold()
    protected = PROTECTED_ROOT_TEXT.casefold()
    return text == protected or text.startswith(protected + "/")


def _ordinary_path(root, relative_name):
    """Return an existing ordinary file below an explicit ordinary root."""
    root = Path(root)
    if not root.is_absolute() or not isinstance(relative_name, str) or not relative_name:
        raise ValueError("V5_REAL_REQUEST_PATH")
    relative = Path(relative_name)
    if (relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts)
            or any(part in ("", ".", "..") for part in root.parts)
            or _protected_lexically(root)):
        raise ValueError("V5_REAL_REQUEST_PATH")
    # Check every existing parent component before resolving, including the
    # caller-supplied root ancestry, so neither root nor request can be a link.
    requested = root.joinpath(*relative.parts)
    for item in (root, *root.parents):
        if item.is_symlink():
            raise ValueError("V5_REAL_REQUEST_SYMLINK")
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("V5_REAL_REQUEST_SYMLINK")
    if any(term in part.casefold() for part in (*root.parts, *relative.parts) for term in FORBIDDEN_PATH_TERMS):
        raise ValueError("V5_REAL_REQUEST_FORBIDDEN_PATH")
    try:
        request_mode = requested.lstat().st_mode
    except OSError as error:
        raise ValueError("V5_REAL_REQUEST_PATH") from error
    if not root.is_dir() or not stat.S_ISREG(request_mode):
        raise ValueError("V5_REAL_REQUEST_PATH")
    resolved_root = root.resolve(strict=True)
    resolved_path = requested.resolve(strict=True)
    if not _under(resolved_path, resolved_root):
        raise ValueError("V5_REAL_REQUEST_PATH")
    return requested


def _read_one(path, expected_sha256):
    if not _sha(expected_sha256):
        raise ValueError("V5_REAL_REQUEST_EXPECTED_SHA")
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError("V5_REAL_REQUEST_PATH")
        with path.open("rb") as stream:
            raw = stream.read(MAX_REQUEST_BYTES + 1)
    except OSError as error:
        raise ValueError("V5_REAL_REQUEST_PATH") from error
    if not raw or len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("V5_REAL_REQUEST_SIZE")
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("V5_REAL_REQUEST_SHA")
    try:
        return json.loads(raw)
    except (TypeError, ValueError) as error:
        raise ValueError("V5_REAL_REQUEST_JSON") from error


def load_sealed_train_request(root, relative_name, expected_sha256):
    """Load exactly one bounded, digest-pinned intermediate request envelope.

    The returned object is a deep JSON-decoded request suitable only for a
    later formal caller to pass to ``boundary.execute``.  This function does
    not accept a release, held labels, or any outcome/data-loader callback.

    ``SCHEMA`` is a new DESIGN/INTERMEDIATE envelope, not an existing formal
    evidence schema.  The released v3 four-shard fold package
    (``ranking-v3-real-train-fold-v1``) has no adapter here; therefore this
    loader neither proves a sealed real v5 request exists nor grants access or
    authority to create/train one.
    """
    path = _ordinary_path(root, relative_name)
    envelope = _read_one(path, expected_sha256)
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS:
        raise ValueError("V5_REAL_REQUEST_SCHEMA")
    request = envelope["request"]
    if (envelope["schema"] != SCHEMA or envelope["roles"] != ["TRAIN"]
            or envelope["source_sha256"] != boundary.SOURCE_SHA256
            or envelope["package_receipt_sha256"] != boundary.PACKAGE_SHA256
            or not _sha(envelope["request_sha256"]) or not isinstance(request, dict)
            or envelope["request_sha256"] != digest(request)
            or request.get("source_sha256") != envelope["source_sha256"]):
        raise ValueError("V5_REAL_REQUEST_ENVELOPE_BINDING")
    if not isinstance(request.get("rows"), list) or not 0 < len(request["rows"]) <= MAX_ROWS:
        raise ValueError("V5_REAL_REQUEST_ROW_BOUND")
    # Boundary's v4-backed parser enforces exact request/row fields, all six
    # known families, unique UIDs, TRAIN-only roles and fit-only cycle keys.
    # Thus no held labels can be smuggled in as fit_cycles or extra fields.
    try:
        boundary.prepare_request(request)
    except (TypeError, ValueError) as error:
        raise ValueError("V5_REAL_REQUEST_CONTENT") from error
    return request
