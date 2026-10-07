"""Create-once bounded storage for a future real v5 single-fit caller.

This module is storage only: it grants no authority and performs no model,
network, training, label, or runtime work.  It fsyncs file contents and does
normal readback, but does not claim portable power-loss directory-entry
durability because it does not fsync parent directories.
"""
import hashlib
import json
import math
import os
import stat
from pathlib import Path

PRODUCTION_PREFIX = "/ssd/cjc/gnn_model_ranking_v5_train_"
PROTECTED_ROOTS = ("/ssd/cjc/multimode_ate_gnn_v1",)
MODEL_MAX_BYTES = 1024 * 1024
LOG_MAX_BYTES = 3 * 1024 * 1024
LOG_RECORD_MAX_BYTES = 20 * 1024
LOG_RECORD_COUNT = 122
FREEZE_MAX_BYTES = 20 * 1024
RECEIPT_MAX_BYTES = 20 * 1024
ARTIFACTS = frozenset(("model.pt", "fitting.jsonl", "freeze.json", "worker_receipt.json"))
JSON_MAX_DEPTH = 64
JSON_MAX_NODES = 4096
JSON_MAX_CONTAINER_ITEMS = 1024
JSON_MAX_STRING_CHARS = 2048
JSON_MAX_INT_BITS = 1024


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _validate_json(value):
    """Bound the graph before the encoder can allocate an unbounded JSON string."""
    nodes = 0
    active = set()

    def visit(item, depth):
        nonlocal nodes
        if depth > JSON_MAX_DEPTH:
            raise ValueError("V5_REAL_STORE_JSON_DEPTH")
        nodes += 1
        if nodes > JSON_MAX_NODES:
            raise ValueError("V5_REAL_STORE_JSON_NODES")
        kind = type(item)
        if kind is str:
            if len(item) > JSON_MAX_STRING_CHARS:
                raise ValueError("V5_REAL_STORE_JSON_STRING")
            return
        if kind is int:
            if item.bit_length() > JSON_MAX_INT_BITS:
                raise ValueError("V5_REAL_STORE_JSON_INT")
            return
        if kind is float:
            if not math.isfinite(item):
                raise ValueError("V5_REAL_STORE_JSON_FLOAT")
            return
        if kind in (type(None), bool):
            return
        if kind not in (list, dict):
            raise ValueError("V5_REAL_STORE_JSON_TYPE")
        identity = id(item)
        if identity in active:
            raise ValueError("V5_REAL_STORE_JSON_CYCLE")
        if len(item) > JSON_MAX_CONTAINER_ITEMS:
            raise ValueError("V5_REAL_STORE_JSON_CONTAINER")
        active.add(identity)
        try:
            if kind is list:
                for child in item:
                    visit(child, depth + 1)
            else:
                for key, child in item.items():
                    if type(key) is not str:
                        raise ValueError("V5_REAL_STORE_JSON_KEY")
                    visit(key, depth + 1)
                    visit(child, depth + 1)
        finally:
            active.remove(identity)

    visit(value, 0)


def _canonical(value, limit):
    """Return canonical JSON plus newline without growing beyond *limit*."""
    _validate_json(value)
    encoded = bytearray()
    encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"), allow_nan=False)
    for chunk in encoder.iterencode(value):
        raw = chunk.encode("utf-8")
        if len(raw) > limit - len(encoded):
            raise ValueError("V5_REAL_STORE_JSON_BOUND")
        encoded.extend(raw)
    if len(encoded) >= limit:
        raise ValueError("V5_REAL_STORE_JSON_BOUND")
    encoded.append(0x0A)
    return bytes(encoded)


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("V5_REAL_STORE_DUPLICATE_KEY")
        value[key] = item
    return value


def _lexical_output(output):
    text = str(output).replace("\\", "/")
    if (not text or text != text.strip() or "\\" in str(output) or "//" in text
            or not (text.startswith("/") or (len(text) >= 3 and text[1:3] == ":/"))):
        raise ValueError("V5_REAL_STORE_OUTPUT_PATH")
    parts = text.split("/")
    if any(part in ("", ".", "..") for part in parts[1:]):
        raise ValueError("V5_REAL_STORE_OUTPUT_PATH")
    if any(text == root or text.startswith(root + "/") for root in PROTECTED_ROOTS):
        raise ValueError("V5_REAL_STORE_PROTECTED_ROOT")
    if not text.startswith(PRODUCTION_PREFIX):
        raise ValueError("V5_REAL_STORE_OUTPUT_PATH")
    suffix = text[len(PRODUCTION_PREFIX):]
    if not suffix or "/" in suffix:
        raise ValueError("V5_REAL_STORE_OUTPUT_PATH")
    return Path(text)


def _lstat(path):
    try:
        return Path(path).lstat()
    except OSError as error:
        raise ValueError("V5_REAL_STORE_PATH") from error


def _check_existing_ancestors(path):
    """All existing ancestors must be ordinary directories, never links."""
    for item in (path, *path.parents):
        try:
            mode = item.lstat().st_mode
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ValueError("V5_REAL_STORE_PATH") from error
        if stat.S_ISLNK(mode):
            raise ValueError("V5_REAL_STORE_SYMLINK")
        if item != path and not stat.S_ISDIR(mode):
            raise ValueError("V5_REAL_STORE_ANCESTOR")


class RealArtifactStore:
    def __init__(self, output):
        self.output = _lexical_output(output)  # lexical rejection precedes every filesystem operation
        _check_existing_ancestors(self.output)
        parent_mode = _lstat(self.output.parent).st_mode
        if not stat.S_ISDIR(parent_mode):
            raise ValueError("V5_REAL_STORE_PARENT")
        try:
            self.output.mkdir(mode=0o700, parents=False, exist_ok=False)
        except FileExistsError:
            raise
        except OSError as error:
            raise ValueError("V5_REAL_STORE_CREATE") from error
        mode = _lstat(self.output).st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise ValueError("V5_REAL_STORE_CREATE")

    def _path(self, name):
        if name not in ARTIFACTS:
            raise ValueError("V5_REAL_STORE_ARTIFACT")
        _check_existing_ancestors(self.output)
        mode = _lstat(self.output).st_mode
        if stat.S_ISLNK(mode):
            raise ValueError("V5_REAL_STORE_SYMLINK")
        if not stat.S_ISDIR(mode):
            raise ValueError("V5_REAL_STORE_OUTPUT_DIR")
        return self.output / name

    def _read(self, name, limit):
        path = self._path(name); mode = _lstat(path).st_mode
        if stat.S_ISLNK(mode):
            raise ValueError("V5_REAL_STORE_SYMLINK")
        if not stat.S_ISREG(mode):
            raise ValueError("V5_REAL_STORE_ORDINARY_FILE")
        try:
            with path.open("rb") as stream:
                raw = stream.read(limit + 1)
        except OSError as error:
            raise ValueError("V5_REAL_STORE_READ") from error
        if len(raw) > limit:
            raise ValueError("V5_REAL_STORE_READ_BOUND")
        return raw

    def _write(self, name, raw, limit):
        if type(raw) is not bytes or len(raw) > limit:
            raise ValueError("V5_REAL_STORE_WRITE_BOUND")
        path = self._path(name)
        try:
            with path.open("xb") as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        except FileExistsError:
            raise
        except OSError as error:
            raise ValueError("V5_REAL_STORE_WRITE") from error
        return raw

    def persist_model_bytes(self, raw, expected_sha256):
        if type(raw) is not bytes or not raw or len(raw) > MODEL_MAX_BYTES:
            raise ValueError("V5_REAL_STORE_MODEL_BOUND")
        if _sha(raw) != expected_sha256:
            raise ValueError("V5_REAL_STORE_MODEL_INPUT")
        self._write("model.pt", raw, MODEL_MAX_BYTES)
        return self.ack_model(expected_sha256)

    def ack_model(self, expected_sha256):
        raw = self._read("model.pt", MODEL_MAX_BYTES)
        if not raw or _sha(raw) != expected_sha256:
            raise ValueError("V5_REAL_STORE_MODEL_ACK")
        return expected_sha256

    def persist_logs(self, records):
        if not isinstance(records, list) or len(records) != LOG_RECORD_COUNT:
            raise ValueError("V5_REAL_STORE_LOG_COUNT")
        lines = []
        for record in records:
            try:
                raw = _canonical(record, LOG_RECORD_MAX_BYTES)
            except ValueError as error:
                if str(error) in ("V5_REAL_STORE_JSON_BOUND", "V5_REAL_STORE_JSON_STRING"):
                    raise ValueError("V5_REAL_STORE_LOG_RECORD_BOUND") from error
                raise
            lines.append(raw)
        data = b"".join(lines)
        if len(data) > LOG_MAX_BYTES:
            raise ValueError("V5_REAL_STORE_LOG_BOUND")
        self._write("fitting.jsonl", data, LOG_MAX_BYTES)
        return self.ack_logs(_sha(data))

    def ack_logs(self, expected_sha256):
        raw = self._read("fitting.jsonl", LOG_MAX_BYTES)
        if _sha(raw) != expected_sha256:
            raise ValueError("V5_REAL_STORE_LOG_ACK")
        return expected_sha256

    def persist_freeze(self, payload, expected_sha256):
        try:
            canonical_payload = _canonical(payload, FREEZE_MAX_BYTES)
        except ValueError as error:
            if str(error) == "V5_REAL_STORE_JSON_BOUND":
                raise ValueError("V5_REAL_STORE_FREEZE_BOUND") from error
            raise
        if _sha(canonical_payload[:-1]) != expected_sha256:
            raise ValueError("V5_REAL_STORE_FREEZE_INPUT")
        try:
            raw = _canonical({"payload": payload, "sha256": expected_sha256}, FREEZE_MAX_BYTES)
        except ValueError as error:
            if str(error) == "V5_REAL_STORE_JSON_BOUND":
                raise ValueError("V5_REAL_STORE_FREEZE_BOUND") from error
            raise
        self._write("freeze.json", raw, FREEZE_MAX_BYTES)
        reread, sha = self.read_freeze(expected_sha256)
        if reread != payload or sha != expected_sha256:
            raise ValueError("V5_REAL_STORE_FREEZE_ACK")
        return expected_sha256

    def read_freeze(self, expected_sha256):
        raw = self._read("freeze.json", FREEZE_MAX_BYTES)
        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, TypeError, ValueError, RecursionError) as error:
            raise ValueError("V5_REAL_STORE_FREEZE_READ") from error
        if (not isinstance(value, dict) or set(value) != {"payload", "sha256"}
                or value["sha256"] != expected_sha256
                or _sha(_canonical(value["payload"], FREEZE_MAX_BYTES)[:-1]) != expected_sha256
                or _canonical(value, FREEZE_MAX_BYTES) != raw):
            raise ValueError("V5_REAL_STORE_FREEZE_READ")
        return value["payload"], expected_sha256

    def persist_receipt(self, receipt):
        try:
            raw = _canonical(receipt, RECEIPT_MAX_BYTES)
        except ValueError as error:
            if str(error) in ("V5_REAL_STORE_JSON_BOUND", "V5_REAL_STORE_JSON_STRING"):
                raise ValueError("V5_REAL_STORE_RECEIPT_BOUND") from error
            raise
        self._write("worker_receipt.json", raw, RECEIPT_MAX_BYTES)
        reread = self._read("worker_receipt.json", RECEIPT_MAX_BYTES)
        if _sha(reread) != _sha(raw):
            raise ValueError("V5_REAL_STORE_RECEIPT_ACK")
        return _sha(raw)
