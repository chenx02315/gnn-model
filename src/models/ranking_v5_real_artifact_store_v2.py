"""Freeze-only v2 subclass. Storage is never training/release authority."""
from src.models import ranking_v5_freeze_codec_v2 as codec
from src.models.ranking_v5_real_artifact_store import (
    RealArtifactStore as _LegacyStore, ARTIFACTS, PRODUCTION_PREFIX, PROTECTED_ROOTS,
    MODEL_MAX_BYTES, LOG_MAX_BYTES, LOG_RECORD_MAX_BYTES, LOG_RECORD_COUNT, RECEIPT_MAX_BYTES,
    JSON_MAX_DEPTH, JSON_MAX_NODES, JSON_MAX_CONTAINER_ITEMS, JSON_MAX_STRING_CHARS, JSON_MAX_INT_BITS,
    _canonical, _validate_json, _sha, _unique_object, _lexical_output,
    _check_existing_ancestors, _lstat,
)

FREEZE_MAX_BYTES = codec.FREEZE_MAX_BYTES


class RealArtifactStore(_LegacyStore):
    def persist_freeze(self, payload, expected_sha256):
        raw = codec.encode(payload, expected_sha256)
        self._write('freeze.json', raw, FREEZE_MAX_BYTES)
        reread, actual = self.read_freeze(expected_sha256)
        if reread != payload or actual != expected_sha256:
            raise ValueError('V5_REAL_STORE_V2_FREEZE_ACK:count=0:limit=0')
        return expected_sha256

    def read_freeze(self, expected_sha256):
        return codec.decode(self._read('freeze.json', FREEZE_MAX_BYTES), expected_sha256)
