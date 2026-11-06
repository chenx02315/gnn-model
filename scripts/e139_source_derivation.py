"""Bounded, byte-exact LOCAL derivation; no loading, execution, IO or authority.

Spec has exactly schema/origins/rules. Origins enumerate the entire input set,
each with name, sha256 and effective_sha256. Rules have source, old_hex,
new_hex and count. Hex is lowercase, old is nonempty, count is a positive int.
Matches (including self-overlaps) are counted on ORIGINAL bytes; any overlap
between matches is rejected. Replacements never cascade. Identity derivations
use an empty rules list, not no-op rules. Names are opaque labels, not paths.
The spec is already parsed: duplicate JSON keys must be rejected by its caller.
Hashes prove consistency only, not permission, independent review or readiness.
"""

import hashlib
import json
import re


SCHEMA = "e139-source-derivation-v1"
MAX_SOURCES = 64
MAX_RULES = 256
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_LITERAL_BYTES = 4096
MAX_OCCURRENCES = 65536


class DerivationError(ValueError):
    """Malformed, unpinned or ambiguous derivation."""


def _require(condition, message):
    if not condition:
        raise DerivationError(message)


def _keys(value, keys):
    _require(type(value) is dict and set(value) == set(keys), "invalid fields")


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _pin(value):
    _require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "invalid SHA256")


def _literal(value, nonempty=False):
    _require(type(value) is str and len(value) <= MAX_LITERAL_BYTES * 2,
             "literal size/type")
    _require(re.fullmatch(r"(?:[0-9a-f]{2})*", value) is not None, "invalid hex")
    _require(not nonempty or value != "", "empty old literal")
    return bytes.fromhex(value)


class DerivationResult:
    """Private bytes and public metadata returned as independent snapshots."""

    __slots__ = ("__sources", "__manifest_json")

    def __init__(self, sources, manifest):
        self.__sources = tuple(sorted(sources.items()))
        self.__manifest_json = json.dumps(manifest, sort_keys=True, ensure_ascii=True,
                                          separators=(",", ":"), allow_nan=False)

    def private_sources(self):
        return dict(self.__sources)

    def public_manifest(self):
        return json.loads(self.__manifest_json)


def derive(sources, spec):
    """Validate exact finite spec and return pinned effective bytes + manifest.

    Bounds apply separately to original and effective byte sets. Work is bounded
    by 64 sources, 256 rules, 4MiB/source, 16MiB/set, 4096-byte literals and
    65536 total occurrences. Does not inspect filesystem or Python syntax.
    """
    _keys(spec, ("schema", "origins", "rules"))
    _require(spec["schema"] == SCHEMA, "unknown schema")
    _require(type(sources) is dict and 0 < len(sources) <= MAX_SOURCES, "source count/type")
    _require(type(spec["origins"]) is list and len(spec["origins"]) == len(sources), "origin count/type")
    _require(type(spec["rules"]) is list and len(spec["rules"]) <= MAX_RULES, "rule count/type")
    origins = {}
    total = 0
    for origin in spec["origins"]:
        _keys(origin, ("name", "sha256", "effective_sha256"))
        name = origin["name"]
        _require(type(name) is str and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name), "invalid name")
        _require(name not in origins and name in sources, "duplicate/unknown origin")
        _pin(origin["sha256"])
        _pin(origin["effective_sha256"])
        data = sources[name]
        _require(type(data) is bytes and len(data) <= MAX_SOURCE_BYTES, "source size/type")
        total += len(data)
        _require(total <= MAX_TOTAL_BYTES, "total source size")
        _require(_sha(data) == origin["sha256"], "origin pin mismatch")
        origins[name] = dict(origin)
    _require(set(sources) == set(origins), "unlisted source")
    edits = {name: [] for name in origins}
    seen = set()
    normalized_rules = []
    occurrences = 0
    for rule in spec["rules"]:
        _keys(rule, ("source", "old_hex", "new_hex", "count"))
        name = rule["source"]
        _require(type(name) is str and name in origins, "unknown rule source")
        old = _literal(rule["old_hex"], nonempty=True)
        new = _literal(rule["new_hex"])
        _require(old != new, "no-op rule")
        count = rule["count"]
        _require(type(count) is int and 0 < count <= MAX_OCCURRENCES, "invalid count")
        key = (name, old)
        _require(key not in seen, "duplicate rule")
        seen.add(key)
        data = sources[name]
        cursor = 0
        found = 0
        while True:
            start = data.find(old, cursor)
            if start < 0:
                break
            found += 1
            occurrences += 1
            _require(found <= count and occurrences <= MAX_OCCURRENCES, "excess occurrences")
            edits[name].append((start, start + len(old), new))
            cursor = start + 1
        _require(found == count, "occurrence count mismatch")
        normalized_rules.append(dict(rule))
    effective = {}
    total = 0
    for name, origin in sorted(origins.items()):
        spans = sorted(edits[name])
        cursor = 0
        output_size = len(sources[name])
        for start, end, new in spans:
            _require(start >= cursor, "overlapping matches")
            output_size += len(new) - (end - start)
            cursor = end
        _require(output_size <= MAX_SOURCE_BYTES, "effective source size")
        total += output_size
        _require(total <= MAX_TOTAL_BYTES, "total effective size")
        pieces = []
        cursor = 0
        for start, end, new in spans:
            pieces.extend((sources[name][cursor:start], new))
            cursor = end
        pieces.append(sources[name][cursor:])
        data = b"".join(pieces)
        _require(_sha(data) == origin["effective_sha256"], "effective pin mismatch")
        effective[name] = data
    normalized_rules.sort(key=lambda r: (r["source"], r["old_hex"]))
    canonical = {"schema": SCHEMA, "origins": [origins[n] for n in sorted(origins)],
                 "rules": normalized_rules}
    encoded = json.dumps(canonical, sort_keys=True, ensure_ascii=True,
                         separators=(",", ":"), allow_nan=False).encode("ascii")
    rules_encoded = json.dumps(normalized_rules, sort_keys=True, ensure_ascii=True,
                               separators=(",", ":"), allow_nan=False).encode("ascii")
    manifest = {"schema": "e139-source-derivation-manifest-v1",
                "spec_sha256": _sha(encoded), "rules_sha256": _sha(rules_encoded),
                "origins": canonical["origins"], "rules": normalized_rules,
                "sources": [{**origins[n], "origin_bytes": len(sources[n]),
                             "effective_bytes": len(effective[n])} for n in sorted(origins)]}
    return DerivationResult(effective, manifest)
