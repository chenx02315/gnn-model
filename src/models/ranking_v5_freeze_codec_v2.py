"""Freeze-only capacity codec; legacy canonical bytes and SHA, no authority.

Generic model/log/receipt JSON limits are not changed. Validate metadata before
fit and payloads before encoding; bound tokens before allocating decoded graphs.
"""
import hashlib
import json
import math
import re

from src.models.runtime_ranking_v3 import FAMILIES, Fold

FREEZE_MAX_BYTES = 16 * 1024 * 1024
MAX_CANDIDATES = 1706
MAX_UID_CHARS = 2048
MAX_FOLD_UIDS = 20000
JSON_MAX_NODES = 3 * MAX_CANDIDATES + 32
JSON_MAX_DEPTH = 4
PAYLOAD_FIELDS = frozenset(('family', 'fitting_uids_sha256', 'heldout_uids_sha256',
                            'scores', 'order', 'epsilon', 'top_k'))
FAMILY_NAMES = frozenset(FAMILIES.values())


def _fail(stage, count=0, limit=0):
    raise ValueError(f'V5_FREEZE_CODEC_V2_{stage}:count={count}:limit={limit}')


def _require(ok, stage, count=0, limit=0):
    if not ok:
        _fail(stage, count, limit)


def _pin(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _uid(value):
    _require(type(value) is str, 'UID_TYPE')
    _require(0 < len(value) <= MAX_UID_CHARS, 'UID_CHARS', len(value), MAX_UID_CHARS)


def _quoted_size(uid):
    _uid(uid)
    return len(json.dumps(uid, ensure_ascii=True, separators=(',', ':')).encode('ascii'))


def _capacity(count, quoted_bytes):
    _require(0 < count <= MAX_CANDIDATES, 'CANDIDATES', count, MAX_CANDIDATES)
    upper = 2 * quoted_bytes + 68 * count + 1024
    _require(upper <= FREEZE_MAX_BYTES, 'CAPACITY', upper, FREEZE_MAX_BYTES)
    return upper


def _uid_hash(values):
    digest = hashlib.sha256()
    for chunk in json.JSONEncoder(sort_keys=True, separators=(',', ':'), allow_nan=False).iterencode(values):
        digest.update(chunk.encode('ascii'))
    return digest.hexdigest()


def preflight(fold):
    """Metadata only, no scores/labels/file I/O/encoder of a full freeze graph."""
    _require(type(fold) is Fold, 'FOLD_TYPE')
    _require(type(fold.family) is str and fold.family in FAMILY_NAMES, 'FAMILY')
    _require(type(fold.fitting) is tuple and type(fold.heldout) is tuple, 'FOLD_UID_TYPE')
    _require(0 < len(fold.fitting) and len(fold.fitting)+len(fold.heldout) <= MAX_FOLD_UIDS,
             'FOLD_UID_COUNT', len(fold.fitting)+len(fold.heldout), MAX_FOLD_UIDS)
    _require(0 < len(fold.heldout) <= MAX_CANDIDATES, 'CANDIDATES', len(fold.heldout), MAX_CANDIDATES)
    fitting, held = set(), set()
    for uid in fold.fitting:
        _uid(uid)
        _require(uid not in fitting, 'FITTING_DUPLICATE', len(fitting), len(fold.fitting))
        fitting.add(uid)
    quoted = 0
    for uid in fold.heldout:
        _uid(uid)
        _require(uid not in held and uid not in fitting, 'HELD_JOIN', len(held), len(fold.heldout))
        held.add(uid)
        quoted += _quoted_size(uid)
    upper = _capacity(len(held), quoted)
    return dict(status='PASS_FREEZE_CAPACITY_PREFLIGHT_ONLY', family=fold.family,
                candidate_count=len(held), fitting_count=len(fitting), quoted_uid_bytes=quoted,
                freeze_upper_bound_bytes=upper, freeze_max_bytes=FREEZE_MAX_BYTES,
                fitting_uids_sha256=_uid_hash(fold.fitting), heldout_uids_sha256=_uid_hash(fold.heldout))


preflight_fold = preflight


def _graph(value):
    nodes = 0
    def visit(item, depth):
        nonlocal nodes
        _require(depth <= JSON_MAX_DEPTH, 'DEPTH', depth, JSON_MAX_DEPTH)
        nodes += 1
        _require(nodes <= JSON_MAX_NODES, 'NODES', nodes, JSON_MAX_NODES)
        if type(item) is dict:
            for key, child in item.items():
                visit(key, depth+1)
                visit(child, depth+1)
        elif type(item) is list:
            for child in item:
                visit(child, depth+1)
    visit(value, 0)


def validate_payload(payload):
    _require(type(payload) is dict, 'PAYLOAD_TYPE')
    _require(len(payload) == 7 and set(payload) == PAYLOAD_FIELDS, 'PAYLOAD_FIELDS', len(payload), 7)
    _require(type(payload['family']) is str and payload['family'] in FAMILY_NAMES, 'FAMILY')
    _require(_pin(payload['fitting_uids_sha256']) and _pin(payload['heldout_uids_sha256']), 'UID_SHA')
    _require(type(payload['epsilon']) is float and payload['epsilon'] == .01
             and type(payload['top_k']) is int and payload['top_k'] == 10, 'REPLAY_CONSTANTS')
    scores, order = payload['scores'], payload['order']
    _require(type(scores) is dict and type(order) is list, 'CANDIDATE_TYPE')
    _require(0 < len(scores) <= MAX_CANDIDATES and len(order) == len(scores),
             'CANDIDATES', len(scores), MAX_CANDIDATES)
    quoted = 0
    for uid, score in scores.items():
        _uid(uid)
        _require(type(score) is float and math.isfinite(score), 'SCORE')
        quoted += _quoted_size(uid)
    _capacity(len(scores), quoted)
    for uid in order:
        _uid(uid)
    _require(len(set(order)) == len(order) and set(order) == set(scores), 'ORDER_JOIN')
    _require(order == sorted(scores, key=lambda uid: (-scores[uid], uid)), 'ORDER')
    _graph(payload)


def _stream_json(value, limit, newline):
    _require(type(limit) is int and 0 < limit <= FREEZE_MAX_BYTES, 'LIMIT', 0, FREEZE_MAX_BYTES)
    raw = bytearray()
    for chunk in json.JSONEncoder(sort_keys=True, separators=(',', ':'), allow_nan=False).iterencode(value):
        part = chunk.encode('ascii')
        _require(len(part) <= limit-len(raw), 'BYTES', len(raw)+len(part), limit)
        raw.extend(part)
    if newline:
        _require(len(raw) < limit, 'BYTES', len(raw)+1, limit)
        raw.append(10)
    return bytes(raw)


def payload_bytes(payload):
    validate_payload(payload)
    return _stream_json(payload, FREEZE_MAX_BYTES, False)


canonical_payload = payload_bytes


def encode(payload, expected_sha256, *, limit=FREEZE_MAX_BYTES):
    _require(_pin(expected_sha256), 'EXPECTED_SHA')
    raw_payload = payload_bytes(payload)
    _require(hashlib.sha256(raw_payload).hexdigest() == expected_sha256, 'PAYLOAD_SHA')
    envelope = {'payload': payload, 'sha256': expected_sha256}
    _graph(envelope)
    return _stream_json(envelope, limit, True)


encode_envelope = encode


def _scan(raw):
    """Count tokens/depth/decoded string chars before json.loads allocates objects."""
    stack, nodes, index, size = [], 0, 0, len(raw)
    while index < size:
        c = raw[index]
        if c in b' \t\r\n,:':
            index += 1
            continue
        if c in (125, 93):
            _require(bool(stack) and stack.pop() == (123 if c == 125 else 91), 'LEXICAL')
            index += 1
            continue
        nodes += 1
        _require(nodes <= JSON_MAX_NODES, 'NODES', nodes, JSON_MAX_NODES)
        _require(len(stack) <= JSON_MAX_DEPTH, 'DEPTH', len(stack), JSON_MAX_DEPTH)
        if c in (123, 91):
            stack.append(c)
            index += 1
            continue
        if c == 34:
            index += 1
            chars = 0
            while index < size and raw[index] != 34:
                c = raw[index]
                _require(32 <= c < 128, 'STRING_ENCODING')
                if c == 92:
                    _require(index+1 < size, 'LEXICAL')
                    escape = raw[index+1]
                    if escape == 117:
                        digits = raw[index+2:index+6]
                        _require(len(digits) == 4 and all(d in b'0123456789abcdefABCDEF' for d in digits), 'LEXICAL')
                        value = int(digits, 16)
                        index += 6
                        if 0xD800 <= value <= 0xDBFF and raw[index:index+2] == b'\\u':
                            low = raw[index+2:index+6]
                            if len(low) == 4 and all(d in b'0123456789abcdefABCDEF' for d in low) and 0xDC00 <= int(low, 16) <= 0xDFFF:
                                index += 6
                    else:
                        _require(escape in b'"\\/bfnrt', 'LEXICAL')
                        index += 2
                else:
                    index += 1
                chars += 1
                _require(chars <= MAX_UID_CHARS, 'UID_CHARS', chars, MAX_UID_CHARS)
            _require(index < size, 'LEXICAL')
            index += 1
            continue
        if c in b'-0123456789':
            start = index
            while index < size and raw[index] in b'-+0123456789.eE':
                index += 1
                _require(index-start <= 32, 'NUMBER_CHARS', index-start, 32)
            continue
        found = False
        for literal in (b'true', b'false', b'null'):
            if raw[index:index+len(literal)] == literal:
                index += len(literal)
                found = True
                break
        _require(found, 'LEXICAL')
    _require(not stack, 'LEXICAL')


def _unique(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, 'DUPLICATE_KEY', len(result), JSON_MAX_NODES)
        result[key] = value
    return result


def decode(raw, expected_sha256=None):
    _require(type(raw) is bytes and 0 < len(raw) <= FREEZE_MAX_BYTES, 'READ_BYTES',
             len(raw) if type(raw) is bytes else 0, FREEZE_MAX_BYTES)
    _require(raw.endswith(b'\n'), 'CANONICAL_LF')
    _scan(raw)
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=_unique,
                           parse_constant=lambda _: _fail('NONFINITE'))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        _fail('JSON')
    _require(type(value) is dict and len(value) == 2 and set(value) == {'payload', 'sha256'}, 'ENVELOPE')
    declared = value['sha256']
    _require(_pin(declared) and (expected_sha256 is None or (_pin(expected_sha256) and expected_sha256 == declared)), 'EXPECTED_SHA')
    _require(encode(value['payload'], declared) == raw, 'CANONICAL')
    return value['payload'], declared


decode_envelope = decode
