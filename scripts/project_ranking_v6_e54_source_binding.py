"""E54 fixed handoff byte binding and TRAIN-only metadata projection."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

BASE = Path(r'C:\Users\86155\Desktop\new lab\metadata_handoff_20261018_r1')
RECEIPT = BASE / 'receipt_v2.json'
PROVENANCE = BASE / 'source_provenance_v2.tsv'
EXPECTED_RECEIPT = '48c164e99e653c1d00dbf8e7655447e2ffc09c9519c63b7191dff9a151b7456d'
EXPECTED_PROVENANCE = 'b1bfb85632209948cd23c353cbc93da8d70871478f2f53098a8f9a255fc11ccb'
EXPECTED_CANDIDATES = 'f55420e29e94ae74dff90f042c72fd7bd76ffa511b214ac89d7a238a18bd678e'
EXPECTED_NORMALIZED = '59be15d3cb9e0c3a1d96bc368472df419c4a3d26fafdf491563a8bd7639d503a'
LIMIT = 128 * 1024
TSV_LIMIT = 1024 * 1024
OUTPUT_LIMIT = 65536
SELECTED = frozenset((('schema_version',), ('sha256', 'source_provenance'),
                      ('sha256', 'candidate_space'), ('sha256', 'normalized_measurements')))
TRAIN = (b'aes_core', b's13207', b's15850', b's35932', b's38417', b'spi')
STAGES = (b'hf_coarse', b'hmf_coarse', b'hf_refine', b'hmf_refine')
BASENAMES = {
    b'hf_coarse': frozenset((b'measurements.tsv', b'02_hf_coarse__measurements.tsv')),
    b'hmf_coarse': frozenset((b'measurements.tsv', b'03_hmf_coarse__measurements.tsv')),
    b'hf_refine': frozenset((b'hf_measurements.tsv', b'04_integer_refine__hf_measurements.tsv')),
    b'hmf_refine': frozenset((b'hmf_measurements.tsv', b'04_integer_refine__hmf_measurements.tsv')),
}
HEADER = b'circuit\tstage\tsource_sha256\tnormalized_sha256\trow_count\tsource_basename'


def _receipt_fields(raw):
    """Scan JSON syntax in bytes; ignored values are never json-decoded/evaluated."""
    if type(raw) is not bytes or not 0 < len(raw) <= LIMIT or any(c > 127 for c in raw):
        raise ValueError('INPUT_BOUND_ASCII')
    selected = {}
    tokens = 0

    def ws(i):
        while i < len(raw) and raw[i] in b' \t\r\n': i += 1
        return i

    def string(i):
        if i >= len(raw) or raw[i] != 34: raise ValueError('STRING_START')
        i += 1
        while i < len(raw):
            c = raw[i]
            if c == 34: return i + 1
            if c < 32: raise ValueError('STRING_CONTROL')
            if c == 92:
                i += 1
                if i >= len(raw): raise ValueError('ESCAPE_END')
                if raw[i] == 117:
                    if len(raw[i+1:i+5]) != 4 or any(c not in b'0123456789abcdefABCDEF' for c in raw[i+1:i+5]):
                        raise ValueError('UNICODE_ESCAPE')
                    i += 4
                elif raw[i] not in b'"\\/bfnrt': raise ValueError('ESCAPE_TOKEN')
            i += 1
        raise ValueError('STRING_END')

    def value(i, path, depth):
        nonlocal tokens
        tokens += 1
        if depth > 32 or tokens > 8192: raise ValueError('STRUCTURE_BOUND')
        i = ws(i)
        start = i
        if i >= len(raw): raise ValueError('VALUE_END')
        c = raw[i]
        if c == 34:
            i = string(i)
        elif c == 123:
            i = ws(i+1)
            keys = set()
            if i < len(raw) and raw[i] == 125: i += 1
            else:
                while True:
                    end = string(i)
                    key = json.loads(raw[i:end].decode('ascii'))  # field name, not a result value
                    if key in keys: raise ValueError('DUPLICATE_KEY')
                    keys.add(key)
                    i = ws(end)
                    if i >= len(raw) or raw[i] != 58: raise ValueError('COLON')
                    i = ws(value(i+1, path+(key,), depth+1))
                    if i >= len(raw): raise ValueError('OBJECT_END')
                    if raw[i] == 125:
                        i += 1
                        break
                    if raw[i] != 44: raise ValueError('OBJECT_COMMA')
                    i = ws(i+1)
        elif c == 91:
            i = ws(i+1)
            if i < len(raw) and raw[i] == 93: i += 1
            else:
                while True:
                    i = ws(value(i, path+(None,), depth+1))
                    if i >= len(raw): raise ValueError('ARRAY_END')
                    if raw[i] == 93:
                        i += 1
                        break
                    if raw[i] != 44: raise ValueError('ARRAY_COMMA')
                    i = ws(i+1)
        else:
            match = re.match(rb'(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)',raw[i:])
            if not match: raise ValueError('SCALAR_TOKEN')
            i += len(match.group())
        if path in SELECTED:
            if c != 34: raise ValueError('SELECTED_STRING_REQUIRED')
            selected[path] = json.loads(raw[start:i].decode('ascii'))
        return i

    end = ws(value(0, (), 0))
    if end != len(raw) or set(selected) != SELECTED: raise ValueError('JSON_END_OR_FIELDS')
    if selected[('schema_version',)] != 'formal-candidate-space-v2-receipt': raise ValueError('SCHEMA')
    hashes = {p[-1]: v for p,v in selected.items() if len(p) == 2}
    if any(not re.fullmatch('[0-9a-f]{64}',v) for v in hashes.values()): raise ValueError('SHA_SHAPE')
    if hashes['candidate_space'] != EXPECTED_CANDIDATES or hashes['normalized_measurements'] != EXPECTED_NORMALIZED:
        raise ValueError('ANCHOR_MISMATCH')
    return {'schema_version':selected[('schema_version',)], 'sha256':hashes}


def project_receipt(raw, expected_receipt=EXPECTED_RECEIPT, expected_provenance=EXPECTED_PROVENANCE):
    # Reject byte mismatch BEFORE JSON field-name or selected-value decoding.
    if type(raw) is not bytes or not 0 < len(raw) <= LIMIT:
        raise ValueError('RECEIPT_BOUND')
    if hashlib.sha256(raw).hexdigest() != expected_receipt:
        raise ValueError('RECEIPT_SHA_MISMATCH')
    selected = _receipt_fields(raw)
    if selected['sha256']['source_provenance'] != expected_provenance:
        raise ValueError('PROVENANCE_BINDING_MISMATCH')
    return selected


def decode_selected(raw):
    return raw.decode('ascii')


def project_provenance(raw, expected_sha=EXPECTED_PROVENANCE):
    if type(raw) is not bytes or not 0 < len(raw) <= TSV_LIMIT:
        raise ValueError('PROVENANCE_BOUND')
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        raise ValueError('PROVENANCE_SHA_MISMATCH')
    lines = raw.split(b'\n')
    if lines[-1] == b'':
        lines.pop()
    if not lines or lines[0] != HEADER:
        raise ValueError('HEADER')
    rows, excluded, seen = [], 0, set()
    for ordinal, line in enumerate(lines[1:], 1):
        # Flat TSV only. Quoted/multiline records are never silently reinterpreted.
        if not line or line.count(b'\t') != 5 or b'"' in line or any(c < 32 and c != 9 for c in line):
            raise ValueError('FLAT_TSV_REQUIRED')
        circuit = line.split(b'\t', 1)[0]
        if circuit not in TRAIN:
            excluded += 1
            continue  # No non-TRAIN field decoding, including hashes/count/basename.
        cells = line.split(b'\t')
        if any(c > 127 for c in line):
            raise ValueError('SELECTED_ASCII')
        stage = cells[1]
        if stage not in STAGES or (circuit, stage) in seen:
            raise ValueError('STAGE_OR_DUPLICATE')
        if any(re.fullmatch(rb'[a-f0-9]{64}', value) is None for value in cells[2:4]):
            raise ValueError('SOURCE_SHA_SHAPE')
        if re.fullmatch(rb'(?:0|[1-9][0-9]{0,11})', cells[4]) is None:
            raise ValueError('ROW_COUNT_SHAPE')
        if cells[5] not in BASENAMES[stage]:
            raise ValueError('SOURCE_BASENAME')
        seen.add((circuit, stage))
        row = dict(zip(('circuit', 'stage', 'source_sha256', 'normalized_sha256', 'row_count', 'source_basename'),
                       (decode_selected(value) for value in cells)))
        row['row_count'] = int(row['row_count'])
        row['logical_ordinal'] = ordinal  # Data-row ordinal, header excluded, one-based.
        row['physical_line'] = ordinal + 1
        rows.append(row)
    if len(rows) != 24 or seen != {(c, s) for c in TRAIN for s in STAGES}:
        raise ValueError('TRAIN_24_GRID')
    return dict(rows=rows, excluded_non_train_rows=excluded,
                logical_rows_scanned=len(lines)-1, train_rows_selected=24,
                non_train_value_fields_decoded=False, row_order_preserved=True)


def identity(info, cross_api=False, platform=None):
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if cross_api and (sys.platform if platform is None else platform) == 'win32':
        fields = fields[:-1]
    return tuple(getattr(info, key) for key in fields)


def verify_identity(path_before, fd_before, path_after, fd_after, platform=None):
    if (identity(path_before) != identity(path_after) or identity(fd_before) != identity(fd_after)
        or identity(path_before, True, platform) != identity(fd_before, True, platform)
        or identity(path_after, True, platform) != identity(fd_after, True, platform)):
        raise ValueError('METADATA_CHANGED')


def file_gate(info, limit):
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
        or getattr(info, 'st_file_attributes', 0) & 0x400 or not 0 < info.st_size <= limit):
        raise ValueError('PLAIN_SINGLE_LINK_FILE_REQUIRED')


def stable_read(path, limit, expected_bytes=None):
    original = os.lstat(path)
    file_gate(original, limit)
    if expected_bytes is not None and original.st_size != expected_bytes:
        raise ValueError('EXPECTED_BYTE_COUNT')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
                 | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        file_gate(before, limit)
        if identity(original, True) != identity(before, True):
            raise ValueError('METADATA_CHANGED')
        chunks, count = [], 0
        while True:
            chunk = stream.read(min(65536, limit + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            if count > limit:
                raise ValueError('METADATA_READ_BOUND')
            chunks.append(chunk)
        after_path, after_fd = os.lstat(path), os.fstat(stream.fileno())
        file_gate(after_path, limit)
        file_gate(after_fd, limit)
        verify_identity(original, before, after_path, after_fd)
        if count != before.st_size:
            raise ValueError('METADATA_CHANGED')
    return b''.join(chunks)


def result_for(receipt_raw, provenance_raw, selected, provenance):
    return dict(status='PASS_BOUND_TRAIN_PROVENANCE_METADATA',
        files=dict(receipt=dict(path=str(RECEIPT), byte_count=len(receipt_raw),
                                sha256=hashlib.sha256(receipt_raw).hexdigest()),
                   provenance=dict(path=str(PROVENANCE), byte_count=len(provenance_raw),
                                   sha256=hashlib.sha256(provenance_raw).hexdigest())),
        receipt_selected=selected, provenance=provenance,
        whole_metadata_bytes_read_for_sha=True, nonwhitelist_receipt_values_decoded=False,
        quality_or_outcome_files_opened=False, non_train_provenance_values_decoded=False,
        source_snapshot_files_opened=False, remote_files_written=False,
        protected_directory_visited=False, acl_changed=False, training_release=False)


def project_pair(receipt_raw, provenance_raw, expected_receipt=EXPECTED_RECEIPT, expected_provenance=EXPECTED_PROVENANCE):
    """Fixture-capable pure API; no filesystem opens or mutation of earlier projectors."""
    selected = project_receipt(receipt_raw, expected_receipt, expected_provenance)
    provenance = project_provenance(provenance_raw, selected['sha256']['source_provenance'])
    return result_for(receipt_raw, provenance_raw, selected, provenance)


def main():
    try:
        if len(sys.argv) != 1:
            raise ValueError('FIXED_TWO_METADATA_FILES_ONLY')
        receipt_raw = stable_read(RECEIPT, LIMIT, 1368)
        selected = project_receipt(receipt_raw)
        # Do not open provenance until receipt bytes and the exact provenance pin bind.
        provenance_raw = stable_read(PROVENANCE, TSV_LIMIT, 5880)
        provenance = project_provenance(provenance_raw, selected['sha256']['source_provenance'])
        result = result_for(receipt_raw, provenance_raw, selected, provenance)
        raw = json.dumps(result, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
        if len(raw.encode('ascii')) + 1 > OUTPUT_LIMIT:
            raise ValueError('OUTPUT_BOUND')
        print(raw)
        return 0
    except Exception:
        print('{"status":"FAIL_CLOSED_SOURCE_BINDING","code":"FIXED_METADATA_REJECTED"}')
        return 2


if __name__ == '__main__':
    sys.exit(main())
