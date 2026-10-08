"""Read-only single-fit artifact integrity checks, never a training release.

Invoke only after the existing external resource guard completes. All exact
expectations and raw-file hashes must come from a trusted caller, independently
of these files. Self-consistent worker claims alone are not proof. This neither
loads a checkpoint nor reads package/held data, and cannot establish output
freshness, genuine consent, parent RSS enforcement, or hostile-filesystem safety.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import stat
from copy import deepcopy

PRODUCTION_PREFIX = '/ssd/cjc/gnn_model_ranking_v5_train_'
PROTECTED_ROOTS = ('/ssd/cjc/multimode_ate_gnn_v1',)
LIMITS = {'model.pt': 1024**2, 'fitting.jsonl': 3*1024**2,
          'freeze.json': 20*1024, 'worker_receipt.json': 20*1024}
LOG_RECORD_MAX_BYTES = 20*1024
FAMILIES = frozenset(('iwls_aes_core', 'iscas89_s13207', 'iscas89_s15850',
                      'iscas89_s35932', 'iscas89_s38417', 'iwls_spi'))
SEEDS = (20260824, 20260825, 20260826)
SOURCE_SHA256 = 'b89b455ace9d545c0afd54fe9fded98e4db4abd56f58fe09a0cce28b88215d9c'
PACKAGE_SHA256 = '964703dc441fea95c3b1b301dfd6dd01a2cf38f817d82597ff00450287e43868'
FALSE_FIELDS = frozenset(('authentic_user_consent_proven', 'full_source_file_binding_verified',
    'parent_sampled_rss_enforcement_proven', 'physical_worker_limits_verified',
    'formal_training_authorized_by_this_function', 'new_formal_18_fit_release'))
RECEIPT_FIELDS = FALSE_FIELDS | {'status', 'caller_must_use_existing_resource_guard',
    'input_identity', 'approval_integrity', 'observed_process_preconditions',
    'boundary_receipt', 'fitting_log_sha256', 'worker_receipt_sha256'}
BOUNDARY_FIELDS = frozenset(('scope', 'family', 'seed', 'model', 'model_ack_sha256',
    'freeze_sha256', 'expected_model_sha256', 'canonical_request_sha256',
    'release_sha256', 'source_binding_sha256', 'head_recipe_sha256',
    'held_labels_replayed', 'metrics'))
LOG_FIELDS = frozenset(('scope', 'epoch', 'phase', 'K', 'epsilon', 'recipe_sha256',
    'families', 'macro_head_loss', 'objective_signal_families', 'macro_family_count',
    'macro_pair_softplus_reference', 'canonical_request_sha256'))
ROW_INTS = frozenset(('actions', 'positive_count', 'negative_count',
    'first_positive_rank', 'hit_at_10', 'negatives_before_first_positive'))
ROW_BOOLS = frozenset(('guaranteed_hit_by_size', 'strict_score_hit_certificate', 'tie_at_boundary'))
ROW_NUMBERS = frozenset(('top10_cycle_regret', 'head_softplus', 'pair_softplus_reference'))
ROW_FIELDS = ROW_INTS | ROW_BOOLS | ROW_NUMBERS | {'head_gap', 'family'}


def _require(ok, code):
    if not ok:
        raise ValueError('V5_TRAIN_READBACK_' + code)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _is_sha(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def _object(value, fields):
    _require(type(value) is dict and set(value) == fields, 'SCHEMA')


def _json_bounds(value):
    nodes = 0
    def visit(item, depth):
        nonlocal nodes
        nodes += 1
        _require(depth <= 64 and nodes <= 4096, 'JSON_GRAPH_BOUND')
        kind = type(item)
        if kind is str:
            _require(len(item) <= 2048, 'JSON_STRING_BOUND')
        elif kind is int:
            _require(item.bit_length() <= 1024, 'JSON_INT_BOUND')
        elif kind is float:
            _require(math.isfinite(item), 'JSON_NONFINITE')
        elif kind in (list, dict):
            _require(len(item) <= 1024, 'JSON_CONTAINER_BOUND')
            if kind is dict:
                for key, child in item.items():
                    _require(type(key) is str, 'JSON_KEY')
                    visit(key, depth+1); visit(child, depth+1)
            else:
                for child in item:
                    visit(child, depth+1)
        else:
            _require(kind in (bool, type(None)), 'JSON_TYPE')
    try:
        visit(value, 0)
    except RecursionError as error:
        raise ValueError('V5_TRAIN_READBACK_JSON_DEPTH') from error


def _canonical(value):
    _json_bounds(value)
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _decode(raw):
    def unique(pairs):
        value = {}
        for key, child in pairs:
            _require(key not in value, 'DUPLICATE_KEY')
            value[key] = child
        return value
    def constant(_):
        raise ValueError('V5_TRAIN_READBACK_JSON_NONFINITE')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique, parse_constant=constant)
        _json_bounds(value)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ValueError('V5_TRAIN_READBACK_JSON_INVALID') from error
    _require(_canonical(value) + b'\n' == raw, 'JSON_CANONICAL')
    return value


def _root(output):
    _require(type(output) is str, 'ROOT')
    text = output.replace('\\', '/')
    folded = text.casefold()
    _require(not any(folded == p.casefold() or folded.startswith(p.casefold()+'/')
                     for p in PROTECTED_ROOTS), 'PROTECTED_ROOT')
    _require(text == output and text == text.strip() and '//' not in text
             and text.startswith(PRODUCTION_PREFIX), 'ROOT')
    suffix = text[len(PRODUCTION_PREFIX):]
    _require(bool(suffix) and '/' not in suffix and suffix not in ('.', '..')
             and not any(p in ('.', '..', '') for p in text.split('/')[1:]), 'ROOT')
    return Path(text)


def _ordinary(info, directory=False):
    _require(not stat.S_ISLNK(info.st_mode)
             and not (getattr(info, 'st_file_attributes', 0) & 0x400), 'SYMLINK')
    _require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), 'ORDINARY_PATH')


def _read(root, name):
    limit = LIMITS[name]
    try:
        for ancestor in (root, *root.parents):
            _ordinary(ancestor.lstat(), directory=True)
        path = root / name
        before = path.lstat()
        _ordinary(before)
        _require(0 < before.st_size <= limit, 'FILE_BOUND')
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, 'rb') as stream:
            opened = os.fstat(stream.fileno())
            _ordinary(opened)
            _require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino)
                     and opened.st_size == before.st_size, 'FILE_CHANGED')
            raw = stream.read(limit+1)
            after = os.fstat(stream.fileno())
        final = path.lstat()
        _ordinary(final)
        _require(len(raw) == before.st_size and len(raw) <= limit
                 and (final.st_dev, final.st_ino) == (before.st_dev, before.st_ino)
                 and after.st_size == final.st_size == before.st_size
                 and after.st_mtime_ns == final.st_mtime_ns == before.st_mtime_ns, 'FILE_CHANGED')
        return raw
    except OSError as error:
        raise ValueError('V5_TRAIN_READBACK_FILE_IO') from error


def _expectations(receipt, freeze, pins):
    _object(pins, set(LIMITS))
    _require(all(_is_sha(value) for value in pins.values()), 'TRUSTED_SHA')
    _json_bounds(receipt); _json_bounds(freeze)
    _require(len(_canonical(receipt))+1 <= LIMITS['worker_receipt.json']
             and len(_canonical(freeze))+1 <= LIMITS['freeze.json'], 'EXPECTATION_BOUND')
    _object(receipt, RECEIPT_FIELDS)
    _require(receipt['status'] == 'PASS_SINGLE_FIT_CALLBACK_ADAPTER_ONLY'
             and all(receipt[k] is False for k in FALSE_FIELDS)
             and receipt['caller_must_use_existing_resource_guard'] is True, 'NONAUTHORITY')
    b = receipt['boundary_receipt']
    _object(b, BOUNDARY_FIELDS)
    _require(b['scope'] == 'RANKING_V5_TRAIN_EXECUTION_BOUNDARY' and b['model'] == 'candidate_mlp'
             and type(b['family']) is str and b['family'] in FAMILIES
             and type(b['seed']) is int and b['seed'] in SEEDS
             and type(b['held_labels_replayed']) is bool, 'BOUNDARY_PROTOCOL')
    _require(all(_is_sha(v) for k, v in b.items() if k.endswith('sha256')), 'BOUNDARY_SHA')
    identity = receipt['input_identity']
    _object(identity, {'package_receipt_sha256', 'source_sha256', 'fold_manifest_sha256', 'family', 'seed'})
    _require(identity['family'] == b['family'] and type(identity['seed']) is int
             and identity['seed'] == b['seed']
             and identity['source_sha256'] == SOURCE_SHA256
             and identity['package_receipt_sha256'] == PACKAGE_SHA256
             and all(_is_sha(v) for k, v in identity.items() if k.endswith('sha256')), 'INPUT_BINDING')
    approval = receipt['approval_integrity']
    _object(approval, {'status', 'authentic_user_consent_proven', 'training_authorized_by_this_function',
        'release_sha256', 'authorization_sha256', 'review_sha256', 'physical_gate_sha256'})
    _require(approval['status'] == 'PASS_APPROVAL_BYTES_INTEGRITY_ONLY'
             and approval['authentic_user_consent_proven'] is False
             and approval['training_authorized_by_this_function'] is False
             and approval['release_sha256'] == b['release_sha256']
             and all(_is_sha(v) for k, v in approval.items() if k.endswith('sha256')), 'APPROVAL_BINDING')
    observed = receipt['observed_process_preconditions']
    _object(observed, {'status', 'address_space_limits', 'core_limits', 'threads',
        'parent_sampled_rss_enforcement_proven', 'authentic_user_consent_proven'})
    _require(observed['status'] == 'PASS_CHILD_PREREQUISITES_ONLY'
             and type(observed['threads']) is int and observed['threads'] == 1
             and observed['parent_sampled_rss_enforcement_proven'] is False
             and observed['authentic_user_consent_proven'] is False, 'PROCESS_SCHEMA')
    for key, number in (('address_space_limits', 8*1024**3), ('core_limits', 0)):
        _require(type(observed[key]) is list and len(observed[key]) == 2
                 and all(type(v) is int and v == number for v in observed[key]), 'PROCESS_LIMIT')
    metrics = b['metrics']
    if b['held_labels_replayed']:
        _object(metrics, {'hit_at_10', 'hit_found', 'attempt_count', 'charged_runtime_s',
                          'best_cycle_regret_at_10', 'freeze_sha256'})
        _require(type(metrics['hit_at_10']) is int and metrics['hit_at_10'] in (0, 1)
                 and type(metrics['hit_found']) is bool
                 and metrics['hit_at_10'] == int(metrics['hit_found'])
                 and type(metrics['attempt_count']) is int and 1 <= metrics['attempt_count'] <= 10
                 and all(type(metrics[k]) in (int, float) for k in ('charged_runtime_s', 'best_cycle_regret_at_10'))
                 and metrics['charged_runtime_s'] > 0
                 and metrics['best_cycle_regret_at_10'] >= 0
                 and metrics['freeze_sha256'] == b['freeze_sha256'], 'METRICS')
    else:
        _require(metrics is None, 'METRICS')
    _object(freeze, {'payload', 'sha256'})
    payload = freeze['payload']
    _object(payload, {'family', 'fitting_uids_sha256', 'heldout_uids_sha256', 'scores', 'order', 'epsilon', 'top_k'})
    _require(payload['family'] == b['family'] and type(payload['epsilon']) is float and payload['epsilon'] == .01
             and type(payload['top_k']) is int and payload['top_k'] == 10
             and _is_sha(payload['fitting_uids_sha256']) and _is_sha(payload['heldout_uids_sha256'])
             and type(payload['scores']) is dict and bool(payload['scores'])
             and all(type(k) is str and bool(k) and type(v) is float for k, v in payload['scores'].items())
             and type(payload['order']) is list
             and payload['order'] == sorted(payload['scores'], key=lambda uid: (-payload['scores'][uid], uid)), 'FREEZE_SCHEMA')
    _require(_sha(_canonical(payload)) == freeze['sha256'] == b['freeze_sha256'], 'FREEZE_BINDING')
    if b['held_labels_replayed']:
        limit = min(10, len(payload['order']))
        _require(metrics['attempt_count'] <= limit
                 and (metrics['hit_found'] or metrics['attempt_count'] == limit), 'METRICS_ATTEMPTS')
    _require(receipt['fitting_log_sha256'] == pins['fitting.jsonl']
             and b['model_ack_sha256'] == b['expected_model_sha256'] == pins['model.pt']
             and _sha(_canonical(freeze)+b'\n') == pins['freeze.json']
             and _sha(_canonical(receipt)+b'\n') == pins['worker_receipt.json']
             and _sha(_canonical({k: v for k, v in receipt.items() if k != 'worker_receipt_sha256'}))
                 == receipt['worker_receipt_sha256'], 'EXPECTED_SHA_BINDING')
    return b


def _logs(raw, boundary):
    lines = raw.splitlines(keepends=True)
    _require(len(lines) == 122, 'LOG_COUNT')
    families = sorted(FAMILIES - {boundary['family']})
    for index, line in enumerate(lines):
        _require(0 < len(line) <= LOG_RECORD_MAX_BYTES, 'LOG_RECORD_BOUND')
        record = _decode(line)
        _object(record, LOG_FIELDS)
        _require(record['scope'] == 'FITTING_ONLY_DIAGNOSTIC_NOT_RELEASE'
                 and type(record['epoch']) is int and record['epoch'] == min(index, 120)
                 and record['phase'] == ('INITIAL' if index == 0 else 'FINAL' if index == 121 else 'EPOCH')
                 and type(record['K']) is int and record['K'] == 10 and record['epsilon'] == '101/100'
                 and record['recipe_sha256'] == boundary['head_recipe_sha256']
                 and record['canonical_request_sha256'] == boundary['canonical_request_sha256']
                 and type(record['families']) is list and len(record['families']) == 5, 'LOG_BINDING')
        for row, family in zip(record['families'], families):
            _object(row, ROW_FIELDS)
            _require(row['family'] == family and all(type(row[k]) is int for k in ROW_INTS)
                     and all(type(row[k]) is bool for k in ROW_BOOLS)
                     and all(type(row[k]) in (int, float) for k in ROW_NUMBERS)
                     and (row['head_gap'] is None or type(row['head_gap']) in (int, float)), 'LOG_ROW_TYPE')
            guaranteed = row['negative_count'] < 10
            gap = row['head_gap']
            _require(2 <= row['actions'] <= 20000
                     and row['positive_count'] >= 1 and row['negative_count'] >= 1
                     and row['positive_count'] + row['negative_count'] == row['actions']
                     and 1 <= row['first_positive_rank'] <= row['negative_count'] + 1
                     and row['hit_at_10'] in (0, 1)
                     and row['hit_at_10'] == int(row['first_positive_rank'] <= 10)
                     and row['negatives_before_first_positive'] == row['first_positive_rank'] - 1
                     and all(row[k] >= 0 for k in ROW_NUMBERS)
                     and row['guaranteed_hit_by_size'] is guaranteed
                     and (gap is None) == guaranteed
                     and row['strict_score_hit_certificate'] is (guaranteed or gap > 0)
                     and row['tie_at_boundary'] is (not guaranteed and gap == 0)
                     and (not guaranteed or row['head_softplus'] == 0), 'LOG_ROW_SEMANTICS')
        _require(all(type(record[k]) in (int, float) for k in ('macro_head_loss', 'macro_pair_softplus_reference'))
                 and type(record['objective_signal_families']) is int
                 and 0 <= record['objective_signal_families'] <= 5
                 and type(record['macro_family_count']) is int and record['macro_family_count'] == 5, 'LOG_SCALAR')
        _require(record['macro_head_loss'] >= 0 and record['macro_pair_softplus_reference'] >= 0
                 and record['objective_signal_families'] == sum(
                     not row['guaranteed_hit_by_size'] for row in record['families']), 'LOG_SCALAR_SEMANTICS')


def validate_train_artifact_readback(output, *, expected_receipt, expected_freeze, trusted_file_sha256):
    """Validate four fixed files against exact independent caller expectations.

    No writes, checkpoint decoding, guard invocation, retries or authority are
    provided. A fresh create-once output and trusted expectations are external
    prerequisites, not facts established by this function's PASS status.
    """
    root = _root(output)  # arbitrary/protected paths rejected before ANY I/O
    b = _expectations(expected_receipt, expected_freeze, trusted_file_sha256)
    # Snapshot only after bounded graph validation; I/O must not observe later
    # caller mutation of the expectations or turn a new claim into a trusted pin.
    expected_receipt, expected_freeze, trusted_file_sha256 = deepcopy(
        (expected_receipt, expected_freeze, trusted_file_sha256))
    b = expected_receipt['boundary_receipt']
    for name in LIMITS:
        raw = _read(root, name)
        _require(_sha(raw) == trusted_file_sha256[name], 'FILE_SHA')
        if name == 'fitting.jsonl':
            _logs(raw, b)
        elif name in ('freeze.json', 'worker_receipt.json'):
            expected = expected_freeze if name == 'freeze.json' else expected_receipt
            _require(_canonical(_decode(raw)) == _canonical(expected), 'EXACT_EXPECTATION')
    return {'status': 'PASS_TRAIN_ARTIFACT_READBACK_INTEGRITY_ONLY',
            'family': b['family'], 'seed': b['seed'], 'log_record_count': 122,
            'file_sha256': dict(trusted_file_sha256),
            'formal_training_authorized_by_this_function': False,
            'new_formal_18_fit_release': False,
            'parent_sampled_rss_enforcement_proven': False}
