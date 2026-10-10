"""Pure independent-input/candidate identity binding, never authorization.

The outer caller must authenticate request/package identity, approval trust
anchors and source bytes BEFORE constructing this context. Inputs must not be
derived from worker receipts/logs. This module checks supplied bytes/contracts,
not provenance or user consent. No I/O, checkpoint decode, Torch or execution.
Parent-measured artifact pins are observations, not preknown authorization.

Private readback helpers are reused solely for current pure schema/semantics;
they are NOT a stable public API. Production authenticated-package preflight,
parent bootstrap/prelaunch integration and resource enforcement remain absent.
Scores are candidate values: rebuilding their freeze does NOT verify numerical
model predictions or held metrics against an independently executed model.
"""
from copy import deepcopy
from dataclasses import dataclass, fields
import hashlib
import json
import math

from src.models import ranking_v5_approval_binding as approval
from src.models import ranking_v5_execution_boundary as boundary
from src.models import ranking_v5_train_artifact_readback as readback
from src.models.runtime_ranking_v3 import FAMILIES, Fold, digest, freeze_ranking


def _require(ok, code):
    if not ok:
        raise ValueError('V5_INDEPENDENT_FIT_' + code)


def _sha(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def _snapshot(value, cap=12*1024**2):
    """Reject non-plain/unbounded graphs before deepcopy (including cycles)."""
    nodes = 0
    def visit(item, depth):
        nonlocal nodes
        nodes += 1
        _require(depth <= 64 and nodes <= 400000, 'GRAPH_BOUND')
        kind = type(item)
        if kind is str:
            _require(len(item) <= 2048, 'STRING_BOUND')
        elif kind is int:
            _require(item.bit_length() <= 1024, 'INT_BOUND')
        elif kind is float:
            _require(math.isfinite(item), 'NONFINITE')
        elif kind in (dict, list, tuple):
            _require(len(item) <= 20000, 'CONTAINER_BOUND')
            if kind is dict:
                for key, child in item.items():
                    _require(type(key) is str, 'KEY_TYPE')
                    visit(key, depth+1); visit(child, depth+1)
            else:
                for child in item:
                    visit(child, depth+1)
        else:
            _require(kind in (bool, type(None)), 'VALUE_TYPE')
    visit(value, 0)
    # Bounded graph first; JSON byte cap is a second bound, before snapshot.
    size = 0
    for chunk in json.JSONEncoder(sort_keys=True, separators=(',', ':'), allow_nan=False).iterencode(value):
        size += len(chunk.encode())
        _require(size <= cap, 'BYTE_BOUND')
    return deepcopy(value)


@dataclass(frozen=True, slots=True)
class IndependentFitContext:
    family: str
    seed: int
    canonical_request_sha256: str
    release_sha256: str
    source_binding_sha256: str
    head_recipe_sha256: str
    fold_manifest_sha256: str
    source_sha256: str
    package_receipt_sha256: str
    authorization_sha256: str
    review_sha256: str
    physical_gate_sha256: str
    fitting_uids: tuple
    heldout_uids: tuple
    fitting_uids_sha256: str
    heldout_uids_sha256: str
    # (family, actions, positive_count, negative_count), sorted by family.
    recipe_class_counts: tuple

    @property
    def fitting_count(self):
        return len(self.fitting_uids)

    @property
    def heldout_count(self):
        return len(self.heldout_uids)


def _validate_context(context):
    _require(type(context) is IndependentFitContext, 'CONTEXT_TYPE')
    _snapshot({field.name: getattr(context, field.name) for field in fields(context)})
    _require(type(context.family) is str and context.family in FAMILIES.values()
             and type(context.seed) is int and context.seed in boundary.SEEDS, 'CONTEXT_IDENTITY')
    for field in fields(context):
        if field.name.endswith('sha256'):
            _require(_sha(getattr(context, field.name)), 'CONTEXT_SHA')
    _require(context.source_sha256 == boundary.SOURCE_SHA256
             and context.package_receipt_sha256 == boundary.PACKAGE_SHA256, 'CONTEXT_SOURCE')
    for uids in (context.fitting_uids, context.heldout_uids):
        _require(type(uids) is tuple and bool(uids)
                 and all(type(uid) is str and bool(uid) for uid in uids)
                 and uids == tuple(sorted(set(uids))), 'CONTEXT_UIDS')
    _require(not set(context.fitting_uids) & set(context.heldout_uids)
             and digest(context.fitting_uids) == context.fitting_uids_sha256
             and digest(context.heldout_uids) == context.heldout_uids_sha256, 'CONTEXT_UID_SHA')
    counts = context.recipe_class_counts
    expected_families = sorted(set(FAMILIES.values()) - {context.family})
    _require(type(counts) is tuple and len(counts) == 5, 'CONTEXT_COUNTS')
    for row, family in zip(counts, expected_families):
        _require(type(row) is tuple and len(row) == 4 and type(row[0]) is str
                 and row[0] == family and all(type(v) is int and v >= 1 for v in row[1:])
                 and row[1] == row[2]+row[3], 'CONTEXT_COUNTS')
    _require(sum(row[1] for row in counts) == context.fitting_count, 'CONTEXT_COUNTS')


def build_independent_fit_context(request, release, expected_sources, input_identity,
                                 authorization_raw, review_raw, *, family, seed,
                                 trusted_authorization_sha256, trusted_review_sha256,
                                 trusted_physical_gate_sha256):
    """Derive immutable identities from externally authenticated inputs only.

    Acceptance proves neither callback/input provenance nor authentic release.
    Fold-manifest SHA is an external package identity, not derivable here from
    request rows; the authenticated package preflight must establish that link.
    """
    request = _snapshot(request)
    release = _snapshot(release, 20000)
    sources = _snapshot(expected_sources, 64000)
    identity = _snapshot(input_identity, 20000)
    _require(type(family) is str and family in FAMILIES.values()
             and type(seed) is int and seed in boundary.SEEDS, 'TASK_IDENTITY')
    for raw in (authorization_raw, review_raw):
        _require(type(raw) is bytes and 0 < len(raw) <= approval.MAX_EVIDENCE_BYTES, 'EVIDENCE_BOUND')
    for pin in (trusted_authorization_sha256, trusted_review_sha256, trusted_physical_gate_sha256):
        _require(_sha(pin), 'TRUSTED_PIN')
    integrity = approval.validate_approval_integrity(release, sources, authorization_raw, review_raw,
        trusted_authorization_sha256=trusted_authorization_sha256,
        trusted_review_sha256=trusted_review_sha256,
        trusted_physical_gate_sha256=trusted_physical_gate_sha256)
    _require(type(identity) is dict and set(identity) == {'family', 'seed', 'source_sha256',
        'package_receipt_sha256', 'fold_manifest_sha256'}, 'INPUT_IDENTITY_SCHEMA')
    _require(type(identity['family']) is str and identity['family'] == family
             and type(identity['seed']) is int and identity['seed'] == seed
             and identity['source_sha256'] == boundary.SOURCE_SHA256
             and identity['package_receipt_sha256'] == boundary.PACKAGE_SHA256
             and _sha(identity['fold_manifest_sha256']), 'INPUT_IDENTITY')
    _require(type(request) is dict and request.get('family') == family
             and type(request.get('seed')) is int and request['seed'] == seed, 'REQUEST_IDENTITY')
    fold, _, _, recipe = boundary.prepare_request(request)
    counts = tuple((f, len(g['positive'])+len(g['negative']), len(g['positive']), len(g['negative']))
                   for f, g in sorted(recipe['families'].items()))
    context = IndependentFitContext(family, seed, digest(request), digest(release), digest(sources),
        digest(recipe), identity['fold_manifest_sha256'], identity['source_sha256'],
        identity['package_receipt_sha256'], integrity['authorization_sha256'],
        integrity['review_sha256'], integrity['physical_gate_sha256'], tuple(fold.fitting),
        tuple(fold.heldout), digest(fold.fitting), digest(fold.heldout), counts)
    _validate_context(context)
    return context


def verify_candidate_fit_artifacts(context, candidate_worker_receipt, freeze_envelope,
                                   log_records, parent_measured_file_sha256):
    """Bind candidate evidence to independent context; do not certify its numbers.

    No candidate value becomes a trusted expectation: receipt/freezes are passed
    to pure readback schema helpers only AFTER independent identity comparisons.
    Raw file measurements and canonical-byte checks do not decode checkpoints.
    """
    _validate_context(context)
    receipt = _snapshot(candidate_worker_receipt, readback.LIMITS['worker_receipt.json'])
    freeze = _snapshot(freeze_envelope, readback.LIMITS['freeze.json'])
    records = _snapshot(log_records, readback.LIMITS['fitting.jsonl'])
    pins = _snapshot(parent_measured_file_sha256, 20000)
    _require(type(receipt) is dict and set(receipt) == readback.RECEIPT_FIELDS, 'RECEIPT_SCHEMA')
    b = receipt['boundary_receipt']
    _require(type(b) is dict and set(b) == readback.BOUNDARY_FIELDS, 'BOUNDARY_SCHEMA')
    independent = {key: getattr(context, key) for key in (
        'family', 'seed', 'canonical_request_sha256', 'release_sha256',
        'source_binding_sha256', 'head_recipe_sha256')}
    _require(all(type(b[key]) is type(value) and b[key] == value
                 for key, value in independent.items()), 'BOUNDARY_IDENTITY')
    expected_identity = {key: getattr(context, key) for key in (
        'family', 'seed', 'source_sha256', 'package_receipt_sha256', 'fold_manifest_sha256')}
    _require(type(receipt['input_identity']) is dict
             and receipt['input_identity'] == expected_identity
             and type(receipt['input_identity'].get('seed')) is int, 'INPUT_IDENTITY_BINDING')
    a = receipt['approval_integrity']
    _require(type(a) is dict and all(a.get(key) == getattr(context, key) for key in (
        'release_sha256', 'authorization_sha256', 'review_sha256', 'physical_gate_sha256')),
        'APPROVAL_IDENTITY')
    _require(b['held_labels_replayed'] is True and type(b['metrics']) is dict
             and bool(b['metrics']), 'HELD_REPLAY_REQUIRED')
    _require(type(freeze) is dict and set(freeze) == {'payload', 'sha256'}
             and type(freeze['payload']) is dict and type(freeze['payload'].get('scores')) is dict,
             'FREEZE_SCHEMA')
    fold = Fold(context.family, context.fitting_uids, context.heldout_uids)
    rebuilt, rebuilt_sha = freeze_ranking(freeze['payload']['scores'], fold)
    _require(freeze['payload'] == rebuilt and freeze['sha256'] == rebuilt_sha
             and b['freeze_sha256'] == rebuilt_sha, 'INDEPENDENT_FREEZE_BINDING')
    # Private PURE helpers: no root validation, file read or checkpoint decode.
    readback._expectations(receipt, freeze, pins)
    _require(type(records) is list and len(records) == 122, 'LOG_COUNT')
    raw_parts, total = [], 0
    for record in records:
        raw = readback._canonical(record)+b'\n'
        total += len(raw)
        _require(len(raw) <= readback.LOG_RECORD_MAX_BYTES
                 and total <= readback.LIMITS['fitting.jsonl'], 'LOG_BYTE_BOUND')
        raw_parts.append(raw)
    raw_logs = b''.join(raw_parts)
    _require(hashlib.sha256(raw_logs).hexdigest() == pins['fitting.jsonl'], 'MEASURED_LOG_SHA')
    readback._logs(raw_logs, b)
    for record in records:
        _require(record['recipe_sha256'] == context.head_recipe_sha256
                 and record['canonical_request_sha256'] == context.canonical_request_sha256,
                 'LOG_IDENTITY')
        for row, expected in zip(record['families'], context.recipe_class_counts):
            actual = (row['family'], row['actions'], row['positive_count'], row['negative_count'])
            _require(actual == expected, 'LOG_INDEPENDENT_CLASS_COUNTS')
    return dict(status='PASS_FIT_CONTEXT_BINDING_ONLY', family=context.family, seed=context.seed,
                fitting_count=context.fitting_count, heldout_count=context.heldout_count,
                numerical_model_predictions_verified=False, numerical_held_metrics_verified=False,
                callback_provenance_authenticated=False, authentic_user_consent_proven=False,
                formal_training_authorized_by_this_function=False, new_formal_18_fit_release=False)
