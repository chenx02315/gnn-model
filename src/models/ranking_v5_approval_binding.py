"""Pure integrity checks for externally trusted v5 approval evidence.

This module does not authenticate a user or an auditor. Trust anchors must
come from an independently verified caller, never from these JSON objects.
It performs no I/O, makes no release, and has no training entry point.
"""
from copy import deepcopy
import hashlib
import json

from src.models import ranking_v5_execution_boundary as boundary
from src.models.runtime_ranking_v3 import digest

AUTH_FIELDS = frozenset(('schema', 'authorization_id', 'scope', 'roles', 'planned_fits',
                         'seeds', 'source_sha256', 'package_receipt_sha256', 'retry_count'))
REVIEW_FIELDS = frozenset(('schema', 'status', 'scope', 'authorization_sha256',
                           'release_sha256', 'source_binding_sha256', 'physical_gate_sha256'))
SCOPE = 'V5_HEAD_TOP10_TRAIN_ONLY_18_FITS'
MAX_EVIDENCE_BYTES = 20000


def _decode(raw, pin):
    if (type(raw) is not bytes or not 0 < len(raw) <= MAX_EVIDENCE_BYTES
            or not boundary._sha(pin) or hashlib.sha256(raw).hexdigest() != pin):
        raise ValueError('V5_APPROVAL_RAW_PIN')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('V5_APPROVAL_DUPLICATE_KEY')
            value[key] = item
        return value
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError('V5_APPROVAL_OBJECT')
    return value


def review_subject(release):
    """Noncircular subject: review pins all release fields except its own hash."""
    if not isinstance(release, dict) or set(release) != boundary.RELEASE_FIELDS:
        raise ValueError('V5_APPROVAL_RELEASE_SCHEMA')
    return digest({key: value for key, value in release.items()
                   if key != 'independent_review_receipt_sha256'})


def validate_approval_integrity(release, expected_sources, authorization_raw, review_raw, *,
                                trusted_authorization_sha256, trusted_review_sha256,
                                trusted_physical_gate_sha256):
    """Check bytes against caller-provided trusted pins, not authority itself.

    All three pins must be obtained independently of release/evidence input.
    Tests can prove rejection/order/integrity only, not genuine user consent.
    """
    release = deepcopy(release)
    sources = deepcopy(expected_sources)
    boundary.validate_release(release, sources)
    if (release['user_authorization_sha256'] != trusted_authorization_sha256
            or release['independent_review_receipt_sha256'] != trusted_review_sha256
            or not boundary._sha(trusted_physical_gate_sha256)):
        raise ValueError('V5_APPROVAL_EXTERNAL_ANCHORS')
    auth = _decode(authorization_raw, trusted_authorization_sha256)
    review = _decode(review_raw, trusted_review_sha256)
    expected_auth = dict(schema='v5-explicit-authorization-evidence-v1',
        authorization_id=release['user_authorization_id'], scope=SCOPE, roles=['TRAIN'],
        planned_fits=18, seeds=list(boundary.SEEDS), source_sha256=boundary.SOURCE_SHA256,
        package_receipt_sha256=boundary.PACKAGE_SHA256, retry_count=0)
    if (set(auth) != AUTH_FIELDS or auth != expected_auth
            or type(auth['planned_fits']) is not int or type(auth['retry_count']) is not int
            or any(type(seed) is not int for seed in auth['seeds'])):
        raise ValueError('V5_APPROVAL_AUTH_SCOPE')
    expected_review = dict(schema='v5-independent-release-binding-review-v1',
        status='PASS_V5_RELEASE_BINDING_REVIEW', scope=SCOPE,
        authorization_sha256=trusted_authorization_sha256, release_sha256=review_subject(release),
        source_binding_sha256=digest(sources), physical_gate_sha256=trusted_physical_gate_sha256)
    if set(review) != REVIEW_FIELDS or review != expected_review:
        raise ValueError('V5_APPROVAL_REVIEW_SCOPE')
    return dict(status='PASS_APPROVAL_BYTES_INTEGRITY_ONLY', authentic_user_consent_proven=False,
                training_authorized_by_this_function=False, release_sha256=digest(release),
                authorization_sha256=trusted_authorization_sha256, review_sha256=trusted_review_sha256,
                physical_gate_sha256=trusted_physical_gate_sha256)
