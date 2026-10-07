import copy
import hashlib
import json
import unittest
from src.models import ranking_v5_approval_binding as approval
from src.models import ranking_v5_execution_boundary as boundary
from src.models.ranking_v5_physical_worker import _test_release
from src.models.runtime_ranking_v3 import digest


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def fixture():
    sources = {name: 'a' * 64 for name in boundary.REQUIRED_SOURCE_BINDINGS}
    release = _test_release(sources)
    auth = dict(schema='v5-explicit-authorization-evidence-v1', authorization_id=release['user_authorization_id'],
        scope=approval.SCOPE, roles=['TRAIN'], planned_fits=18, seeds=list(boundary.SEEDS),
        source_sha256=boundary.SOURCE_SHA256, package_receipt_sha256=boundary.PACKAGE_SHA256, retry_count=0)
    auth_raw = raw(auth); auth_pin = hashlib.sha256(auth_raw).hexdigest()
    release['user_authorization_sha256'] = auth_pin
    physical_pin = 'b' * 64
    review = dict(schema='v5-independent-release-binding-review-v1', status='PASS_V5_RELEASE_BINDING_REVIEW',
        scope=approval.SCOPE, authorization_sha256=auth_pin, release_sha256=approval.review_subject(release),
        source_binding_sha256=digest(sources), physical_gate_sha256=physical_pin)
    review_raw = raw(review); review_pin = hashlib.sha256(review_raw).hexdigest()
    release['independent_review_receipt_sha256'] = review_pin
    return release, sources, auth_raw, review_raw, dict(trusted_authorization_sha256=auth_pin,
        trusted_review_sha256=review_pin, trusted_physical_gate_sha256=physical_pin)


class ApprovalTests(unittest.TestCase):
    def test_integrity_is_not_consent_or_training_authority(self):
        release, sources, auth, review, pins = fixture()
        result = approval.validate_approval_integrity(release, sources, auth, review, **pins)
        self.assertFalse(result['authentic_user_consent_proven'])
        self.assertFalse(result['training_authorized_by_this_function'])

    def test_external_pin_drift_and_raw_tamper_rejected(self):
        for key in fixture()[-1]:
            release, sources, auth, review, pins = fixture(); pins[key] = 'c' * 64
            with self.assertRaises(ValueError):
                approval.validate_approval_integrity(release, sources, auth, review, **pins)
        release, sources, auth, review, pins = fixture()
        with self.assertRaisesRegex(ValueError, 'RAW_PIN'):
            approval.validate_approval_integrity(release, sources, auth + b' ', review, **pins)

    def test_old_scope_role_float_and_extra_auth_rejected_even_rehashed(self):
        for key, value in (('scope', 'R4'), ('roles', ['TRAIN','BLIND_TEST']), ('planned_fits',18.0),
                           ('retry_count',False), ('unexpected',True)):
            release, sources, auth, review, pins = fixture(); value_auth = json.loads(auth); value_auth[key] = value
            auth = raw(value_auth); pins['trusted_authorization_sha256'] = hashlib.sha256(auth).hexdigest()
            release['user_authorization_sha256'] = pins['trusted_authorization_sha256']
            with self.assertRaisesRegex(ValueError, 'AUTH_SCOPE'):
                approval.validate_approval_integrity(release, sources, auth, review, **pins)

    def test_source_or_release_mutation_invalidates_review(self):
        release, sources, auth, review, pins = fixture()
        release['user_authorization_id'] = 'different'
        with self.assertRaises(ValueError):
            approval.validate_approval_integrity(release, sources, auth, review, **pins)
        release, sources, auth, review, pins = fixture()
        sources[next(iter(sources))] = 'd' * 64; release['source_binding'] = copy.deepcopy(sources)
        with self.assertRaisesRegex(ValueError, 'REVIEW_SCOPE'):
            approval.validate_approval_integrity(release, sources, auth, review, **pins)

    def test_duplicate_keys_and_oversize_raw_refused(self):
        value = b'{"a":1,"a":2}'
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_KEY'):
            approval._decode(value, hashlib.sha256(value).hexdigest())
        value = b' ' * 20001
        with self.assertRaisesRegex(ValueError, 'RAW_PIN'):
            approval._decode(value, hashlib.sha256(value).hexdigest())
