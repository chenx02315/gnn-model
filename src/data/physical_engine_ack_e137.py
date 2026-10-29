"""Pure digest-only evidence/ACK joins; not identity proof or a release controller.

The caller must obtain the expected review SHA from an independently trusted
channel, persist reviewed raw evidence and consume its one-use ledger before
release. A SHA alone authenticates neither a reviewer nor a physical engine.
Deadline enforcement, nonce generation and cross-process single use are external.
"""
import re
from .physical_replay_source_reader_e135 import require,sha,canonical,decode

CAP = 65536
TRUSTED_REVIEW_SHA256 = None
ROLE = 'execution'
HASH_KEYS = ('authorization_sha256','original_clock_sha256','role2_payload_sha256','instance_sha256','metadata_sha256')
CONTEXT_KEYS = set(HASH_KEYS)|{'nonce','role'}


def _hex(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None


def _decode(raw):
    require(type(raw) is bytes and 0 < len(raw) <= CAP,'ACK_ENCODED_CAP')
    value = decode(raw)  # Reject duplicate keys and nonfinite JSON constants.
    require(type(value) is dict,'ACK_OBJECT_REQUIRED')
    return value


def _context(value):
    require(set(value) == CONTEXT_KEYS and value['role'] == ROLE and
        all(_hex(value[k]) for k in HASH_KEYS+('nonce',)),'ACK_EXACT_INSTANCE_CONTEXT')
    return value


def make_evidence(bindings):
    """Digest-only redacted envelope; never receives code, paths or env values."""
    require(type(bindings) is dict,'ACK_BINDINGS_OBJECT')
    _context(bindings)
    raw = canonical(dict(bindings,schema='e137-redacted-engine-evidence-v1'))
    require(len(raw) <= CAP,'ACK_ENCODED_CAP')
    return raw


def evidence_context(raw):
    value = _decode(raw)
    require(value.get('schema') == 'e137-redacted-engine-evidence-v1' and set(value) == CONTEXT_KEYS|{'schema'},
        'ACK_EVIDENCE_SCHEMA')
    return _context({k:value[k] for k in CONTEXT_KEYS})


def make_ack(evidence_raw):
    """Construct an untrusted candidate ACK, never an authorization."""
    context = evidence_context(evidence_raw)
    return canonical(dict(context,schema='e137-engine-instance-ack-v1',decision='ACK',evidence_sha256=sha(evidence_raw)))


def validate_ack(ack_raw,evidence_raw,review_raw,trusted_review_sha256=None):
    """The optional expected SHA is TRUSTED external input, not ACK/review data.

    Never derive it from review_raw at a call site and call that authentication.
    This pure API cannot verify the origin of that external trust assertion.
    """
    trusted = TRUSTED_REVIEW_SHA256 if trusted_review_sha256 is None else trusted_review_sha256
    require(_hex(trusted),'ACK_TRUSTED_REVIEW_SHA_REQUIRED')
    context = evidence_context(evidence_raw)
    ack = _decode(ack_raw)
    expected = dict(context,schema='e137-engine-instance-ack-v1',decision='ACK',evidence_sha256=sha(evidence_raw))
    require(ack == expected and set(ack) == set(expected),'ACK_EXACT_BINDING_NO_ADDITIONAL_FIELDS')
    review = _decode(review_raw)
    require(sha(review_raw) == trusted,'ACK_TRUSTED_REVIEW_BYTES')
    reviewed = dict(context,evidence_sha256=sha(evidence_raw))
    require(set(review) == {'schema','status','reviewed'} and review['schema'] == 'e137-engine-instance-review-v1' and
        review['status'] == 'PASS' and type(review['reviewed']) is dict and review['reviewed'] == reviewed and
        set(review['reviewed']) == set(reviewed),'ACK_EXACT_REVIEW_MAPPING')
    return dict(bindings_matched=True,evidence_sha256=sha(evidence_raw),ack_sha256=sha(ack_raw),review_sha256=trusted,
        reviewer_authenticity_proven=False,physical_identity_proven=False,cross_process_single_use_proven=False,
        raw_persistence_proven=False,deadlines_enforced=False,execution_ready=False)
