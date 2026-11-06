"""Pure forensic ASCII representation candidate, NOT authorization or release.

The executed E138 grant/source/phase remain immutable. Returned bytes preserve
the OLD grant semantics (including its consumed r1 scope); they are not a grant
for any future run. A future live package requires new explicit whole-package
authorization, a new phase and a fresh independent audit. No IO or executor.
"""
import copy

from src.data import physical_e138_contract as contract
from src.data import physical_runtime_bootstrap_e138 as bootstrap

EXECUTED_AUTH_SHA256='bcaa8da7adc2e61daa35ccd50ce42dfd4131de180c7f3ca3adbbc86e8403dd74'
EXECUTED_PROPOSAL_SHA256='6e4d52d540aa3c776f7d443a1a14f0764ab90fa11657585d8d6c1b6c8acd0b4b'
CAP=65536


class EncodingCandidate:
    __slots__=('_raw','_metadata')
    def __init__(self,raw,metadata):self._raw,self._metadata=raw,metadata
    def __repr__(self):return '<E138 ASCII COUNTERFACTUAL NOT_AUTHORIZATION_NOT_RELEASE>'
    def __reduce_ex__(self,protocol):raise TypeError('E138_CANDIDATE_PRIVATE_BYTES_NOT_SERIALIZABLE')
    def private_candidate_bytes(self):return self._raw
    def public_metadata(self):return copy.deepcopy(self._metadata)


def build(authority_raw,proposal_raw):
    """Convert only the exact executed grant, without altering its meaning.

    Native contract validation of the original bytes establishes consistency
    against the executed pins, NOT permission to reuse the consumed attempt.
    Candidate hash equality/decoder agreement likewise creates no authority.
    """
    contract.require(type(authority_raw) is bytes and 0<len(authority_raw)<=CAP and
        type(proposal_raw) is bytes and 0<len(proposal_raw)<=CAP,'E138_ENCODING_INPUT_BOUND')
    # Strict native JSON parsing rejects duplicates and non-finite values before
    # canonicalization can erase their evidence or select one duplicate value.
    original=contract.decode(authority_raw)
    proposal=contract.decode(proposal_raw)
    contract.require(contract.sha(authority_raw)==EXECUTED_AUTH_SHA256 and
        contract.sha(proposal_raw)==EXECUTED_PROPOSAL_SHA256,'E138_ENCODING_EXECUTED_INPUT_PINS')
    contract.check_authority(authority_raw,proposal_raw,EXECUTED_AUTH_SHA256,EXECUTED_PROPOSAL_SHA256)
    contract.require(original['approved_scope']==contract.POLICY==proposal['scope_if_granted'] and
        original['proposal_sha256']==contract.sha(proposal_raw),'E138_ENCODING_EXACT_EXECUTED_SCOPE')
    candidate=contract.canonical(original)  # ensure_ascii=True, no new grant data.
    contract.require(0<len(candidate)<=CAP and candidate.isascii(),'E138_ENCODING_CANDIDATE_BOUND_OR_ASCII')
    native=contract.decode(candidate)
    frozen=bootstrap.decode(candidate)  # Exact unchanged bootstrap decoder.
    contract.require(native==original==frozen and contract.canonical(native)==candidate,
        'E138_ENCODING_SEMANTIC_OR_DECODER_DISAGREEMENT')
    metadata=dict(schema='e138-authority-encoding-counterfactual-v1',
        status='NOT_AUTHORIZATION_NOT_RELEASE',original_bytes=len(authority_raw),
        original_sha256=EXECUTED_AUTH_SHA256,proposal_sha256=EXECUTED_PROPOSAL_SHA256,
        candidate_bytes=len(candidate),candidate_sha256=contract.sha(candidate),
        encoding='CANONICAL_ASCII_JSON_WITH_UNICODE_ESCAPES',semantic_equality_verified=True,
        exact_executed_scope_preserved=True,native_contract_decoder_agrees=True,
        frozen_bootstrap_decoder_agrees=True,authorization_created=False,
        executed_attempt_reuse_permitted=False,future_live_package_requires_new_explicit_authorization=True,
        future_live_package_requires_new_phase_and_audit=True,execution_ready=False,
        tool_execution_verified=False,training_release=False)
    return EncodingCandidate(candidate,metadata)
