"""Implementation-only composition of one pinned TRAIN fold and frozen replay.

This is not a physical worker, permission grant, CLI, memory watchdog or
18-fit launcher. External callers own authentic authority, source-file
verification, process isolation and durable callbacks. No Torch import occurs.
"""
from copy import deepcopy

from src.models import ranking_v5_approval_binding as approval
from src.models import ranking_v5_bound_input_reader as inputs
from src.models import ranking_v5_execution_boundary as boundary
from src.models import ranking_v5_held_replay_reader as held
from src.models.runtime_ranking_v3 import digest


def compose_single_fit(package_root, family, seed, release, expected_sources,
                       authorization_raw, review_raw, *,
                       trusted_authorization_sha256, trusted_review_sha256,
                       trusted_physical_gate_sha256, fit, predict, model_sha256,
                       persist_model, persist_freeze, read_frozen):
    """Compose integrity checks and callbacks, without authenticating consent.

    Trusted pins must come from independent external evidence, not from these
    input JSON objects. Formal entry remains closed in the repository contract.
    A positive mocked test proves call ordering only, never physical training.
    """
    release, sources = deepcopy(release), deepcopy(expected_sources)
    # Test-only synthetic authority must not accidentally become a real caller.
    authorization_id = release.get('user_authorization_id') if isinstance(release, dict) else None
    if (not isinstance(authorization_id, str) or not authorization_id
            or any(word in authorization_id.upper() for word in ('TEST_ONLY', 'SYNTHETIC'))):
        raise ValueError('V5_COMPOSITION_NONFORMAL_AUTHORITY')
    callbacks = (fit, predict, model_sha256, persist_model, persist_freeze, read_frozen)
    if any(not callable(callback) for callback in callbacks):
        raise ValueError('V5_COMPOSITION_CALLBACKS')
    integrity = approval.validate_approval_integrity(
        release, sources, authorization_raw, review_raw,
        trusted_authorization_sha256=trusted_authorization_sha256,
        trusted_review_sha256=trusted_review_sha256,
        trusted_physical_gate_sha256=trusted_physical_gate_sha256)
    loaded = deepcopy(inputs.load_bound_fold_request(package_root, family, seed))
    identity = loaded['input_identity']
    if (loaded.get('status') != inputs.STATUS
            or set(identity) != {'package_receipt_sha256', 'source_sha256',
                                 'fold_manifest_sha256', 'family', 'seed'}
            or identity['package_receipt_sha256'] != boundary.PACKAGE_SHA256
            or identity['source_sha256'] != boundary.SOURCE_SHA256
            or identity['family'] != family or identity['seed'] != seed
            or type(identity['seed']) is not int
            or not boundary._sha(identity['fold_manifest_sha256'])):
        raise ValueError('V5_COMPOSITION_INPUT_IDENTITY')
    request = loaded['request']
    if request.get('family') != family or request.get('seed') != seed:
        raise ValueError('V5_COMPOSITION_REQUEST_IDENTITY')
    fold, _, _, _ = boundary.prepare_request(request)
    frozen = {}

    def reread(expected_sha):
        value = read_frozen(expected_sha)
        # Snapshot the independently persisted read so later callbacks cannot
        # mutate the object used as the proof authorizing held-label path access.
        frozen['value'] = deepcopy(value)
        return deepcopy(value)

    def held_labels(uids, freeze_sha):
        return held.load_frozen_held_outcomes(
            package_root, deepcopy(identity), fold, uids, freeze_sha,
            deepcopy(frozen.get('value')))

    result = boundary.execute(
        request, release, sources, fit=fit, predict=predict,
        model_sha256=model_sha256, persist_model=persist_model,
        persist_freeze=persist_freeze, read_frozen=reread,
        load_held_labels=held_labels)
    return dict(status='PASS_CALLBACK_COMPOSITION_ONLY',
                authentic_user_consent_proven=False,
                physical_worker_limits_verified=False,
                formal_training_authorized_by_this_function=False,
                input_identity=deepcopy(identity), approval_integrity=integrity,
                boundary_receipt=result,
                composition_sha256=digest({'input_identity': identity,
                                          'approval_integrity': integrity,
                                          'boundary_receipt': result}))
