"""One CPU fit callback adapter, not a launcher or an authorization grant.

The caller MUST use the existing resource guard before invocation. This adapter
does not prove authentic consent, full source-file binding, or parent RSS
watchdog enforcement. No Torch import, CLI, environment mutation, retries,
or 18-fit scheduler is provided; formal entry remains closed.

The sealed composition's fit callback lacks request SHA. Consequently this
adapter loads one bound snapshot and uses the same execution boundary directly,
rather than rereading inputs or changing sealed APIs.
"""
from copy import deepcopy
import hashlib
import io
import operator

from src.models import ranking_v5_approval_binding as approval
from src.models import ranking_v5_bound_input_reader as inputs
from src.models import ranking_v5_execution_boundary as boundary
from src.models import ranking_v5_held_replay_reader as held
from src.models import ranking_v5_package_binding as package_binding
from src.models import ranking_v5_physical_worker as physical
from src.models import ranking_v5_real_artifact_store as artifacts
from src.models import ranking_v5_worker_resource_context as resource_context
from src.models.runtime_ranking_v3 import FAMILIES, digest


class BoundedModelBuffer(io.BytesIO):
    """Refuse writes/seeks/truncates beyond 1 MiB before BytesIO allocates."""
    def __init__(self):
        super().__init__()

    def write(self, value):
        size = memoryview(value).nbytes
        if size > artifacts.MODEL_MAX_BYTES - self.tell():
            raise ValueError('V5_SINGLE_FIT_MODEL_BOUND')
        return super().write(value)

    def writelines(self, lines):
        for line in lines:
            self.write(line)

    def __setstate__(self, state):
        raise ValueError('V5_SINGLE_FIT_MODEL_RESTORE_UNSUPPORTED')

    def seek(self, offset, whence=0):
        offset, whence = operator.index(offset), operator.index(whence)
        if whence == 0:
            target = offset
        elif whence == 1:
            target = self.tell() + offset
        elif whence == 2:
            view = self.getbuffer()
            try:
                target = view.nbytes + offset
            finally:
                view.release()
        else:
            raise ValueError('V5_SINGLE_FIT_MODEL_SEEK')
        if not 0 <= target <= artifacts.MODEL_MAX_BYTES:
            raise ValueError('V5_SINGLE_FIT_MODEL_BOUND')
        return super().seek(offset, whence)

    def truncate(self, size=None):
        size = self.tell() if size is None else operator.index(size)
        if not 0 <= size <= artifacts.MODEL_MAX_BYTES:
            raise ValueError('V5_SINGLE_FIT_MODEL_BOUND')
        return super().truncate(size)


_LOG_FIELDS = frozenset(('scope', 'epoch', 'phase', 'K', 'epsilon',
    'recipe_sha256', 'families', 'macro_head_loss', 'objective_signal_families',
    'macro_family_count', 'macro_pair_softplus_reference', 'canonical_request_sha256'))
_FAMILY_FIELDS = frozenset(('family', 'actions', 'positive_count', 'negative_count',
    'first_positive_rank', 'hit_at_10', 'negatives_before_first_positive',
    'top10_cycle_regret', 'head_gap', 'head_softplus', 'guaranteed_hit_by_size',
    'strict_score_hit_certificate', 'tie_at_boundary', 'pair_softplus_reference'))


def execute_single_fit(package_root, family, seed, release, expected_sources,
                       authorization_raw, review_raw, *, output,
                       torch, np, trusted_authorization_sha256,
                       trusted_review_sha256, trusted_physical_gate_sha256):
    """Load once and persist one fit/freeze/replay through validated callbacks.

    Independent trusted pins are integrity evidence, not authentic consent.
    There is intentionally no public bypass for current-process checks. Their
    success still does not prove the caller used the required parent watchdog.
    Failure preserves partial create-once evidence; it never retries/overwrites.
    """
    release, sources = deepcopy(release), deepcopy(expected_sources)
    authority = release.get('user_authorization_id') if isinstance(release, dict) else None
    if (not isinstance(authority, str) or not authority
            or any(word in authority.upper() for word in ('TEST_ONLY', 'SYNTHETIC'))):
        raise ValueError('V5_SINGLE_FIT_NONFORMAL_AUTHORITY')
    integrity = approval.validate_approval_integrity(
        release, sources, authorization_raw, review_raw,
        trusted_authorization_sha256=trusted_authorization_sha256,
        trusted_review_sha256=trusted_review_sha256,
        trusted_physical_gate_sha256=trusted_physical_gate_sha256)
    if not package_binding._lexical_root_allowed(package_root):
        raise ValueError('V5_SINGLE_FIT_ROOT')
    if not isinstance(family, str) or family not in FAMILIES.values():
        raise ValueError('V5_SINGLE_FIT_FAMILY')
    if type(seed) is not int or seed not in boundary.SEEDS:
        raise ValueError('V5_SINGLE_FIT_SEED')
    artifacts._lexical_output(output)  # no filesystem operations
    observed_context = resource_context.check_current_process()
    snapshot = deepcopy(inputs.load_bound_fold_request(package_root, family, seed))
    if not isinstance(snapshot, dict) or set(snapshot) != {'status', 'request', 'input_identity'}:
        raise ValueError('V5_SINGLE_FIT_INPUT_SCHEMA')
    identity = snapshot['input_identity']
    if (snapshot['status'] != inputs.STATUS or not isinstance(identity, dict)
            or set(identity) != {'package_receipt_sha256', 'source_sha256',
                                 'fold_manifest_sha256', 'family', 'seed'}
            or identity['package_receipt_sha256'] != boundary.PACKAGE_SHA256
            or identity['source_sha256'] != boundary.SOURCE_SHA256
            or identity['family'] != family or type(identity['seed']) is not int
            or identity['seed'] != seed or not boundary._sha(identity['fold_manifest_sha256'])):
        raise ValueError('V5_SINGLE_FIT_INPUT_IDENTITY')
    request = snapshot['request']
    if not isinstance(request, dict) or request.get('family') != family or request.get('seed') != seed:
        raise ValueError('V5_SINGLE_FIT_REQUEST_IDENTITY')
    fold, _, _, _ = boundary.prepare_request(request)
    request_sha = digest(request)
    state, logs, frozen = {}, [], {}
    log_bytes = 0

    def fit(prepared, recipe, fit_seed):
        nonlocal log_bytes
        resource_context.check_current_process()
        torch.set_num_threads(1)
        # Avoid resetting an already initialized interop pool. If it was
        # initialized with another size, Torch's setter must fail closed.
        if torch.get_num_interop_threads() != 1:
            torch.set_num_interop_threads(1)
        if (type(torch.get_num_threads()) is not int or torch.get_num_threads() != 1
                or type(torch.get_num_interop_threads()) is not int
                or torch.get_num_interop_threads() != 1):
            raise ValueError('V5_SINGLE_FIT_TORCH_THREADS')
        # The boundary already validated release/request before this callback.
        state['store'] = artifacts.RealArtifactStore(output)
        recipe_sha = digest(recipe)
        families = sorted(recipe['families'])

        def emit(record):
            nonlocal log_bytes
            if len(logs) >= artifacts.LOG_RECORD_COUNT:
                raise ValueError('V5_SINGLE_FIT_LOG_COUNT')
            raw = artifacts._canonical(record, artifacts.LOG_RECORD_MAX_BYTES)
            position = len(logs)
            phase = 'INITIAL' if position == 0 else ('FINAL' if position == 121 else 'EPOCH')
            epoch = min(position, 120)
            if (not isinstance(record, dict) or set(record) != _LOG_FIELDS
                    or record['scope'] != 'FITTING_ONLY_DIAGNOSTIC_NOT_RELEASE'
                    or type(record['epoch']) is not int or record['epoch'] != epoch
                    or record['phase'] != phase or record['K'] != 10
                    or record['epsilon'] != '101/100'
                    or record['canonical_request_sha256'] != request_sha
                    or record['recipe_sha256'] != recipe_sha
                    or not isinstance(record['families'], list)
                    or len(record['families']) != len(families)):
                raise ValueError('V5_SINGLE_FIT_LOG_BINDING')
            for row, expected_family in zip(record['families'], families):
                if (not isinstance(row, dict) or set(row) != _FAMILY_FIELDS
                        or row['family'] != expected_family
                        or any(type(value) not in (int, float, bool, type(None))
                               for key, value in row.items() if key != 'family')):
                    raise ValueError('V5_SINGLE_FIT_LOG_FAMILY')
            if any(type(record[key]) not in (int, float) for key in (
                    'macro_head_loss', 'objective_signal_families', 'macro_family_count',
                    'macro_pair_softplus_reference')):
                raise ValueError('V5_SINGLE_FIT_LOG_SCALAR')
            if len(raw) > artifacts.LOG_MAX_BYTES - log_bytes:
                raise ValueError('V5_SINGLE_FIT_LOG_BOUND')
            log_bytes += len(raw)
            logs.append(deepcopy(record))

        model = physical.fit_prepared(torch, np, prepared, recipe, fit_seed, emit, request_sha)
        # Fail before model/freeze/held access if the fixed loop did not emit all records.
        state['log_sha'] = state['store'].persist_logs(logs)
        return model

    def model_sha(model):
        with BoundedModelBuffer() as buffer:
            torch.save(model.state_dict(), buffer)
            raw = buffer.getvalue()
        if not raw:
            raise ValueError('V5_SINGLE_FIT_MODEL_EMPTY')
        state['model_raw'] = raw
        return hashlib.sha256(raw).hexdigest()

    def persist_model(model, expected):
        return state['store'].persist_model_bytes(state.pop('model_raw'), expected)

    def predict(model, uids, features):
        with torch.no_grad():
            values = model(torch.tensor(features, dtype=torch.float32, device='cpu')).detach().cpu().tolist()
        if len(values) != len(uids):
            raise ValueError('V5_SINGLE_FIT_PREDICT_SHAPE')
        return dict(zip(uids, values))

    def persist_freeze(payload, sha):
        return state['store'].persist_freeze(payload, sha)

    def reread(sha):
        value = state['store'].read_freeze(sha)
        frozen['value'] = deepcopy(value)
        return deepcopy(value)

    def held_labels(uids, sha):
        return held.load_frozen_held_outcomes(package_root, deepcopy(identity), fold,
                                             uids, sha, deepcopy(frozen.get('value')))

    result = boundary.execute(request, release, sources, fit=fit, predict=predict,
                              model_sha256=model_sha, persist_model=persist_model,
                              persist_freeze=persist_freeze, read_frozen=reread,
                              load_held_labels=held_labels)
    receipt = dict(status='PASS_SINGLE_FIT_CALLBACK_ADAPTER_ONLY',
                   authentic_user_consent_proven=False,
                   full_source_file_binding_verified=False,
                   parent_sampled_rss_enforcement_proven=False,
                   physical_worker_limits_verified=False,
                   formal_training_authorized_by_this_function=False,
                   new_formal_18_fit_release=False,
                   caller_must_use_existing_resource_guard=True,
                   input_identity=deepcopy(identity), approval_integrity=integrity,
                   observed_process_preconditions=observed_context,
                   boundary_receipt=result, fitting_log_sha256=state['log_sha'])
    receipt['worker_receipt_sha256'] = digest(receipt)
    state['store'].persist_receipt(receipt)
    return receipt


if __name__ == '__main__':
    raise SystemExit('V5_SINGLE_FIT_CLI_CLOSED: use only a separately guarded external caller')
