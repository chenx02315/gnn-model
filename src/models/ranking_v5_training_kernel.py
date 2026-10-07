"""Isolated synthetic integration; no CLI, file I/O, or real-training release.

The previous worker and its release cannot authorize this kernel. Real entry,
freeze persistence and held scoring deliberately remain outside this module.
"""
import math

from src.models import ranking_v4_training_worker as v4
from src.models.ranking_v5_head_objective import build_recipe, fitting_log_record, torch_loss
from src.models.runtime_ranking_v3 import digest, make_candidate_ranker

SCOPE = 'RANKING_V5_SYNTHETIC_INTEGRATION_ONLY'
EPOCHS = 120


def prepare(request):
    if not isinstance(request, dict) or request.get('scope') != SCOPE:
        raise ValueError('V5_SYNTHETIC_SCOPE_REQUIRED')
    fold, prepared, _, _ = v4.prepare_request(dict(request, scope=v4.SCOPE))
    by_uid = {row['action_uid']: row for row in request['rows']}
    recipe = build_recipe([
        {'action_uid': uid, 'family': by_uid[uid]['family'],
         'total_cycles': request['fit_cycles'][uid]}
        for uid in prepared['fit_uids']], heldout_family=fold.family)
    return prepared, recipe


def log_record(scores, recipe, pairs, *, epoch, phase, request_sha256):
    if (type(epoch) is not int or phase not in ('INITIAL', 'EPOCH', 'FINAL')
            or (phase == 'INITIAL' and epoch != 0)
            or (phase == 'EPOCH' and not 1 <= epoch <= EPOCHS)
            or (phase == 'FINAL' and epoch != EPOCHS) or not v4._sha(request_sha256)):
        raise ValueError('V5_LOG_BINDING_OR_STAGE')
    record = fitting_log_record(scores, recipe, epoch=epoch, phase=phase)
    if set(pairs) != set(recipe['families']):
        raise ValueError('V5_PAIR_FAMILY_JOIN')
    family_means = []
    for row in record['families']:
        group = recipe['families'][row['family']]
        expected = {(p, n) for p in group['positive'] for n in group['negative']}
        actual = pairs[row['family']]
        if len(actual) != len(expected) or set(actual) != expected:
            raise ValueError('V5_COMPLETE_PAIR_REFERENCE_REQUIRED')
        losses = []
        for p, n in actual:
            value = scores[n] - scores[p]
            if not math.isfinite(value):
                raise ValueError('V5_PAIR_REFERENCE_NONFINITE')
            losses.append(max(value, 0.) + math.log1p(math.exp(-abs(value))))
        row['pair_softplus_reference'] = math.fsum(losses) / len(losses)
        family_means.append(row['pair_softplus_reference'])
    record['macro_pair_softplus_reference'] = math.fsum(family_means) / len(family_means)
    record['canonical_request_sha256'] = request_sha256
    return record


def fit_synthetic(torch, np, request, emit):
    """Future synthetic gate entry, never a formal execution permit.

    All logs use fitting scores only; emit is a caller-owned bounded sink.
    No held features, held labels, graphs, epoch selection, or retries enter fit.
    """
    prepared, recipe = prepare(request)  # reject real/old scopes before any torch call
    if not callable(emit):
        raise ValueError('V5_LOG_SINK_REQUIRED')
    from src.models.runtime_training_v2 import seed_everything
    seed_everything(request['seed'], torch, np)
    uids = prepared['fit_uids']
    index = {uid: i for i, uid in enumerate(uids)}
    x = torch.tensor(prepared['fit_features'], dtype=torch.float32, device='cpu')
    model = make_candidate_ranker(torch)
    optimizer = torch.optim.Adam(model.parameters(), lr=.001, weight_decay=.0001)
    request_sha = digest(request)

    def record(epoch, phase):
        with torch.no_grad():
            values = model(x).detach().cpu().tolist()
        if len(values) != len(uids):
            raise ValueError('V5_LOG_SCORE_SHAPE')
        emit(log_record(dict(zip(uids, values)), recipe, prepared['pairs'],
                        epoch=epoch, phase=phase, request_sha256=request_sha))

    model.train()
    record(0, 'INITIAL')
    for epoch in range(1, EPOCHS + 1):
        optimizer.zero_grad()
        loss = torch_loss(model(x), index, recipe, torch)
        loss.backward()
        optimizer.step()
        record(epoch, 'EPOCH')
    model.eval()
    record(EPOCHS, 'FINAL')
    return model
