"""Design-only first-hit top-10 objective and fitting logs; no trainer or I/O.

Exact max-positive / tenth-negative boundary. This targets ANY near-optimal
hit, not all positive ranks, ATPG cost, or cross-family generalization.
"""
import hashlib
import json
import math

K = 10
MAX_ROWS = 20000
FIELDS = frozenset(('action_uid', 'family', 'total_cycles'))


def build_recipe(rows, *, heldout_family):
    if not isinstance(heldout_family, str) or not heldout_family:
        raise ValueError('HEAD_HELD_SENTINEL')
    if not isinstance(rows, (list, tuple)) or not 0 < len(rows) <= MAX_ROWS:
        raise ValueError('HEAD_ROW_BOUND')
    groups, uids = {}, set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != FIELDS:
            raise ValueError('HEAD_ROW_ALLOWLIST')
        uid, family, cycles = row['action_uid'], row['family'], row['total_cycles']
        if not isinstance(uid, str) or not uid or not isinstance(family, str) or not family:
            raise ValueError('HEAD_METADATA')
        if family == heldout_family:
            raise ValueError('HEAD_HELD_LABEL_FORBIDDEN')
        if uid in uids or type(cycles) is not int or cycles <= 0:
            raise ValueError('HEAD_UID_OR_CYCLES')
        uids.add(uid); groups.setdefault(family, []).append((uid, cycles))
    families = {}
    for family, members in sorted(groups.items()):
        oracle = min(c for _, c in members)
        positive = tuple(sorted(u for u, c in members if 100*c <= 101*oracle))
        negative = tuple(sorted(u for u, c in members if 100*c > 101*oracle))
        if not positive or not negative:
            raise ValueError('HEAD_CLASS_COVERAGE')
        families[family] = {'positive': positive, 'negative': negative,
                            'oracle_cycles': oracle, 'cycles': dict(members)}
    return {'schema': 'ranking-v5-head-design-v1', 'K': K,
            'heldout_family_forbidden': heldout_family, 'families': families}


def validate_recipe(recipe):
    if (not isinstance(recipe, dict) or set(recipe) != {'schema','K','heldout_family_forbidden','families'}
            or recipe['schema'] != 'ranking-v5-head-design-v1' or type(recipe['K']) is not int
            or recipe['K'] != K or not isinstance(recipe['families'], dict) or not recipe['families']):
        raise ValueError('HEAD_RECIPE')
    rows=[]
    for family, group in recipe['families'].items():
        if not isinstance(group,dict) or set(group) != {'positive','negative','oracle_cycles','cycles'} or not isinstance(group['cycles'],dict):
            raise ValueError('HEAD_RECIPE_GROUP')
        rows.extend({'action_uid':u,'family':family,'total_cycles':c} for u,c in group['cycles'].items())
    if build_recipe(rows,heldout_family=recipe['heldout_family_forbidden']) != recipe:
        raise ValueError('HEAD_RECIPE_REBUILD')


def validate_scores(scores, recipe):
    validate_recipe(recipe)
    expected = {u for g in recipe['families'].values() for u in g['cycles']}
    if not isinstance(scores, dict) or set(scores) != expected:
        raise ValueError('HEAD_SCORE_EXACT_JOIN')
    if any(isinstance(v, bool) or not isinstance(v, (float, int)) or not math.isfinite(v) for v in scores.values()):
        raise ValueError('HEAD_SCORE_FINITE')


def family_logs(scores, recipe):
    validate_scores(scores, recipe)
    logs = []
    for family, group in sorted(recipe['families'].items()):
        positive, negative = group['positive'], group['negative']
        order = sorted(group['cycles'], key=lambda u: (-scores[u], u))
        first = next(i+1 for i, u in enumerate(order) if u in set(positive))
        best = max(scores[u] for u in positive)
        guaranteed = len(negative) < K
        boundary = None if guaranteed else sorted((scores[u] for u in negative), reverse=True)[K-1]
        gap = None if guaranteed else best-boundary
        if gap is not None and not math.isfinite(gap):
            raise ValueError('HEAD_GAP_NONFINITE')
        loss = 0. if guaranteed else max(-gap, 0.)+math.log1p(math.exp(-abs(gap)))
        logs.append({'family': family, 'actions': len(order), 'positive_count': len(positive),
            'negative_count': len(negative), 'first_positive_rank': first, 'hit_at_10': int(first <= K),
            'negatives_before_first_positive': first-1,
            'top10_cycle_regret': min(group['cycles'][u]/group['oracle_cycles']-1 for u in order[:K]),
            'head_gap': gap, 'head_softplus': loss, 'guaranteed_hit_by_size': guaranteed,
            'strict_score_hit_certificate': guaranteed or gap > 0,
            'tie_at_boundary': not guaranteed and gap == 0})
    return logs


def loss_reference(scores, recipe):
    logs = family_logs(scores, recipe)
    return sum(g['head_softplus'] for g in logs)/len(logs)


def torch_loss(scores, index, recipe, torch):
    """Differentiable almost everywhere; called only by future authorized code.

    Zero-signal, guaranteed-hit families retain macro denominator explicitly.
    No tensor->float conversion or sorting labels by observed runtime.
    """
    validate_recipe(recipe)
    expected = {u for g in recipe['families'].values() for u in g['cycles']}
    if recipe.get('K') != K or set(index) != expected or set(index.values()) != set(range(len(expected))):
        raise ValueError('HEAD_TENSOR_JOIN')
    if scores.ndim != 1 or len(scores) != len(expected) or not torch.isfinite(scores).all().item():
        raise ValueError('HEAD_TENSOR_FINITE')
    losses = []
    for group in recipe['families'].values():
        if len(group['negative']) < K:
            losses.append(scores[0]*0.)
        else:
            positive = scores[[index[u] for u in group['positive']]].max()
            negatives = scores[[index[u] for u in group['negative']]]
            boundary = torch.topk(negatives,K,sorted=True).values[-1]
            losses.append(torch.nn.functional.softplus(boundary-positive))
    loss=torch.stack(losses).mean()
    if not torch.isfinite(loss).item():
        raise ValueError('HEAD_TENSOR_LOSS_NONFINITE')
    return loss


def fitting_log_record(scores, recipe, *, epoch, phase):
    if type(epoch) is not int or epoch < 0 or phase not in ('INITIAL', 'EPOCH', 'FINAL'):
        raise ValueError('HEAD_LOG_STAGE')
    rows = family_logs(scores, recipe)
    digest = hashlib.sha256(json.dumps(recipe,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
    return {'scope': 'FITTING_ONLY_DIAGNOSTIC_NOT_RELEASE', 'epoch': epoch, 'phase': phase,
            'K': K, 'epsilon': '101/100', 'recipe_sha256': digest, 'families': rows,
            'macro_head_loss': sum(r['head_softplus'] for r in rows)/len(rows),
            'objective_signal_families': sum(not r['guaranteed_hit_by_size'] for r in rows),
            'macro_family_count': len(rows)}
