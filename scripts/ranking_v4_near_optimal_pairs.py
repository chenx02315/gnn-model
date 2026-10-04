"""Pure, local-only v4 near-optimal pair recipe kernel.

This is not a trainer, runner, release gate, or result receipt generator.
"""
import hashlib
import json
import math

PAIR_CAP_PER_FAMILY = 4096  # Engineering bound; not an empirically tuned parameter.
EPSILON_NUMERATOR = 101
EPSILON_DENOMINATOR = 100
ROW_FIELDS = frozenset(('action_uid', 'family', 'total_cycles'))


def _canonical_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    allow_nan=False).encode('utf-8')).hexdigest()


def _pair_id(family, positive_uid, negative_uid):
    return _canonical_digest([family, positive_uid, negative_uid])


def _validate_rows(rows, heldout_family):
    if not isinstance(heldout_family, str) or not heldout_family:
        raise ValueError('V4_HELDOUT_FAMILY')
    if not isinstance(rows, (list, tuple)) or not rows:
        raise ValueError('V4_EMPTY_FITTING')
    uids, families = set(), {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != ROW_FIELDS:
            raise ValueError('V4_ROW_ALLOWLIST')
        uid, family, cycles = row['action_uid'], row['family'], row['total_cycles']
        if not isinstance(uid, str) or not uid or not isinstance(family, str) or not family:
            raise ValueError('V4_ROW_METADATA')
        if family == heldout_family:
            raise ValueError('V4_HELDOUT_IN_FITTING')
        if type(cycles) is not int or cycles <= 0:
            raise ValueError('V4_CYCLES')
        if uid in uids:
            raise ValueError('V4_UID_UNIQUE')
        uids.add(uid); families.setdefault(family, []).append((uid, cycles))
    return families


def build_near_optimal_pair_recipe(rows, *, heldout_family):
    """Return deterministic per-family positive-vs-negative ranking pairs.

    Positivity uses exactly ``100 * cycles <= 101 * family_oracle``.  The
    heldout family is an explicit forbidden sentinel, never silently ignored.
    """
    groups = _validate_rows(rows, heldout_family)
    family_count = len(groups)
    recipe_families = {}
    for family in sorted(groups):
        members = sorted(groups[family])
        oracle = min(cycles for unused_uid, cycles in members)
        positive = [uid for uid, cycles in members if EPSILON_DENOMINATOR * cycles <= EPSILON_NUMERATOR * oracle]
        negative = [uid for uid, cycles in members if EPSILON_DENOMINATOR * cycles > EPSILON_NUMERATOR * oracle]
        if not positive or not negative:
            raise ValueError('V4_CLASS_COVERAGE:' + family)
        candidates = sorted((_pair_id(family, pos, neg), pos, neg)
                            for pos in positive for neg in negative)
        chosen = candidates[:PAIR_CAP_PER_FAMILY]
        recipe_families[family] = {
            'oracle_cycles': oracle,
            'positive_count': len(positive),
            'negative_count': len(negative),
            'candidate_pair_count': len(candidates),
            'selected_pair_count': len(chosen),
            'family_macro_weight': 1.0 / family_count,
            'pairs': [{'pair_id': pair_id, 'positive_uid': pos, 'negative_uid': neg}
                      for pair_id, pos, neg in chosen],
        }
    recipe = {
        'schema_version': 'ranking-v4-near-optimal-pair-recipe-v1',
        'scope': 'LOCAL_ONLY_DESIGN_KERNEL_NO_TRAINING',
        'heldout_family_forbidden': heldout_family,
        'epsilon_comparison': '100*cycles<=101*family_oracle_cycles',
        'pair_cap_per_family': PAIR_CAP_PER_FAMILY,
        'cap_rationale': 'ENGINEERING_BOUND_NOT_EMPIRICALLY_TUNED',
        'family_macro_weighting': 'mean_of_per_family_pair_means',
        'families': recipe_families,
    }
    return {'recipe': recipe, 'recipe_sha256': _canonical_digest(recipe),
            'family_count': family_count,
            'selected_pair_count': sum(item['selected_pair_count'] for item in recipe_families.values())}


def family_macro_pairwise_softplus(scores, recipe):
    """Reference loss: higher scores are better; each family weighs 1 / N."""
    families = recipe.get('families', {})
    if not families or not isinstance(scores, dict):
        raise ValueError('V4_LOSS_INPUT')
    total = 0.0
    for family, data in families.items():
        pairs, weight = data.get('pairs'), data.get('family_macro_weight')
        if not pairs or weight != 1.0 / len(families):
            raise ValueError('V4_LOSS_RECIPE:' + family)
        losses = []
        for pair in pairs:
            try:
                margin = float(scores[pair['negative_uid']]) - float(scores[pair['positive_uid']])
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError('V4_LOSS_SCORES') from exc
            if not math.isfinite(margin):
                raise ValueError('V4_LOSS_SCORES')
            losses.append(max(margin, 0.0) + math.log1p(math.exp(-abs(margin))))
        total += weight * (sum(losses) / len(losses))
    return total
