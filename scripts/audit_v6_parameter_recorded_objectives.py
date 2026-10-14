"""Read-only independent PL objective audit, fixed E11 r2 evidence only.

No model/oracle imports, Torch, RNG, remote calls or experiment execution.
"""
import hashlib
import itertools
import json
import math
from pathlib import Path
import stat

RESULT = Path(__file__).resolve().parents[2] / 'runtime_training_staging_20260928/v6_parameter_container_20261014_r2/result.json'
PIN = '7d09d523eb3276d5510ede18a4514828d70219e8d2943679215bc28845568044'

def independent_values(scores, costs, k):
    pos = '5'
    neg = [u for u in sorted(scores) if u != pos]
    offset = max(scores.values())
    weights = {u: math.exp(s - offset) for u, s in scores.items()}
    def prefix_probability(prefix):
        remaining = list(neg)
        probability = 1.0
        for u in prefix:
            probability *= weights[u] / math.fsum([weights[pos]] + [weights[v] for v in remaining])
            remaining.remove(u)
        return probability, remaining
    risk = math.fsum(prefix_probability(order)[0] for order in itertools.permutations(neg, k))
    contributions = []
    for length in range(k):
        for prefix in itertools.permutations(neg, length):
            probability, remaining = prefix_probability(prefix)
            numerator = math.fsum([weights[pos] * costs[pos]] + [weights[u] * costs[u] for u in remaining])
            denominator = math.fsum([weights[pos]] + [weights[u] for u in remaining])
            contributions.append(probability * numerator / denominator)
    return risk, math.fsum(contributions) / (k * max(costs.values()))

def audit():
    if RESULT.is_symlink() or RESULT.resolve() != RESULT:
        raise ValueError('FIXED_ORDINARY_EVIDENCE_REQUIRED')
    before_stat = RESULT.stat()
    if not stat.S_ISREG(before_stat.st_mode) or before_stat.st_size > 262144:
        raise ValueError('EVIDENCE_BOUND')
    raw = RESULT.read_bytes()
    after_stat = RESULT.stat()
    if (before_stat.st_size,before_stat.st_mtime_ns) != (after_stat.st_size,after_stat.st_mtime_ns):
        raise ValueError('EVIDENCE_CHANGED')
    if hashlib.sha256(raw).hexdigest() != PIN:
        raise ValueError('EVIDENCE_SHA')
    child = json.loads(raw)['child']
    records = child['per_case_seed']
    expected = {(case,seed) for case in ('mixed','rare') for seed in (11,29,47,83)}
    if len(records)!=8 or {(s['pilot_freeze_payload']['case_id'],s['pilot_freeze_payload']['seed']) for s in records}!=expected:
        raise ValueError('FIXED_CASE_SEEDS')
    errors = []
    for summary in records:
        p = summary['pilot_freeze_payload']
        before = independent_values(p['scores'],p['costs'],3)
        after = independent_values(summary['proposed_scores'],p['costs'],3)
        observed = (summary['risk_before'],summary['normalized_cost_before'],
                    summary['proposed_risk_after'],summary['proposed_normalized_cost_after'])
        errors.extend(abs(x-y) for x,y in zip(before+after,observed))
        if after[0]-before[0]>1e-12 or after[1]-before[1]>-1e-8:
            raise ValueError('JOINT_DECREASE')
    maximum = max(errors)
    if maximum>1e-12:
        raise ValueError('OBJECTIVE_MISMATCH')
    return {'status':'PASS_RECORDED_OBJECTIVE_AUDIT_ONLY','case_seed_count':8,
            'before_after_checks':16,'max_absolute_error':maximum,
            'result_sha256':PIN,'torch_replay':False,'pilot_resampling':False,
            'train_release':False}

if __name__ == '__main__':
    print(json.dumps(audit(),sort_keys=True))
