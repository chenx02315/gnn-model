"""Run only the fixed pre-registered uniform synthetic precision fixture."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.models.ranking_v6_large_precision_reference import run_uniform_precision

CONTRACT_SHA = '32439239728d70112078a9af26a5dbf3a46b70bab4679347fa7a4fd6ff63478c'


def run():
    raw = (ROOT / 'contracts/ranking_v6_large_precision_gate_v1.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != CONTRACT_SHA:
        raise ValueError('CONTRACT_PIN')
    contract = json.loads(raw)
    result = run_uniform_precision(n=contract['n'], k=contract['k'], seeds=tuple(contract['seeds']),
                                  pilot_samples=contract['pilot_samples'], main_samples=contract['main_samples'],
                                  alpha=contract['alpha'], max_radius=contract['max_radius'])
    result['contract_sha256'] = hashlib.sha256(raw).hexdigest()
    result['real_label_reads'] = result['remote_calls'] = result['training_runs'] = 0
    return result


def exit_code_for(result):
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    result = run()
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(exit_code_for(result))
