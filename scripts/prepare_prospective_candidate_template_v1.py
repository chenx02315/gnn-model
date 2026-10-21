"""Create a bounded offline symbolic proposal; no real endpoints or ATPG."""
import hashlib
import json
from pathlib import Path
import sys
from src.data import prospective_candidate_template_v1 as domain

ROOT = Path(__file__).resolve().parents[1]
REFERENCE_SHA = '4394d366098c7c64614dced1cade709373b315fc3749a8f93404d5c496ecfb94'


def run(output):
    output = Path(output).resolve()
    staging = (ROOT.parent / 'runtime_training_staging_20260928').resolve()
    domain.require(output.parent == staging and output.name.startswith('v6_e68_templates_'), 'LOCAL_NEW_OUTPUT_ONLY')
    reference = ROOT.parent / 'phase4_closure_driver_v2_reference.py'
    domain.require(reference.is_file() and not reference.is_symlink()
        and reference.stat().st_size == 52317, 'EXACT_REFERENCE_REQUIRED')
    domain.require(hashlib.sha256(reference.read_bytes()).hexdigest() == REFERENCE_SHA, 'REFERENCE_SHA_MISMATCH')
    rows = domain.templates()
    orders = {c:{str(seed):domain.seeded_template_order(c, seed)
        for seed in (20260824,20260825,20260826)} for c in domain.CIRCUITS}
    sample = domain.expand('spi',1,{1:1})
    result = domain.summary()
    result.update(reference_source_sha256=REFERENCE_SHA,
        hypothetical_alias_example=dict(synthetic_counts_only=True,
            h_full=1,m_full_by_h={'1':1},template_count=462,integer_actions=len(sample)),
        random_order_sha256={c:{seed:domain.digest(order) for seed,order in value.items()}
            for c,value in orders.items()},
        frozen_model_order_available=False, real_candidate_count_applied_to_plan=False)
    payloads = {name:(json.dumps(value,sort_keys=True,indent=2)+'\n').encode('utf-8')
        for name,value in [('templates.json',rows),('proposed_random_orders.json',orders)]}
    domain.require(sum(len(raw) for raw in payloads.values()) <= 524288, 'OUTPUT_TOTAL_CAP')
    result['local_artifacts'] = {name:dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        for name,raw in payloads.items()}
    payloads['summary.json']=(json.dumps(result,sort_keys=True,indent=2)+'\n').encode('utf-8')
    domain.require(sum(len(raw) for raw in payloads.values()) <= 524288, 'OUTPUT_TOTAL_CAP')
    output.mkdir(exist_ok=False)
    for name,raw in payloads.items():
        with (output/name).open('xb') as stream:
            stream.write(raw)
    print(json.dumps(dict(status=result['status'],template_count=len(rows),
        integer_action_count=None,execution_ready=False)))
    return result


if __name__ == '__main__':
    domain.require(len(sys.argv)==2, 'ONE_OUTPUT_ARGUMENT_REQUIRED')
    run(sys.argv[1])
