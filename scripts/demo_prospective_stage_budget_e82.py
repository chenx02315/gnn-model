"""Local E81 synthetic plan connected to E82 exclusive file budget journal."""
import hashlib
import json
from pathlib import Path
import sys

from scripts.demo_prospective_tessent_stage_e81 import demo as stage_demo
from src.data.prospective_stage_budget_journal_v2 import Journal, load

ROOT = Path(__file__).resolve().parents[1]


def demo(folder):
    previous = stage_demo()
    plan = previous['budget_plan']
    path = folder / 'budget.jsonl'
    snapshots = []
    with Journal.create(path, plan, max_tessent_calls=3,
                        max_translation_calls=2, phase_envelope_ns=60) as journal:
        for task in plan:
            token = journal.reserve(task['task_uid'])
            snapshots.append(journal.settle(token, 'SUCCESS',
                4 if task['kind'] == 'STATUS_TRANSLATION' else 5, True))
        live = journal.snapshot()
    replay = load(path)
    if not (live['declared_plan_complete'] and live['durable_debit_ack_verified']
            and live['consumed_counts'] == {'TESSENT_STAGE': 3, 'STATUS_TRANSLATION': 2}
            and live['asserted_elapsed_ns_sum'] == 23
            and replay['head_sha256'] == live['head_sha256']
            and replay['structural_replay_valid']
            and not replay['fsync_acknowledgments_verified']
            and replay['asserted_elapsed_ns_sum'] is None):
        raise AssertionError('LIVE_ACK_AND_REPLAY_BOUNDARIES')
    rejected = False
    try:
        Journal.create(path, plan, max_tessent_calls=3,
                       max_translation_calls=2, phase_envelope_ns=60)
    except FileExistsError:
        rejected = True
    if not rejected:
        raise AssertionError('EXISTING_PHASE_PATH_WAS_REUSED')
    names = ('src/data/prospective_stage_budget_journal_v2.py',
             'tests/test_prospective_stage_budget_journal_v2.py',
             'scripts/demo_prospective_stage_budget_e82.py',
             'contracts/prospective_stage_budget_e82_v2.json')
    sources = {}
    for name in names:
        raw = (ROOT / name).read_bytes()
        if len(raw) > 131072:
            raise ValueError('LOCAL_SOURCE_BOUND')
        sources[name] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    raw = path.read_bytes()
    return dict(schema='e82-local-budget-connection-v2',
        status='PASS_LOCAL_SYNTHETIC_FILE_CONNECTION_ONLY',
        sources=sources, budget_plan=plan, snapshots=snapshots,
        live=live, replay=replay, existing_phase_path_rejected=rejected,
        journal=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),
        fabricated_elapsed_ns=23, fabricated_elapsed_is_measured_runtime=False,
        namespace_anchor_enforced_outside_library=False,
        power_loss_durability_verified=False, linux_qualification=False,
        actual_processes_launched=0,new_remote_sessions=0,new_containers=0,
        execution_ready=False,training_release=False)


def main():
    if len(sys.argv) != 2:
        raise ValueError('ONE_NEW_LOCAL_OUTPUT_DIRECTORY')
    folder = Path(sys.argv[1]).resolve()
    if (folder.parent != (ROOT.parent/'runtime_training_staging_20260928').resolve()
            or not folder.name.startswith('v6_e82_budget_')):
        raise ValueError('FIXED_LOCAL_OUTPUT_SCOPE')
    folder.mkdir(exist_ok=False)
    value = demo(folder)
    with (folder/'summary.json').open('x',encoding='utf-8',newline='\n') as stream:
        json.dump(value,stream,sort_keys=True,indent=2)
        stream.write('\n')
    print(value['status'])


if __name__ == '__main__':
    main()
