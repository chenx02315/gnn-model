"""E83 local fake-only paired-journal fixtures; never launch a subprocess."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

from scripts.demo_prospective_tessent_stage_e81 import demo as recipe_demo
from src.data.prospective_task_lifecycle_bridge_v1 import Bridge, load

ROOT = Path(__file__).resolve().parents[1]


def fixture_module():
    path = ROOT/'tests/test_prospective_lifecycle_journal_v2.py'
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise ValueError('FIXED_LOCAL_SYNTHETIC_HELPER_ONLY')
    spec = importlib.util.spec_from_file_location('_e83_fake_fixture', path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def run_case(folder, case):
    fake = fixture_module()
    plan = recipe_demo()['budget_plan']
    profiles = {node['task_uid']: 'success' for node in plan}
    if case == 'known_failure':
        profiles[plan[0]['task_uid']] = 'failure'
    snapshots, callbacks = [], []
    with Bridge.create(folder, 'synthetic-phase-e83-'+case, plan,
            max_tessent_calls=3, max_translation_calls=2, phase_envelope_ns=60,
            profiles=profiles, clock_session='synthetic-clock') as bridge:
        for index, node in enumerate(plan):
            backend = fake.Backend(index+1)
            if case == 'unknown_spawn' and index == 0:
                backend.launch_error = RuntimeError('synthetic unknown spawn')
            elapsed = 4 if node['kind'] == 'STATUS_TRANSLATION' else 5
            try:
                snapshots.append(bridge.run(node['task_uid'], profiles[node['task_uid']],
                    backend, fake.Clock((100+index*20, 100+index*20+elapsed))))
            except (ValueError, RuntimeError, OSError):
                if case == 'success':
                    raise
                snapshots.append(bridge.snapshot())
            callbacks.append(list(backend.calls))
            if case != 'success':
                break
        live = bridge.snapshot()
        next_blocked = None
        if case != 'success':
            try:
                bridge.run(plan[1]['task_uid'], profiles[plan[1]['task_uid']],
                    fake.Backend(99), fake.Clock((200,204)))
            except (ValueError,RuntimeError,OSError):
                next_blocked = True
            if next_blocked is not True:
                raise AssertionError('FAILED_PHASE_ADVANCED')
    replay = load(folder)
    if replay['phase_complete_live_acknowledged'] or replay['observed_interval_ns_sum_or_None'] is not None:
        raise AssertionError('REPLAY_IS_NOT_HISTORICAL_ACK')
    if case == 'success':
        if not live['phase_complete_live_acknowledged'] or live['observed_interval_ns_sum_or_None'] != 23:
            raise AssertionError('CURRENT_ATTEMPT_NOT_CUMULATIVE_SETTLEMENT')
    elif live['observed_interval_ns_sum_or_None'] is not None:
        raise AssertionError('INCOMPLETE_PHASE_COST_MUST_BE_UNKNOWN')
    files = {}
    for name in ('binding.json','budget.jsonl','lifecycle.jsonl'):
        raw = (folder/name).read_bytes()
        if len(raw) > 1048576:
            raise ValueError('LOCAL_FIXTURE_BOUND')
        files[name] = dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    return dict(case=case,live=live,replay=replay,callbacks=callbacks,
        snapshots=snapshots,next_task_blocked=next_blocked,files=files)


def main():
    if len(sys.argv) != 2:
        raise ValueError('ONE_NEW_LOCAL_OUTPUT_DIRECTORY')
    folder = Path(sys.argv[1]).resolve()
    if (folder.parent != (ROOT.parent/'runtime_training_staging_20260928').resolve()
            or not folder.name.startswith('v6_e83_paired_')):
        raise ValueError('FIXED_LOCAL_OUTPUT_SCOPE')
    folder.mkdir(exist_ok=False)
    cases = [run_case(folder/case,case) for case in ('success','known_failure','unknown_spawn')]
    sources = {}
    for name in ('src/data/prospective_task_lifecycle_bridge_v1.py',
                 'tests/test_prospective_task_lifecycle_bridge_v1.py',
                 'scripts/demo_prospective_task_lifecycle_e83.py',
                 'contracts/prospective_task_lifecycle_e83_v1.json',
                 'src/data/prospective_stage_budget_journal_v2.py',
                 'src/data/prospective_stage_budget_v1.py',
                 'src/data/prospective_lifecycle_journal_v2.py',
                 'tests/test_prospective_lifecycle_journal_v2.py',
                 'scripts/demo_prospective_tessent_stage_e81.py',
                 'tests/test_prospective_tessent_stage_v1.py',
                 'src/data/prospective_tessent_stage_v1.py',
                 'src/data/prospective_request_features_v1.py',
                 'src/data/prospective_stage_observation_v1.py'):
        raw = (ROOT/name).read_bytes()
        if len(raw)>131072:
            raise ValueError('LOCAL_SOURCE_BOUND')
        sources[name] = dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    value = dict(schema='e83-local-paired-journal-connection-v1',
        status='PASS_LOCAL_SYNTHETIC_PAIRED_CONNECTION_ONLY',cases=cases,sources=sources,
        fabricated_elapsed_is_measured_atpg_runtime=False,
        actual_processes_launched=0,new_remote_sessions=0,new_containers=0,
        execution_ready=False,training_release=False)
    with (folder/'summary.json').open('x',encoding='utf-8',newline='\n') as stream:
        json.dump(value,stream,sort_keys=True,indent=2)
        stream.write('\n')
    print(value['status'])


if __name__=='__main__':
    main()
