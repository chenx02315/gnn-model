"""Offline synthetic recipe -> report -> observation -> debit connection only."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

from src.data import prospective_request_features_v1 as features
from src.data import prospective_stage_observation_v1 as observations
from src.data import prospective_tessent_stage_v1 as stage
from src.data.prospective_stage_budget_v1 import DeclaredTaskBudget

ROOT = Path(__file__).resolve().parents[1]


def demo():
    helper = ROOT/'tests/test_prospective_tessent_stage_v1.py'
    if helper.is_symlink() or not helper.is_file() or helper.stat().st_size > 24576:
        raise ValueError('FIXED_SYNTHETIC_FIXTURE_ONLY')
    spec = importlib.util.spec_from_file_location('_e81_synthetic_fixture', helper)
    fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
    freeze = fixture.freeze()
    before = features.build_features(freeze)
    requests, recipes, texts, results = [], [], [], []
    pre_text = fixture.PRE.replace('25', '30')  # Fabricated inherited DS+DI=45.
    parent = None
    # These are pre-known fabricated report strings, not future real outcomes.
    for index, mode in enumerate(('H','M','F')):
        request = fixture.request(mode, control=(dict(kind='PATTERN_LIMIT',value=3)
            if mode == 'F' else None), parent=parent['attempt_uid'] if parent else None)
        if parent:
            request['parent_result_sha256'] = parent['result_sha256']
        recipe = stage.compile_stage(freeze, request)
        stats = fixture.STATS if mode != 'F' else fixture.STATS.replace('30','90').replace('15','5')
        log = fixture.markers(recipe)
        report_sha = observations.digest(dict(statistics=stats, stil=fixture.STIL,
            log=log, pre=pre_text if mode != 'H' else None))
        result = dict(run_uid=request['run_uid'],action_uid=request['action_uid'],
            attempt_uid=request['attempt_uid'],stage=mode,stage_index=1,
            request_sha256=observations.digest(request),process_identity=dict(host='synthetic-host',
                boot_id='11111111-2222-3333-4444-555555555555',pid=7+index,start_ticks=100+index),
            status='SUCCESS',returncode=0,generated_patterns=2,
            detected_common_faults=95 if mode=='F' else 45,cycles=99,
            elapsed_ns=5,result_sha256=report_sha,termination_verified=True)
        requests.append(request);recipes.append(recipe);results.append(result)
        texts.append((stats,fixture.STIL,log));parent=result
    plan=[]
    for recipe in recipes:
        uid=recipe['attempt_uid'];deps=[]
        if recipe['required_tasks']:
            deps=[uid+':translation']
            plan.append(dict(task_uid=deps[0],kind='STATUS_TRANSLATION',stage=recipe['stage'],
                request_sha256=recipe['request_sha256'],depends_on=[],timeout_ns=10,cleanup_ns=2))
        plan.append(dict(task_uid=uid+':tessent',kind='TESSENT_STAGE',stage=recipe['stage'],
            request_sha256=recipe['request_sha256'],depends_on=deps,timeout_ns=10,cleanup_ns=2))
    budget=DeclaredTaskBudget(plan,3,2,60)
    parsed=[];snapshots=[]
    for index,(recipe,text) in enumerate(zip(recipes,texts)):
        uid=recipe['attempt_uid']
        if recipe['required_tasks']:
            token=budget.reserve(uid+':translation')
            snapshots.append(budget.settle(token,'SUCCESS',4,True))
        token=budget.reserve(uid+':tessent')
        if recipe['stage']=='H':
            parsed.append(stage.parse_reports(*text,recipe))
        else:
            parsed.append(stage.parse_reports(*text,recipe,pre_text,
                parsed[-1]['detected_common_faults']))
        results[index].update(generated_patterns=parsed[-1]['generated_patterns'],
            detected_common_faults=parsed[-1]['detected_common_faults'],
            cycles=parsed[-1]['ate_cycles'])
        snapshots.append(budget.settle(token,'SUCCESS',5,True))
    joined=observations.join_stage_observations(freeze,'run-1',requests,results)
    if features.build_features(freeze)!=before:
        raise ValueError('OUTCOME_CHANGED_FEATURES')
    paths=('src/data/prospective_tessent_stage_v1.py','tests/test_prospective_tessent_stage_v1.py',
        'src/data/prospective_stage_budget_v1.py','tests/test_prospective_stage_budget_v1.py',
        'scripts/demo_prospective_tessent_stage_e81.py','contracts/prospective_tessent_stage_e81_v1.json')
    sources={}
    for name in paths:
        path=ROOT/name
        if path.is_symlink() or not path.is_file() or path.stat().st_size>65536:
            raise ValueError('FIXED_LOCAL_SOURCE_BOUND')
        raw=path.read_bytes();sources[name]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    return dict(schema='e81-offline-stage-connection-v1',status='PASS_SYNTHETIC_STAGE_CONNECTION_ONLY',
        sources=sources,requests=requests,recipes=recipes,parsed_reports=parsed,observations=joined,
        budget_plan=plan,budget_snapshots=snapshots,final_budget=budget.snapshot(),
        fixture_reports_and_future_parent_hashes_known_in_advance=True,
        translation_steps_are_only_synthetic_assertions=True,real_translation_implemented=False,
        online_adaptive_request_binding_implemented=False,physical_resource_guard_implemented=False,
        durable_budget_implemented=False,real_report_dialect_qualified=False,
        actual_processes_launched=0,new_remote_sessions=0,new_containers=0,new_training_runs=0,
        execution_ready=False,training_release=False)


def main():
    if len(sys.argv)!=2:
        raise ValueError('ONE_NEW_LOCAL_OUTPUT_DIRECTORY')
    folder=Path(sys.argv[1]).resolve()
    if folder.parent!=(ROOT.parent/'runtime_training_staging_20260928').resolve() or not folder.name.startswith('v6_e81_stage_'):
        raise ValueError('FIXED_LOCAL_OUTPUT_SCOPE')
    value=demo();folder.mkdir(exist_ok=False)
    with (folder/'summary.json').open('x',encoding='utf-8',newline='\n') as stream:
        json.dump(value,stream,sort_keys=True,indent=2);stream.write('\n')
    print(json.dumps(dict(status=value['status'],execution_ready=False,training_release=False)))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
