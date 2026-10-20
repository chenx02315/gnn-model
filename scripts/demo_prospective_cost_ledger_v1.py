"""Deterministic toy events only. Does not run ATPG, a scheduler or a model."""
import hashlib
import json
from pathlib import Path
import sys
from src.data.prospective_attempt_ledger_v1 import Journal, load, COST_NODE
from src.data.prospective_capture_plan_v1 import assess_plan

PLAN_SHA = 'a' * 64
UTC = '2030-01-01T00:00:00Z'


def provenance():
    return dict(driver_sha256='b'*64, config_sha256='c'*64, plan_sha256=PLAN_SHA,
        input_sha256='d'*64, command_sha256='e'*64, environment_cohort='synthetic-env',
        clock_identity='synthetic-clock', output_root='/synthetic/not-a-real-output',
        job_identity='synthetic-not-submitted')


def planned(attempt_id, call_key, parents=None, retry_of=None):
    return dict(attempt_id=attempt_id, circuit='toy-circuit', action='candidate_A',
        call_key=call_key, parents=parents or [], retry_of=retry_of,
        provenance=provenance(), cost_node=COST_NODE)


def started(attempt_id, ns):
    return dict(attempt_id=attempt_id, clock_session='synthetic-clock',
        monotonic_ns=ns, utc=UTC, execution_identity=dict(host='toy-host', job_id=None, pid=None))


def ended(attempt_id, ns, state='SUCCESS'):
    success = state == 'SUCCESS'
    return dict(attempt_id=attempt_id, state=state, clock_session='synthetic-clock',
        monotonic_ns=ns, utc=UTC, termination_verified=True,
        d95=True if success else None, ate_cycles=123 if success else None,
        output_artifact_sha256='f'*64 if success else None)


def run(output):
    root = Path(__file__).resolve().parents[2] / 'runtime_training_staging_20260928'
    output = Path(output).resolve()
    if output.parent != root.resolve() or not output.name.startswith('v6_e65_synthetic_'):
        raise ValueError('SYNTHETIC_RECEIPT_PATH')
    output.mkdir(exist_ok=False)
    path = output / 'toy_events.jsonl'
    with Journal.create(str(path), PLAN_SHA) as journal:
        for attempt_id, key, parents, retry, start_ns, end_ns, state in (
            ('prefix', 'toy-prefix', [], None, 0, 10_000_000_000, 'SUCCESS'),
            ('failed', 'toy-finish', ['prefix'], None, 10_000_000_000, 12_000_000_000, 'FAILED'),
            ('retry', 'toy-finish', ['prefix'], 'failed', 12_000_000_000, 15_000_000_000, 'SUCCESS')):
            journal.append('PLAN', planned(attempt_id, key, parents, retry))
            journal.append('START', started(attempt_id, start_ns))
            journal.append('END', ended(attempt_id, end_ns, state))
        journal.append('CACHE', dict(action='candidate_B', attempt_id='prefix', circuit='toy-circuit',
            call_key='toy-prefix', provenance=provenance(), output_artifact_sha256='f'*64))
        journal.append('LINK', dict(action='candidate_B', attempt_id='retry'))
        live = journal.aggregate(['candidate_A', 'candidate_B'])
        unfinished = planned('unfinished', 'toy-unknown')
        unfinished['action'] = 'candidate_C'
        journal.append('PLAN', unfinished)
        incomplete = journal.aggregate(['candidate_C'])
    replay = load(str(path))
    replay_result = replay.aggregate(['candidate_A', 'candidate_B'])
    assert live == replay_result
    assert replay_result['attempt_ids'] == ['failed', 'prefix', 'retry']
    assert replay_result['physical_atpg_wall_ns_sum'] == 15_000_000_000
    assert not incomplete['complete'] and incomplete['incomplete_attempt_ids'] == ['unfinished']
    plan_path = Path(__file__).resolve().parents[1] / 'contracts/prospective_capture_plan_v1.template.json'
    assessment = assess_plan(json.loads(plan_path.read_text(encoding='utf-8')))
    result = dict(status='PASS_SYNTHETIC_DEMONSTRATION_ONLY',
        timing_values='FABRICATED_FIXTURE_VALUES_NOT_MEASURED_RUNTIME',
        explanation='10s shared prefix + 2s failed attempt + 3s retry = 15s physical union, not 30s action-incidence sum',
        complete_physical_interval_example=replay_result,
        incomplete_example=incomplete, plan_assessment=assessment,
        journal_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        real_attempts_executed=0, model_training=False, remote_access=False,
        execution_ready=False, formal_performance_claim=False)
    raw = json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2) + '\n'
    with (output / 'summary.json').open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(raw)
    print(json.dumps(dict(status=result['status'], journal_sha256=result['journal_sha256'],
        summary_sha256=hashlib.sha256(raw.encode('utf-8')).hexdigest(), execution_ready=False)))
    return 0


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('expected one new synthetic receipt directory')
    raise SystemExit(run(sys.argv[1]))
