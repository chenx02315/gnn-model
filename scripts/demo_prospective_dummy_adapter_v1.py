"""Own fixed local Python dummy processes only; no ATPG or model invocation."""
import hashlib
import json
from pathlib import Path
import sys
from src.data.prospective_attempt_ledger_v1 import Journal, load
from src.data.prospective_dummy_adapter_v1 import run_dummy, SYNTHETIC_PLAN_SHA256


def require(ok, code):
    if not ok:
        raise ValueError(code)


def run(output):
    root = Path(__file__).resolve().parents[2] / 'runtime_training_staging_20260928'
    output = Path(output).resolve()
    if output.parent != root.resolve() or not output.name.startswith('v6_e66_dummy_demo_'):
        raise ValueError('DUMMY_RECEIPT_PATH')
    output.mkdir(exist_ok=False)
    path = output / 'dummy_events.jsonl'
    receipts = []
    with Journal.create(str(path), SYNTHETIC_PLAN_SHA256) as journal:
        for profile in ('success', 'failure', 'timeout'):
            receipt = run_dummy(journal, 'local-'+profile, profile,
                timeout_s=0.1 if profile == 'timeout' else 1.0)
            require(receipt['status'] == 'DUMMY_TERMINAL_RECORDED', 'TERMINAL_RECEIPT_REQUIRED')
            require(receipt['child_reaped'] and receipt['ledger_terminal_recorded'], 'REAP_AND_ACK_REQUIRED')
            receipts.append(receipt)
        live = journal.aggregate(['dummy-success', 'dummy-failure', 'dummy-timeout'])
    replay = load(str(path))
    require(replay.aggregate(['dummy-success', 'dummy-failure', 'dummy-timeout']) == live, 'REPLAY_MISMATCH')
    require(live['physical_atpg_wall_ns_sum'] == sum(r['recorded_interval_ns'] for r in receipts), 'INTERVAL_SUM_MISMATCH')
    states = {key: value['state'] for key, value in replay.snapshot()['attempts'].items()}
    require(states == {'local-success': 'SUCCESS', 'local-failure': 'FAILED', 'local-timeout': 'TIMEOUT'}, 'STATE_MISMATCH')
    require(receipts[0]['returncode'] == 0 and receipts[1]['returncode'] == 7, 'EXIT_CODE_MISMATCH')
    result = dict(status='PASS_LOCAL_DUMMY_PROCESS_INTEGRATION_ONLY', receipts=receipts,
        states=states, replay_matches_live=True, ledger_interval_sum=live,
        journal_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        timing_note='Measured local dummy record-to-reap interval includes journal/launch/wait/cleanup; not ATPG runtime',
        dummy_children=3, real_atpg_attempts=0, remote_access=False,
        real_runner_integration=False, execution_ready=False, training_release=False)
    with (output / 'summary.json').open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps(dict(status=result['status'], states=states,
        replay_matches_live=True, dummy_children=3, execution_ready=False)))
    return 0


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('expected a new local dummy receipt directory')
    raise SystemExit(run(sys.argv[1]))
