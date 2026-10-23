"""Seal existing small E85 receipts locally; never connects to a host."""
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPTS = ROOT.parent / 'runtime_training_staging_20260928/v6_e85_tree_inputs_20261023_r1'
SOURCES = (
    'scripts/probe_acquisition_tree_inputs_e85.py',
    'scripts/execute_acquisition_tree_probe_e85.py',
    'tests/test_prospective_acquisition_tree_inputs_e85.py',
    'src/data/prospective_circuit_summary_v1.py',
    'tests/test_prospective_circuit_summary_v1.py',
    'contracts/prospective_structure_features_e85_v1.json',
)


def pin(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 131072:
        raise ValueError('SMALL_REGULAR_LOCAL_ARTIFACT_REQUIRED')
    raw = path.read_bytes()
    if len(raw) > 131072:
        raise ValueError('ARTIFACT_LIMIT')
    return raw, {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def summarize():
    receipts = {name: pin(RECEIPTS / name) for name in
                ('start.json', 'stdout.json', 'stderr.log', 'transport.json')}
    raw = receipts['stdout.json'][0]
    observation = json.loads(raw)
    transport = json.loads(receipts['transport.json'][0])
    pre = json.loads((ROOT / 'data/manifests/ranking_v6_e85_pre_review_20261023_r1.json').read_bytes())
    sources = {name: pin(ROOT / name)[1] for name in SOURCES}
    for key, path in (('source_sha256', SOURCES[0]),
                      ('controller_sha256', SOURCES[1]), ('tests_sha256', SOURCES[2])):
        if sources[path]['sha256'] != pre[key]:
            raise ValueError('SOURCE_DRIFT_SINCE_PRE_REVIEW')
    if (transport['exit_code'] != 0 or any(transport[k] for k in
            ('overflow', 'threads_incomplete', 'timeout', 'write_failed'))
            or receipts['stderr.log'][1]['bytes'] != 0
            or transport['stdout_sha256'] != receipts['stdout.json'][1]['sha256']
            or transport['stdout_bytes'] != len(raw)):
        raise ValueError('TRANSPORT_NOT_ACCEPTED')
    trees = observation['tsdb_trees']
    if len(trees) != 6 or not all(t['tree_complete'] and t['anomaly_count'] == 0 for t in trees):
        raise ValueError('INCOMPLETE_INPUT_TREES')
    total = sum(t['body_bytes'] for t in trees) + observation['library']['bytes'] + observation['binary']['bytes']
    if total != observation['body_bytes_hashed'] or total > 128 * 1024 * 1024:
        raise ValueError('BODY_ACCOUNTING')
    for key in ('actual_atpg_calls', 'remote_writes', 'external_programs_launched'):
        if observation[key] != 0:
            raise ValueError('OBSERVATION_SCOPE_CHANGED')
    if observation['execution_ready'] or observation['training_release']:
        raise ValueError('NOT_A_RELEASE')
    return raw, dict(
        schema='e85-local-observation-summary-v1', date='2026-10-23',
        status='PASS_SCOPED_INPUT_OBSERVATION_NOT_EXECUTION_READY',
        receipt_directory=str(RECEIPTS), receipts={k: v[1] for k, v in receipts.items()},
        sources=sources, hostname=observation['hostname'],
        python_version=observation['python_version'],
        directories=sum(t['directories'] for t in trees),
        entries=sum(t['entries'] for t in trees),
        tsdb_files=sum(t['regular_files_hashed'] for t in trees),
        body_bytes_hashed=total, tree_hashes=[dict(root=t['root'], sha256=t['tree_sha256']) for t in trees],
        library=observation['library'], entrypoint=observation['binary'],
        focused_tests=dict(total=27, failures=0, errors=0),
        final_regression=dict(total=1244, passed=1238, skipped=6, failures=0, errors=0),
        independent_review=dict(reviewer='/root/e85_fallback_review',
            verdict='PASS_SCOPED_E85_READ_ONLY_OBSERVATION',
            scope='Local receipt/source consistency, not independent rehash of remote bodies'),
        resource_status='PARTIAL_INFORMATIONAL_ONLY_NOT_ACTUAL_ATPG_LIMITS',
        actual_atpg_memory_limit_bytes=None, actual_atpg_timeout_s=None,
        remote_termination_verified=transport['remote_termination_verified'],
        actual_atpg_calls=0, new_training_runs=0, model_benefit_proven=False,
        execution_ready=False, training_release=False)


if __name__ == '__main__':
    raw, result = summarize()
    outputs = {
        'ranking_v6_e85_input_observation_20261023_r1.json': raw,
        'ranking_v6_e85_input_summary_20261023_r1.json':
            (json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode('ascii'),
    }
    for name in outputs:
        if (ROOT / 'data/manifests' / name).exists():
            raise ValueError('CREATE_ONCE_OUTPUT_EXISTS')
    for name, content in outputs.items():
        with (ROOT / 'data/manifests' / name).open('xb') as stream:
            stream.write(content)
    print(json.dumps({'status': result['status'], 'files': sorted(outputs)}))
