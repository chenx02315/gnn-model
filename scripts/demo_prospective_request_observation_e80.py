"""Local synthetic connection only; no checkpoint, real results or processes."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

from src.data import prospective_request_features_v1 as features
from src.data import prospective_stage_observation_v1 as observations

ROOT = Path(__file__).resolve().parents[1]


def demonstrate():
    helper = ROOT / 'tests/test_prospective_stage_observation_v1.py'
    if helper.is_symlink() or not helper.is_file() or helper.stat().st_size > 24576:
        raise ValueError('FIXED_LOCAL_SYNTHETIC_HELPER')
    spec = importlib.util.spec_from_file_location('_e80_synthetic_helper', helper)
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    freeze, requests, results = fixture.hf_fixture()
    before = features.build_features(freeze)
    first = observations.join_stage_observations(freeze, 'run-1', requests, results)
    changed = copy.deepcopy(results)
    changed[-1].update(generated_patterns=40, detected_common_faults=94, cycles=10000)
    second = observations.join_stage_observations(freeze, 'run-1', requests, changed)
    if first['feature_bundle_sha256'] != second['feature_bundle_sha256']:
        raise ValueError('RESULT_CHANGED_FEATURES')
    rejected = []
    for schema in ('runtime-training-v2', 'REALIZED_COUNT_V1', 'unknown'):
        try:
            features.assess_checkpoint_schema(schema)
        except ValueError:
            rejected.append(schema)
        else:
            raise ValueError('LEGACY_SCHEMA_ACCEPTED')
    mismatch = copy.deepcopy(results)
    mismatch[-1]['request_sha256'] = '0' * 64
    try:
        observations.join_stage_observations(freeze, 'run-1', requests, mismatch)
    except ValueError as exc:
        join_rejection = str(exc)
    else:
        raise ValueError('INCORRECT_JOIN_ACCEPTED')
    sources = ('contracts/prospective_request_observation_e80_v1.json',
        'src/data/prospective_request_features_v1.py',
        'src/data/prospective_stage_observation_v1.py',
        'tests/test_prospective_request_features_v1.py',
        'tests/test_prospective_stage_observation_v1.py',
        'scripts/demo_prospective_request_observation_e80.py')
    pins = {}
    for name in sources:
        path = ROOT / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
            raise ValueError('FIXED_SMALL_LOCAL_SOURCE')
        raw = path.read_bytes()
        pins[name] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    return dict(schema='e80-synthetic-connection-v1',
        status='PASS_LOCAL_REQUEST_OBSERVATION_CONNECTION_ONLY', sources=pins,
        inputs_are_fabricated=True, graph_digest_is_synthetic=True,
        common_fault_count_is_synthetic=True, requests=requests, synthetic_results=results,
        freeze=freeze, before_features=before, subset_features=features.build_features(freeze, ['hf']),
        observations=first, changed_outcome_observations=second,
        feature_bundle_unchanged_by_outcomes=True,
        rejected_legacy_or_unknown_schema_ids=rejected,
        new_schema_metadata_assessment=features.assess_checkpoint_schema('REQUESTED_COUNT_V1'),
        mismatched_join_rejection=join_rejection,
        new_remote_sessions=0, new_containers=0, new_atpg_calls=0, new_training_runs=0,
        real_checkpoint_authenticated=False, legacy_compatibility_proved=False,
        execution_ready=False, training_release=False, inference_release=False)


def main():
    if len(sys.argv) != 2:
        raise ValueError('ONE_NEW_LOCAL_OUTPUT_DIRECTORY')
    folder = Path(sys.argv[1]).resolve()
    staging = (ROOT.parent / 'runtime_training_staging_20260928').resolve()
    if folder.parent != staging or not folder.name.startswith('v6_e80_connection_'):
        raise ValueError('FIXED_LOCAL_OUTPUT_SCOPE')
    value = demonstrate()
    folder.mkdir(exist_ok=False)
    with (folder / 'summary.json').open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps(dict(status=value['status'], execution_ready=False, training_release=False)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
