"""Generate exact acquisition DAG and source-backed readiness from local metadata."""
import csv
import hashlib
import json
from pathlib import Path
import sys

from src.data.prospective_acquisition_pilot_v1 import build_plan, validate_plan


ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    'contracts/model_convergence_e84_v1.json',
    'contracts/data_split_v1.json',
    'data/manifests/ranking_v6_e70_observation_summary_20261021_r1.json',
    'data/manifests/ranking_v6_e79_convergence_20261022_r1.json',
    'src/data/prospective_acquisition_pilot_v1.py',
    'src/data/prospective_request_features_v1.py',
    'src/data/prospective_tessent_stage_v1.py',
    'scripts/probe_acquisition_inputs_e84.py',
    'scripts/execute_acquisition_input_probe_e84.py',
    'scripts/prepare_prospective_acquisition_e84.py',
)


def prepare():
    evidence, docs = {}, {}
    for name in SOURCES:
        path = ROOT / name
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 131072:
            raise ValueError('FIXED_SMALL_SOURCE')
        raw = path.read_bytes()
        if len(raw) > 131072:
            raise ValueError('SOURCE_CAP')
        evidence[name] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        if name.endswith('.json'):
            docs[name] = json.loads(raw)
    split = docs[SOURCES[1]]['formal_runtime_membership']
    train = sorted(row['circuit'] for row in split['TRAIN'])
    if train != ['aes_core', 's13207', 's15850', 's35932', 's38417', 'spi']:
        raise ValueError('TRAIN_MEMBERSHIP_CHANGED')
    observation = docs[SOURCES[2]]
    plan = build_plan()
    validate_plan(plan)
    root = '/temp/jiangchuanc/multimode_ate_phase4_20260825_A'
    inputs = {}
    for circuit in ('aes_core', 'spi'):
        base = root + '/10_circuits/' + circuit
        inputs[circuit] = dict(
            top_module=observation['current_config_metadata'][circuit]['TOP_MODULE'],
            declared_common_fault_count=observation[
                'common_fault_counts_declared_by_current_manifests'][circuit],
            count_body_authenticated=False,
            cell_library=observation['current_config_metadata'][circuit]['CELL_LIBRARY'],
            config=base + '/01_config/config.env',
            common_root=base + '/03_fault_universe/common_' + circuit + '_m16_phase4_v2',
            tsdb_by_mode={mode: base + '/99_tmp/' + mode + '_mapped_tsdb'
                          for mode in ('H', 'M', 'F')},
            input_source='Current E70 metadata plus inspected reference-driver path recipes',
            input_identity_currently_authenticated=False)
    return dict(schema='e84-acquisition-preparation-v1',
        status='EXACT_ACQUISITION_PLAN_PREPARED_REAL_INPUT_AND_RESOURCE_GAPS_REMAIN',
        evidence=evidence, plan=plan, input_references=inputs,
        historical_requests={circuit: 'EXACT_INVOCATION_REQUEST_JOIN_NOT_YET_VERIFIED'
                             for circuit in train},
        resolved_dependencies=['No old model/checkpoint needed to collect new data',
            'No graph needed to run ATPG; graph authentication required before structural ablation',
            'Literal roster needs no outcome-derived full-H/conditional-M endpoints',
            'Finite exact task upper bound: 48 Tessent and 30 translation calls',
            'Two separate 39-task phases fit the existing 64-task phase bound'],
        remaining_before_real_collection=['Executable/environment and immutable TSDB input identities',
            'Common-fault body/mapping semantics and translation implementation qualification',
            'Actual ATPG memory/timeout/license/thread/disk/output caps and enforcement',
            'Real runner integration and exact-parent live-output late binding',
            'Zero-pattern report dialect and combined H/M/F cycles qualification',
            'Whole bounded acquisition package review and execution release'],
        real_atpg_calls=0, new_training_runs=0, execution_ready=False,
        training_release=False)


def main():
    if len(sys.argv) != 2:
        raise ValueError('ONE_NEW_OUTPUT_DIRECTORY')
    target = Path(sys.argv[1]).resolve()
    staging = (ROOT.parent / 'runtime_training_staging_20260928').resolve()
    if target.parent != staging or not target.name.startswith('v6_e84_acquisition_'):
        raise ValueError('FIXED_STAGING_SCOPE')
    result = prepare()
    target.mkdir(exist_ok=False)
    with (target / 'preparation.json').open('x', encoding='ascii', newline='\n') as stream:
        json.dump(result, stream, sort_keys=True, indent=2, ensure_ascii=True)
        stream.write('\n')
    with (target / 'requested_actions.tsv').open('x', encoding='ascii', newline='') as stream:
        writer = csv.writer(stream, delimiter='\t', lineterminator='\n')
        writer.writerow(('circuit', 'action_uid', 'scheme', 'h_request', 'm_request',
                         'f_control_kind', 'f_control_value'))
        for phase in result['plan']['phases']:
            for row in phase['requested_roster']:
                writer.writerow((phase['circuit'], row['action_uid'], row['scheme'],
                    row['h_request'], '' if row['m_request'] is None else row['m_request'],
                    'COVERAGE_PERCENT', '95'))
    print(json.dumps(dict(status=result['status'], action_count=18,
        tessent_calls_upper=48, translation_calls_upper=30, execution_ready=False)))


if __name__ == '__main__':
    main()
