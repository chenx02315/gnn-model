"""Offline E71 handoff from two pinned E70 metadata projections; no remote IO."""
import hashlib
import json
from pathlib import Path

from src.data.prospective_input_binding_v1 import IDENTITIES, bind_requests
from src.data.prospective_process_observation_v1 import summarize_observations

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    'data/manifests/ranking_v6_e70_A_metadata_20261021_r1.json':
        '3cab19a331f97742c676c13503ccaae6b613f521ffd3bead520e288eef8089cc',
    'data/manifests/ranking_v6_e70_A_FLOW_metadata_20261021_r1.json':
        'c96cb1c28e55ceb145605e1c7bfa6bf10dbb64762e60201c79f1f2bbd474c902',
}
A_ROOT = '/temp/jiangchuanc/multimode_ate_phase4_20260825_A'


def prepare(root=ROOT):
    files, sources = {}, {}
    for relative, expected in SOURCES.items():
        path = Path(root) / relative
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 8192:
            raise ValueError('FIXED_SMALL_PROJECTION_REQUIRED')
        raw = path.read_bytes()
        actual = hashlib.sha256(raw).hexdigest()
        if len(raw) > 8192 or actual != expected:
            raise ValueError('E70_PROJECTION_PIN_MISMATCH')
        document = json.loads(raw)
        for row in document['files']:
            if row['status'] == 'READ':
                if row['path'] in files:
                    raise ValueError('DUPLICATE_SOURCE_PATH')
                files[row['path']] = row
        sources[relative] = dict(bytes=len(raw), sha256=actual)
    examples = {}
    for circuit in ('aes_core', 'spi'):
        pins = {name: None for name in IDENTITIES}
        paths = dict(driver=A_ROOT+'/00_framework/phase4_closure_driver_v2.py',
            common_tcl=A_ROOT+'/00_framework/mapped_flow_v2/stage_mapped_common_atpg_no_tsdb_v2.tcl',
            incremental_tcl=A_ROOT+'/00_framework/mapped_flow_v2/stage_mapped_incremental_atpg_no_tsdb_v3.tcl',
            config=A_ROOT+'/10_circuits/'+circuit+'/01_config/config.env')
        for name, path in paths.items():
            pins[name] = files[path]['sha256']
        config = files[paths['config']]['metadata']
        if any(config[key] != value for key, value in
               (('CIRCUIT', circuit), ('H_CHAIN_COUNT', '64'), ('M_CHAIN_COUNT', '16'), ('F_CHAIN_COUNT', '4'))):
            raise ValueError('FIXED_MODE_CONFIG_MISMATCH')
        # Fixed tiny fabricated coordinates exercise wiring, not a measured roster.
        rows = [dict(action_uid=circuit+':toy:HF', scheme='HF', h_request=1, m_request=None),
                dict(action_uid=circuit+':toy:HMF', scheme='HMF', h_request=1, m_request=1)]
        examples[circuit] = bind_requests(circuit, rows, pins)
    events = []
    for index, circuit in enumerate(('aes_core', 'spi'), 1):
        for offset, role in enumerate(('endpoint', 'probe')):
            number = 2 * index + offset
            aid = 'synthetic-%d' % number
            identity = dict(host='synthetic-host', boot_id='synthetic-boot',
                            pid=number, start_ticks=number * 100)
            events.extend([
                dict(event='PLANNED', attempt_id=aid, circuit=circuit, cost_role=role,
                     command_sha256=hashlib.sha256(('toy-command-%d' % number).encode('ascii')).hexdigest(),
                     input_binding_sha256=examples[circuit]['binding_sha256']),
                dict(event='LAUNCHED', attempt_id=aid, monotonic_ns=number * 1000, **identity),
                dict(event='REAPED', attempt_id=aid, monotonic_ns=number * 1000 + 10,
                     status='failed' if offset else 'success', returncode=7 if offset else 0,
                     termination_verified=True, **identity)])
    observations = summarize_observations(events)
    return dict(schema='prospective-input-binding-preparation-v1',
        status='PASS_LOCAL_WIRING_ONLY_SYNTHETIC_COORDINATES', sources=sources,
        synthetic_examples=examples, synthetic_observation_events=events,
        synthetic_observation_summary=observations,
        timestamps_are_fabricated_not_measurements=True, real_roster_frozen=False,
        fault_manifest_digest_is_not_fault_body_digest=True,
        actual_atpg_jobs=0, remote_sessions=0, execution_ready=False, training_release=False)


if __name__ == '__main__':
    print(json.dumps(prepare(), sort_keys=True, indent=2, allow_nan=False))
