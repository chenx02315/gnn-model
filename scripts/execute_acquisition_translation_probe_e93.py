"""Build and execute one reviewed E93 read-only compatibility payload."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'scripts/probe_acquisition_translation_e93.py'
CORE = ROOT / 'src/data/prospective_fault_translation_v2.py'
E88 = ROOT / 'data/manifests/ranking_v6_e88_input_observation_20261023_r1.json'
E90 = ROOT / 'data/manifests/ranking_v6_e90_input_observation_20261023_r1.json'
E93_REVIEW = ROOT / 'data/manifests/ranking_v6_e93_review_20261023_r1.json'
TRANSPORT = ROOT / 'scripts/run_prospective_metadata_v1.py'
TRANSPORT_SHA = 'e0b1e62352781f96dc7d0e5a2a1a27e7f278b63c8aaaa07dbd946c1795c0f434'
CORE_SHA = '2488abc20cf6e55aabb5d80317615645ed9bbaf80eb97d75f05920befd8b1961'
E88_SHA = 'f46ed9fea9f5fecaea146ae75807db06fbd75887fc21a995a8da44ebe65b09c8'
E90_SHA = 'd4d2ca335e74d20b9837d29013cfbf366150dfba499e9d3fa5aa335fff7e0e8b'
PHASE = ROOT.parent / 'runtime_training_staging_20260928/v6_e93_translation_compat_20261023_r1'
PAYLOAD_MAX = 65536
RESPONSE_MAX = 16384


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('DUPLICATE_JSON_KEY')
            value[key] = item
        return value
    return json.loads(raw.decode('ascii'), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(
                          ValueError('NONFINITE_JSON')))


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2,
                       allow_nan=False) + '\n').encode('ascii')


def write_new(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def input_binding(e88_raw, e90_raw, review_raw, core_raw):
    if sha(e88_raw) != E88_SHA or sha(e90_raw) != E90_SHA:
        raise ValueError('INPUT_OBSERVATION_SOURCE_PIN')
    e88 = decode(e88_raw)
    e90 = decode(e90_raw)
    review = decode(review_raw)
    if (e88.get('schema') != 'e88-acquisition-semantics-probe-v1' or
            e88.get('status') != 'PASS_BOUNDED_NAMESPACE_SETS_AND_LAUNCHER_BODY_ONLY' or
            e88.get('files_read') != 11):
        raise ValueError('E88_OBSERVATION_NOT_QUALIFIED')
    if (e90.get('schema') != 'e90-resource-dialect-observation-v1' or
            e90.get('status') != 'PASS_BOUNDED_METADATA_NOT_RESOURCE_ADMISSION'):
        raise ValueError('E90_OBSERVATION_NOT_QUALIFIED')
    if (review.get('schema') != 'e93-path-policy-review-v1' or
            review.get('verdict') != 'PASS_SCOPED_PATH_POLICY_IMPLEMENTATION' or
            review.get('core_sha256') != CORE_SHA or sha(core_raw) != CORE_SHA):
        raise ValueError('CORE_REVIEW_OR_SOURCE_PIN')
    roots = {item.get('circuit'): item for item in e88.get('roots', [])
             if type(item) is dict}
    mtfi = {item.get('circuit'): item for item in e90.get('files', [])
            if type(item) is dict and item.get('role') == 'MTFI_H'}
    if set(roots) != {'aes_core', 'spi'} or set(mtfi) != {'aes_core', 'spi'}:
        raise ValueError('OBSERVATION_CIRCUIT_SET')
    circuits = {}
    for circuit in ('aes_core', 'spi'):
        files = roots[circuit].get('files', {})
        source = mtfi[circuit]
        if (roots[circuit].get('status') != 'COMMON_INPUT_SETS_EQUAL' or
                source.get('status') != 'BOUNDED_METADATA_OBSERVED'):
            raise ValueError('OBSERVATION_ITEM_STATUS')
        def pin(name):
            value = files.get(name, {}).get('sha256')
            if re.fullmatch('[0-9a-f]{64}', value or '') is None:
                raise ValueError('E88_FILE_PIN')
            return value
        source_pin = source.get('sha256')
        if re.fullmatch('[0-9a-f]{64}', source_pin or '') is None:
            raise ValueError('E90_MTFI_PIN')
        count = roots[circuit].get('expected_common_count')
        if type(count) is not int or isinstance(count, bool):
            raise ValueError('E88_COMMON_COUNT')
        circuits[circuit] = {
            'common_count': count, 'manifest': pin('manifest.json'),
            'mapping': pin('canonical_fault_mapping.tsv'),
            'M_basic': pin('M_common_initial_faults.basic'),
            'F_basic': pin('F_common_initial_faults.basic'),
            'source_mtfi': source_pin}
    return {'schema': 'e93-translation-input-binding-v1',
            'core_sha256': CORE_SHA,
            'observations': {'e88': E88_SHA, 'e90': E90_SHA},
            'circuits': circuits}


def build_payload(reader_raw, core_raw, binding):
    invocation = (b'\nraise SystemExit(main(' +
                  json.dumps(binding, sort_keys=True, separators=(',', ':'),
                             allow_nan=False).encode('ascii') + b',' +
                  repr(core_raw).encode('ascii') + b'))\n')
    payload = reader_raw + invocation
    if len(payload) > PAYLOAD_MAX:
        raise ValueError('PAYLOAD_BYTE_BOUND')
    return payload


def validate_response(raw, binding=None):
    value = decode(raw)
    if (set(value) != {'schema', 'validation_role', 'observation_sha256',
                       'files_read', 'body_bytes', 'input_files', 'results',
                       'actual_atpg_calls', 'training_runs', 'remote_writes',
                       'programs_launched', 'execution_ready',
                       'training_release'} or
            value.get('schema') != 'e93-real-input-translation-compatibility-v1' or
            value.get('validation_role') !=
            'READ_ONLY_COMPUTED_COMPATIBILITY_NOT_TESSENT_ACCEPTANCE_ATPG_OR_PILOT_COST'):
        raise ValueError('RESPONSE_SCHEMA_ROLE')
    observations = value.get('observation_sha256')
    if (type(observations) is not dict or set(observations) != {'e88', 'e90'} or
            any(re.fullmatch('[0-9a-f]{64}', pin or '') is None
                for pin in observations.values()) or
            (binding is not None and observations != binding['observations'])):
        raise ValueError('RESPONSE_OBSERVATION_PINS')
    if (value.get('files_read') != 10 or
            type(value.get('body_bytes')) is not int or
            not 0 < value['body_bytes'] <= 33554432 or
            any(value.get(name) != 0 for name in
                ('actual_atpg_calls', 'training_runs', 'remote_writes',
                 'programs_launched')) or
            value.get('execution_ready') is not False or
            value.get('training_release') is not False):
        raise ValueError('RESPONSE_BUDGET_OR_BOUNDARY')
    input_files = value.get('input_files')
    expected_files = {(circuit, role) for circuit in ('aes_core', 'spi')
                      for role in ('manifest', 'mapping', 'M_basic', 'F_basic',
                                   'source_mtfi')}
    if (type(input_files) is not list or len(input_files) != 10 or
            {(item.get('circuit'), item.get('role')) for item in input_files
             if type(item) is dict} != expected_files):
        raise ValueError('RESPONSE_INPUT_FILE_SET')
    for item in input_files:
        if (set(item) != {'circuit', 'role', 'sha256', 'bytes'} or
                re.fullmatch('[0-9a-f]{64}', item.get('sha256', '') or '') is None or
                type(item.get('bytes')) is not int or isinstance(item['bytes'], bool) or
                not 0 < item['bytes'] <= 8388608):
            raise ValueError('RESPONSE_INPUT_FILE_METADATA')
        if binding is not None and item['sha256'] != \
                binding['circuits'][item['circuit']][item['role']]:
            raise ValueError('RESPONSE_INPUT_FILE_PIN_BINDING')
    if sum(item['bytes'] for item in input_files) != value['body_bytes']:
        raise ValueError('RESPONSE_BODY_ACCOUNTING')
    rows = value.get('results')
    if type(rows) is not list or len(rows) != 4:
        raise ValueError('FOUR_RESULTS_REQUIRED')
    expected = {(circuit, 'H_TO_' + mode) for circuit in ('aes_core', 'spi')
                for mode in ('M', 'F')}
    if {(row.get('circuit'), row.get('transition')) for row in rows} != expected:
        raise ValueError('RESULT_SET')
    allowed = {'circuit', 'transition', 'status', 'output_mtfi_sha256',
               'manifest_sha256', 'byte_counts', 'input_sha256'}
    for row in rows:
        if set(row) != allowed or row.get('status') != 'PASS_COMPUTED_COMPATIBILITY_ONLY':
            raise ValueError('RESULT_STATUS_OR_FIELDS')
        if any(re.fullmatch('[0-9a-f]{64}', row.get(key, '') or '') is None
               for key in ('output_mtfi_sha256', 'manifest_sha256')):
            raise ValueError('RESULT_SHA')
        counts = row.get('byte_counts')
        pins = row.get('input_sha256')
        if (type(counts) is not dict or set(counts) !=
                {'mapping', 'source_mtfi', 'target_basic', 'output_mtfi',
                 'manifest'} or
                any(type(number) is not int or isinstance(number, bool) or
                    not 0 < number <= 8388608 for number in counts.values())):
            raise ValueError('RESULT_BYTE_COUNTS')
        if (type(pins) is not dict or set(pins) !=
                {'mapping', 'source_mtfi', 'target_basic'} or
                any(re.fullmatch('[0-9a-f]{64}', pin or '') is None
                    for pin in pins.values())):
            raise ValueError('RESULT_INPUT_PINS')
        if binding is not None:
            expected = binding['circuits'][row['circuit']]
            target = row['transition'][-1]
            if pins != {'mapping': expected['mapping'],
                        'source_mtfi': expected['source_mtfi'],
                        'target_basic': expected[target + '_basic']}:
                raise ValueError('RESULT_INPUT_PIN_BINDING')
    forbidden = ('fault_rows', 'class_frequency', 'class_counts',
                 'detected_entries', 'cycles', 'runtime')
    serialized = json.dumps(value, sort_keys=True).lower()
    if any(label in serialized for label in forbidden):
        raise ValueError('FORBIDDEN_RESPONSE_LABEL')
    return value


def main():
    if (len(sys.argv) != 3 or
            re.fullmatch('[a-f0-9]{64}', sys.argv[1]) is None or
            re.fullmatch('[a-f0-9]{64}', sys.argv[2]) is None):
        raise ValueError('READER_AND_CORE_REVIEWED_SHA_REQUIRED')
    reader_raw = SOURCE.read_bytes()
    core_raw = CORE.read_bytes()
    if len(reader_raw) > 32768 or sha(reader_raw) != sys.argv[1]:
        raise ValueError('READER_CHANGED')
    if sha(core_raw) != sys.argv[2] or sys.argv[2] != CORE_SHA:
        raise ValueError('CORE_CHANGED')
    transport_raw = TRANSPORT.read_bytes()
    if sha(transport_raw) != TRANSPORT_SHA:
        raise ValueError('TRANSPORT_CHANGED')
    binding = input_binding(E88.read_bytes(), E90.read_bytes(), E93_REVIEW.read_bytes(),
                            core_raw)
    payload = build_payload(reader_raw, core_raw, binding)
    spec = importlib.util.spec_from_file_location('e93_pinned_transport', TRANSPORT)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    fingerprint = helper.verify_cached_host('A')
    PHASE.mkdir(exist_ok=False)
    write_new(PHASE / 'start.json', encode({
        'schema': 'e93-translation-compat-start-v1',
        'reader_sha256': sys.argv[1], 'core_sha256': sys.argv[2],
        'transport_sha256': TRANSPORT_SHA, 'input_binding': binding,
        'endpoint': 'vnc.buptic.top', 'expected_hostname': 'bupt-vncs2',
        'host_fingerprint': fingerprint, 'sessions_max': 1,
        'automatic_retries': 0, 'fixed_files': 10,
        'per_file_bytes_max': 8388608, 'body_bytes_max': 33554432,
        'response_bytes_max': RESPONSE_MAX, 'payload_bytes': len(payload),
        'payload_bytes_max': PAYLOAD_MAX,
        'helper_address_space_bytes': 268435456, 'helper_cpu_seconds': 20,
        'transport_seconds': 60, 'directory_scans': 0,
        'program_launches': 0, 'remote_writes': 0, 'actual_atpg_calls': 0,
        'training_runs': 0,
        'validation_role':
            'READ_ONLY_COMPUTED_COMPATIBILITY_NOT_TESSENT_ACCEPTANCE_ATPG_OR_PILOT_COST'}))
    result = helper.transport(helper.command('A'), payload, RESPONSE_MAX)
    write_new(PHASE / 'stdout.json', result['stdout'])
    write_new(PHASE / 'stderr.log', result['stderr'])
    receipt = {key: value for key, value in result.items()
               if key not in ('stdout', 'stderr')}
    receipt.update(stdout_bytes=len(result['stdout']),
                   stderr_bytes=len(result['stderr']),
                   stdout_sha256=sha(result['stdout']),
                   stderr_sha256=sha(result['stderr']))
    write_new(PHASE / 'transport.json', encode(receipt))
    if (result['exit_code'] != 0 or result['stderr'] or
            any(result[key] for key in
                ('timeout', 'overflow', 'write_failed', 'threads_incomplete'))):
        raise ValueError('PROBE_FAILED_NO_AUTOMATIC_RETRY')
    value = validate_response(result['stdout'], binding)
    print(json.dumps({'validation_role': value['validation_role'],
                      'four_results_validated': True,
                      'execution_ready': False, 'training_release': False},
                     sort_keys=True))


if __name__ == '__main__':
    main()

