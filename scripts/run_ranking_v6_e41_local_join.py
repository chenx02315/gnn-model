"""One bounded three-input local metadata diagnostic; no dynamic paths."""
import csv
import io
import json
import os
import sys
from scripts import diagnose_ranking_v6_e34_local_groups as stable
from scripts import diagnose_ranking_v6_e41_declared_attempts as diagnostic

BASE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                    'runtime_training_staging_20260928')
SPECS = (
    ('E40', os.path.join(BASE, 'v6_e40_result_paths_20261017_r1', 'stdout.log'),
     '49bb5cb21036827dd5d3e3f69b5d0eda72c5e1321fa0c110a04774b1cfa38858'),
    ('s35932', os.path.join(BASE, 'runtime_attempt_remediation_v2_r1_remote', 'outputs_v2', 's35932_attempt_manifest_v2_remediated.tsv'),
     'af7236dc484e2a5e3a489787f98ec1ae5963ec34fe625585cd59820c48b4db36'),
    ('s38417', os.path.join(BASE, 'runtime_attempt_remediation_v2_r1_remote', 'outputs_v2', 's38417_attempt_manifest_v2_remediated.tsv'),
     '30aea1c23bc6751c3b17e1e2e32ae36fc3cbd7934f03df22fb78df1f7c962300'))


def main():
    try:
        if len(sys.argv) != 1: raise ValueError('NO_DYNAMIC_PATHS')
        total = 0
        selected = []
        payload = None
        for kind, path, digest in SPECS:
            raw = stable._stable_bytes(path, digest, min(8 * 1024 * 1024, 12 * 1024 * 1024 - total))
            total += len(raw)
            if len(raw) > 8 * 1024 * 1024: raise ValueError('FILE_BOUND')
            if kind == 'E40':
                if len(raw) != 5858: raise ValueError('PROJECTION_BYTES')
                payload = json.loads(raw.decode('ascii'))
                continue
            rows = csv.DictReader(io.StringIO(raw.decode('utf-8')), delimiter='\t')
            if tuple(rows.fieldnames or ()) != stable.reader.MANIFEST_FIELDS: raise ValueError('SCHEMA')
            for index, row in enumerate(rows, 1):
                if (index > 20000 or set(row) != set(stable.reader.MANIFEST_FIELDS)
                    or any(type(v) is not str or len(v) > 65536 for v in row.values())
                    or row['circuit'] != kind or row['role'] != 'TRAIN'
                    or row['family'] != stable.reader.FAMILIES[kind]):
                    raise ValueError('MANIFEST_SCOPE_OR_BOUND')
                selected.append({key: row[key] for key in diagnostic.FIELDS})
        if len(selected) != 6985: raise ValueError('FROZEN_ATTEMPT_ROWS')
        result = diagnostic.diagnose(payload, selected)
        result['fixed_local_input_audit'] = dict(file_count=3, total_bytes=total,
            sha256=[spec[2] for spec in SPECS], selected_metadata_rows=len(selected),
            input_bytes_decoded_as_csv_but_wall_status_not_analyzed=True,
            original_measurements_or_logs_opened=False, remote_calls=0,
            windows_hard_memory_cap_or_peak_claimed=False, workers=1, automatic_retries=0)
        encoded = json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False)
        if len(encoded.encode('ascii')) > 65536: raise ValueError('OUTPUT_BOUND')
        print(encoded)
        return 0
    except Exception:
        print('{"status":"FAIL_CLOSED_E41_LOCAL_METADATA_JOIN","code":"INPUT_OR_DIAGNOSTIC_REJECTED"}')
        return 2


if __name__ == '__main__': sys.exit(main())
