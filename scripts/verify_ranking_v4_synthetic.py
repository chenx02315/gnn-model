"""Synthetic-only subprocess grid. No source data, remote access or real release."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

from src.models.runtime_ranking_v3 import FAMILIES, FEATURES, digest, plan_folds, replay_frozen
from src.models.ranking_v3_freeze_io import read_freeze
from src.models.run_runtime_ranking_v3 import SEEDS


def fixture():
    rows, labels = [], {}
    for circuit, family in sorted(FAMILIES.items()):
        for i in range(3):
            uid = 'synthetic:' + circuit + ':' + str(i)
            rows.append(dict(action_uid=uid, circuit=circuit, family=family, role='TRAIN',
                             **{f: float(i) for f in FEATURES}))
            labels[uid] = dict(total_cycles=100 + i * 10, policy_charged_runtime_s=2 + i,
                               execution_status='SUCCESS', is_d95_feasible=1)
    return rows, labels


def write_once(path, value):
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(raw).hexdigest()


def run(output):
    from src.models.preflight_runtime_v2 import parse_lock, validate_installed_dependencies
    installed = validate_installed_dependencies(parse_lock(Path('requirements/runtime_v2.lock.txt')))
    output = Path(output).absolute()
    if any(p.is_symlink() for p in (output, *output.parents)):
        raise ValueError('V4_SYNTHETIC_OUTPUT_SYMLINK')
    output.mkdir(exist_ok=False)
    rows, labels = fixture()
    source_sha = digest({'synthetic_rows': rows, 'synthetic_labels': labels})
    records = []
    repeats = {}
    for fold in plan_folds(rows):
        for seed in SEEDS:
            # One additional identical seed execution per family verifies determinism.
            for repeat in range(2 if seed == SEEDS[0] else 1):
                key = fold.family + '_' + str(seed) + '_' + str(repeat)
                request = dict(scope='RANKING_V4_SYNTHETIC_ONLY', source_sha256=source_sha,
                               family=fold.family, seed=seed, model='candidate_mlp', rows=rows,
                               fit_cycles={u: labels[u]['total_cycles'] for u in fold.fitting})
                request_path = output / (key + '.request.json')
                sha = write_once(request_path, request)
                target = output / key
                argv = [sys.executable, '-m', 'src.models.ranking_v4_training_worker',
                        '--request', str(request_path), '--request-sha256', sha, '--output', str(target)]
                process = subprocess.run(argv, capture_output=True, text=True, timeout=180)
                write_once(output / (key + '.process.json'),
                           dict(argv=argv, exit_code=process.returncode, stdout=process.stdout, stderr=process.stderr))
                if process.returncode != 0:
                    raise RuntimeError('V4_SYNTHETIC_SUBPROCESS_FAILED:' + key)
                receipt = json.loads((target / 'worker_receipt.json').read_text())
                if receipt['request_sha256'] != sha or receipt['held_labels_supplied'] is not False:
                    raise ValueError('V4_SYNTHETIC_REQUEST_BINDING')
                freeze = read_freeze(target / 'freeze.json', receipt['freeze_sha256'])
                # Held labels are selected only AFTER persisted freeze digest readback.
                result = replay_frozen(freeze, receipt['freeze_sha256'], fold,
                                       {u: labels[u] for u in fold.heldout})
                model_sha = hashlib.sha256((target / 'model.pt').read_bytes()).hexdigest()
                identity = (fold.family, seed)
                if identity in repeats:
                    if repeats[identity] != (freeze, model_sha):
                        raise ValueError('V4_SYNTHETIC_DETERMINISM')
                else:
                    repeats[identity] = (freeze, model_sha)
                records.append(dict(family=fold.family, seed=seed, repeat=repeat,
                                    request_sha256=sha, freeze_sha256=receipt['freeze_sha256'],
                                    model_sha256=model_sha, evaluation=result))
    value = dict(status='PASS_SYNTHETIC_SUBPROCESS_GRID', scope='SYNTHETIC_ONLY_NOT_REAL_TRAINING',
                 independent_review_pending=True, unique_family_seed_count=len(repeats),
                 subprocess_count=len(records), determinism_repeats=6, records=records,
                 python=sys.version, platform=platform.platform(), kernel=platform.release(),
                 installed_versions=installed, real_training_release=False)
    if len(repeats) != 18 or len(records) != 24:
        raise ValueError('V4_SYNTHETIC_GRID')
    sha = write_once(output / 'synthetic_receipt.json', value)
    return dict(status=value['status'], receipt_sha256=sha, subprocess_count=24)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.output), sort_keys=True))


if __name__ == '__main__':
    main()
