"""Read-only bounded snapshot of the single r3 experiment."""
import json
from pathlib import Path

ROOT = Path('/ssd/cjc/gnn_model_ranking_v4_train_dec61b0_20261005_r3')


def main():
    if not ROOT.is_dir() or any(p.is_symlink() for p in (ROOT, *ROOT.parents)):
        raise ValueError('R3_MONITOR_ROOT')
    values = []
    for path in sorted((ROOT / 'experiment').glob('*.memory.json')):
        if len(values) >= 18 or path.is_symlink() or path.stat().st_size > 10000:
            raise ValueError('R3_MONITOR_BOUND')
        values.append(json.loads(path.read_bytes()))
    exit_path = ROOT / 'exit_receipt.json'
    evaluations = list((ROOT / 'experiment').glob('*/evaluation.json'))
    if len(evaluations) > 18:
        raise ValueError('R3_MONITOR_GRID')
    result = dict(expected=18, completed=len(evaluations),
                  exit_receipt=json.loads(exit_path.read_bytes()) if exit_path.exists() else None,
                  resource_stops=[v.get('error', v['status']) for v in values if v['status'] != 'PASS_BOUNDED_WORKER'],
                  peak_completed_combined_rss_bytes=max((v['peak_combined_rss_bytes'] for v in values), default=0))
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
