"""Read-only bounded r4 progress snapshot."""
import json
from pathlib import Path

ROOT = Path('/ssd/cjc/gnn_model_ranking_v4_train_af05de0_20261005_r4')
MAX_RECEIPT_BYTES = 10 * 1024


def _reject_symlink(path):
    if any(item.is_symlink() for item in (Path(path), *Path(path).parents)):
        raise ValueError('R4_MONITOR_SYMLINK')


def _read_small(path):
    path = Path(path); _reject_symlink(path)
    if not path.is_file() or path.stat().st_size > MAX_RECEIPT_BYTES:
        raise ValueError('R4_MONITOR_RECEIPT_BOUND')
    return json.loads(path.read_bytes())


def snapshot():
    _reject_symlink(ROOT)
    launch = _read_small(ROOT / 'launch_receipt.json')
    experiment = ROOT / 'experiment'
    _reject_symlink(experiment)
    if not experiment.is_dir():
        raise ValueError('R4_MONITOR_EXPERIMENT')
    evaluations = list(experiment.glob('*/evaluation.json'))
    memory_paths = list(experiment.glob('*.memory.json'))
    if len(evaluations) > 18 or len(memory_paths) > 18: raise ValueError('R4_MONITOR_ARTIFACT_BOUND')
    for path in evaluations:
        _reject_symlink(path)
    memory = [_read_small(path) for path in memory_paths]
    exit_path = ROOT / 'exit_receipt.json'
    return {'completed': len(evaluations), 'expected': 18, 'supervisor_pid': launch['pid'],
            'exit_receipt': _read_small(exit_path) if exit_path.exists() else None,
            'peak_completed_combined_rss_bytes': max((item['peak_combined_rss_bytes'] for item in memory), default=0),
            'resource_stops': [item.get('error') for item in memory if item['status'] != 'PASS_BOUNDED_WORKER']}


if __name__ == '__main__': print(json.dumps(snapshot(), sort_keys=True))
