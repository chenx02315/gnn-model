"""Read-only bounded progress snapshot of the one v4 experiment."""
import json
from pathlib import Path
ROOT = Path('/ssd/cjc/gnn_model_ranking_v4_train_687c96d_20261005_r2')


def snapshot():
    launch = json.loads((ROOT / 'launch_receipt.json').read_text())
    evaluations = list((ROOT / 'experiment').glob('*/evaluation.json'))
    memory_paths = list((ROOT / 'experiment').glob('*.memory.json'))
    if len(evaluations) > 18 or len(memory_paths) > 18:
        raise ValueError('MONITOR_ARTIFACT_BOUND')
    memory = [json.loads(p.read_text()) for p in memory_paths]
    exit_path = ROOT / 'exit_receipt.json'
    return dict(completed=len(evaluations), expected=18, supervisor_pid=launch['pid'],
                exit_receipt=json.loads(exit_path.read_text()) if exit_path.exists() else None,
                peak_completed_combined_rss_bytes=max((m['peak_combined_rss_bytes'] for m in memory), default=0),
                resource_stops=[m.get('error') for m in memory if m['status'] != 'PASS_BOUNDED_WORKER'])


if __name__ == '__main__':
    print(json.dumps(snapshot(), sort_keys=True))
