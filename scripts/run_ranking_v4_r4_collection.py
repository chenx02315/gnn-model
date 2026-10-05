"""Invoke the exact audited bounded collector from the fixed immutable snapshot."""
import hashlib
from pathlib import Path
import runpy
import sys

CODE = Path('/ssd/cjc/gnn_model_ranking_v4_exit_boundary_ml_fe67d2d_20261005_r1/code')
COLLECTOR = Path('/ssd/cjc/collect_ranking_v4_r4_results.py')
SHA256 = '0c9cfc5fc0485209c8408974b81ea3ae64985999d9ecfb86ff7c1e16b1b77321'


def main():
    if Path.cwd().resolve() != CODE.resolve() or any(path.is_symlink() for path in (CODE, *CODE.parents, COLLECTOR)):
        raise ValueError('R4_COLLECTION_WRAPPER_PATH')
    with COLLECTOR.open('rb') as stream:
        raw = stream.read(20001)
    if len(raw) > 20000 or hashlib.sha256(raw).hexdigest() != SHA256:
        raise ValueError('R4_COLLECTION_WRAPPER_SHA')
    sys.path.insert(0, str(CODE.resolve()))
    runpy.run_path(str(COLLECTOR), run_name='__main__')


if __name__ == '__main__':
    main()
