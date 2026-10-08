"""Read-only fixed B runtime metadata probe, not a training/environment PASS."""
import importlib.metadata as metadata
import importlib.util
import json
import os
import platform
import sys

NAMES = ('Jinja2','MarkupSafe','cloudpickle','filelock','fsspec','joblib','mpmath',
         'networkx','numpy','nvidia-cublas-cu12','nvidia-cuda-cupti-cu12',
         'nvidia-cuda-nvrtc-cu12','nvidia-cuda-runtime-cu12','nvidia-cudnn-cu12',
         'nvidia-cufft-cu12','nvidia-curand-cu12','nvidia-cusolver-cu12',
         'nvidia-cusparse-cu12','nvidia-nccl-cu12','nvidia-nvjitlink-cu12',
         'nvidia-nvtx-cu12','pip','scikit-learn','scipy','setuptools','sympy',
         'threadpoolctl','torch','triton','typing_extensions','xgboost')
INTERPRETER = '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/venv/bin/python'


def probe():
    if sys.platform != 'linux' or sys.executable != INTERPRETER or os.getcwd() != '/ssd/cjc':
        raise ValueError('V5_METADATA_FIXED_RUNTIME_REQUIRED')
    if any('/ssd/cjc/multimode_ate_gnn_v1' in path for path in sys.path):
        raise ValueError('V5_METADATA_PROTECTED_SEARCH_PATH')
    if any(name == 'torch' or name.startswith('torch.') or name == 'numpy'
           or name.startswith('numpy.') for name in sys.modules):
        raise ValueError('V5_METADATA_ML_PRELOADED')
    versions, roots = {}, {}
    for name in NAMES:
        dist = metadata.distribution(name)
        versions[name], roots[name] = dist.version, str(dist.locate_file(''))
    origins = {name:importlib.util.find_spec(name).origin for name in ('torch','numpy')}
    return dict(status='READ_ONLY_RUNTIME_METADATA_ONLY',python=sys.version.split()[0],
                interpreter=sys.executable,platform=platform.platform(),cwd=os.getcwd(),
                versions=versions,distribution_roots=roots,top_level_origins=origins,
                ml_imported=False,actual_fits=0,formal_release=False,
                actual_linux_resource_proof=False,
                claim_boundary='Metadata and top-level origin lookup only; no ML import, fully isolated environment, RSS or training proof')


if __name__ == '__main__': print(json.dumps(probe(),sort_keys=True))
