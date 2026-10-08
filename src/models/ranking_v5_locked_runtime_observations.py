"""Read-only fixed runtime metadata observations; no ML imports or release.

The caller must independently authenticate supplied lock bytes first. Matching
versions and paths is not dependency-content sealing, an import fence, a check
of transitive imports/compiled extensions, resource proof, or training consent.
No source, package data, or output file is read/written by this module.
"""
import hashlib
from importlib import metadata, util
import os
from pathlib import PurePosixPath
import re
import sys


INTERPRETER = '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/venv/bin/python'
SITE_ROOT = '/ssd/cjc/gnn_model_runtime_v2_98efbd4f_20261002T235119/venv/lib/python3.11/site-packages'
CWD = '/ssd/cjc'
PYTHON_VERSION = (3, 11, 2)
SEARCH_PATHS = (
    '/usr/lib/python311.zip', '/usr/lib/python3.11', '/usr/lib/python3.11/lib-dynload',
    '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/venv/lib/python3.11/site-packages',
    SITE_ROOT,
)
MAX_LOCK_BYTES = 64 * 1024
MAX_LOCK_LINES = 128
MAX_PATH_CHARS = 2048
HEAVY_ROOTS = frozenset(('torch', 'numpy', 'scipy', 'sklearn', 'xgboost'))
LOCK_PINS = (
    ('jinja2', '3.1.6'), ('markupsafe', '3.0.3'), ('cloudpickle', '3.1.2'),
    ('filelock', '4.0.9'), ('fsspec', '2026.9.0'), ('joblib', '1.6.0'),
    ('mpmath', '1.3.0'), ('networkx', '3.6.1'), ('numpy', '2.1.3'),
    ('nvidia-cublas-cu12', '12.4.5.8'), ('nvidia-cuda-cupti-cu12', '12.4.127'),
    ('nvidia-cuda-nvrtc-cu12', '12.4.127'), ('nvidia-cuda-runtime-cu12', '12.4.127'),
    ('nvidia-cudnn-cu12', '9.1.0.70'), ('nvidia-cufft-cu12', '11.2.1.3'),
    ('nvidia-curand-cu12', '10.3.5.147'), ('nvidia-cusolver-cu12', '11.6.1.9'),
    ('nvidia-cusparse-cu12', '12.3.1.170'), ('nvidia-nccl-cu12', '2.21.5'),
    ('nvidia-nvjitlink-cu12', '12.4.127'), ('nvidia-nvtx-cu12', '12.4.127'),
    ('pip', '26.2.1'), ('scikit-learn', '1.5.2'), ('scipy', '1.14.1'),
    ('setuptools', '66.1.1'), ('sympy', '1.13.1'), ('threadpoolctl', '3.7.0'),
    ('torch', '2.5.1'), ('triton', '3.1.0'), ('typing-extensions', '4.16.0'),
    ('xgboost', '2.1.2'),
)
_FIELDS = frozenset(('platform', 'interpreter', 'python_version', 'cwd', 'sys_path', 'versions',
                     'distribution_roots', 'top_level_origins', 'heavy_ml_preloaded'))
_TOP_LEVEL = ('torch', 'numpy')


def parse_lock_bytes(raw):
    """Exact 31-pin pure parser; supplied bytes alone are not a trust anchor."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_LOCK_BYTES:
        raise ValueError('V5_RUNTIME_LOCK_BOUND')
    try:
        lines = raw.decode('ascii').splitlines()
    except UnicodeError as error:
        raise ValueError('V5_RUNTIME_LOCK_ENCODING') from error
    if len(lines) > MAX_LOCK_LINES:
        raise ValueError('V5_RUNTIME_LOCK_LINES')
    pins = {}
    for line in lines:
        if len(line) > 1024:
            raise ValueError('V5_RUNTIME_LOCK_LINE_BOUND')
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(r'([A-Za-z0-9][A-Za-z0-9_.-]{0,100})==([A-Za-z0-9][A-Za-z0-9.+_-]{0,100})', line)
        if match is None:
            raise ValueError('V5_RUNTIME_LOCK_PIN_SYNTAX')
        name = re.sub(r'[-_.]+', '-', match[1]).lower()
        if name in pins:
            raise ValueError('V5_RUNTIME_LOCK_DUPLICATE')
        pins[name] = match[2]
    if pins != dict(LOCK_PINS):
        raise ValueError('V5_RUNTIME_LOCK_EXACT_PINS')
    return pins


def _runtime(platform, interpreter, python_version, cwd):
    if type(platform) is not str or platform != 'linux':
        raise ValueError('V5_RUNTIME_PLATFORM')
    if type(interpreter) is not str or interpreter != INTERPRETER:
        raise ValueError('V5_RUNTIME_INTERPRETER')
    if (type(python_version) is not tuple or len(python_version) != 3
            or any(type(value) is not int for value in python_version)
            or python_version != PYTHON_VERSION):
        raise ValueError('V5_RUNTIME_PYTHON')
    if type(cwd) is not str or cwd != CWD:
        raise ValueError('V5_RUNTIME_CWD')


def _normal_path(value):
    if (type(value) is not str or not 0 < len(value) <= MAX_PATH_CHARS
            or '\\' in value or any(ord(char) < 32 for char in value)
            or value != value.strip()):
        return False
    path = PurePosixPath(value)
    return (path.is_absolute() and path.as_posix() == value
            and '..' not in path.parts
            and not value.startswith('/ssd/cjc/multimode_ate_gnn_v1'))


def _search_paths(paths):
    # Lexical only: never stat/resolve unexpected or protected candidates.
    if (type(paths) is not list or len(paths) != len(SEARCH_PATHS)
            or any(not _normal_path(path) for path in paths)
            or tuple(paths) != SEARCH_PATHS):
        raise ValueError('V5_RUNTIME_SEARCH_PATHS')


def validate_observations(lock_raw, observations):
    """Validate fabricated or fresh metadata equally; establish no provenance."""
    pins = parse_lock_bytes(lock_raw)
    if type(observations) is not dict or set(observations) != _FIELDS:
        raise ValueError('V5_RUNTIME_OBSERVATION_FIELDS')
    _runtime(observations['platform'], observations['interpreter'],
             observations['python_version'], observations['cwd'])
    _search_paths(observations['sys_path'])
    if observations['heavy_ml_preloaded'] is not False:
        raise ValueError('V5_RUNTIME_PRELOADED_HEAVY')
    versions, roots, origins = (observations['versions'], observations['distribution_roots'],
                                observations['top_level_origins'])
    if type(versions) is not dict or set(versions) != set(pins):
        raise ValueError('V5_RUNTIME_DISTRIBUTION_SET')
    if any(type(versions[name]) is not str or versions[name] != pin for name, pin in pins.items()):
        raise ValueError('V5_RUNTIME_VERSION_DRIFT')
    if type(roots) is not dict or set(roots) != set(pins):
        raise ValueError('V5_RUNTIME_ROOT_SET')
    if any(not _normal_path(path) or path != SITE_ROOT for path in roots.values()):
        raise ValueError('V5_RUNTIME_DISTRIBUTION_ROOT')
    if type(origins) is not dict or set(origins) != set(_TOP_LEVEL):
        raise ValueError('V5_RUNTIME_ORIGIN_SET')
    if any(not _normal_path(origins[name])
           or origins[name] != SITE_ROOT + '/' + name + '/__init__.py' for name in _TOP_LEVEL):
        raise ValueError('V5_RUNTIME_TOP_LEVEL_ORIGIN')
    return dict(status='PASS_FIXED_RUNTIME_METADATA_ONLY',
                dependency_lock_sha256=hashlib.sha256(lock_raw).hexdigest(),
                distribution_count=len(pins), versions=dict(versions),
                distribution_roots=dict(roots), top_level_origins=dict(origins),
                platform='linux', interpreter=INTERPRETER,
                python_version=list(PYTHON_VERSION), cwd=CWD, sys_path=list(SEARCH_PATHS),
                observation_provenance_proven=False, dependency_contents_sealed=False,
                transitive_import_origins_verified=False, compiled_extensions_verified=False,
                ml_imported=False, actual_fits=0, actual_linux_resource_proof=False,
                actual_ml_permitted=False, formal_training_release=False,
                authentic_user_consent_proven=False)


def _preloaded_heavy():
    return any(type(name) is str and name.partition('.')[0] in HEAVY_ROOTS
               for name in tuple(sys.modules))


def observe_runtime(lock_raw):
    """Query exactly 31 distributions and two top-level specs, without ML import.

    Fixed runtime/cwd and preloaded-heavy checks precede every metadata/spec
    query. This records metadata locations, not symlink resolution, file-byte
    integrity, namespace search paths, or eventual dynamic import behavior.
    """
    _runtime(sys.platform, sys.executable, tuple(sys.version_info[:3]), os.getcwd())
    _search_paths(sys.path)
    if _preloaded_heavy():
        raise ValueError('V5_RUNTIME_PRELOADED_HEAVY')
    pins = parse_lock_bytes(lock_raw)
    versions, roots, origins = {}, {}, {}
    for name in sorted(pins):
        try:
            distribution = metadata.distribution(name)
        except metadata.PackageNotFoundError as error:
            raise ValueError('V5_RUNTIME_DISTRIBUTION_MISSING:' + name) from error
        versions[name] = distribution.version
        roots[name] = str(distribution.locate_file(''))
    for name in _TOP_LEVEL:
        spec = util.find_spec(name)
        if spec is None:
            raise ValueError('V5_RUNTIME_SPEC_MISSING:' + name)
        origins[name] = spec.origin
    if _preloaded_heavy():
        raise ValueError('V5_RUNTIME_QUERY_IMPORTED_HEAVY')
    return validate_observations(lock_raw, dict(platform=sys.platform,
        interpreter=sys.executable, python_version=tuple(sys.version_info[:3]), cwd=os.getcwd(),
        sys_path=list(sys.path),
        versions=versions, distribution_roots=roots, top_level_origins=origins,
        heavy_ml_preloaded=False))
