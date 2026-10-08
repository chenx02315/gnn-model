"""Pure bounded caller-source/lock integrity, not an import fence or consent.

The caller obtains bytes and the manifest trust anchor independently. This
module does not read paths, import Torch, inspect an installed environment,
execute sources or launch a process. Namespace-package/path provenance and
fresh runtime preflight are separate mandatory checks before execution.
"""
import hashlib
import json
import re

FILES = frozenset((
    'src/models/runtime_ranking_v3.py', 'src/models/runtime_training_v2.py',
    'src/models/neural_ranking_v3.py', 'src/models/run_runtime_ranking_v3.py',
    'src/models/ranking_v3_freeze_io.py', 'src/data/ranking_v3_real_fold_package.py',
    'scripts/ranking_v4_near_optimal_pairs.py', 'src/models/ranking_v4_training_worker.py',
    'src/models/ranking_v4_memory_guard.py', 'src/models/preflight_runtime_v2.py',
    'src/models/ranking_v5_execution_boundary.py', 'src/models/ranking_v5_head_objective.py',
    'src/models/ranking_v5_training_kernel.py', 'src/models/ranking_v5_physical_worker.py',
    'src/models/ranking_v5_approval_binding.py', 'src/models/ranking_v5_bound_input_reader.py',
    'src/models/ranking_v5_package_binding.py', 'src/models/ranking_v5_real_request_loader.py',
    'src/models/ranking_v5_v3_fold_adapter.py', 'src/models/ranking_v5_held_replay_reader.py',
    'src/models/ranking_v5_real_artifact_store.py', 'src/models/ranking_v5_single_fit_worker.py',
    'src/models/ranking_v5_worker_resource_context.py',
    'src/models/ranking_v5_parent_guard_receipt.py',
    'src/models/ranking_v5_caller_source_binding.py', 'requirements/runtime_v2.lock.txt',
))
MAX_FILE_BYTES = 64 * 1024
MAX_TOTAL_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 20000
SCHEMA = 'v5-caller-source-bytes-v1'


def _sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('V5_CALLER_DUPLICATE_KEY')
        result[key] = value
    return result


def parse_lock_bytes(raw):
    """Parse exact pins only; does not claim the packages are installed."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_FILE_BYTES:
        raise ValueError('V5_CALLER_LOCK_BOUND')
    try:
        lines = raw.decode('utf-8').splitlines()
    except UnicodeError as error:
        raise ValueError('V5_CALLER_LOCK_ENCODING') from error
    pins = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(r'([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9.+_-]*)', line)
        if match is None:
            raise ValueError('V5_CALLER_UNPINNED_LOCK')
        name = re.sub(r'[-_.]+', '-', match[1]).lower()
        if name in pins:
            raise ValueError('V5_CALLER_DUPLICATE_LOCK')
        pins[name] = match[2]
    if not {'numpy', 'torch', 'scipy', 'scikit-learn', 'xgboost'} <= set(pins):
        raise ValueError('V5_CALLER_INCOMPLETE_LOCK')
    return pins


def validate_source_bytes(manifest_raw, source_bytes, *, trusted_manifest_sha256):
    """Exact 26-file supplied-byte integrity only, before any ML import.

    No trust anchor may be derived from the supplied manifest as authorization.
    Same-user mutations, source bootstrap and package search paths are not
    secured by this pure function. Future caller changes must revise the set.
    """
    if (type(manifest_raw) is not bytes or not 0 < len(manifest_raw) <= MAX_MANIFEST_BYTES
            or not _sha(trusted_manifest_sha256)
            or hashlib.sha256(manifest_raw).hexdigest() != trusted_manifest_sha256):
        raise ValueError('V5_CALLER_MANIFEST_PIN')
    try:
        manifest = json.loads(manifest_raw, object_pairs_hook=_unique,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError('V5_CALLER_NONFINITE')))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('V5_CALLER_MANIFEST_JSON') from error
    if (type(manifest) is not dict or set(manifest) != {'schema', 'formal_training_release', 'sources'}
            or manifest['schema'] != SCHEMA or manifest['formal_training_release'] is not False
            or type(manifest['sources']) is not dict or set(manifest['sources']) != FILES
            or any(not _sha(pin) for pin in manifest['sources'].values())):
        raise ValueError('V5_CALLER_MANIFEST_SCHEMA')
    if type(source_bytes) is not dict or set(source_bytes) != FILES:
        raise ValueError('V5_CALLER_SOURCE_SET')
    total = 0
    for name in sorted(FILES):
        raw = source_bytes[name]
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_FILE_BYTES:
            raise ValueError('V5_CALLER_SOURCE_BOUND:' + name)
        total += len(raw)
        if total > MAX_TOTAL_BYTES:
            raise ValueError('V5_CALLER_TOTAL_BOUND')
        if hashlib.sha256(raw).hexdigest() != manifest['sources'][name]:
            raise ValueError('V5_CALLER_SOURCE_DRIFT:' + name)
    versions = parse_lock_bytes(source_bytes['requirements/runtime_v2.lock.txt'])
    return dict(status='PASS_CALLER_SUPPLIED_BYTES_INTEGRITY_ONLY',
                manifest_sha256=trusted_manifest_sha256, source_count=len(FILES),
                total_source_bytes=total, sources=dict(manifest['sources']), locked_versions=versions,
                installed_dependencies_verified=False, runtime_import_origins_verified=False,
                parent_sampled_rss_enforcement_proven=False, authentic_user_consent_proven=False,
                formal_training_release=False)
