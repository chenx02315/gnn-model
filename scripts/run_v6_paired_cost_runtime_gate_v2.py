"""E21 single released paired synthetic diagnostic, strict one-run resource gate."""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import selectors
import stat
import subprocess
import sys
import time

HOST_ROOT = Path('/ssd/cjc/gnn_model_v6_paired_cost_runtime_20261015_r2')
IMAGE = 'sha256:66ec58a325c4165749971d95dbbe1636d8423cc7328be110c5df38ed42ca57e7'
SITE = '/ssd/cjc/gnn_model_runtime_v2_98efbd4f_20261002T235119/venv/lib/python3.11/site-packages'
NAME = 'gnn-v6-paired-cost-runtime-20261015-r2'
TORCH_RUNTIME_VERSION = '2.5.1+cu124'
NAMES = ["runner.py","_contract.json","contracts/ranking_v6_complete_cost_fit_protocol_v1.json","_protocol_tests.py","src/models/runtime_ranking_v3.py","src/models/ranking_v6_scorer_vjp_bridge.py","src/models/ranking_v6_first_hit_exact_gradient.py","src/models/ranking_v6_first_hit_reference.py","src/models/ranking_v6_complete_first_hit_reference.py","src/models/ranking_v6_synthetic_fit_no_prior.py","src/models/ranking_v6_conditional_control_reference.py","src/models/ranking_v6_conditional_survival_reference.py","src/models/ranking_v6_complete_cost_fit_protocol.py","src/models/ranking_v6_complete_cost_paired_fit.py","src/models/ranking_v6_complete_cost_paired_runtime_v2.py"]
NAMES = set(NAMES)


def require_authorized(contract):
    """Exact E21 one-run release; bool-as-int and widened limits are rejected."""
    fixed = {
    "status": "RELEASED_ONE_RUN_PAIRED_RUNTIME_DIAGNOSTIC_ONLY",
    "execution_authorized": True,
    "authorization": "E21 user-authorized single synthetic paired diagnostic; one run, six models, 144 optimizer steps, zero retries; no production training release.",
    "root": "/ssd/cjc/gnn_model_v6_paired_cost_runtime_20261015_r2",
    "image_id": "sha256:66ec58a325c4165749971d95dbbe1636d8423cc7328be110c5df38ed42ca57e7",
    "shared_site": "/ssd/cjc/gnn_model_runtime_v2_98efbd4f_20261002T235119/venv/lib/python3.11/site-packages",
    "python": "3.11.2",
    "torch": "2.5.1",
    "torch_runtime_version": "2.5.1+cu124",
    "numpy": "2.1.3",
    "sympy": "1.13.1",
    "memory_bytes": 1073741824,
    "swap_extra_bytes": 0,
    "address_space_bytes": 8589934592,
    "workers": 1,
    "cpus": 1,
    "pids_limit": 64,
    "timeout_seconds": 120,
    "log_limit_bytes": 524288,
    "network": "none",
    "root_filesystem": "read_only",
    "tmpfs_bytes": 67108864,
    "formal_runs": 1,
    "planned_formal_runs": 1,
    "automatic_retries": 0,
    "scope": "E21_PAIRED_COST_RUNTIME_DIAGNOSTIC_ONLY",
    "expected_child_status": "COMPLETE_PAIRED_SYNTHETIC_FIT_DIAGNOSTIC_ONLY",
    "expected_parent_status": "PASS_GUARDED_PAIRED_RUNTIME_ONLY",
    "source_count": 15,
    "bundle_entries": 16,
    "archive_limit_bytes": 131072,
    "unpacked_limit_bytes": 262144,
    "file_limit_bytes": 65536,
    "factory_sha256": "d64eb0fe17a00886d6464ae016805b1474e7324e95ad8e223aba44502709759c",
    "planned_optimizer_steps_per_arm": 72,
    "planned_optimizer_steps_total": 144,
    "dependency_integrity_limit": "Read-only bind and fresh versions/origins are verified; metadata is not a full immutable hash of every installed dependency or native library. Only the single E21 synthetic diagnostic is released; no production training release follows.",
    "authorization_id": "E21_FULL_STAGE_20261015_ONE_RUN",
    "planned_models": 6,
    "protocol_sha256": "5075785d758137c37bae3a5e352d3e9c9846cb87585ea48f94bc606a48da815c"
}
    # Human-readable annotations are not authority; every operational field is.
    annotations = {'authorization', 'dependency_integrity_limit'}
    if type(contract) is not dict or any(
            type(contract.get(key)) is not type(value) or contract.get(key) != value
            for key, value in fixed.items() if key not in annotations):
        raise ValueError('E21_EXECUTION_LOCKED')


def validate_torch_runtime_version(observed, contract):
    """Distribution metadata and runtime build identity are separate pins."""
    if (contract.get('torch_runtime_version') != TORCH_RUNTIME_VERSION
            or type(observed) is not str or observed != TORCH_RUNTIME_VERSION):
        raise ValueError('TORCH_RUNTIME_VERSION')


def read_small(path, maximum=65536):
    path = Path(path)
    if not path.is_absolute() or any(p in ('.', '..') for p in path.parts):
        raise ValueError('ABSOLUTE_FILE_PATH')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    fd = None
    try:
        for component in path.parts[1:-1]:
            next_parent = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = next_parent
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
            raise ValueError('ORDINARY_FILE_BOUND')
        data = os.read(fd, maximum + 1)
        after = os.fstat(fd)
        observed_path = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_nlink)
        if len(data) != before.st_size or identity(before) != identity(after) or identity(after) != identity(observed_path):
            raise ValueError('FILE_IDENTITY')
        return data
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def preflight(root, expected):
    raw = read_small(root / '_source_manifest.json', 8192)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('MANIFEST_PIN')
    manifest = json.loads(raw)
    if set(manifest) != {'sources'} or set(manifest['sources']) != NAMES:
        raise ValueError('SOURCE_ALLOWLIST')
    for name, pin in manifest['sources'].items():
        if hashlib.sha256(read_small(root / name)).hexdigest() != pin:
            raise ValueError('SOURCE_PIN')
    contract = json.loads(read_small(root / '_contract.json'))
    require_authorized(contract)
    if (contract['root'] != str(HOST_ROOT) or contract['image_id'] != IMAGE
            or contract['shared_site'] != SITE or contract['formal_runs'] != 1
            or contract['planned_formal_runs'] != 1
            or contract['automatic_retries'] != 0
            or contract['scope'] != 'E21_PAIRED_COST_RUNTIME_DIAGNOSTIC_ONLY'
            or contract['expected_child_status'] != 'COMPLETE_PAIRED_SYNTHETIC_FIT_DIAGNOSTIC_ONLY'
            or contract['expected_parent_status'] != 'PASS_GUARDED_PAIRED_RUNTIME_ONLY'
            or contract['source_count'] != len(NAMES) or contract['bundle_entries'] != len(NAMES) + 1):
        raise ValueError('CONTRACT_SCOPE')
    fixed = {'python': '3.11.2', 'torch': '2.5.1', 'torch_runtime_version': TORCH_RUNTIME_VERSION,
             'numpy': '2.1.3', 'sympy': '1.13.1',
             'memory_bytes': 1073741824, 'swap_extra_bytes': 0, 'address_space_bytes': 8589934592,
             'workers': 1, 'cpus': 1, 'pids_limit': 64, 'timeout_seconds': 120,
             'log_limit_bytes': 524288, 'network': 'none', 'root_filesystem': 'read_only',
             'tmpfs_bytes': 67108864, 'archive_limit_bytes': 131072,
             'unpacked_limit_bytes': 262144, 'file_limit_bytes': 65536,
             'planned_optimizer_steps_per_arm': 72, 'planned_optimizer_steps_total': 144}
    if any(type(contract.get(key)) is not type(value) or contract.get(key) != value
           for key, value in fixed.items()):
        raise ValueError('CONTRACT_FIXED_LIMITS')
    if manifest['sources']['src/models/runtime_ranking_v3.py'] != contract['factory_sha256']:
        raise ValueError('FACTORY_PIN')
    return contract


def child(expected):
    return _child_after_gate(expected)


def _child_after_gate(expected):
    root = Path('/opt/app')
    contract = preflight(root, expected)
    require_authorized(contract)
    if sys.version.split()[0] != contract['python']:
        raise ValueError('PYTHON_VERSION')
    resource.setrlimit(resource.RLIMIT_AS, (8589934592, 8589934592))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    observed = {}
    for name in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max'):
        # cgroup control files report st_size=0 despite having bounded contents.
        with open(Path('/sys/fs/cgroup') / name, 'rb') as control:
            raw = control.read(129)
        if len(raw) > 128:
            raise ValueError('CGROUP_READ_BOUND')
        observed[name] = raw.decode().strip()
    cpu = observed['cpu.max'].split()
    if (observed['memory.max'] != '1073741824' or observed['memory.swap.max'] != '0'
            or observed['pids.max'] != '64' or cpu[0] == 'max' or int(cpu[0]) != int(cpu[1])):
        raise ValueError('CGROUP_LIMITS')
    for key in ('OMP_NUM_THREADS', 'MKL_NUM_THREADS', 'OPENBLAS_NUM_THREADS', 'NUMEXPR_NUM_THREADS'):
        if os.environ.get(key) != '1':
            raise ValueError('THREAD_ENV')
    if os.environ.get('CUDA_VISIBLE_DEVICES') != '':
        raise ValueError('CUDA_ENV')
    if (os.getuid() != int(os.environ['V6_HOST_UID']) or os.getgid() != int(os.environ['V6_HOST_GID'])
            or os.getuid() == 0):
        raise ValueError('CONTAINER_USER')
    sys.path[:0] = [str(root), '/opt/site']
    import importlib.metadata as metadata
    for name in ('torch', 'numpy', 'sympy'):
        if metadata.version(name) != contract[name]:
            raise ValueError('DEPENDENCY_VERSION')
    import torch
    validate_torch_runtime_version(torch.__version__, contract)
    if str(Path(torch.__file__).resolve()) != '/opt/site/torch/__init__.py':
        raise ValueError('TORCH_ORIGIN')
    torch.set_num_threads(1)
    torch.set_num_interop_threads(1)
    if torch.get_num_threads() != 1 or torch.get_num_interop_threads() != 1:
        raise ValueError('TORCH_THREADS')
    import types
    for name, folder in [('src', root / 'src'), ('src.models', root / 'src/models')]:
        module = types.ModuleType(name)
        module.__path__ = [str(folder)]
        sys.modules[name] = module
    from src.models import ranking_v6_complete_cost_paired_runtime_v2 as probe
    if probe.SCOPE != contract['scope']:
        raise ValueError('PROBE_SCOPE')
    result = probe.run(torch, release=contract)
    # Identity/source/version reread does not claim full dependency immutability.
    preflight(root, expected)
    result.update({'source_manifest_sha256': expected, 'python': sys.version.split()[0],
                   'torch': torch.__version__, 'cgroup_limits': observed,
                   'address_space_limit': resource.getrlimit(resource.RLIMIT_AS),
                   'image_id': IMAGE, 'checkpoint_reads': 0, 'real_label_reads': 0,
                   'formal_production_training_runs': 0})
    print(json.dumps(result, sort_keys=True))


def cleanup_owned(process, expected):
    errors = []
    try:
        own = subprocess.run(['docker', 'inspect', NAME, '--format', '{{index .Config.Labels "cjc.v6.manifest"}}'],
                             capture_output=True, timeout=10)
        if own.returncode == 0 and own.stdout.decode().strip() == expected:
            killed = subprocess.run(['docker', 'kill', NAME], capture_output=True, timeout=10)
            if killed.returncode != 0:
                errors.append('OWN_CONTAINER_KILL_UNCONFIRMED')
        else:
            errors.append('OWN_CONTAINER_IDENTITY_UNCONFIRMED')
    except Exception as cleanup:
        errors.append(type(cleanup).__name__)
    finally:
        try:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)
        except Exception as cleanup:
            errors.append('CLIENT_' + type(cleanup).__name__)
    return errors


def validate_child_receipt(result, expected, protocol):
    """Require a full real-session receipt, never a status-string success stub."""
    digest = lambda value: hashlib.sha256(json.dumps(value, sort_keys=True,
        separators=(',', ':'), allow_nan=False).encode('ascii')).hexdigest()
    pin = lambda value: type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None
    require = lambda ok: None if ok else (_ for _ in ()).throw(ValueError('CHILD_RECEIPT'))
    require(type(result) is dict)
    require(result.get('status') == 'COMPLETE_PAIRED_SYNTHETIC_FIT_DIAGNOSTIC_ONLY')
    require(result.get('scope') == 'E21_PAIRED_COST_RUNTIME_DIAGNOSTIC_ONLY')
    require(result.get('source_manifest_sha256') == expected)
    require(result.get('image_id') == IMAGE and result.get('python') == '3.11.2')
    validate_torch_runtime_version(result.get('torch'), {'torch_runtime_version': TORCH_RUNTIME_VERSION})
    for key in ('actual_torch_proof', 'protocol_completed', 'fitting_executed',
                'execution_released', 'all_parameters_restored', 'rng_restored',
                'final_weights_discarded', 'all_snapshots_frozen_before_comparative_evaluation'):
        require(result.get(key) is True)
    require(result.get('train_release') is False)
    for key, value in {'real_optimizer_steps': 144, 'optimizer_steps': 144,
                       'sessions_created': 6, 'restored_sessions': 6,
                       'synthetic_fitting_runs': 6, 'real_label_reads': 0,
                       'checkpoint_reads': 0, 'checkpoint_writes': 0, 'retry_count': 0}.items():
        require(type(result.get(key)) is int and result[key] == value)
    config_hash = digest(protocol)
    require(digest(result.get('protocol')) == config_hash and result.get('protocol_sha256') == config_hash)
    records = result.get('records')
    require(type(records) is list and len(records) == 6 and result.get('freezes') == records)
    arms = ('EXACT_TRUNCATED_CONTROL', 'EXACT_COMPLETE_TREATMENT')
    for record, (seed, arm) in zip(records, ((s, a) for s in (11, 29, 47) for a in arms)):
        payload = record['payload']
        require(record.get('freeze_sha256') == digest(payload))
        require(payload.get('seed') == seed and payload.get('arm') == arm
                and payload.get('protocol_sha256') == config_hash and payload.get('steps') == 24)
        require(pin(payload.get('initial_parameter_sha256')) and pin(payload.get('final_parameter_sha256')))
        logs = payload.get('fit_step_logs')
        require(type(logs) is list and len(logs) == 24)
        previous = payload['initial_parameter_sha256']
        for step, log in enumerate(logs):
            require(type(log.get('step')) is int and log['step'] == step
                    and log.get('parameter_before_sha256') == previous
                    and pin(log.get('parameter_after_sha256')) and pin(log.get('gradient_sha256')))
            previous = log['parameter_after_sha256']
        require(previous == payload['final_parameter_sha256'])
    for control, treatment in zip(records[::2], records[1::2]):
        require(control['payload']['initial_parameter_sha256'] == treatment['payload']['initial_parameter_sha256'])
    envelope = result.get('runtime_freeze_envelope')
    require(type(envelope) is dict and envelope.get('execution_kind') == 'injected_torch'
            and envelope.get('runtime_scope') == result['scope']
            and envelope.get('protocol_sha256') == config_hash
            and envelope.get('freeze_sha256') == [r['freeze_sha256'] for r in records]
            and result.get('runtime_freeze_envelope_sha256') == digest(envelope))


def parent(expected):
    return _parent_after_gate(expected)


def _parent_after_gate(expected):
    if Path(__file__).resolve().parent != HOST_ROOT or HOST_ROOT.resolve() != HOST_ROOT:
        raise ValueError('HOST_ROOT')
    contract = preflight(HOST_ROOT, expected)
    require_authorized(contract)
    image = subprocess.run(['docker', 'image', 'inspect', IMAGE, '--format', '{{.Id}}'],
                           capture_output=True, check=True, timeout=10).stdout.decode().strip()
    if image != IMAGE:
        raise ValueError('IMAGE_PIN')
    collision = subprocess.run(['docker', 'container', 'inspect', NAME],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    if collision.returncode == 0:
        raise ValueError('CONTAINER_NAME_EXISTS')
    if os.getuid() == 0:
        raise ValueError('NONROOT_HOST_USER_REQUIRED')
    with open('/proc/meminfo', 'rb') as memory_info:
        memory_raw = memory_info.read(8193)
    if len(memory_raw) > 8192:
        raise ValueError('MEMINFO_BOUND')
    match = re.search(rb'^MemAvailable:\s+(\d+) kB$', memory_raw, re.MULTILINE)
    host_mem_available_kib = int(match.group(1)) if match else 0
    if host_mem_available_kib < 2 * 1024 * 1024:
        raise ValueError('HOST_MEMORY_HEADROOM')
    fd = os.open(HOST_ROOT / 'actual.once.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as marker:
        json.dump({'source_manifest_sha256': expected, 'image': IMAGE, 'automatic_retries': 0}, marker)
        marker.flush()
        os.fsync(marker.fileno())
    cmd = ['docker', 'run', '--rm', '--pull=never', '--name', NAME,
           '--user', str(os.getuid()) + ':' + str(os.getgid()), '--log-driver', 'none',
           '--label', 'cjc.v6.manifest=' + expected, '--read-only', '--network', 'none',
           '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
           '--memory', '1g', '--memory-swap', '1g', '--cpus', '1', '--pids-limit', '64',
           '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m', '-v', SITE + ':/opt/site:ro',
           '-v', str(HOST_ROOT) + ':/opt/app:ro']
    for key, value in {'OMP_NUM_THREADS': '1', 'MKL_NUM_THREADS': '1', 'OPENBLAS_NUM_THREADS': '1',
                       'NUMEXPR_NUM_THREADS': '1', 'CUDA_VISIBLE_DEVICES': '',
                       'PYTHONDONTWRITEBYTECODE': '1', 'TORCH_HOME': '/tmp/torch',
                       'XDG_CACHE_HOME': '/tmp/cache', 'V6_HOST_UID': str(os.getuid()),
                       'V6_HOST_GID': str(os.getgid())}.items():
        cmd += ['-e', key + '=' + value]
    cmd += ['--entrypoint', '/usr/bin/python3', IMAGE, '-I', '-S', '-B', '/opt/app/runner.py', '--child', expected]
    process = None
    output = bytearray()
    selector = None
    deadline, failure, cleanup_errors = time.monotonic() + 120, None, []
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            if time.monotonic() > deadline:
                raise TimeoutError('TIMEOUT')
            for key, _ in selector.select(.25):
                data = os.read(key.fileobj.fileno(), 8192)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                if len(output) + len(data) > contract['log_limit_bytes']:
                    raise ValueError('LOG_BOUND')
                output.extend(data)
        process.wait(timeout=5)
    except Exception as exc:
        failure = str(exc)
        if process is not None:
            cleanup_errors = cleanup_owned(process, expected)
    finally:
        if selector is not None:
            selector.close()
    with open(HOST_ROOT / 'actual.log', 'xb') as log:
        log.write(output)
    child_result = None
    if not failure and process is not None and process.returncode == 0:
        try:
            child_result = json.loads(output.decode().strip().splitlines()[-1])
            if not isinstance(child_result, dict):
                raise ValueError('CHILD_RESULT_SCHEMA')
            preflight(HOST_ROOT, expected)
            protocol = json.loads(read_small(HOST_ROOT / 'contracts/ranking_v6_complete_cost_fit_protocol_v1.json'))
            validate_child_receipt(child_result, expected, protocol)
        except Exception as parse:
            failure = 'CHILD_PARSE_' + type(parse).__name__
            child_result = None
    result = {'status': 'PASS_GUARDED_PAIRED_RUNTIME_ONLY' if child_result
              and child_result.get('status') == 'COMPLETE_PAIRED_SYNTHETIC_FIT_DIAGNOSTIC_ONLY' else 'FAIL_PAIRED_RUNTIME',
              'exit_code': None if process is None else process.returncode, 'failure': failure, 'cleanup_errors': cleanup_errors,
              'cleanup_confirmed': not cleanup_errors, 'child': child_result,
              'source_manifest_sha256': expected, 'raw_log_sha256': hashlib.sha256(output).hexdigest(),
              'raw_log_bytes': len(output), 'formal_runs': 1, 'planned_formal_runs': 1,
              'planned_optimizer_steps_per_arm': 72, 'planned_optimizer_steps_total': 144,
              'automatic_retries': 0,
              'container_image': IMAGE, 'memory_enforcement': 'Docker cgroup 1GiB, zero extra swap',
              'host_mem_available_kib_before_launch': host_mem_available_kib,
              'dependency_integrity_limit': contract['dependency_integrity_limit']}
    with open(HOST_ROOT / 'result.json', 'x') as artifact:
        json.dump(result, artifact, sort_keys=True)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'].startswith('PASS_') else 1


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] not in ('--parent', '--child') or not re.fullmatch('[0-9a-f]{64}', sys.argv[2]):
        raise SystemExit('EXACT_MODE_AND_MANIFEST_REQUIRED')
    if sys.argv[1] == '--child':
        child(sys.argv[2])
    else:
        raise SystemExit(parent(sys.argv[2]))
