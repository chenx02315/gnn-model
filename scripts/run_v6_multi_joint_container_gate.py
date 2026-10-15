"""Pinned once-only B synthetic VJP, no fit, optimizer or real-data mounts."""
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

HOST_ROOT = Path('/ssd/cjc/gnn_model_v6_multi_positive_joint_20261015_r1')
IMAGE = 'sha256:66ec58a325c4165749971d95dbbe1636d8423cc7328be110c5df38ed42ca57e7'
SITE = '/ssd/cjc/gnn_model_runtime_v2_98efbd4f_20261002T235119/venv/lib/python3.11/site-packages'
NAME = 'gnn-v6-multi-positive-joint-20261015-r1'
NAMES = ["runner.py","_contract.json","src/models/runtime_ranking_v3.py","src/models/ranking_v6_scorer_vjp_bridge.py","src/models/ranking_v6_synthetic_real_bridge_adapter.py","src/models/ranking_v6_multi_positive_joint_caller.py","src/models/ranking_v6_multi_positive_conditional_risk.py","src/models/ranking_v6_multi_positive_risk_control.py","src/models/ranking_v6_multi_positive_complete_cost.py","src/models/ranking_v6_multi_positive_joint_probe.py","_protocol_tests.py","src/models/ranking_v6_synthetic_joint_freeze.py"]
NAMES = set(NAMES)

def require_authorized(contract):
    expected = json.loads("{\n  \"status\": \"AUTHORIZED_ONE_E29_SYNTHETIC_MULTI_POSITIVE_JOINT_VJP_AFTER_REVIEW_AND_FRESH_GATES_NOT_TRAINING\",\n  \"authorization\": \"User approved all three proposed stages. This contract permits one new isolated synthetic forward/backward validation, no optimizer or fitting. Stage three remains protocol design only.\",\n  \"root\": \"/ssd/cjc/gnn_model_v6_multi_positive_joint_20261015_r1\",\n  \"image_id\": \"sha256:66ec58a325c4165749971d95dbbe1636d8423cc7328be110c5df38ed42ca57e7\",\n  \"shared_site\": \"/ssd/cjc/gnn_model_runtime_v2_98efbd4f_20261002T235119/venv/lib/python3.11/site-packages\",\n  \"python\": \"3.11.2\", \"torch\": \"2.5.1\", \"numpy\": \"2.1.3\", \"sympy\": \"1.13.1\",\n  \"memory_bytes\": 1073741824, \"swap_extra_bytes\": 0, \"address_space_bytes\": 8589934592,\n  \"workers\": 1, \"cpus\": 1, \"pids_limit\": 64, \"timeout_seconds\": 120,\n  \"log_limit_bytes\": 524288, \"network\": \"none\", \"root_filesystem\": \"read_only\", \"tmpfs_bytes\": 67108864,\n  \"formal_runs\": 1, \"automatic_retries\": 0,\n  \"scope\": \"SYNTHETIC_MULTI_POSITIVE_JOINT_VJP_ONLY\",\n  \"expected_child_status\": \"PASS_REAL_FACTORY_MULTI_POSITIVE_JOINT_VJP_ONLY\",\n  \"expected_parent_status\": \"PASS_GUARDED_MULTI_POSITIVE_JOINT_VJP_ONLY\",\n  \"source_count\": 12, \"bundle_entries\": 13,\n  \"factory_sha256\": \"d64eb0fe17a00886d6464ae016805b1474e7324e95ad8e223aba44502709759c\",\n  \"scorer\": \"Unchanged existing seven-feature 7->32 ReLU->32 ReLU->1 MLP, 1345 parameters, CPU float64; one newly initialized synthetic probe model, no checkpoint.\",\n  \"fixture\": {\"actions\": 6, \"positive_count\": 2, \"k\": 3, \"seed\": 11, \"pilot_samples\": 32, \"main_samples\": 480, \"risk_weight\": 0.5, \"normalized_cost_weight\": 1.0},\n  \"finite_difference\": {\"epsilon\": 0.000001, \"absolute_tolerance\": 1e-8, \"relative_tolerance\": 1e-5, \"active_coordinate_min_absolute_derivative\": 1e-7, \"relu_mask_must_match\": true},\n  \"probe_limits\": {\"mc_estimator_calls\": 1, \"optimizer_calls\": 0, \"accepted_updates\": 0, \"real_label_reads\": 0, \"checkpoint_reads\": 0, \"training_runs\": 0, \"blind_access\": false, \"lsf_tessent_calls\": 0},\n  \"dependency_integrity_limit\": \"Pinned image, read-only dependency bind, fresh versions/origins and source readback; not a full immutable digest of all shared-site dependencies or native libraries. Synthetic validation is not real TRAIN release.\",\n  \"real_training_release\": false\n}\n\r\n")
    if type(contract) is not dict or json.dumps(contract, sort_keys=True, allow_nan=False) != json.dumps(expected, sort_keys=True):
        raise ValueError('E29_EXECUTION_LOCKED')


def validate_torch_runtime_version(observed):
    if not isinstance(observed, str):
        raise ValueError('TORCH_RUNTIME_VERSION')
    value = str.__str__(observed)
    if type(value) is not str or value != '2.5.1+cu124':
        raise ValueError('TORCH_RUNTIME_VERSION')
    return value


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
            or contract['automatic_retries'] != 0
            or contract['scope'] != 'SYNTHETIC_MULTI_POSITIVE_JOINT_VJP_ONLY'
            or contract['expected_child_status'] != 'PASS_REAL_FACTORY_MULTI_POSITIVE_JOINT_VJP_ONLY'
            or contract['expected_parent_status'] != 'PASS_GUARDED_MULTI_POSITIVE_JOINT_VJP_ONLY'
            or contract['source_count'] != 12 or contract['bundle_entries'] != 13):
        raise ValueError('CONTRACT_SCOPE')
    fixed = {'python': '3.11.2', 'torch': '2.5.1', 'numpy': '2.1.3', 'sympy': '1.13.1',
             'memory_bytes': 1073741824, 'swap_extra_bytes': 0, 'address_space_bytes': 8589934592,
             'workers': 1, 'cpus': 1, 'pids_limit': 64, 'timeout_seconds': 120,
             'log_limit_bytes': 524288, 'network': 'none', 'root_filesystem': 'read_only',
             'tmpfs_bytes': 67108864}
    if any(type(contract.get(key)) is not type(value) or contract.get(key) != value
           for key, value in fixed.items()):
        raise ValueError('CONTRACT_FIXED_LIMITS')
    if manifest['sources']['src/models/runtime_ranking_v3.py'] != contract['factory_sha256']:
        raise ValueError('FACTORY_PIN')
    return contract


def child(expected):
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
    torch_runtime_version = validate_torch_runtime_version(torch.__version__)
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
    from src.models import ranking_v6_multi_positive_joint_probe as probe
    if probe.SCOPE != contract['scope']:
        raise ValueError('PROBE_SCOPE')
    result = probe.verify(torch, scope=probe.SCOPE)
    # Identity/source/version reread does not claim full dependency immutability.
    preflight(root, expected)
    result.update({'source_manifest_sha256': expected, 'python': sys.version.split()[0],
                   'torch': torch_runtime_version, 'cgroup_limits': observed,
                   'address_space_limit': resource.getrlimit(resource.RLIMIT_AS),
                   'image_id': IMAGE})
    validate_child_receipt(result, expected)
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


def check_protocol_receipt(root, expected):
    receipt = json.loads(read_small(root / 'protocol.receipt.json', 4096))
    fixed = {'status': 'PASS_NO_TORCH_LINUX_PROTOCOL', 'testsRun': 16,
             'skipped': 0, 'failures': 0, 'errors': 0, 'torch_imported': False,
             'source_manifest_sha256': expected,
             'protocol_source_sha256': hashlib.sha256(read_small(root / '_protocol_tests.py')).hexdigest()}
    if type(receipt) is not dict or any(type(receipt.get(k)) is not type(v) or receipt[k] != v
                                        for k, v in fixed.items()):
        raise ValueError('LINUX_PROTOCOL_RECEIPT')
    return receipt


def validate_child_receipt(result, expected):
    if type(result) is not dict:
        raise ValueError('CHILD_RECEIPT')
    json.dumps(result, allow_nan=False)
    fixed = {'status': 'PASS_REAL_FACTORY_MULTI_POSITIVE_JOINT_VJP_ONLY',
             'scope': 'SYNTHETIC_MULTI_POSITIVE_JOINT_VJP_ONLY',
             'source_manifest_sha256': expected, 'python': '3.11.2', 'image_id': IMAGE,
             'weights_unchanged': True, 'existing_grad_unchanged': True,
             'rng_preserved': True, 'threads_preserved': True,
             'deterministic_vjp': True, 'relu_masks_unchanged': True,
             'full_nonlinear_exact_objectives_recomputed': True,
             'mc_finite_difference_is_frozen_linear_surrogate_only': True,
             'separate_phase_vjps': True, 'accepted_update': False,
             'real_training_release': False, 'mc_estimator_calls': 1,
             'parameter_count': 1345, 'action_count': 6, 'positive_count': 2,
             'mc_nominal_work': 9216, 'k': 3, 'seed': 11,
             'dtype': 'float64', 'cpu_threads_during_probe': 1,
             'fitting_performed': False, 'optimizer_implemented': False,
             'blind_access': False, 'lsf_tessent_calls': 0,
             'held_corrupt_readback_loader_calls': 0,
             'held_fixture_mirrors_fit_features_not_independent_population': True,
             'optimizer_calls': 0, 'training_runs': 0, 'checkpoint_reads': 0,
             'real_label_reads': 0}
    for key, value in fixed.items():
        if type(result.get(key)) is not type(value) or result[key] != value:
            raise ValueError('CHILD_RECEIPT_' + key)
    validate_torch_runtime_version(result.get('torch'))
    held = result.get('synthetic_held_freeze_proof')
    held_fixed = {'held_outcome_release': True, 'freeze_verified_before_loader_access': True,
                  'loader_calls': 1, 'outcome_count': 6, 'synthetic_only': True,
                  'scope': 'generated_bounded_fixture_only', 'actual_training': False,
                  'real_data_access': False, 'real_heldout_release': False,
                  'fit_performed': False, 'generalization_claim': False}
    if type(held) is not dict or any(type(held.get(k)) is not type(v) or held[k] != v
                                     for k, v in held_fixed.items()):
        raise ValueError('CHILD_HELD_FREEZE_RECEIPT')
    pin = held.get('freeze_sha256')
    if type(pin) is not str or re.fullmatch('[0-9a-f]{64}', pin) is None or held.get('readback_sha256') != pin:
        raise ValueError('CHILD_HELD_FREEZE_PIN')
    observed = result.get('cgroup_limits')
    if (type(observed) is not dict or observed.get('memory.max') != '1073741824'
            or observed.get('memory.swap.max') != '0' or observed.get('pids.max') != '64'):
        raise ValueError('CHILD_CGROUP_RECEIPT')
    cpu = observed.get('cpu.max', '').split()
    if len(cpu) != 2 or not all(v.isdigit() for v in cpu) or int(cpu[0]) <= 0 or int(cpu[0]) != int(cpu[1]):
        raise ValueError('CHILD_CPU_RECEIPT')


def parent(expected):
    if Path(__file__).resolve().parent != HOST_ROOT or HOST_ROOT.resolve() != HOST_ROOT:
        raise ValueError('HOST_ROOT')
    contract = preflight(HOST_ROOT, expected)
    require_authorized(contract)
    protocol_receipt = check_protocol_receipt(HOST_ROOT, expected)
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
                if len(output) + len(data) > 524288:
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
            validate_child_receipt(child_result, expected)
        except Exception as parse:
            failure = 'CHILD_PARSE_' + type(parse).__name__
            child_result = None
    result = {'status': 'PASS_GUARDED_MULTI_POSITIVE_JOINT_VJP_ONLY' if child_result
              and child_result.get('status') == 'PASS_REAL_FACTORY_MULTI_POSITIVE_JOINT_VJP_ONLY' else 'FAIL_MULTI_POSITIVE_JOINT_VJP',
              'exit_code': None if process is None else process.returncode, 'failure': failure, 'cleanup_errors': cleanup_errors,
              'cleanup_confirmed': not cleanup_errors, 'child': child_result,
              'source_manifest_sha256': expected, 'raw_log_sha256': hashlib.sha256(output).hexdigest(),
              'raw_log_bytes': len(output), 'formal_runs': 1, 'automatic_retries': 0,
              'container_image': IMAGE, 'memory_enforcement': 'Docker cgroup 1GiB, zero extra swap',
              'host_mem_available_kib_before_launch': host_mem_available_kib,
              'linux_protocol': protocol_receipt,
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
