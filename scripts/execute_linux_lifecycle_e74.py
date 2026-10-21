"""One authorized, synthetic, one-container Linux lifecycle attempt (stdlib only).

Transport invokes this on B with one strict JSON request on stdin. It is not a
general remote command runner. Never invoke it locally as a test of Linux.
"""
import base64
import hashlib
import json
import os
import re
import selectors
import stat
import subprocess
import sys
import time

ROOT = '/ssd/cjc/gnn_model_linux_lifecycle_e72_20261021_r1'
NAME = 'gnn-e74-lifecycle-20261021-r1'
SOURCE_SHA = '3a777175d1f4687e03950c5dd0aa97b8c3cba3a90905be672af274f7c28dea15'
SCOPE_SHA = '82fa3c895afbde96935d2c849ca07e5fc7159a0715400fbd2b9f5bde56639dad'
AUTH_SHA = 'd758c91cd61a0aaa3745387892acf5b82de327c3a27c83dc0db0d623029a1bda'
AMEND_SHA = 'c656364f5ec261f8039fb0eaa4db8777ebfb243ed2dd70cef02e539d7928577e'
NEW_AUTH_SHA = '3c3363fae281a84938ba2d288060cb542afd375345c5d5777bf7ec17b93a7ce1'
HEX = re.compile(r'[0-9a-f]{64}\Z')
FIELDS = ('Id', 'Image', 'Config.Labels', 'HostConfig.Memory', 'HostConfig.MemorySwap',
          'HostConfig.PidsLimit', 'HostConfig.ReadonlyRootfs', 'HostConfig.Privileged',
          'HostConfig.NetworkMode', 'HostConfig.CgroupnsMode', 'Config.User',
          'Config.Entrypoint', 'Config.Cmd', 'HostConfig.CapDrop',
          'HostConfig.SecurityOpt', 'HostConfig.DeviceRequests', 'HostConfig.Devices',
          'HostConfig.Init', 'HostConfig.Runtime', 'Config.WorkingDir',
          'HostConfig.Tmpfs', 'HostConfig.IpcMode', 'HostConfig.PidMode',
          'HostConfig.CgroupParent', 'Config.Healthcheck', 'Mounts',
          'State.Running', 'State.ExitCode', 'State.Status')
FORMAT = '\n'.join('{{json .%s}}' % key for key in FIELDS)
LABEL = 'gnn.e74.attempt'
MARK = NEW_AUTH_SHA[:24]
READ_CAP = 11000
NORMAL_READ_CAP = READ_CAP - 2000
SESSION_SECONDS = 55


class CommandError(ValueError):
    def __init__(self, reason, raw=b''):
        super().__init__(reason)
        self.raw = raw


class Budget:
    def __init__(self):
        self.deadline = time.monotonic() + SESSION_SECONDS
        self.read_bytes = 0

    def time(self, requested, cleanup=False):
        remain = self.deadline - time.monotonic() - (0 if cleanup else 15)
        require(remain > 0, 'SESSION_DEADLINE')
        return min(requested, remain)

    def consume(self, count, cleanup=False):
        self.read_bytes += count
        require(self.read_bytes <= (READ_CAP if cleanup else NORMAL_READ_CAP),
                'CUMULATIVE_READ_CAP')

    def allowance(self, cleanup=False):
        remain = (READ_CAP if cleanup else NORMAL_READ_CAP) - self.read_bytes
        require(remain > 0, 'CUMULATIVE_READ_CAP')
        return min(1024, remain)


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def pairs_unique(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, 'DUPLICATE_JSON_KEY')
        out[key] = value
    return out


def bad_constant(value):
    raise ValueError('NONFINITE_JSON:' + value)


def parse(raw):
    return json.loads(raw, object_pairs_hook=pairs_unique, parse_constant=bad_constant)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def validate(request):
    require(type(request) is dict and set(request) == {'image_id', 'source_b64', 'manifest'}, 'REQUEST_KEYS')
    image = request['image_id']
    require(type(image) is str and image.startswith('sha256:') and HEX.fullmatch(image[7:]), 'IMAGE_ID')
    b64 = request['source_b64']
    require(type(b64) is str and len(b64) <= 19116, 'SOURCE_BOUND')
    source = base64.b64decode(b64, validate=True)
    require(len(source) <= 14336 and hashlib.sha256(source).hexdigest() == SOURCE_SHA, 'SOURCE_SHA')
    manifest = request['manifest']
    require(type(manifest) is dict and set(manifest) ==
            {'image_id', 'source_sha256', 'auth_sha256', 'amendment_sha256'}, 'MANIFEST_KEYS')
    require(manifest == {'image_id': image, 'source_sha256': SOURCE_SHA,
                        'auth_sha256': NEW_AUTH_SHA, 'amendment_sha256': AMEND_SHA}, 'MANIFEST_PIN')
    require(len(source) + len(encode(manifest)) <= 25000, 'UPLOAD_BOUND')
    return image, source, manifest


def run(argv, timeout=5, limit=8192, budget=None, cleanup=False):
    """Bounded subprocess output and wall time; no shell, no inherited stdin."""
    require(0 < timeout <= 30, 'COMMAND_BUDGET')
    if budget is not None:
        timeout = budget.time(timeout, cleanup)
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, shell=False, close_fds=True)
    raw = bytearray()
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while selector.get_map():
                require(time.monotonic() < deadline, 'COMMAND_TIMEOUT')
                for key, _ in selector.select(min(.1, max(0, deadline - time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(),
                                    budget.allowance(cleanup) if budget is not None else 1024)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        if budget is not None:
                            budget.consume(len(chunk), cleanup)
                        require(len(raw) + len(chunk) <= limit, 'COMMAND_OUTPUT_BOUND')
                        raw.extend(chunk)
            code = proc.wait(timeout=max(.001, deadline - time.monotonic()))
        return code, bytes(raw)
    except Exception as exc:
        raise CommandError(str(exc), bytes(raw)) from exc
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=1)
        proc.stdout.close()


def checked(argv, timeout=5, limit=8192, budget=None, cleanup=False):
    code, raw = run(argv, timeout, limit, budget, cleanup)
    if code != 0:
        raise CommandError('COMMAND_FAILED', raw)
    return raw


def root_new():
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = ROOT.strip('/').split('/')
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        os.mkdir(parts[-1], 0o700, dir_fd=fd)
        child = os.open(parts[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        os.fsync(fd)
        return child
    finally:
        os.close(fd)


def write_at(directory, name, body, mode, identity=None):
    require(name in ('gate.py', 'execution_manifest.json', 'container.id'), 'FILE_NAME')
    require(len(body) <= (14336 if name == 'gate.py' else 12000), 'FILE_SIZE')
    flags = os.O_WRONLY | os.O_NOFOLLOW | (os.O_CREAT | os.O_EXCL if identity is None else 0)
    fd = os.open(name, flags, mode, dir_fd=directory)
    try:
        obj = os.fstat(fd)
        require(stat.S_ISREG(obj.st_mode) and obj.st_nlink == 1, 'FILE_IDENTITY')
        found = (obj.st_dev, obj.st_ino)
        require(identity is None or identity == found, 'FILE_CHANGED')
        os.fchmod(fd, mode)
        os.ftruncate(fd, 0)
        view = memoryview(body)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
        os.fsync(directory)
        return found
    finally:
        os.close(fd)


def cid_from_file(directory):
    try:
        fd = os.open('container.id', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    except FileNotFoundError:
        return None
    try:
        obj = os.fstat(fd)
        require(stat.S_ISREG(obj.st_mode) and obj.st_nlink == 1 and obj.st_size <= 65, 'CID_FILE_IDENTITY')
        value = os.read(fd, 66).decode('ascii').strip()
        require(HEX.fullmatch(value), 'CID_FILE_CONTENT')
        return value
    finally:
        os.close(fd)


def inspect(cid, budget=None, cleanup=False):
    raw = checked(['docker', 'container', 'inspect', '--format', FORMAT, cid],
                  limit=8192, budget=budget, cleanup=cleanup)
    lines = raw.decode('utf-8').splitlines()
    require(len(lines) == len(FIELDS), 'INSPECT_FIELDS')
    config = dict(zip(FIELDS, (parse(line) for line in lines)))
    require(config['Id'] == cid, 'INSPECT_ID')
    return config


def cleanup_state(cid, budget):
    projection = ('{{json .Id}}\n{{json .Image}}\n'
                  '{{json (index .Config.Labels "gnn.e74.attempt")}}\n'
                  '{{json .State.Running}}\n{{json .State.ExitCode}}')
    raw = checked(['docker', 'container', 'inspect', '--format', projection, cid],
                  limit=512, budget=budget, cleanup=True)
    values = [parse(line) for line in raw.decode('utf-8').splitlines()]
    require(len(values) == 5 and values[0] == cid, 'CLEANUP_PROJECTION')
    return dict(image=values[1], label=values[2], running=values[3], exit_code=values[4])


def verify(config, image, user):
    expected = {'Image': image, 'HostConfig.Memory': 134217728,
                'HostConfig.MemorySwap': 134217728, 'HostConfig.PidsLimit': 16,
                'HostConfig.ReadonlyRootfs': True, 'HostConfig.Privileged': False,
                'HostConfig.NetworkMode': 'none', 'HostConfig.CgroupnsMode': 'private',
                'Config.User': user, 'Config.Entrypoint': ['python3'],
                'Config.Cmd': ['-I', '-S', '-B', '/gate.py'],
                'HostConfig.CapDrop': ['ALL'], 'HostConfig.SecurityOpt': ['no-new-privileges'],
                'HostConfig.Runtime': 'runc', 'Config.WorkingDir': '/tmp',
                'HostConfig.IpcMode': 'none', 'HostConfig.PidMode': '',
                'HostConfig.CgroupParent': '',
                'HostConfig.Tmpfs': {'/tmp': 'rw,nosuid,nodev,noexec,size=1048576,mode=1777'}}
    require(all(config.get(key) == value for key, value in expected.items()), 'CONTAINER_CONFIG')
    require(config.get('Config.Labels', {}).get(LABEL) == MARK, 'CONTAINER_LABEL')
    health = config['Config.Healthcheck']
    require(type(health) is dict and health.get('Test') == ['NONE'], 'HEALTHCHECK_DISABLED')
    require(not config['HostConfig.DeviceRequests'] and not config['HostConfig.Devices']
            and config['HostConfig.Init'] is False, 'DEVICES_INIT')
    mounts = config['Mounts']
    require(type(mounts) is list and len(mounts) in (1, 2), 'MOUNT_COUNT')
    bind = [m for m in mounts if m.get('Type') == 'bind']
    require(len(bind) == 1 and bind[0].get('Source') == ROOT + '/gate.py'
            and bind[0].get('Destination') == '/gate.py' and bind[0].get('RW') is False,
            'SCRIPT_MOUNT')
    tmp = [m for m in mounts if m.get('Type') == 'tmpfs']
    require(len(tmp) == len(mounts)-1 and all(m.get('Destination') == '/tmp' for m in tmp), 'TMPFS_MOUNT')


def gate_valid(gate):
    require(type(gate) is dict and set(gate) == {'schema', 'status', 'gate_pass',
            'environment', 'profiles', 'universal_process_tree_termination_proved',
            'durable_runner_integrated', 'real_atpg_jobs', 'training', 'execution_ready',
            'training_release'}, 'GATE_KEYS')
    require(gate['schema'] == 'prospective-linux-lifecycle-gate-v2' and
            gate['status'] == 'PASS_SYNTHETIC_GROUP_ONLY' and gate['gate_pass'] is True, 'GATE_STATUS')
    require(all(gate[k] is False for k in ('universal_process_tree_termination_proved',
            'durable_runner_integrated', 'training', 'execution_ready', 'training_release'))
            and gate['real_atpg_jobs'] == 0, 'GATE_BOUNDARY')
    env = gate['environment']
    require(type(env) is dict and env.get('platform') == 'linux' and
            env.get('memory_limit_bytes') == 134217728 and env.get('swap_limit_bytes') == 0 and
            env.get('pids_max') == 16 and env.get('oom_group') in (0, 1) and
            env.get('oom_group_atomic_kill_guaranteed') is False and
            env.get('kernel_configuration_observed') is True and
            env.get('active_oom_test') is False and
            env.get('production_atpg_limits_verified') is False, 'GATE_ENVIRONMENT')
    rows = gate['profiles']
    require(type(rows) is list and len(rows) == 3 and
            [r.get('profile') for r in rows] == ['success', 'failure', 'timeout_group'], 'GATE_PROFILES')
    for row in rows:
        require(type(row) is dict and row.get('leader_reaped') is True and
                row.get('observed_group_empty') is True and
                type(row.get('observed_interval_ns')) is int and row['observed_interval_ns'] > 0,
                'GATE_CLEANUP')
    require(rows[0].get('returncode') == 0 and rows[0].get('timed_out') is False and
            rows[1].get('returncode') == 7 and rows[1].get('timed_out') is False and
            rows[2].get('timed_out') is True and
            type(rows[2].get('grandchild_pid')) is int and rows[2]['grandchild_pid'] > 1,
            'GATE_RESULTS')


def execute(request):
    image, source, manifest = validate(request)
    require(sys.platform == 'linux' and os.uname().nodename == 'bupt-gpus1', 'B_HOST_ONLY')
    require(os.getuid() != 0, 'NONROOT_REQUIRED')
    started = time.monotonic()
    budget = Budget()
    info = checked(['docker', 'info', '--format',
                    '{{json .CgroupVersion}}\n{{json .OSType}}\n{{if index .Runtimes "runc"}}true{{else}}false{{end}}'],
                   limit=128, budget=budget)
    require(info.decode().splitlines() == ['"2"', '"linux"', 'true'], 'CGROUP2_RUNC')
    image_format = '{{json .Id}}\n{{json .Config.Volumes}}\n{{json .Os}}'
    image_info = checked(['docker', 'image', 'inspect', '--format', image_format, image],
                         limit=1024, budget=budget)
    image_fields = [parse(s) for s in image_info.decode().splitlines()]
    require(len(image_fields) == 3 and image_fields[0] == image and
            not image_fields[1] and image_fields[2] == 'linux', 'IMAGE_ID_VOLUMES_OS')
    directory = root_new()  # Exclusive: no retry after a prior attempt.
    cid = None
    journal = None
    receipt = dict(manifest, schema='e74-linux-lifecycle-execution-v1', host='bupt-gpus1',
                   status='BLOCKED_OR_FAILED_NO_RETRY', gate_pass=False, phase='ROOT_CREATED',
                   execution_ready=False, training_release=False, retry_allowed=False)

    def persist():
        nonlocal journal
        journal = write_at(directory, 'execution_manifest.json', encode(receipt), 0o600, journal)

    try:
        write_at(directory, 'gate.py', source, 0o444)
        receipt['phase'] = 'CREATE_ATTEMPT'
        persist()
        require(time.monotonic() - started < 15, 'PREFLIGHT_TIME_BUDGET')
        user = '%d:%d' % (os.getuid(), os.getgid())
        argv = ['docker', 'create', '--pull=never', '--cidfile', ROOT + '/container.id',
                '--name', NAME, '--label', LABEL + '=' + MARK, '--network', 'none',
                '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                '--memory', '134217728', '--memory-swap', '134217728', '--pids-limit', '16',
                '--cgroupns', 'private', '--user', user,
                '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=1048576,mode=1777',
                '--mount', 'type=bind,src=' + ROOT + '/gate.py,dst=/gate.py,readonly',
                '--entrypoint', 'python3', '--init=false', '--no-healthcheck',
                '--workdir', '/tmp', '--ipc', 'none', '--runtime', 'runc',
                '--env', 'NVIDIA_VISIBLE_DEVICES=void', image, '-I', '-S', '-B', '/gate.py']
        response = checked(argv, limit=128, budget=budget).decode('ascii').strip()
        require(HEX.fullmatch(response), 'CREATE_RESPONSE_ID')
        cid = cid_from_file(directory)
        require(cid == response, 'CIDFILE_RESPONSE_MISMATCH')
        receipt.update(container_id=cid, phase='CREATED')
        persist()
        config = inspect(cid, budget)
        verify(config, image, user)
        require(config['State.Running'] is False and config['State.Status'] == 'created', 'CREATED_STATE')
        receipt.update(config_sha256=hashlib.sha256(encode(config)).hexdigest(), phase='START_ATTEMPT')
        persist()
        require(time.monotonic() - started < 20, 'START_TIME_BUDGET')
        code, output = run(['docker', 'start', '--attach', cid], timeout=30,
                           limit=8192, budget=budget)
        receipt.update(attach_exit=code, output_sha256=hashlib.sha256(output).hexdigest())
        receipt.update(output_bytes=len(output),
                       output_prefix_b64=base64.b64encode(output[:512]).decode('ascii'))
        state = inspect(cid, budget)
        receipt.update(container_exit=state['State.ExitCode'], running=state['State.Running'])
        require(code == 0 and state['State.Running'] is False and
                state['State.ExitCode'] == 0 and state['State.Status'] == 'exited', 'CONTAINER_EXIT')
        gate = parse(output.decode('utf-8'))
        gate_valid(gate)
        receipt.update(gate_result=gate, status='PASS_LINUX_SYNTHETIC_GATE',
                       gate_pass=True, phase='COMPLETE', cleanup_verified=True)
        require(len(encode(receipt)) <= 8192, 'RECEIPT_BOUND')
    except Exception as exc:
        receipt.update(status='BLOCKED_OR_FAILED_NO_RETRY', gate_pass=False, phase='FAILED')
        receipt['reason'] = type(exc).__name__ + ':' + str(exc)[:120]
        if isinstance(exc, CommandError):
            receipt.update(output_bytes=len(exc.raw),
                           output_sha256=hashlib.sha256(exc.raw).hexdigest(),
                           output_prefix_b64=base64.b64encode(exc.raw[:512]).decode('ascii'))
        if cid is None:
            try:
                cid = cid_from_file(directory)
            except Exception:
                pass
        if cid and HEX.fullmatch(cid):
            receipt['container_id'] = cid
            try:
                config = cleanup_state(cid, budget)
                require(config['image'] == image and config['label'] == MARK, 'CLEANUP_IDENTITY')
                run(['docker', 'kill', cid], timeout=5, limit=512, budget=budget, cleanup=True)
                state = cleanup_state(cid, budget)
                require(state['running'] is False, 'STOP_UNVERIFIED')
                receipt.update(cleanup_verified=True, running=False,
                               container_exit=state['exit_code'])
            except Exception:
                receipt['cleanup_verified'] = False
        else:
            receipt['cleanup_verified'] = False
    finally:
        receipt['read_bytes'] = budget.read_bytes
        try:
            persist()
        except Exception:
            receipt.update(status='BLOCKED_OR_FAILED_NO_RETRY', gate_pass=False,
                           journal_verified=False)
        os.close(directory)
    return receipt


def main(request=None):
    try:
        require(len(sys.argv) == 1, 'NO_ARGUMENTS')
        if request is None:
            raw = sys.stdin.buffer.read(32769)
            require(len(raw) <= 32768, 'REQUEST_BOUND')
            request = parse(raw.decode('utf-8'))
        receipt = execute(request)
    except Exception as exc:
        receipt = dict(schema='e74-linux-lifecycle-execution-v1',
                       status='BLOCKED_OR_FAILED_NO_RETRY', gate_pass=False,
                       execution_ready=False, training_release=False,
                       reason=type(exc).__name__ + ':' + str(exc)[:120])
    print(json.dumps(receipt, sort_keys=True, separators=(',', ':'), allow_nan=False))
    return 0 if receipt.get('gate_pass') is True else 2


if __name__ == '__main__':
    raise SystemExit(main())
