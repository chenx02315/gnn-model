"""Fixed one-shot held E98 registration helper. No main or automatic execution."""
import hashlib
import json
import os
import platform
import re
import selectors
import stat
import subprocess
import sys
import time

ROOT = '/temp/jiangchuanc/gnn_model_acceptance_e98_20261024_r1_bundle'
BINDIR = '/cad/lsf/9.1/linux2.6-glibc2.3-x86_64/bin/'
MANIFEST_SHA256 = 'c6780832d3d0e62d030c4cc74814f2f9550be710ade154f40bf6ec0512bd29ef'
AUTH = 'contracts/prospective_acceptance_authorization_e98_20261024.json'
AUTH_SHA256 = 'da27486a2ed20d55c8b8de7071882364c9648ab49054d2a319d07cb2a73076f5'
CONFIG_SHA256 = '3f1babe5cb5ce50a5fe08a86b9befa3f28f6ba73e96c5cd180e5add540bdf76b'
RETIREMENT_PATH = '/temp/jiangchuanc/gnn_model_acceptance_e98_20261024_r1_control/retirement_result.json'
RETIREMENT_SHA256 = 'c88cb018b0138096235d62fcc1c86a29aab4349434e219db7903f6d206a98d82'
MODULES = ('prospective_acceptance_materializer_v1', 'prospective_acceptance_process_v1',
    'prospective_acceptance_coordinator_v1', 'prospective_acceptance_scratch_v1',
    'prospective_lsf_memory_preflight_v1', 'prospective_fault_translation_v2',
    'prospective_tessent_acceptance_v1')
TESTS = ('prospective_acceptance_materializer_v1', 'prospective_acceptance_process_v1',
    'prospective_acceptance_coordinator_v1', 'prospective_acceptance_scratch_v1',
    'prospective_lsf_memory_preflight_v1', 'prospective_acceptance_linux_e97')
FILES = frozenset(tuple('src/data/' + n + '.py' for n in MODULES) +
    tuple('tests/test_' + n + '.py' for n in TESTS) + (
    'src/__init__.py', 'src/data/__init__.py', 'tests/__init__.py', 'scripts/__init__.py',
    'tests/test_prospective_acquisition_tree_inputs_e85.py',
    'scripts/probe_acquisition_tree_inputs_e85.py', 'scripts/run_acceptance_job_e98.py', AUTH,
    'data/manifests/ranking_v6_e85_input_observation_20261023_r1.json',
    'data/manifests/ranking_v6_e93_input_observation_20261023_r1.json'))
EXECUTABLE_METADATA = {
    'bsub': (1049094, 4806296, 1404903280000000000),
    'bjobs': (1049093, 3325944, 1405069844000000000),
    'blaunch': (1049092, 3082016, 1404504459000000000)}
CLIENT_CAP = 8192  # Two clients together cannot exceed the approved 16 KiB.


class RegisterError(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise RegisterError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _pairs(rows):
    result = {}
    for key, value in rows:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def _directory(path):
    require(path.startswith('/') and os.path.normpath(path) == path, 'PATH_CANONICAL')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.split('/')[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read(path, cap):
    parent = _directory(path.rsplit('/', 1)[0])
    fd = None
    try:
        name = path.rsplit('/', 1)[1]
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                0 <= before.st_size <= cap, 'FILE_TYPE_OR_BOUND')
        raw = bytearray()
        while len(raw) < before.st_size:
            chunk = os.read(fd, min(65536, before.st_size - len(raw)))
            require(bool(chunk), 'FILE_SHORT_READ')
            raw.extend(chunk)
        after = os.fstat(fd)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                and after.st_nlink == 1 and (named.st_dev, named.st_ino) ==
                (after.st_dev, after.st_ino), 'FILE_CHANGED')
        return bytes(raw), before
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def _verify_retirement():
    require(re.fullmatch('[0-9a-f]{64}', RETIREMENT_SHA256) is not None,
            'RETIRED_JOB_PROOF_PIN_REQUIRED')
    raw, _ = _read(RETIREMENT_PATH, 16384)
    require(sha(raw) == RETIREMENT_SHA256, 'RETIRED_JOB_PROOF_CHANGED')
    proof = json.loads(raw.decode('ascii'), object_pairs_hook=_pairs)
    require(type(proof) is dict and proof.get('schema') == 'e98-old-job-retirement-result-v1'
        and type(proof.get('job_id')) is int and proof['job_id'] == 394230
        and proof.get('terminal_confirmed') is True and proof.get('terminal_state') in ('DONE', 'EXIT')
        and proof.get('authorization_sha256') == AUTH_SHA256
        and type(proof.get('cancellation_attempted')) is bool
        and type(proof.get('latest_bjobs_stdout_bytes')) is int and 0 < proof['latest_bjobs_stdout_bytes'] <= 8192
        and type(proof.get('latest_bjobs_stdout_sha256')) is str
        and re.fullmatch('[0-9a-f]{64}', proof['latest_bjobs_stdout_sha256']) is not None,
        'RETIRED_JOB_TERMINAL_REQUIRED')
    return RETIREMENT_SHA256


def _verify():
    _verify_retirement()
    raw, _ = _read(ROOT + '/e98_code_manifest.json', 65536)
    require(sha(raw) == MANIFEST_SHA256, 'MANIFEST_PIN')
    manifest = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs)
    require(type(manifest) is dict and set(manifest) == {'schema', 'files'} and
            manifest['schema'] == 'e98-code-manifest-v1' and
            type(manifest['files']) is dict and set(manifest['files']) == FILES,
            'MANIFEST_MEMBERS')
    total = len(raw)
    for name in sorted(FILES):
        digest = manifest['files'][name]
        require(type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest), 'MEMBER_PIN_FORMAT')
        content, _ = _read(ROOT + '/' + name, 1048576 - total)
        total += len(content)
        require(total <= 1048576 and sha(content) == digest, 'MEMBER_PIN')
        if name == AUTH:
            require(sha(content) == AUTH_SHA256, 'AUTHORIZATION_PIN')
    config, _ = _read('/cad/lsf/conf/lsf.conf', 262144)
    require(sha(config) == CONFIG_SHA256, 'FRESH_CONFIG_PIN')
    units = []
    for line in config.splitlines():
        line = line.strip()
        if re.match(rb'LSF_UNIT_FOR_LIMITS(?:\s|=|$)', line):
            units.append(line)
    require(len(units) == 1 and re.fullmatch(rb'LSF_UNIT_FOR_LIMITS\s*=\s*MB\s*(?:#.*)?',
                                          units[0]), 'EXPLICIT_MB_REQUIRED')
    for name, (ino, size, mtime) in EXECUTABLE_METADATA.items():
        # Metadata only: never read executable bodies.
        parent = _directory(BINDIR.rstrip('/'))
        try:
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                 info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) ==
                (43, ino, size, mtime, 0, 10007, 0o755), 'EXECUTABLE_METADATA')
        finally:
            os.close(parent)
    return total


def _argv():
    return [BINDIR + 'bsub', '-H', '-rn', '-n', '1', '-q', 'normal', '-m', 'bupt-vncs2',
        '-J', 'gnn_e98_acceptance_r1', '-M', '512', '-R', 'rusage[mem=512] span[hosts=1]',
        '-W', '45', '-cwd', ROOT, '-oo', ROOT + '/registration/stdout.log',
        '-eo', ROOT + '/registration/stderr.log', BINDIR + 'blaunch', '/usr/bin/python3',
        '-I', '-S', '-B', ROOT + '/scripts/run_acceptance_job_e98.py']


def _persist(directory, name, raw):
    require(len(raw) <= 16384, 'ARTIFACT_BOUND')
    fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                 dir_fd=directory)
    try:
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            require(type(count) is int and 0 < count <= len(raw) - offset, 'ARTIFACT_SHORT_WRITE')
            offset += count
        os.fsync(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        readback = bytearray()
        while len(readback) < len(raw):
            chunk = os.read(fd, len(raw) - len(readback))
            require(bool(chunk), 'ARTIFACT_READBACK_SHORT')
            readback.extend(chunk)
        info = os.fstat(fd)
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == len(raw)
            and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600
            and bytes(readback) == raw and
            (info.st_dev, info.st_ino) == (named.st_dev, named.st_ino), 'ARTIFACT_IDENTITY')
    finally:
        os.close(fd)
    os.fsync(directory)


def _client(argv):
    """Capture a fixed client only; kill that client on bound, never any job."""
    started = time.monotonic()
    deadline = started + 30
    child = None
    output = {'stdout': bytearray(), 'stderr': bytearray()}
    status = 'CLIENT_SPAWN_UNKNOWN'
    returncode = None
    try:
        environment = dict(os.environ)
        environment.update(LANG='C', LC_ALL='C')
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, close_fds=True, shell=False, env=environment)
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ, 'stdout')
            selector.register(child.stderr, selectors.EVENT_READ, 'stderr')
            while selector.get_map():
                remaining = CLIENT_CAP - sum(len(value) for value in output.values())
                require(remaining > 0, 'CLIENT_OUTPUT_BOUND')
                require(time.monotonic() < deadline - 5, 'CLIENT_TIMEOUT')
                for key, _ in selector.select(0.1):
                    remaining = CLIENT_CAP - sum(len(value) for value in output.values())
                    require(remaining > 0, 'CLIENT_OUTPUT_BOUND')
                    chunk = os.read(key.fileobj.fileno(), min(4096, remaining))
                    if chunk:
                        output[key.data].extend(chunk)
                    else:
                        selector.unregister(key.fileobj)
            returncode = child.wait(timeout=max(0.001, deadline - 5 - time.monotonic()))
        status = 'CLIENT_COMPLETE'
    except BaseException:
        status = 'CLIENT_FAILURE_UNKNOWN'
    finally:
        if child is not None:
            if child.poll() is None:
                try:
                    child.kill()  # This is the scheduler CLIENT PID, not a job or process group.
                    child.wait(timeout=max(0.001, deadline - time.monotonic()))
                except BaseException:
                    status = 'CLIENT_CLEANUP_UNCONFIRMED'
            returncode = child.poll()
            for pipe in (child.stdout, child.stderr):
                if pipe is not None:
                    pipe.close()
    return dict(status=status, returncode=returncode,
                stdout=bytes(output['stdout']), stderr=bytes(output['stderr']))


def _submission_id(result):
    if result['status'] != 'CLIENT_COMPLETE' or type(result['returncode']) is not int or result['returncode'] != 0:
        return None
    match = re.fullmatch(rb'Job <([1-9][0-9]{0,18})> is submitted to queue <normal>\.\n?', result['stdout'])
    if match is None:
        return None
    value = int(match.group(1))
    return value if value < 2**63 else None


def _json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False).encode('ascii')


def register():
    require(sys.platform.startswith('linux') and platform.node() == 'bupt-vncs2', 'LINUX_HOST_REQUIRED')
    verified_bytes = _verify()
    root = _directory(ROOT)
    directory = None
    try:
        os.mkdir('registration', 0o700, dir_fd=root)
        os.fsync(root)
        directory = os.open('registration', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
        info = os.fstat(directory)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
                stat.S_IMODE(info.st_mode) == 0o700, 'REGISTRATION_DIRECTORY')
        argv = _argv()
        _persist(directory, 'intent.json', _json(dict(schema='e98-registration-intent-v1',
            argv=argv, manifest_sha256=MANIFEST_SHA256, fresh_config_sha256=CONFIG_SHA256,
            only_attempt_consumed_before_spawn=True, automatic_retries=0)))
        submission = _client(argv)  # Exactly one attempt, never retried even without an ID.
        _persist(directory, 'bsub_stdout.bin', submission['stdout'])
        _persist(directory, 'bsub_stderr.bin', submission['stderr'])
        job_id = _submission_id(submission)
        result = dict(schema='e98-held-registration-result-v1', job_id=job_id,
            jobs_submitted=1 if job_id is not None else None, submission_attempted=True,
            submission_status=submission['status'], submission_returncode=submission['returncode'],
            status='UNKNOWN_SUBMISSION_CONSUMED_NO_RETRY', automatic_retries=0,
            registration_review_passed=False, pre_resume_review_passed=False,
            automatic_resume=False, actual_job_memory_proof=False,
            manifest_sha256=MANIFEST_SHA256, verified_bundle_bytes=verified_bytes,
            program_launch_attempts=1)
        # Persist the submission outcome before any optional exact-ID inspection.
        _persist(directory, 'submission_result.json', _json(result))
        if job_id is not None:
            query = _client([BINDIR + 'bjobs', '-l', str(job_id)])
            _persist(directory, 'bjobs_stdout.bin', query['stdout'])
            _persist(directory, 'bjobs_stderr.bin', query['stderr'])
            result.update(status='REGISTERED_HELD_REVIEW_PENDING', program_launch_attempts=2,
                bjobs_status=query['status'], bjobs_returncode=query['returncode'],
                bjobs_stdout_bytes=len(query['stdout']), bjobs_stdout_sha256=sha(query['stdout']),
                bjobs_stderr_bytes=len(query['stderr']), bjobs_stderr_sha256=sha(query['stderr']))
        _persist(directory, 'result.json', _json(result))
        return result
    finally:
        if directory is not None:
            os.close(directory)
        os.close(root)
