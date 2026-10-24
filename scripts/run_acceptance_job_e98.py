"""Fail-closed E98 job entry. Importing this file grants no launch authority."""
import hashlib
import contextlib
import importlib
import importlib.abc
import importlib.util
import io
import json
import os
import platform
import re
import stat
import sys
import time
import unittest

ROOT = '/temp/jiangchuanc/gnn_model_acceptance_e98_20261024_r1_bundle'
E98_ACCEPTANCE_ROOT = '/temp/jiangchuanc/multimode_ate_acceptance_e98_20261024_r1'
QUEUE_LEASE = 86400
REVIEW_AGE = 300
AUTH = 'contracts/prospective_acceptance_authorization_e98_20261024.json'
AUTH_SHA256 = 'da27486a2ed20d55c8b8de7071882364c9648ab49054d2a319d07cb2a73076f5'
E85 = 'data/manifests/ranking_v6_e85_input_observation_20261023_r1.json'
E93 = 'data/manifests/ranking_v6_e93_input_observation_20261023_r1.json'
TEST_MODULES = tuple('tests.test_' + name for name in (
    'prospective_acceptance_materializer_v1', 'prospective_acceptance_process_v1',
    'prospective_acceptance_coordinator_v1', 'prospective_acceptance_scratch_v1',
    'prospective_lsf_memory_preflight_v1', 'prospective_acceptance_linux_e97'))
MODULES = tuple('src.data.' + name for name in (
    'prospective_acceptance_materializer_v1', 'prospective_acceptance_process_v1',
    'prospective_acceptance_coordinator_v1', 'prospective_acceptance_scratch_v1',
    'prospective_lsf_memory_preflight_v1', 'prospective_fault_translation_v2',
    'prospective_tessent_acceptance_v1'))
EMPTY = ('src/__init__.py', 'src/data/__init__.py', 'tests/__init__.py',
         'scripts/__init__.py')
HELPERS = ('tests/test_prospective_acquisition_tree_inputs_e85.py',
           'scripts/probe_acquisition_tree_inputs_e85.py')
FILES = frozenset(tuple(n.replace('.', '/') + '.py' for n in MODULES + TEST_MODULES)
                  + EMPTY + HELPERS + (AUTH, E85, E93, 'scripts/run_acceptance_job_e98.py'))
PERMIT_KEYS = frozenset(('schema', 'job_id', 'authorization_sha256', 'code_manifest_sha256',
    'recipe_sha256', 'registration_review_sha256', 'pre_resume_review_sha256',
    'resume_intent_sha256', 'issued_at_epoch', 'queue_start_lease_seconds'))
REVIEW_KEYS = frozenset(('schema', 'stage', 'job_id', 'passed', 'independent', 'reviewer',
    'reviewed_at_epoch', 'authorization_sha256', 'code_manifest_sha256', 'recipe_sha256',
    'registration_evidence_sha256', 'observation_sha256'))
INTENT_KEYS = frozenset(('schema', 'job_id', 'issued_at_epoch', 'authorization_sha256',
    'code_manifest_sha256', 'recipe_sha256', 'registration_review_sha256',
    'pre_resume_review_sha256', 'observation_sha256', 'registration_evidence_sha256',
    'queue_start_lease_seconds', 'resume_attempt_consumed', 'automatic_retries'))


class EntryError(Exception):
    pass


def require(ok, code):
    if not ok:
        raise EntryError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _pairs(rows):
    result = {}
    for key, value in rows:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def parse(raw):
    return json.loads(raw.decode('ascii'), object_pairs_hook=_pairs)


def validate_permit(permit):
    require(type(permit) is dict and set(permit) == PERMIT_KEYS, 'PERMIT_KEYS')
    require(permit['schema'] == 'e98-queue-permit-v1', 'PERMIT_SCHEMA')
    require(type(permit['job_id']) is int and 0 < permit['job_id'] < 2**63,
            'PERMIT_JOB_ID')
    require(permit['authorization_sha256'] == AUTH_SHA256, 'AUTHORIZATION_PIN')
    require(all(type(permit[key]) is str and re.fullmatch('[0-9a-f]{64}', permit[key])
                for key in ('code_manifest_sha256', 'recipe_sha256',
                    'registration_review_sha256', 'pre_resume_review_sha256',
                    'resume_intent_sha256')), 'PERMIT_PINS')
    require(type(permit['queue_start_lease_seconds']) is int and
            permit['queue_start_lease_seconds'] == QUEUE_LEASE, 'FIXED_QUEUE_LEASE')
    require(type(permit['issued_at_epoch']) is int and
            0 <= time.time() - permit['issued_at_epoch'] <= QUEUE_LEASE, 'QUEUE_LEASE_EXPIRED_OR_FUTURE')
    require(sys.platform.startswith('linux') and platform.node() == 'bupt-vncs2',
            'LINUX_HOST_REQUIRED')
    require(os.environ.get('LSB_JOBID') == str(permit['job_id']) and
            os.environ.get('LSB_JOBINDEX') in (None, '0'), 'EXACT_NONARRAY_JOB_REQUIRED')
    require(os.environ.get('LSB_DJOB_NUMPROC') == '1' and
            os.environ.get('LSB_MCPU_HOSTS', '').split() == ['bupt-vncs2', '1'],
            'ACTUAL_SINGLE_WORKER_ENV_REQUIRED')


def validate_review_chain(permit, registration_raw, pre_resume_raw, intent_raw):
    """Review freshness is measured at consumed resume intent, not worker start."""
    for raw, key in ((registration_raw, 'registration_review_sha256'),
                     (pre_resume_raw, 'pre_resume_review_sha256'),
                     (intent_raw, 'resume_intent_sha256')):
        require(type(raw) is bytes and len(raw) <= 16384 and sha(raw) == permit[key], 'REVIEW_CHAIN_PIN')
    intent = parse(intent_raw)
    require(type(intent) is dict and set(intent) == INTENT_KEYS and
            intent['schema'] == 'e98-resume-intent-v1', 'RESUME_INTENT_SCHEMA')
    binding = ('job_id', 'issued_at_epoch', 'authorization_sha256', 'code_manifest_sha256',
               'recipe_sha256', 'registration_review_sha256', 'pre_resume_review_sha256',
               'queue_start_lease_seconds')
    require(all(type(intent[k]) is type(permit[k]) and intent[k] == permit[k] for k in binding)
            and intent['resume_attempt_consumed'] is True and
            type(intent['automatic_retries']) is int and intent['automatic_retries'] == 0,
            'RESUME_INTENT_BINDING')
    for key in ('registration_evidence_sha256', 'observation_sha256'):
        require(type(intent[key]) is str and re.fullmatch('[0-9a-f]{64}', intent[key]), 'INTENT_EVIDENCE_PIN')
    for stage, raw in (('registration', registration_raw), ('pre_resume', pre_resume_raw)):
        receipt = parse(raw)
        require(type(receipt) is dict and set(receipt) == REVIEW_KEYS and
                receipt['schema'] == 'e98-independent-review-v1' and receipt['stage'] == stage,
                'REVIEW_SCHEMA')
        require(receipt['passed'] is True and receipt['independent'] is True and
                type(receipt['reviewer']) is str and re.fullmatch('[A-Za-z0-9_.-]{1,64}', receipt['reviewer']),
                'INDEPENDENT_REVIEW_REQUIRED')
        for key in ('job_id', 'authorization_sha256', 'code_manifest_sha256', 'recipe_sha256'):
            require(type(receipt[key]) is type(permit[key]) and receipt[key] == permit[key], 'REVIEW_BINDING')
        require(receipt['registration_evidence_sha256'] == intent['registration_evidence_sha256'] and
                type(receipt['observation_sha256']) is str and
                re.fullmatch('[0-9a-f]{64}', receipt['observation_sha256']), 'REVIEW_EVIDENCE_BINDING')
        reviewed = receipt['reviewed_at_epoch']
        require(type(reviewed) is int and 0 <= reviewed <= intent['issued_at_epoch'], 'REVIEW_TIME')
        if stage == 'pre_resume':
            require(0 <= intent['issued_at_epoch'] - reviewed <= REVIEW_AGE and
                    receipt['observation_sha256'] == intent['observation_sha256'], 'FRESH_REVIEW_AT_RESUME_REQUIRED')
    return intent


def _directory(path):
    """Open every absolute path component without following any symlink."""
    require(os.path.isabs(path) and os.path.normpath(path) == path, 'ROOT_PATH')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.split('/')[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read(root_fd, name, cap):
    require(name and not name.startswith('/') and
            all(p not in ('', '.', '..') for p in name.split('/')), 'UNSAFE_MEMBER')
    parent = os.dup(root_fd)
    fd = None
    try:
        parts = name.split('/')
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=parent)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                before.st_size <= cap, 'MEMBER_TYPE_OR_SIZE')
        chunks = []
        count = 0
        while count < before.st_size:
            chunk = os.read(fd, min(65536, before.st_size - count))
            require(bool(chunk), 'MEMBER_SHORT_READ')
            chunks.append(chunk)
            count += len(chunk)
            require(count <= cap, 'MEMBER_BOUND')
        after = os.fstat(fd)
        named = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns) and
                count == before.st_size and after.st_nlink == 1 and
                (after.st_dev, after.st_ino) == (named.st_dev, named.st_ino),
                'MEMBER_CHANGED')
        return b''.join(chunks)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def verify_bundle(root_fd, permit):
    raw = _read(root_fd, 'e98_code_manifest.json', 65536)
    require(sha(raw) == permit['code_manifest_sha256'], 'MANIFEST_DIGEST')
    manifest = parse(raw)
    require(type(manifest) is dict and set(manifest) == {'schema', 'files'} and
            manifest['schema'] == 'e98-code-manifest-v1' and
            type(manifest['files']) is dict and set(manifest['files']) == FILES,
            'MANIFEST_MEMBERS')
    snapshot = {}
    total = len(raw)
    for name in sorted(FILES):
        digest = manifest['files'][name]
        require(type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest), 'MEMBER_DIGEST')
        value = _read(root_fd, name, 1048576 - total)
        total += len(value)
        require(total <= 1048576 and sha(value) == digest, 'MEMBER_DIGEST_OR_BUDGET')
        snapshot[name] = value
    require(all(snapshot[n] == b'' for n in EMPTY), 'NONEMPTY_PACKAGE_INIT')
    require(sha(snapshot[AUTH]) == AUTH_SHA256, 'AUTHORIZATION_DIGEST')
    return snapshot


class SnapshotLoader(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Execute verified source bytes, never a later filesystem replacement."""
    def __init__(self, snapshot):
        self.sources = {}
        for name, raw in snapshot.items():
            if name.endswith('.py') and name != 'scripts/run_acceptance_job_e98.py':
                module = name[:-3].replace('/', '.')
                package = module.endswith('.__init__')
                self.sources[module[:-9] if package else module] = (name, raw, package)

    def find_spec(self, fullname, path=None, target=None):
        if fullname in self.sources:
            return importlib.util.spec_from_loader(fullname, self,
                is_package=self.sources[fullname][2])
        if (fullname in ('src', 'tests', 'scripts') or
                fullname.startswith(('src.', 'tests.', 'scripts.'))):
            raise EntryError('UNVERIFIED_IMPORT')

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        name, raw, package = self.sources[module.__name__]
        module.__file__ = ROOT + '/' + name
        if package:
            module.__path__ = [os.path.dirname(module.__file__)]
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)


class BoundedLog(io.StringIO):
    def write(self, value):
        require(len((self.getvalue() + value).encode('utf-8')) <= 65536, 'GATE_LOG_BOUND')
        return super(BoundedLog, self).write(value)


def _gate(job_id):
    stream = BoundedLog()
    try:
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            suite = unittest.TestLoader().loadTestsFromNames(TEST_MODULES)
            result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
        summary = dict(tests=result.testsRun, skipped=len(result.skipped),
                       failures=len(result.failures), errors=len(result.errors))
    except Exception:
        summary = dict(tests=0, skipped=0, failures=0, errors=1)
    passed = summary['tests'] >= 1 and not any(summary[k] for k in
            ('skipped', 'failures', 'errors'))
    return dict(summary=summary, raw_log=stream.getvalue(), system=platform.system(),
                kernel=platform.release(), python=sys.version, job_id=job_id, passed=passed)


def _write_record(runtime_fd, name, evidence, cap=131072):
    raw = json.dumps(evidence, sort_keys=True, ensure_ascii=True,
                     allow_nan=False).encode('ascii')
    require(len(raw) <= cap, 'RECORD_EVIDENCE_BOUND')
    fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=runtime_fd)
    try:
        left = raw
        while left:
            count = os.write(fd, left)
            require(count > 0, 'GATE_SHORT_WRITE')
            left = left[count:]
        os.fsync(fd)
        info = os.fstat(fd)
        named = os.stat(name, dir_fd=runtime_fd, follow_symlinks=False)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                info.st_size == len(raw) and (info.st_dev, info.st_ino) ==
                (named.st_dev, named.st_ino) and os.pread(fd, len(raw), 0) == raw,
                'RECORD_DURABLE_READBACK')
    finally:
        os.close(fd)
    os.fsync(runtime_fd)


def _write_gate(runtime_fd, evidence):
    _write_record(runtime_fd, 'gate.json', evidence)


def bind_e98_recipe(recipe, materializer, raw_e85, raw_e93, expected_sha256):
    """One explicit in-memory adapter, after the unchanged six-module gate.

    Immutable E96 source bytes remain unchanged. Only this isolated worker's
    verified module objects receive the E98 root and its exact compiled pin.
    This adapter performs no filesystem operations or component initialization.
    """
    require(recipe.ROOT == '/temp/jiangchuanc/multimode_ate_acceptance_e94_20261023_r1'
            and materializer.RECIPE_SHA256 ==
            '67c927c315354adf9ad09466fa679e46c3417d64065d0cb44819af8a3e65271e', 'BASE_RECIPE_STATE')
    require(materializer.compiler is recipe, 'SINGLE_RECIPE_MODULE')
    recipe.ROOT = E98_ACCEPTANCE_ROOT
    plan = recipe.compile_acceptance(raw_e85, raw_e93, recipe.E85_SHA256, recipe.E93_SHA256)
    require(plan['root'] == E98_ACCEPTANCE_ROOT and plan['recipe_sha256'] == expected_sha256,
            'E98_RECIPE_PIN')
    require(len(plan['items']) == 4, 'E98_FOUR_CASES_ONLY')
    for item in plan['items']:
        for key in ('future_scratch', 'tcl_path', 'cwd', 'translated_status_path',
                    'translation_manifest_path', 'isolated_tsdb_copy'):
            require(item[key].startswith(E98_ACCEPTANCE_ROOT + '/'), 'E98_OUTPUT_PATH')
    materializer.RECIPE_SHA256 = expected_sha256
    return plan


SAFE_FAILURE_CODES = frozenset(('APPROVED_HARD_CAP', 'MEMORY_LIMIT', 'MEMSW_LIMIT',
    'HIERARCHY_REQUIRED', 'CHAIN_HIERARCHY_REQUIRED', 'JOB_BINDING',
    'LSB_JOBID_MISMATCH', 'LSB_JOB_ARRAY_UNSUPPORTED', 'CGROUP_MEMSW_MISSING',
    'ROOT_OR_JOB_WRITE_ACCESS', 'PROC_REREAD_CHANGED', 'PROCESS_IDENTITY_CHANGED',
    'CURRENT_PID_NOT_IN_WORKER_CGROUP', 'ACTUAL_PREFLIGHT_REQUIRED',
    'ACTUAL_SINGLE_WORKER_ENV_REQUIRED', 'EXACT_NONARRAY_JOB_REQUIRED',
    'QUEUE_LEASE_EXPIRED_OR_FUTURE', 'FIXED_QUEUE_LEASE',
    'SYNTHETIC_GATE_FAILED', 'JOB_WALL_BUDGET', 'E98_RECIPE_PIN'))


def safe_failure(stage, exc):
    code = str(exc)
    return dict(schema='e98-worker-failure-v1', stage=stage,
        code=code if code in SAFE_FAILURE_CODES else 'STAGE_FAILED',
        actual_atpg_calls=0, training_release=False)


def execute(permit, bundle_root):
    deadline = time.monotonic() + 2700
    require(bundle_root == ROOT, 'FIXED_BUNDLE_REQUIRED')
    require(type(permit) is dict and set(permit) == PERMIT_KEYS and
            type(permit['job_id']) is int and 0 < permit['job_id'] < 2**63, 'PERMIT_STRUCTURE')
    root_fd = _directory(bundle_root)
    runtime_fd = None
    loader = None
    stage = 'SOURCE_GATE'
    previous = {k: os.environ.get(k) for k in ('TMPDIR', 'E97_SYNTHETIC_JOB_GATE')}
    try:
        snapshot = verify_bundle(root_fd, permit)
        registration_raw = _read(root_fd, 'e98_registration_review.json', 16384)
        pre_resume_raw = _read(root_fd, 'e98_pre_resume_review.json', 16384)
        intent_raw = _read(root_fd, 'e98_resume_intent.json', 16384)
        validate_review_chain(permit, registration_raw, pre_resume_raw, intent_raw)
        # Exclusive durable claim consumes the only worker start, even on failure.
        _write_record(root_fd, 'e98_worker_start.json', dict(schema='e98-worker-start-v1',
            job_id=permit['job_id'], pid=os.getpid(), consumed=True,
            permit_sha256=sha(json.dumps(permit, sort_keys=True, separators=(',', ':')).encode('ascii'))), 4096)
        os.mkdir('runtime', 0o700, dir_fd=root_fd)
        os.fsync(root_fd)
        runtime_fd = os.open('runtime', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=root_fd)
        stage = 'WORKER_IDENTITY'
        # Runtime/lease failures also consume the sole authenticated worker start.
        validate_permit(permit)
        require(not any(n in ('src', 'tests', 'scripts') or
                        n.startswith(('src.', 'tests.', 'scripts.'))
                        for n in sys.modules), 'ISOLATED_PROCESS_REQUIRED')
        loader = SnapshotLoader(snapshot)
        sys.meta_path.insert(0, loader)
        stage = 'KERNEL_PREFLIGHT'
        preflight = importlib.import_module('src.data.prospective_lsf_memory_preflight_v1')
        proof = preflight.collect_preflight(permit['job_id'], 536870912)
        require(proof.get('memory_preflight_passed') is True, 'ACTUAL_PREFLIGHT_REQUIRED')
        os.environ['TMPDIR'] = ROOT + '/runtime'
        os.environ['E97_SYNTHETIC_JOB_GATE'] = str(permit['job_id'])
        import tempfile
        tempfile.tempdir = None
        stage = 'LINUX_SYNTHETIC_GATE'
        gate = _gate(permit['job_id'])
        gate['memory_preflight'] = proof
        _write_gate(runtime_fd, gate)
        require(gate.get('passed') is True, 'SYNTHETIC_GATE_FAILED')
        require(time.monotonic() < deadline, 'JOB_WALL_BUDGET')
        stage = 'E98_RECIPE_BINDING'
        coordinator = importlib.import_module('src.data.prospective_acceptance_coordinator_v1')
        materializer = importlib.import_module('src.data.prospective_acceptance_materializer_v1')
        plan = bind_e98_recipe(coordinator.recipes, materializer, snapshot[E85], snapshot[E93],
                               permit['recipe_sha256'])
        authority = dict(schema=coordinator.AUTH_SCHEMA, approved=True,
            job_id=permit['job_id'], memory_cap_bytes=536870912,
            recipe_sha256=plan['recipe_sha256'], scope=coordinator.SCOPE)
        process = importlib.import_module('src.data.prospective_acceptance_process_v1')
        license_environment = {key: os.environ[key] for key in process.LICENSE_KEYS
                               if key in os.environ}
        stage = 'FOUR_NO_PATTERN_CASES'
        return coordinator.run_package(snapshot[E85], snapshot[E93], authority,
            license_environment=license_environment, package_deadline=deadline)
    except BaseException as exc:
        if runtime_fd is not None:
            try:
                _write_record(runtime_fd, 'failure.json', safe_failure(stage, exc), 4096)
            except BaseException:
                pass  # Never overwrite, repair, retry, or expose exception strings.
        raise
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        if loader is not None:
            sys.meta_path.remove(loader)
        if runtime_fd is not None:
            os.close(runtime_fd)
        os.close(root_fd)


def main():
    require(len(sys.argv) == 1, 'NO_CLI_ARGUMENTS')
    fd = _directory(ROOT)
    try:
        permit = parse(_read(fd, 'e98_resume_permit.json', 65536))
    finally:
        os.close(fd)
    result = execute(permit, ROOT)
    summary = dict(schema='e98-job-terminal-v1', status=result.get('status'),
        receipt_count=len(result.get('receipts', [])),
        actual_atpg_calls=result.get('actual_atpg_calls'), training_release=False)
    raw = json.dumps(summary, sort_keys=True, ensure_ascii=True)
    require(len(raw.encode('ascii')) <= 4096, 'TERMINAL_BOUND')
    print(raw)


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        print('{"schema":"e98-job-terminal-v1","status":"FAILED","training_release":false}')
        sys.exit(1)
