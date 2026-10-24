"""Fail-closed E97 job entry. Importing this file grants no launch authority."""
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

ROOT = '/temp/jiangchuanc/gnn_model_acceptance_e97_20261024_r1_bundle'
AUTH = 'contracts/prospective_acceptance_authorization_e97_20261024.json'
AUTH_SHA256 = 'db9aa1bd63c7a3f7c9935ff4e99c2931041e59fb225b39e4338b06efd1619935'
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
                  + EMPTY + HELPERS + (AUTH, E85, E93, 'scripts/run_acceptance_job_e97.py'))
PERMIT_KEYS = frozenset(('schema', 'job_id', 'registration_review_passed',
    'pre_resume_review_passed', 'authorization_sha256', 'code_manifest_sha256',
    'issued_at_epoch'))


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
    require(permit['schema'] == 'e97-resume-permit-v1', 'PERMIT_SCHEMA')
    require(type(permit['job_id']) is int and 0 < permit['job_id'] < 2**63,
            'PERMIT_JOB_ID')
    require(permit['registration_review_passed'] is True and
            permit['pre_resume_review_passed'] is True, 'REVIEWS_REQUIRED')
    require(permit['authorization_sha256'] == AUTH_SHA256, 'AUTHORIZATION_PIN')
    require(type(permit['code_manifest_sha256']) is str and
            re.fullmatch('[0-9a-f]{64}', permit['code_manifest_sha256']), 'MANIFEST_PIN')
    require(type(permit['issued_at_epoch']) is int and
            0 <= time.time() - permit['issued_at_epoch'] <= 600, 'PERMIT_FRESHNESS')
    require(sys.platform.startswith('linux') and platform.node() == 'bupt-vncs2',
            'LINUX_HOST_REQUIRED')
    require(os.environ.get('LSB_JOBID') == str(permit['job_id']) and
            os.environ.get('LSB_JOBINDEX') in (None, '0'), 'EXACT_NONARRAY_JOB_REQUIRED')


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
    raw = _read(root_fd, 'e97_code_manifest.json', 65536)
    require(sha(raw) == permit['code_manifest_sha256'], 'MANIFEST_DIGEST')
    manifest = parse(raw)
    require(type(manifest) is dict and set(manifest) == {'schema', 'files'} and
            manifest['schema'] == 'e97-code-manifest-v1' and
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
            if name.endswith('.py') and name != 'scripts/run_acceptance_job_e97.py':
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


def _write_gate(runtime_fd, evidence):
    raw = json.dumps(evidence, sort_keys=True, ensure_ascii=True,
                     allow_nan=False).encode('ascii')
    require(len(raw) <= 131072, 'GATE_EVIDENCE_BOUND')
    fd = os.open('gate.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=runtime_fd)
    try:
        left = raw
        while left:
            count = os.write(fd, left)
            require(count > 0, 'GATE_SHORT_WRITE')
            left = left[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(runtime_fd)


def execute(permit, bundle_root):
    deadline = time.monotonic() + 2700
    require(bundle_root == ROOT, 'FIXED_BUNDLE_REQUIRED')
    validate_permit(permit)
    root_fd = _directory(bundle_root)
    runtime_fd = None
    loader = None
    previous = {k: os.environ.get(k) for k in ('TMPDIR', 'E97_SYNTHETIC_JOB_GATE')}
    try:
        snapshot = verify_bundle(root_fd, permit)
        require(not any(n in ('src', 'tests', 'scripts') or
                        n.startswith(('src.', 'tests.', 'scripts.'))
                        for n in sys.modules), 'ISOLATED_PROCESS_REQUIRED')
        loader = SnapshotLoader(snapshot)
        sys.meta_path.insert(0, loader)
        preflight = importlib.import_module('src.data.prospective_lsf_memory_preflight_v1')
        proof = preflight.collect_preflight(permit['job_id'], 536870912)
        require(proof.get('memory_preflight_passed') is True, 'ACTUAL_PREFLIGHT_REQUIRED')
        os.mkdir('runtime', 0o700, dir_fd=root_fd)
        os.fsync(root_fd)
        runtime_fd = os.open('runtime', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=root_fd)
        os.environ['TMPDIR'] = ROOT + '/runtime'
        os.environ['E97_SYNTHETIC_JOB_GATE'] = str(permit['job_id'])
        import tempfile
        tempfile.tempdir = None
        gate = _gate(permit['job_id'])
        gate['memory_preflight'] = proof
        _write_gate(runtime_fd, gate)
        require(gate.get('passed') is True, 'SYNTHETIC_GATE_FAILED')
        require(time.monotonic() < deadline, 'JOB_WALL_BUDGET')
        coordinator = importlib.import_module('src.data.prospective_acceptance_coordinator_v1')
        plan = coordinator.recipes.compile_acceptance(snapshot[E85], snapshot[E93],
            coordinator.recipes.E85_SHA256, coordinator.recipes.E93_SHA256)
        authority = dict(schema=coordinator.AUTH_SCHEMA, approved=True,
            job_id=permit['job_id'], memory_cap_bytes=536870912,
            recipe_sha256=plan['recipe_sha256'], scope=coordinator.SCOPE)
        process = importlib.import_module('src.data.prospective_acceptance_process_v1')
        license_environment = {key: os.environ[key] for key in process.LICENSE_KEYS
                               if key in os.environ}
        return coordinator.run_package(snapshot[E85], snapshot[E93], authority,
            license_environment=license_environment, package_deadline=deadline)
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
        permit = parse(_read(fd, 'e97_resume_permit.json', 65536))
    finally:
        os.close(fd)
    result = execute(permit, ROOT)
    summary = dict(schema='e97-job-terminal-v1', status=result.get('status'),
        receipt_count=len(result.get('receipts', [])),
        actual_atpg_calls=result.get('actual_atpg_calls'), training_release=False)
    raw = json.dumps(summary, sort_keys=True, ensure_ascii=True)
    require(len(raw.encode('ascii')) <= 4096, 'TERMINAL_BOUND')
    print(raw)


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        print('{"schema":"e97-job-terminal-v1","status":"FAILED","training_release":false}')
        sys.exit(1)
