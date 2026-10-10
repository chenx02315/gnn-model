"""Sealed Linux TRAIN parent; never run without externally reviewed packet pins.

No ML is imported in this parent. The core fence stays unchanged. Supplemental
modules are compiled from independently pinned bytes and explicitly registered
only while that core fence owns the empty local namespaces. Real consent and
packet/release provenance must be independently verified outside this program.
Sampled RSS is not a hard cgroup limit or a hostile same-user sandbox.
"""
import argparse
from contextlib import contextmanager
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from types import ModuleType


PROGRAM = 'scripts/run_v5_train_serial_parent.py'
CLI = 'scripts/run_v5_train_single_fit.py'
CPU_PROGRAM = 'scripts/run_v5_controlled_runtime_gate.py'
FENCE = 'src/models/ranking_v5_frozen_import_fence.py'
FENCE_SHA = 'c8ba5ae9bc8f900a620b7eaf03e37e11f303d9fc8b08ccbc8c423682b0afafed'
OBS = 'src/models/ranking_v5_locked_runtime_observations.py'
CONTEXT = 'src/models/ranking_v5_locked_runtime_imports.py'
EXTRA = ('src/models/ranking_v5_train_artifact_readback.py',
         'src/models/ranking_v5_independent_fit_context.py',
         'src/models/ranking_v5_serial_matrix.py',
         'src/models/ranking_v5_parent_artifact_candidate.py')
INTERPRETER = '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/venv/bin/python'
SEARCH_PATHS = ('/usr/lib/python311.zip', '/usr/lib/python3.11', '/usr/lib/python3.11/lib-dynload',
    '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/venv/lib/python3.11/site-packages',
    '/ssd/cjc/gnn_model_runtime_v2_98efbd4f_20261002T235119/venv/lib/python3.11/site-packages')
ROOT_PATTERN = r'/ssd/cjc/gnn_model_ranking_v5_train_[0-9]{8}_r[1-9][0-9]*'
MANIFEST = 'launch_packet.json'
JSON_CAP = 20000
SOURCE_CAP = 65536
GLOBAL_LOCK = '/ssd/cjc/gnn_model_ranking_v5_serial_parent.lock'
CPU_PINS = {
    OBS: '0524a7b8cce7d017c3fe9fe38dcc86b29a440ed7b373c1c2361ebbb7738459c8',
    CONTEXT: 'b1bddbda1ef6ea2323a1b3face282fbb21cd1a01db64d68dff8deaa28308b1da',
    CPU_PROGRAM: '0a4bb0389cce25c2ac50f3adcc721ac2b2545acbf2d15df3c41d5ac8bca5c462'}
CPU_EVIDENCE = {
    'cpu_gate.child.json': '2044da0ef9c13741b390f6daaf945793701e37d767b0490d7f908449aeb7a87b',
    'cpu_gate.memory.json': '3cfe6dde7b0eb3c5f7bbc1396cb9c56c73449db6bacd4b86090950c724463c66',
    'cpu_gate.launch.json': '60a766bf23876ff589fb34c3ce657994c1ee68daa199912b502f75c61b80181b'}


def require(ok, code):
    if not ok:
        raise ValueError('V5_SERIAL_PARENT_' + code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def ordinary(info, directory=False):
    require(not stat.S_ISLNK(info.st_mode)
            and not getattr(info, 'st_file_attributes', 0) & 0x400, 'LINK')
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), 'ORDINARY')


def path_gate(path):
    path = Path(path)
    for ancestor in path.parents:
        ordinary(ancestor.lstat(), True)
    return path


def read(path, cap):
    path = path_gate(path)
    before = path.lstat(); ordinary(before)
    require(0 < before.st_size <= cap, 'FILE_BOUND')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno()); ordinary(opened)
        require((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) ==
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns), 'FILE_IDENTITY')
        raw = stream.read(cap+1)
        after = os.fstat(stream.fileno())
    final = path.lstat(); ordinary(final)
    require(0 < len(raw) == before.st_size <= cap and all(
        (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns) ==
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        for item in (after, final)), 'FILE_CHANGED')
    return raw


def external(name, raw):
    module = ModuleType(name)
    module.__file__ = 'sealed-parent://' + name
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


def bootstrap(root, program, program_sha):
    require(type(root) is str and re.fullmatch(ROOT_PATTERN, root) is not None, 'ROOT')
    require(program in (PROGRAM, CLI) and pin(program_sha), 'BOOTSTRAP')
    return ('import sys;assert sys.flags.no_site==1 and sys.flags.isolated==1;'
        + 'sys.path[:]=' + repr(list(SEARCH_PATHS)) + ';'
        + 'import os,hashlib,stat;from pathlib import Path;'
        + 'p=Path(' + repr(root+'/'+program) + ');'
        + 'assert all(stat.S_ISDIR(q.lstat().st_mode) for q in p.parents);'
        + 's=p.lstat();assert stat.S_ISREG(s.st_mode) and 0<s.st_size<=65536;'
        + 'f=p.open("rb");raw=f.read(65537);f.close();'
        + 'assert len(raw)==s.st_size and hashlib.sha256(raw).hexdigest()==' + repr(program_sha) + ';'
        + 'os.chdir("/ssd/cjc");exec(compile(raw,str(p),"exec"))')


def runtime():
    require(sys.platform == 'linux' and sys.executable == INTERPRETER
            and tuple(sys.version_info[:3]) == (3, 11, 2) and os.getcwd() == '/ssd/cjc', 'RUNTIME')
    require(sys.flags.no_site == 1 and sys.flags.isolated == 1
            and sys.path == list(SEARCH_PATHS) and 'sitecustomize' not in sys.modules
            and 'usercustomize' not in sys.modules, 'BOOTSTRAP_STATE')


def child_environment():
    """New local repair candidate: retain strict stdlib distutils admission.

    Setuptools 66.1.1 defaults to its own distutils redirect. Select its
    documented-in-installed-source stdlib branch instead of admitting another
    filesystem root or custom alias loader. No inherited environment is used.
    This candidate does not authorize a new remote invocation.
    """
    return dict(PATH='/usr/bin:/bin', LANG='C.UTF-8', LC_ALL='C.UTF-8',
        OMP_NUM_THREADS='1', MKL_NUM_THREADS='1', OPENBLAS_NUM_THREADS='1', NUMEXPR_NUM_THREADS='1',
        CUDA_VISIBLE_DEVICES='', PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1',
        SETUPTOOLS_USE_DISTUTILS='stdlib')


@contextmanager
def supplemental_aliases(sources, cli_module):
    """Inside core fence only; fixed explicit aliases, no disk discovery."""
    require(type(sources) is dict and set(sources) == set(EXTRA), 'EXTRA_SET')
    package = importlib.import_module('src.models')
    scripts = importlib.import_module('scripts')
    require(package.__path__ == [] and package.__spec__.origin == 'sealed://namespace/src.models',
            'CORE_FENCE_REQUIRED')
    require(scripts.__path__ == [] and scripts.__spec__.origin == 'sealed://namespace/scripts'
            and type(cli_module) is ModuleType, 'CORE_FENCE_REQUIRED')
    loaded = {}
    cli_name = 'scripts.run_v5_train_single_fit'
    require(cli_name not in sys.modules and not hasattr(scripts, 'run_v5_train_single_fit'), 'PRELOADED_CLI')
    try:
        sys.modules[cli_name] = cli_module
        setattr(scripts, 'run_v5_train_single_fit', cli_module)
        for path in EXTRA:
            name = path[:-3].replace('/', '.')
            short = name.rsplit('.', 1)[1]
            require(name not in sys.modules and not hasattr(package, short), 'PRELOADED_EXTRA')
            module = ModuleType(name)
            module.__file__ = 'sealed-parent://' + path
            sys.modules[name] = module
            loaded[name] = module
            exec(compile(sources[path], module.__file__, 'exec'), module.__dict__)
            setattr(package, short, module)
        yield tuple(loaded.values())
    finally:
        if sys.modules.get(cli_name) is cli_module:
            del sys.modules[cli_name]
        if getattr(scripts, 'run_v5_train_single_fit', None) is cli_module:
            delattr(scripts, 'run_v5_train_single_fit')
        for name, module in loaded.items():
            short = name.rsplit('.', 1)[1]
            if sys.modules.get(name) is module:
                del sys.modules[name]
            if getattr(package, short, None) is module:
                delattr(package, short)


@contextmanager
def global_worker_lock():
    """Nonblocking advisory cross-parent coordination; no hostile-user claim."""
    import fcntl
    path = path_gate(GLOBAL_LOCK)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        info = os.fstat(fd); ordinary(info)
        require(info.st_size == 0, 'LOCK_CONTENT')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = path.lstat(); ordinary(current)
        require((info.st_dev, info.st_ino) == (current.st_dev, current.st_ino), 'LOCK_CHANGED')
        yield
    finally:
        os.close(fd)


def absent(path):
    path = path_gate(path)
    require(not os.path.lexists(path), 'OUTPUT_EXISTS')


def write_once(path, payload):
    raw = json.dumps(payload, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()+b'\n'
    require(0 < len(raw) <= JSON_CAP, 'SUMMARY_BOUND')
    absent(path)
    with Path(path).open('xb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    require(read(path, JSON_CAP) == raw, 'SUMMARY_READBACK')


def load_packet(root, manifest_sha):
    """Authenticate all source and evidence bytes before package/outcome I/O."""
    require(type(root) is str and re.fullmatch(ROOT_PATTERN, root) is not None and pin(manifest_sha), 'ROOT_PIN')
    raw = read(Path(root)/MANIFEST, JSON_CAP)
    require(sha(raw) == manifest_sha, 'PACKET_SHA')
    # Authenticate the CLI from the separately pinned packet before using parser.
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'DUPLICATE')
            value[key] = item
        return value
    try:
        initial = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, RecursionError) as error:
        raise ValueError('V5_SERIAL_PARENT_PACKET_JSON') from error
    require(type(initial) is dict and type(initial.get('source_sha256')) is dict
            and pin(initial['source_sha256'].get(CLI)), 'CLI_PIN')
    cli_raw = read(Path(root)/CLI, SOURCE_CAP)
    require(sha(cli_raw) == initial['source_sha256'][CLI], 'CLI_SHA')
    cli = external('_v5_serial_train_cli', cli_raw)
    packet = cli._json(raw)
    require(set(packet) == {'schema', 'source_root', 'package_root', 'core_manifest_sha256',
        'source_sha256', 'evidence_sha256', 'prelaunch_sha256'}, 'PACKET_FIELDS')
    require(packet['schema'] == 'v5-train-serial-launch-packet-v1' and packet['source_root'] == root
            and packet['package_root'] == cli.PACKAGE_ROOT
            and packet['core_manifest_sha256'] == cli.CORE_MANIFEST_SHA256, 'PACKET_SCOPE')
    required = cli.CORE_FILES | {CLI, PROGRAM, CPU_PROGRAM, *cli.HELPERS, *EXTRA}
    pins = packet['source_sha256']
    require(type(pins) is dict and set(pins) == required and all(pin(p) for p in pins.values()), 'SOURCE_SET')
    require(all(pins[name] == value for name, value in CPU_PINS.items()), 'CPU_SOURCE_BINDING')
    require(pins[FENCE] == FENCE_SHA, 'FROZEN_FENCE_BINDING')
    source = {name: read(Path(root)/name, SOURCE_CAP) for name in sorted(required)}
    require(sum(map(len, source.values())) <= 1024**2
            and all(sha(source[name]) == pins[name] for name in required), 'SOURCE_BYTES')
    core_raw = cli._read(root, cli.MANIFEST_NAME, JSON_CAP)
    require(sha(core_raw) == cli.CORE_MANIFEST_SHA256, 'CORE_MANIFEST')
    core = cli._json(core_raw)
    require(type(core.get('sources')) is dict and set(core['sources']) == cli.CORE_FILES
            and all(pins[name] == value for name, value in core['sources'].items()), 'CORE_PINS')
    evidence_pins = packet['evidence_sha256']
    require(type(evidence_pins) is dict and set(evidence_pins) == set(cli.EVIDENCE) | set(CPU_EVIDENCE)
            and all(pin(p) for p in evidence_pins.values())
            and all(evidence_pins[name] == p for name, p in CPU_EVIDENCE.items()), 'EVIDENCE_PINS')
    evidence = {name: read(Path(root)/name, JSON_CAP) for name in sorted(evidence_pins)}
    require(all(sha(evidence[name]) == p for name, p in evidence_pins.items()), 'EVIDENCE_BYTES')
    envelopes = packet['prelaunch_sha256']
    names = {f'prelaunch_{f}_{s}.json' for f in cli.FAMILIES for s in cli.SEEDS}
    require(type(envelopes) is dict and set(envelopes) == names and all(pin(p) for p in envelopes.values()), 'ENVELOPE_SET')
    for family in sorted(cli.FAMILIES):
        for seed in cli.SEEDS:
            name = f'prelaunch_{family}_{seed}.json'
            item = cli._envelope(cli._read(root, name, JSON_CAP), envelopes[name], root,
                root+'_'+family+'_'+str(seed), cli.PACKAGE_ROOT, family, seed)
            require(item['helper_sha256'] == {p: pins[p] for p in cli.HELPERS}
                    and all(item[field] == evidence_pins[name] for name, field in cli.EVIDENCE.items()), 'ENVELOPE_PACKET')
    return cli, packet, source, evidence, core_raw


def run(root, manifest_sha):
    runtime()
    cli, packet, source, evidence, core_raw = load_packet(root, manifest_sha)
    fence = external('_v5_serial_fence', source[FENCE])
    python = {p: source[p] for p in cli.CORE_FILES if p.endswith('.py')}
    python_pins = {p: packet['source_sha256'][p] for p in python}
    env = child_environment()
    with global_worker_lock(), fence.sealed_imports(python, python_pins):
        from src.models import ranking_v5_caller_source_binding as binder
        from src.models import ranking_v5_approval_binding as approval
        from src.models import ranking_v5_bound_input_reader as inputs
        from src.models import ranking_v5_parent_guard_receipt as guard_receipt
        from src.models import ranking_v4_memory_guard as guard
        binder.validate_source_bytes(core_raw, {p: source[p] for p in cli.CORE_FILES},
                                     trusted_manifest_sha256=cli.CORE_MANIFEST_SHA256)
        release = cli._json(evidence['release.json'])
        expected = {p: packet['source_sha256'][p] for p in cli.RELEASE_SOURCE_FILES}
        anchors = dict(trusted_authorization_sha256=cli.AUTHORIZATION_SHA256,
            trusted_review_sha256=packet['evidence_sha256']['review.json'],
            trusted_physical_gate_sha256=packet['evidence_sha256']['physical_gate.json'])
        approval.validate_approval_integrity(release, expected, evidence['authorization.json'],
                                            evidence['review.json'], **anchors)
        cpu = external('_v5_serial_cpu_evidence', source[CPU_PROGRAM])
        cpu_child = cli._json(evidence['cpu_gate.child.json'])
        cpu.validate_child(cpu_child, CPU_PINS)
        cpu_launch = cli._json(evidence['cpu_gate.launch.json'])
        cpu_memory = cli._json(evidence['cpu_gate.memory.json'])
        guard_receipt.validate_parent_guard_receipt(cpu_launch['parent_guard_receipt'], cpu_memory)
        require(cpu_launch['child_receipt_sha256'] == CPU_EVIDENCE['cpu_gate.child.json']
                and cpu.typed_equal(cpu_launch['child_receipt'], cpu_child), 'CPU_RECEIPT')
        with supplemental_aliases({p: source[p] for p in EXTRA}, cli) as (_, binding, matrix, collector):
            tasks = matrix.build_train_matrix(root)
            for task in tasks:
                for path in (task.output, task.output+'.stdout.log', task.output+'.stdout.log.memory.json'):
                    absent(path)
            write_once(Path(root)/'matrix.started.json', dict(schema='v5-serial-started-v1',
                packet_sha256=manifest_sha, planned_fits=18, roles=['TRAIN'], automatic_retries=0))
            contexts = {}
            try:
                for task in tasks:
                    loaded = inputs.load_bound_fold_request(cli.PACKAGE_ROOT, task.family, task.seed)
                    contexts[(task.family, task.seed)] = binding.build_independent_fit_context(
                        loaded['request'], release, expected, loaded['input_identity'],
                        evidence['authorization.json'], evidence['review.json'],
                        family=task.family, seed=task.seed, **anchors)
                    del loaded
            except BaseException as error:
                write_once(Path(root)/'matrix.final.json', dict(schema='v5-serial-parent-result-v1',
                    packet_sha256=manifest_sha, status='STOPPED_PREFLIGHT_NO_RETRY',
                    completed_count=0, preflight_context_count=len(contexts),
                    failure_kind=type(error).__name__[:64], automatic_retries=0,
                    actual_parent_guard_used=False, actual_fits_started=0))
                raise
            guards, checks = {}, []
            def execute(task):
                for path in (task.output, task.output+'.stdout.log', task.output+'.stdout.log.memory.json'):
                    absent(path)
                name = f'prelaunch_{task.family}_{task.seed}.json'
                args = [INTERPRETER, '-I', '-S', '-B', '-c',
                    bootstrap(root, CLI, packet['source_sha256'][CLI]), '--source-root', root,
                    '--output', task.output, '--package-root', cli.PACKAGE_ROOT, '--family', task.family,
                    '--seed', str(task.seed), '--envelope-sha256', packet['prelaunch_sha256'][name]]
                guards[(task.family, task.seed)] = guard.run_bounded(args, task.output+'.stdout.log', env)
                return task
            def review(task):
                returned = guards[(task.family, task.seed)]
                reread = cli._json(read(task.output+'.stdout.log.memory.json', JSON_CAP))
                guard_receipt.validate_parent_guard_receipt(returned, reread)
                result = collector.collect_parent_artifact_candidate(root, task.output,
                    task.output+'.stdout.log', context=contexts[(task.family, task.seed)],
                    guard_returned_receipt=returned, guard_reread_receipt=reread)
                checks.append(dict(family=task.family, seed=task.seed,
                    artifact_check=result['artifact_check'], peak_combined_rss_bytes=reread['peak_combined_rss_bytes'],
                    elapsed_seconds=reread['elapsed_seconds']))
                return matrix.ReviewedTask(task, returned, reread, result['artifact_check'], True)
            state = matrix.SerialTrainMatrix(root, tasks).run(execute_once=execute, review_independently=review)
            final = dict(schema='v5-serial-parent-result-v1', packet_sha256=manifest_sha,
                status='PASS_ACTUAL_SERIAL_TRAIN_ARTIFACT_BINDING' if len(state.completed) == 18 else 'STOPPED_NO_RETRY',
                completed_count=len(state.completed), failed_index=state.failed_index,
                failure_kind=state.failure_kind, remaining_count=len(state.remaining), checks=checks,
                automatic_retries=0, workers=1, actual_parent_guard_used=True,
                numerical_model_predictions_verified=False, numerical_held_metrics_verified=False,
                blind_validation_pilot_lsf_tessent_allowed=False)
            write_once(Path(root)/'matrix.final.json', final)
            return final


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', required=True)
    parser.add_argument('--packet-sha256', required=True)
    args = parser.parse_args(argv)
    result = run(args.source_root, args.packet_sha256)
    print(json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False))
    return 0 if result['status'] == 'PASS_ACTUAL_SERIAL_TRAIN_ARTIFACT_BINDING' else 2


if __name__ == '__main__':
    raise SystemExit(main())
