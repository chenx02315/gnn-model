"""E49 frozen-scope name/stat locator. Never open data file contents."""
import errno
import json
import os
import stat
import sys

ROOTS = (
    "/ssd/cjc/gnn_model_ranking_v3_synthetic_0ca7dbf_20261004_r3",
    "/ssd/cjc/gnn_model_ranking_v3_synthetic_0ca7dbf_20261004_r4",
    "/ssd/cjc/gnn_model_ranking_v3_synthetic_0ca7dbf_20261004_r5",
    "/ssd/cjc/gnn_model_ranking_v3_synthetic_589b340_20261004_r1",
    "/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1",
    "/ssd/cjc/gnn_model_ranking_v4_exit_boundary_gate_30664e2_20261005_r1",
    "/ssd/cjc/gnn_model_ranking_v4_exit_boundary_ml_fe67d2d_20261005_r1",
    "/ssd/cjc/gnn_model_ranking_v4_guard_gate_dfbd25c_20261005_r1",
    "/ssd/cjc/gnn_model_ranking_v4_integrated_dec61b0_20261005_r1",
    "/ssd/cjc/gnn_model_ranking_v4_integrated_dec61b0_20261005_r2",
    "/ssd/cjc/gnn_model_ranking_v4_synthetic_445af8f_20261005_r1",
    "/ssd/cjc/gnn_model_ranking_v4_train_687c96d_20261005_r1",
    "/ssd/cjc/gnn_model_ranking_v4_train_687c96d_20261005_r2",
    "/ssd/cjc/gnn_model_ranking_v4_train_af05de0_20261005_r4",
    "/ssd/cjc/gnn_model_ranking_v4_train_dec61b0_20261005_r3",
    "/ssd/cjc/gnn_model_ranking_v5_feature_support_20261012_r1",
    "/ssd/cjc/gnn_model_ranking_v5_import_gate_20261008_r1",
    "/ssd/cjc/gnn_model_ranking_v5_optimizer_gate_20261010_r1",
    "/ssd/cjc/gnn_model_ranking_v5_optimizer_gate_20261010_r2",
    "/ssd/cjc/gnn_model_ranking_v5_optimizer_gate_20261011_r1",
    "/ssd/cjc/gnn_model_ranking_v5_runtime_gate_20261008_r1",
    "/ssd/cjc/gnn_model_ranking_v5_runtime_gate_20261008_r2",
    "/ssd/cjc/gnn_model_ranking_v5_runtime_gate_20261010_r1",
    "/ssd/cjc/gnn_model_ranking_v5_runtime_gate_20261010_r2",
    "/ssd/cjc/gnn_model_ranking_v5_runtime_gate_20261010_r3",
    "/ssd/cjc/gnn_model_ranking_v5_target_cost_20261012_r1",
    "/ssd/cjc/gnn_model_ranking_v5_train_20261010_r1",
    "/ssd/cjc/gnn_model_ranking_v5_train_20261010_r1_iwls_aes_core_20260824",
    "/ssd/cjc/gnn_model_ranking_v5_train_20261011_r1",
    "/ssd/cjc/gnn_model_ranking_v5_train_20261011_r1_iwls_aes_core_20260824",
    "/ssd/cjc/gnn_model_ranking_v5_train_20261011_r2",
    "/ssd/cjc/gnn_model_ranking_v5_train_20261011_r2_iscas89_s13207_20260824",
    "/ssd/cjc/gnn_model_ranking_v5_train_20261011_r2_iscas89_s13207_20260825",
    "/ssd/cjc/gnn_model_ranking_v5_train_20261011_r2_iscas89_s13207_20260826",
    "/ssd/cjc/gnn_model_ranking_v5_train_20261011_r2_iscas89_s15850_20260824",
    "/ssd/cjc/gnn_model_ranking_v5_train_20261011_r2_iscas89_s15850_20260825",
    "/ssd/cjc/gnn_model_ranking_v5_train_20261011_r2_iscas89_s15850_20260826",
    "/ssd/cjc/gnn_model_ranking_v5_train_20261011_r2_iscas89_s35932_20260824",
    "/ssd/cjc/gnn_model_ranking_v5_train_20261011_r2_iscas89_s35932_20260825",
    "/ssd/cjc/gnn_model_ranking_v5_train_20261011_r2_iscas89_s35932_20260826",
    "/ssd/cjc/gnn_model_ranking_v5_train_20261011_r2_iscas89_s38417_20260824",
    "/ssd/cjc/gnn_model_ranking_v5_train_20261011_r2_iscas89_s38417_20260825",
    "/ssd/cjc/gnn_model_ranking_v5_train_20261011_r2_iscas89_s38417_20260826",
    "/ssd/cjc/gnn_model_ranking_v5_train_20261011_r2_iwls_aes_core_20260824",
    "/ssd/cjc/gnn_model_ranking_v5_train_20261011_r2_iwls_aes_core_20260825",
    "/ssd/cjc/gnn_model_ranking_v5_train_20261011_r2_iwls_aes_core_20260826",
    "/ssd/cjc/gnn_model_ranking_v5_train_20261011_r2_iwls_spi_20260824",
    "/ssd/cjc/gnn_model_ranking_v5_train_20261011_r2_iwls_spi_20260825",
    "/ssd/cjc/gnn_model_ranking_v5_train_20261011_r2_iwls_spi_20260826",
    "/ssd/cjc/gnn_model_ranking_v5_train_jit_v2_unit_20261011_r1",
    "/ssd/cjc/gnn_model_ranking_v5_train_parent_posix_unit_20261011_r1",
    "/ssd/cjc/gnn_model_ranking_v5_train_v3_unit_20261011_r1",
    "/ssd/cjc/gnn_model_ranking_v5_verify_20261012_r1",
    "/ssd/cjc/gnn_model_ranking_v5_worker_gate_20261007_r1",
    "/ssd/cjc/gnn_model_runtime_v2_98efbd4f_20261002T235119",
    "/ssd/cjc/gnn_model_runtime_v2_input_stage_98efbd4f_20261002",
    "/ssd/cjc/gnn_model_runtime_v2_source_2184577",
    "/ssd/cjc/gnn_model_runtime_v2_source_98efbd4f",
    "/ssd/cjc/gnn_model_v6_complete_cost_synthetic_20261014_r1",
    "/ssd/cjc/gnn_model_v6_multi_positive_joint_20261015_r1",
    "/ssd/cjc/gnn_model_v6_paired_cost_runtime_20261015_r2",
    "/ssd/cjc/gnn_model_v6_paired_cost_runtime_20261015_r3",
    "/ssd/cjc/gnn_model_v6_parameter_probe_20261014_r1",
    "/ssd/cjc/gnn_model_v6_parameter_probe_20261014_r2",
    "/ssd/cjc/gnn_model_v6_scorer_synthetic_20261013_r1",
    "/ssd/cjc/gnn_model_v6_synthetic_fit_20261014_r1",
    "/ssd/cjc/gnn_model_v6_synthetic_fit_no_prior_20261014_r1",
    "/ssd/cjc/multimode_ate_20260725_B",
    "/ssd/cjc/multimode_ate_eight_circuit_closure_20260811_B",
    "/ssd/cjc/multimode_ate_phase2_20260808_B",
    "/ssd/cjc/multimode_ate_phase4_20260825_B",
    "/ssd/cjc/runtime_graph_topology_audit_v1_20260928_r1",
)
PROTECTED = '/ssd/cjc/multimode_ate_gnn_v1'
EXACT_DIRS = frozenset(('data', 'manifests', 'inputs', 'input', 'package', 'artifacts'))
DIR_PREFIXES = ('formal_candidate_space', 'runtime_training_package', 'runtime_training_staging')
FILES = frozenset(('runtime_training_package_manifest_v2.json', 'receipt_v2.json', 'source_provenance_v2.tsv'))
MAX_DEPTH = 3
MAX_DIRECTORIES = 512
MAX_ENTRIES = 2048
MAX_TOTAL_ENTRIES = 20000
MAX_OUTPUT = 65536
COVERAGE = 'FROZEN_72_ROOTS_WHITELIST_CHILD_DEPTH_3_ONLY'
FALSE_FLAGS = ('file_contents_opened', 'protected_directory_visited', 'remote_files_written', 'training_release', 'global_absence_claimed')
UNAVAILABLE = (errno.ENOENT, errno.ENOTDIR, errno.ELOOP)


def name_shape(name):
    return type(name) is str and 1 <= len(name) <= 180 and all(
        ord(c) < 128 and (c.isalnum() or c in '_.-') for c in name) and name not in ('.', '..')


def allowed_dir(name):
    return name in EXACT_DIRS or name.startswith(DIR_PREFIXES)


def classify(names, lookup):
    if len(names) > MAX_ENTRIES or len(set(names)) != len(names):
        raise ValueError('ENTRY_BOUND_OR_DUPLICATE')
    dirs, files, skipped = [], [], 0
    for name in sorted(names):
        if name not in FILES and not allowed_dir(name):
            continue  # Filter BEFORE stat, including protected and unrelated names.
        if not name_shape(name):
            raise ValueError('NAME_SHAPE')
        info = lookup(name)
        if name in FILES and stat.S_ISREG(info.st_mode):
            files.append(name)
        elif name not in FILES and stat.S_ISDIR(info.st_mode):
            dirs.append(name)
        else:
            skipped += 1
    return dirs, files, skipped


def relative_path(value):
    if value == '.':
        return True
    return type(value) is str and 1 <= len(value.split('/')) <= MAX_DEPTH and all(
        name_shape(n) and allowed_dir(n) and n not in FILES for n in value.split('/'))


def validate_response(result):
    keys = {'status', 'hostname', 'coverage', 'roots', 'directory_count', 'total_entries', *FALSE_FLAGS}
    if type(result) is not dict or set(result) != keys:
        return False
    if result['status'] != 'PASS_SCOPED_NAMED_METADATA' or result['hostname'] != 'bupt-gpus1' or result['coverage'] != COVERAGE:
        return False
    if any(result[k] is not False for k in FALSE_FLAGS):
        return False
    if type(result['roots']) is not list or len(result['roots']) != len(ROOTS):
        return False
    total, count, global_paths = 0, 0, set()
    for row, root in zip(result['roots'], ROOTS):
        if type(row) is not dict or set(row) != {'root', 'availability', 'directories'} or row['root'] != root:
            return False
        rows = row['directories']
        if type(rows) is not list or row['availability'] not in ('available', 'unavailable'):
            return False
        if row['availability'] == 'unavailable':
            if rows: return False
            continue
        if not rows: return False
        expected, seen = {'.'}, set()
        for item in rows:
            if type(item) is not dict or set(item) != {'path', 'entry_count', 'directories', 'named_files', 'skipped', 'depth_limited'}:
                return False
            path = item['path']
            if not relative_path(path) or path not in expected or path in seen:
                return False
            seen.add(path)
            absolute = root + ('' if path == '.' else '/' + path)
            if absolute in global_paths or absolute == PROTECTED or absolute.startswith(PROTECTED + '/'):
                return False
            global_paths.add(absolute)
            depth = 0 if path == '.' else len(path.split('/'))
            n, skip, limited = item['entry_count'], item['skipped'], item['depth_limited']
            if any(type(x) is not int for x in (n, skip, limited)) or not 0 <= n <= MAX_ENTRIES or not 0 <= skip <= n:
                return False
            for key in ('directories', 'named_files'):
                names = item[key]
                if type(names) is not list or any(not name_shape(x) for x in names) or names != sorted(set(names)):
                    return False
                if key == 'directories' and any(not allowed_dir(x) or x in FILES for x in names):
                    return False
                if key == 'named_files' and any(x not in FILES for x in names):
                    return False
            if limited != (len(item['directories']) if depth == MAX_DEPTH else 0):
                return False
            if len(item['directories']) + len(item['named_files']) + skip > n:
                return False
            if depth < MAX_DEPTH:
                expected.update((name if path == '.' else path + '/' + name) for name in item['directories'])
            total += n
            count += 1
        if expected != seen:
            return False
    return (type(result['directory_count']) is int and result['directory_count'] == count <= MAX_DIRECTORIES
            and type(result['total_entries']) is int and result['total_entries'] == total <= MAX_TOTAL_ENTRIES)


def locate(base, api=os):
    """Descriptor-only directory traversal; api injection is for synthetic tests."""
    flags = api.O_RDONLY | api.O_DIRECTORY | api.O_NOFOLLOW
    identities = set()
    totals = {'directories': 0, 'entries': 0}
    def unique(info):
        identity = (info.st_dev, info.st_ino)
        if identity in identities: raise ValueError('GLOBAL_DUPLICATE')
        identities.add(identity)
    def scan(fd, path, rows):
        totals['directories'] += 1
        if totals['directories'] > MAX_DIRECTORIES: raise ValueError('DIRECTORY_BOUND')
        names = []
        with api.scandir(fd) as entries:
            for entry in entries:
                totals['entries'] += 1
                if len(names) >= MAX_ENTRIES or totals['entries'] > MAX_TOTAL_ENTRIES:
                    raise ValueError('ENTRY_BOUND')
                names.append(entry.name)
        infos = {}
        def lookup(name):
            infos[name] = api.stat(name, dir_fd=fd, follow_symlinks=False)
            return infos[name]
        dirs, files, skipped = classify(names, lookup)
        for name in files: unique(infos[name])
        depth = 0 if path == '.' else len(path.split('/'))
        rows.append(dict(path=path, entry_count=len(names), directories=dirs,
                         named_files=files, skipped=skipped,
                         depth_limited=len(dirs) if depth == MAX_DEPTH else 0))
        if depth == MAX_DEPTH: return
        for name in dirs:
            if totals['directories'] >= MAX_DIRECTORIES: raise ValueError('DIRECTORY_BOUND')
            child = api.open(name, flags, dir_fd=fd)
            try:
                info = api.fstat(child)
                before = infos[name]
                if (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino):
                    raise ValueError('DIRECTORY_CHANGED')
                unique(info)
                scan(child, name if path == '.' else path + '/' + name, rows)
            finally:
                api.close(child)
    result_rows = []
    for root in ROOTS:
        if root == PROTECTED or root.startswith(PROTECTED + '/') or not root.startswith('/ssd/cjc/') or not name_shape(root[len('/ssd/cjc/'):]):
            raise ValueError('ROOT_SCOPE')
        if totals['directories'] >= MAX_DIRECTORIES:
            raise ValueError('DIRECTORY_BOUND')
        rows = []
        try:
            fd = api.open(root[len('/ssd/cjc/'):], flags, dir_fd=base)
        except OSError as exc:
            if exc.errno not in UNAVAILABLE: raise
            result_rows.append(dict(root=root, availability='unavailable', directories=[]))
            continue
        try:
            unique(api.fstat(fd))
            scan(fd, '.', rows)
        finally:
            api.close(fd)
        result_rows.append(dict(root=root, availability='available', directories=rows))
    return dict(status='PASS_SCOPED_NAMED_METADATA', hostname=api.uname().nodename,
                coverage=COVERAGE, roots=result_rows, directory_count=totals['directories'],
                total_entries=totals['entries'], **{key: False for key in FALSE_FLAGS})


def main():
    base = None
    try:
        if sys.platform != 'linux' or len(sys.argv) != 1: raise ValueError('LINUX_STDIN_ONLY')
        import resource
        for kind, cap in ((resource.RLIMIT_AS, 1024**3), (resource.RLIMIT_CPU, 20)):
            soft, hard = resource.getrlimit(kind)
            resource.setrlimit(kind, (min([cap] + [v for v in (soft, hard) if v != resource.RLIM_INFINITY]), hard))
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        base = os.open('/', flags)
        for component in ('ssd', 'cjc'):
            child = os.open(component, flags, dir_fd=base)
            os.close(base)
            base = child
        result = locate(base)
        if not validate_response(result): raise ValueError('OUTPUT_SCHEMA')
        raw = json.dumps(result, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
        if len(raw.encode('ascii')) > MAX_OUTPUT: raise ValueError('OUTPUT_BOUND')
        print(raw)
        return 0
    except Exception:
        print('{"status":"FAIL_CLOSED_NAMED_METADATA","code":"SCOPED_LOCATOR_REJECTED"}')
        return 2
    finally:
        if base is not None: os.close(base)


if __name__ == '__main__': sys.exit(main())
