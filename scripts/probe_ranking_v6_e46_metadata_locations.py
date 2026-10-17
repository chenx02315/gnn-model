"""Fixed, one-level directory/name discovery; never open file contents."""
import json
import os
import stat
import sys

ROOTS = (
    'gnn_model_runtime_v2_98efbd4f_20261002T235119/inputs',
    'gnn_model_runtime_v2_input_stage_98efbd4f_20261002/runtime_training_package_v2_r1',
    'gnn_model_runtime_v2_source_2184577/data',
    'gnn_model_runtime_v2_source_98efbd4f/data',
)
MAX_ENTRIES = 2048
MAX_OUTPUT = 65536
EXACT_DIRS = {'data', 'inputs', 'input', 'package', 'artifacts'}
DIR_PREFIXES = ('runtime_training_package', 'formal_candidate_space', 'runtime_training_staging')
FILES = {'runtime_training_package_manifest_v2.json', 'source_provenance_v2.tsv', 'receipt_v2.json'}


def classify(names, lookup):
    if len(names) > MAX_ENTRIES or len(set(names)) != len(names):
        raise ValueError('ENTRY_BOUND')
    directories, files, skipped = [], [], 0
    for name in sorted(names):
        if name not in FILES and name not in EXACT_DIRS and not name.startswith(DIR_PREFIXES):
            continue  # includes checkpoints, environment and unrelated result names
        if not 1 <= len(name) <= 180 or not all(ord(c) < 128 and (c.isalnum() or c in '_.-') for c in name):
            raise ValueError('NAME_SHAPE')
        info = lookup(name)
        if name in FILES and stat.S_ISREG(info.st_mode):
            files.append(name)
        elif name not in FILES and stat.S_ISDIR(info.st_mode):
            directories.append(name)
        else:
            skipped += 1
    return directories, files, skipped


def validate_response(result):
    if type(result) is not dict or set(result) != {'status','hostname','roots','file_contents_opened','recursive_walk','protected_directory_visited','remote_files_written','training_release'}:
        return False
    if result['status'] != 'PASS_FIXED_METADATA_LOCATIONS' or result['hostname'] != 'bupt-gpus1':
        return False
    if any(result[k] is not False for k in ('file_contents_opened','recursive_walk','protected_directory_visited','remote_files_written','training_release')):
        return False
    rows = result['roots']
    if type(rows) is not list or len(rows) != len(ROOTS): return False
    for row, root in zip(rows, ROOTS):
        if type(row) is not dict or set(row) != {'root','entry_count','directories','named_files','skipped'}: return False
        if row['root'] != '/ssd/cjc/' + root: return False
        n = row['entry_count']
        if type(n) is not int or not 0 <= n <= MAX_ENTRIES: return False
        if type(row['skipped']) is not int or not 0 <= row['skipped'] <= n: return False
        for key, kind in (('directories','directory'), ('named_files','file')):
            names = row[key]
            if type(names) is not list or any(type(s) is not str for s in names): return False
            if names != sorted(set(names)): return False
            for name in names:
                if not 1 <= len(name) <= 180 or not all(ord(c) < 128 and (c.isalnum() or c in '_.-') for c in name): return False
                if kind == 'file' and name not in FILES: return False
                if kind == 'directory' and (name in FILES or not (name in EXACT_DIRS or name.startswith(DIR_PREFIXES))): return False
        if len(row['directories']) + len(row['named_files']) + row['skipped'] > n: return False
    return True


def main():
    base = None
    try:
        if sys.platform != 'linux' or len(sys.argv) != 1: raise ValueError('LINUX_STDIN_ONLY')
        import resource
        for kind, cap in ((resource.RLIMIT_AS,1024**3), (resource.RLIMIT_CPU,20)):
            soft, hard = resource.getrlimit(kind)
            resource.setrlimit(kind,(min([cap]+[v for v in (soft,hard) if v != resource.RLIM_INFINITY]),hard))
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        base = os.open('/',flags)
        for component in ('ssd','cjc'):
            child = os.open(component,flags,dir_fd=base)
            os.close(base)
            base = child
        rows = []
        for root in ROOTS:
            fd = os.dup(base)
            try:
                for component in root.split('/'):
                    child = os.open(component,flags,dir_fd=fd)
                    os.close(fd)
                    fd = child
            except Exception:
                os.close(fd)
                raise
            try:
                names = []
                with os.scandir(fd) as entries:
                    for entry in entries:
                        if len(names) >= MAX_ENTRIES: raise ValueError('ENTRY_BOUND')
                        names.append(entry.name)
                dirs, files, skipped = classify(names, lambda n: os.stat(n,dir_fd=fd,follow_symlinks=False))
                rows.append(dict(root='/ssd/cjc/'+root,entry_count=len(names),directories=dirs,named_files=files,skipped=skipped))
            finally:
                os.close(fd)
        result = dict(status='PASS_FIXED_METADATA_LOCATIONS',hostname=os.uname().nodename,roots=rows,
            file_contents_opened=False,recursive_walk=False,protected_directory_visited=False,
            remote_files_written=False,training_release=False)
        if not validate_response(result): raise ValueError('OUTPUT_SCHEMA')
        raw = json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=True)
        if len(raw.encode('ascii')) > MAX_OUTPUT: raise ValueError('OUTPUT_BOUND')
        print(raw)
        return 0
    except Exception:
        print('{"status":"FAIL_CLOSED_METADATA_LOCATIONS","code":"FIXED_DISCOVERY_REJECTED"}')
        return 2
    finally:
        if base is not None: os.close(base)


if __name__ == '__main__': sys.exit(main())
