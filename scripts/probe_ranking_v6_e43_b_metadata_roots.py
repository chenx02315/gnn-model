"""Fixed B root directory-name inventory; no data file opens or recursion."""
import json
import os
import stat
import sys

ROOT = '/ssd/cjc'
PROTECTED = 'multimode_ate_gnn_v1'
PREFIXES = ('gnn_model', 'gnn-model', 'runtime_', 'formal_', 'multimode_ate_')
MAX_ENTRIES = 1024
MAX_ROOTS = 512
MAX_OUTPUT = 65536


def collect(names, lookup):
    if len(names) > MAX_ENTRIES or len(set(names)) != len(names): raise ValueError('ENTRY_BOUND_OR_DUPLICATE')
    selected = []
    skipped = 0
    for name in sorted(names):
        # Exclude before even looking up attributes; never visit this directory.
        if name == PROTECTED or not name.startswith(PREFIXES): continue
        if not name or len(name) > 180 or not all(ord(c) < 128 and (c.isalnum() or c in '_.-') for c in name):
            raise ValueError('PROJECT_NAME_SHAPE')
        info = lookup(name)
        if not stat.S_ISDIR(info.st_mode):
            skipped += 1
            continue
        selected.append(ROOT + '/' + name)
    if len(selected) > MAX_ROOTS: raise ValueError('ROOT_BOUND')
    return selected, skipped


def validate_response(result):
    fields = {'status','root','entry_count','project_roots','non_directory_candidates_skipped',
              'hostname','uid','resource','file_contents_opened','recursive_walk','remote_files_written',
              'protected_directory_visited','training_release'}
    if type(result) is not dict or set(result) != fields: return False
    if result['status'] != 'PASS_B_ROOT_NAMES_ONLY' or result['root'] != ROOT: return False
    if any(result[k] is not False for k in ('file_contents_opened','recursive_walk','remote_files_written','protected_directory_visited','training_release')):
        return False
    if type(result['entry_count']) is not int or not 0 <= result['entry_count'] <= MAX_ENTRIES: return False
    if type(result['non_directory_candidates_skipped']) is not int or not 0 <= result['non_directory_candidates_skipped'] <= result['entry_count']: return False
    roots = result['project_roots']
    if type(roots) is not list or len(roots) > MAX_ROOTS or len(roots) > result['entry_count']: return False
    if len(roots) + result['non_directory_candidates_skipped'] > result['entry_count']: return False
    if any(type(p) is not str for p in roots) or roots != sorted(set(roots)): return False
    for path in roots:
        if not path.startswith(ROOT+'/'): return False
        name = path[len(ROOT)+1:]
        if name == PROTECTED or not name.startswith(PREFIXES) or not 1 <= len(name) <= 180: return False
        if not all(ord(c) < 128 and (c.isalnum() or c in '_.-') for c in name): return False
    if type(result['uid']) is not int or result['uid'] < 0: return False
    if type(result['hostname']) is not str or not 1 <= len(result['hostname']) <= 255: return False
    if not all(32 <= ord(c) < 127 for c in result['hostname']): return False
    r = result['resource']
    return (type(r) is dict and set(r) == {'address_space_limit_bytes','cpu_limit_s','workers'}
            and type(r['workers']) is int and r['workers'] == 1
            and type(r['address_space_limit_bytes']) is int and 0 < r['address_space_limit_bytes'] <= 1024**3
            and type(r['cpu_limit_s']) is int and 0 < r['cpu_limit_s'] <= 20)


def main():
    descriptor = None
    try:
        if sys.platform != 'linux' or len(sys.argv) != 1: raise ValueError('FIXED_LINUX_STDIN_ONLY')
        import resource
        imposed = {'workers': 1}
        for key, cap, label in ((resource.RLIMIT_AS,1024**3,'address_space_limit_bytes'),
                                (resource.RLIMIT_CPU,20,'cpu_limit_s')):
            soft, hard = resource.getrlimit(key)
            bound = min([cap]+[v for v in (soft,hard) if v != resource.RLIM_INFINITY])
            resource.setrlimit(key,(bound,hard))
            imposed[label] = bound
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptor = os.open('/', flags)
        for component in ('ssd','cjc'):
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        names = []
        with os.scandir(descriptor) as entries:
            for entry in entries:
                if len(names) >= MAX_ENTRIES: raise ValueError('ENTRY_BOUND')
                names.append(entry.name)
        roots, skipped = collect(names, lambda name: os.stat(name, dir_fd=descriptor, follow_symlinks=False))
        result = dict(status='PASS_B_ROOT_NAMES_ONLY',root=ROOT,entry_count=len(names),project_roots=roots,
            non_directory_candidates_skipped=skipped,hostname=os.uname().nodename,uid=os.getuid(),resource=imposed,
            file_contents_opened=False,recursive_walk=False,remote_files_written=False,
            protected_directory_visited=False,training_release=False)
        if not validate_response(result): raise ValueError('OUTPUT_SCHEMA')
        encoded = json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=True)
        if len(encoded.encode('ascii')) > MAX_OUTPUT: raise ValueError('OUTPUT_BOUND')
        print(encoded)
        return 0
    except Exception:
        print('{"status":"FAIL_CLOSED_B_ROOT_NAMES","code":"FIXED_ROOT_INVENTORY_REJECTED"}')
        return 2
    finally:
        if descriptor is not None: os.close(descriptor)


if __name__ == '__main__': sys.exit(main())
