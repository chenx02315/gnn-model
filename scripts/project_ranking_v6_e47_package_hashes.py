"""Byte-bound package manifest hash projection; decode only selected values."""
import hashlib
import json
import os
import re
import stat
import sys

PATH = '/ssd/cjc/gnn_model_runtime_v2_input_stage_98efbd4f_20261002/runtime_training_package_v2_r1/runtime_training_package_manifest_v2.json'
EXPECTED_SHA = '66c6776c033c87c2b41fa6cdeb05852e650eb1fe5173600fae2f0d2a8907eafc'
EXPECTED_CANDIDATES = 'f55420e29e94ae74dff90f042c72fd7bd76ffa511b214ac89d7a238a18bd678e'
EXPECTED_NORMALIZED = '59be15d3cb9e0c3a1d96bc368472df419c4a3d26fafdf491563a8bd7639d503a'
LIMIT = 131072
SELECTED = {('schema_version',), ('source_sha256','candidate_receipt'),
            ('source_sha256','candidate_space'), ('source_sha256','normalized_measurements')}


def project(raw):
    """Scan JSON syntax in bytes; ignored values are never json-decoded/evaluated."""
    if type(raw) is not bytes or not 0 < len(raw) <= LIMIT or any(c > 127 for c in raw):
        raise ValueError('INPUT_BOUND_ASCII')
    selected = {}
    tokens = 0

    def ws(i):
        while i < len(raw) and raw[i] in b' \t\r\n': i += 1
        return i

    def string(i):
        if i >= len(raw) or raw[i] != 34: raise ValueError('STRING_START')
        i += 1
        while i < len(raw):
            c = raw[i]
            if c == 34: return i + 1
            if c < 32: raise ValueError('STRING_CONTROL')
            if c == 92:
                i += 1
                if i >= len(raw): raise ValueError('ESCAPE_END')
                if raw[i] == 117:
                    if len(raw[i+1:i+5]) != 4 or any(c not in b'0123456789abcdefABCDEF' for c in raw[i+1:i+5]):
                        raise ValueError('UNICODE_ESCAPE')
                    i += 4
                elif raw[i] not in b'"\\/bfnrt': raise ValueError('ESCAPE_TOKEN')
            i += 1
        raise ValueError('STRING_END')

    def value(i, path, depth):
        nonlocal tokens
        tokens += 1
        if depth > 32 or tokens > 8192: raise ValueError('STRUCTURE_BOUND')
        i = ws(i)
        start = i
        if i >= len(raw): raise ValueError('VALUE_END')
        c = raw[i]
        if c == 34:
            i = string(i)
        elif c == 123:
            i = ws(i+1)
            keys = set()
            if i < len(raw) and raw[i] == 125: i += 1
            else:
                while True:
                    end = string(i)
                    key = json.loads(raw[i:end].decode('ascii'))  # field name, not a result value
                    if key in keys: raise ValueError('DUPLICATE_KEY')
                    keys.add(key)
                    i = ws(end)
                    if i >= len(raw) or raw[i] != 58: raise ValueError('COLON')
                    i = ws(value(i+1, path+(key,), depth+1))
                    if i >= len(raw): raise ValueError('OBJECT_END')
                    if raw[i] == 125:
                        i += 1
                        break
                    if raw[i] != 44: raise ValueError('OBJECT_COMMA')
                    i = ws(i+1)
        elif c == 91:
            i = ws(i+1)
            if i < len(raw) and raw[i] == 93: i += 1
            else:
                while True:
                    i = ws(value(i, path+(None,), depth+1))
                    if i >= len(raw): raise ValueError('ARRAY_END')
                    if raw[i] == 93:
                        i += 1
                        break
                    if raw[i] != 44: raise ValueError('ARRAY_COMMA')
                    i = ws(i+1)
        else:
            match = re.match(rb'(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)',raw[i:])
            if not match: raise ValueError('SCALAR_TOKEN')
            i += len(match.group())
        if path in SELECTED:
            if c != 34: raise ValueError('SELECTED_STRING_REQUIRED')
            selected[path] = json.loads(raw[start:i].decode('ascii'))
        return i

    end = ws(value(0, (), 0))
    if end != len(raw) or set(selected) != SELECTED: raise ValueError('JSON_END_OR_FIELDS')
    if selected[('schema_version',)] != 'runtime-training-package-v2': raise ValueError('SCHEMA')
    hashes = {p[-1]: v for p,v in selected.items() if len(p) == 2}
    if any(not re.fullmatch('[0-9a-f]{64}',v) for v in hashes.values()): raise ValueError('SHA_SHAPE')
    if hashes['candidate_space'] != EXPECTED_CANDIDATES or hashes['normalized_measurements'] != EXPECTED_NORMALIZED:
        raise ValueError('ANCHOR_MISMATCH')
    return {'schema_version':selected[('schema_version',)], 'source_sha256':hashes}


def identity(info):
    return tuple(getattr(info,k) for k in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))


def read_fixed():
    fd = os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        parts = PATH.strip('/').split('/')
        for component in parts[:-1]:
            child = os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd)
            fd = child
        file_fd = os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
        try:
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= LIMIT:
                raise ValueError('FILE_GATE')
            chunks, count = [], 0
            while True:
                chunk = os.read(file_fd,min(8192,LIMIT+1-count))
                if not chunk: break
                chunks.append(chunk)
                count += len(chunk)
                if count > LIMIT: raise ValueError('READ_BOUND')
            raw = b''.join(chunks)
            if identity(before) != identity(os.fstat(file_fd)) or identity(before) != identity(os.stat(parts[-1],dir_fd=fd,follow_symlinks=False)) or len(raw) != before.st_size:
                raise ValueError('FILE_CHANGED')
        finally:
            os.close(file_fd)
    finally:
        os.close(fd)
    if hashlib.sha256(raw).hexdigest() != EXPECTED_SHA: raise ValueError('PACKAGE_SHA_MISMATCH')
    return raw


def validate_response(r):
    if type(r) is not dict or set(r) != {'status','hostname','path','byte_count','file_sha256','selected','whole_bytes_read_for_sha','nonwhitelist_values_decoded','remote_files_written','protected_directory_visited','training_release'}: return False
    if r['status'] != 'PASS_PACKAGE_HASH_PROJECTION' or r['hostname'] != 'bupt-gpus1' or r['path'] != PATH or r['file_sha256'] != EXPECTED_SHA: return False
    if type(r['byte_count']) is not int or not 0 < r['byte_count'] <= LIMIT: return False
    if r['whole_bytes_read_for_sha'] is not True or any(r[k] is not False for k in ('nonwhitelist_values_decoded','remote_files_written','protected_directory_visited','training_release')): return False
    selected = r['selected']
    if type(selected) is not dict or set(selected) != {'schema_version','source_sha256'}: return False
    if selected['schema_version'] != 'runtime-training-package-v2': return False
    h = selected['source_sha256']
    return (type(h) is dict and set(h) == {'candidate_space','normalized_measurements','candidate_receipt'}
            and all(type(v) is str and re.fullmatch('[0-9a-f]{64}',v) for v in h.values())
            and h['candidate_space'] == EXPECTED_CANDIDATES and h['normalized_measurements'] == EXPECTED_NORMALIZED)


def main():
    try:
        if sys.platform != 'linux' or len(sys.argv) != 1: raise ValueError('LINUX_STDIN_ONLY')
        import resource
        for kind,cap in ((resource.RLIMIT_AS,1024**3),(resource.RLIMIT_CPU,20)):
            soft,hard=resource.getrlimit(kind)
            resource.setrlimit(kind,(min([cap]+[v for v in (soft,hard) if v != resource.RLIM_INFINITY]),hard))
        raw = read_fixed()
        result=dict(status='PASS_PACKAGE_HASH_PROJECTION',hostname=os.uname().nodename,path=PATH,
            byte_count=len(raw),file_sha256=EXPECTED_SHA,selected=project(raw),whole_bytes_read_for_sha=True,
            nonwhitelist_values_decoded=False,remote_files_written=False,protected_directory_visited=False,training_release=False)
        if not validate_response(result): raise ValueError('OUTPUT_SCHEMA')
        print(json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=True))
        return 0
    except Exception:
        print('{"status":"FAIL_CLOSED_PACKAGE_HASHES","code":"FIXED_PROJECTION_REJECTED"}')
        return 2


if __name__ == '__main__': sys.exit(main())
