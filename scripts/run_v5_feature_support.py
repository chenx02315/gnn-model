"""One guarded, label-free six-fold diagnostic; no training or retry."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from types import ModuleType

ROOT = '/ssd/cjc/gnn_model_ranking_v5_feature_support_20261012_r1'
PACKAGE = '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/train_folds'
MODULE = 'src/models/ranking_v5_feature_support.py'
GUARD = 'src/models/ranking_v4_memory_guard.py'
GUARD_SHA = '3dcaf6fd545aa1c5358146567cf55a8ac6593aa14af42f31ec965f8f62c79896'
V3_SOURCE = 'src/models/runtime_ranking_v3.py'  # synthetic normalizer equivalence only
V3_SHA = 'd64eb0fe17a00886d6464ae016805b1474e7324e95ad8e223aba44502709759c'
ALLOWED = frozenset((MODULE, GUARD, 'scripts/run_v5_feature_support.py',
                    'tests/test_ranking_v5_feature_support.py',
                    'tests/test_run_v5_feature_support.py', V3_SOURCE))


def feature_audit(allowed):
    def audit(event, values):
        if event=='open':
            target, flags=values[0],values[2]
            if flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):
                raise PermissionError('FEATURE_WRITE_DENIED')
            if type(target) is int:
                return  # fdopen on the reader's already checked descriptor
            if not isinstance(target,(str,bytes,os.PathLike)) or os.fsdecode(target) not in allowed:
                raise PermissionError('FEATURE_ONLY_OPEN_DENIED')
        if event in ('subprocess.Popen','os.system','os.exec','os.posix_spawn','os.fork','os.forkpty',
                     'socket.connect','ctypes.dlopen'):
            raise PermissionError('FEATURE_EXECUTION_DENIED')
        if event=='import' and values[0].split('.')[0] in ('torch','numpy','sklearn','xgboost'):
            raise PermissionError('FEATURE_ML_IMPORT_DENIED')
    return audit


def read(path, cap=1024*1024):
    path = Path(path)
    for part in (path, *path.parents):
        if stat.S_ISLNK(os.lstat(part).st_mode):
            raise ValueError('SYMLINK')
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > cap:
        raise ValueError('FILE_BOUNDARY')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        identity = lambda s: (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        if identity(before) != identity(opened):
            raise ValueError('FILE_CHANGED')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(cap+1)
        if len(raw)>cap or identity(opened)!=identity(os.fstat(fd)) or identity(opened)!=identity(os.lstat(path)):
            raise ValueError('FILE_CHANGED')
        return raw
    finally:
        os.close(fd)


def load_module(name, raw, path):
    module = ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def write_once(path, value):
    raw = (json.dumps(value, sort_keys=True, allow_nan=False)+'\n').encode()
    if len(raw)>65536:
        raise ValueError('OUTPUT_CAP')
    with Path(path).open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if read(path,65536)!=raw:
        raise ValueError('OUTPUT_READBACK')
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest-sha',required=True)
    parser.add_argument('--child',action='store_true')
    args = parser.parse_args()
    if sys.platform!='linux' or sys.version_info[:2]!=(3,11) or str(Path(__file__).parent.parent)!=ROOT:
        raise ValueError('FIXED_LINUX_ENVIRONMENT')
    root=Path(ROOT)
    raw=read(root/'source_manifest.json')
    if hashlib.sha256(raw).hexdigest()!=args.manifest_sha:
        raise ValueError('MANIFEST_PIN')
    manifest=json.loads(raw)
    if set(manifest)!= {'schema','files'} or manifest['schema']!='v5-feature-support-source-v1' or set(manifest['files'])!=ALLOWED:
        raise ValueError('MANIFEST_SCHEMA')
    sources={}
    for name in sorted(ALLOWED):
        sources[name]=read(root/name)
        if hashlib.sha256(sources[name]).hexdigest()!=manifest['files'][name]:
            raise ValueError('SOURCE_PIN')
    if manifest['files'][GUARD]!=GUARD_SHA or manifest['files'][V3_SOURCE]!=V3_SHA:
        raise ValueError('GUARD_PIN')
    if args.child:
        import resource
        if (resource.getrlimit(resource.RLIMIT_AS)!=(8589934592,8589934592)
                or resource.getrlimit(resource.RLIMIT_CORE)!=(0,0)
                or os.getsid(0)!=os.getpid() or os.getpgrp()!=os.getpid()
                or os.environ.get('FEATURE_PARENT_PID')!=str(os.getppid())
                or any(os.environ.get(key)!='1' for key in
                       ('OMP_NUM_THREADS','MKL_NUM_THREADS','OPENBLAS_NUM_THREADS','NUMEXPR_NUM_THREADS'))):
            raise ValueError('GUARDED_CHILD_REQUIRED')
        parent_cmd=read('/proc/'+str(os.getppid())+'/cmdline',4096).split(b'\0')
        expected=[b'/usr/bin/python3',b'-I',b'-S',b'-B',
                  str(root/'scripts/run_v5_feature_support.py').encode(),
                  b'--manifest-sha',args.manifest_sha.encode(),b'']
        if parent_cmd!=expected:
            raise ValueError('GUARDED_PARENT_REQUIRED')
        once=json.loads(read(root/'actual.once.json',4096))
        if once!={'source_manifest_sha256':args.manifest_sha,'automatic_retries':0}:
            raise ValueError('PARENT_ONCE_REQUIRED')
        write_once(root/'child.once.json',{'source_manifest_sha256':args.manifest_sha,
                                          'parent_pid':os.getppid(),'child_pid':os.getpid()})
        module=load_module('feature_support_checked',sources[MODULE],root/MODULE)
        families=tuple(module.FAMILY_NAMES)
        allowed={PACKAGE+'/receipt.json'}
        for family in families:
            allowed.update(PACKAGE+'/fold_'+family+'/'+name for name in
                           ('manifest.json','fit_features.json','heldout_features.json'))
        sys.addaudithook(feature_audit(allowed))
        result=module.analyze_package(PACKAGE)
        output=json.dumps(result,sort_keys=True,allow_nan=False)
        if len(output.encode())>65536:
            raise ValueError('OUTPUT_CAP')
        print(output)
        return
    import fcntl
    lockfd=os.open('/ssd/cjc/gnn_model_ranking_v5_serial_parent.lock',os.O_RDONLY|os.O_NOFOLLOW)
    try:
        fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        write_once(root/'actual.once.json',{'source_manifest_sha256':args.manifest_sha,'automatic_retries':0})
        guard=load_module('feature_guard_checked',sources[GUARD],root/GUARD)
        env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'}
        env['FEATURE_PARENT_PID']=str(os.getpid())
        env.update({key:'1' for key in guard.THREAD_KEYS})
        log=root/'actual.log'
        returned=guard.run_bounded(['/usr/bin/python3','-I','-S','-B',str(root/'scripts/run_v5_feature_support.py'),
                                    '--manifest-sha',args.manifest_sha,'--child'],log,env)
        reread=json.loads(read(str(log)+'.memory.json',65536))
        if reread!=returned or returned['status']!='PASS_BOUNDED_WORKER' or returned['exit_code']!=0 or returned['sample_count']<1:
            raise ValueError('MEMORY_RECEIPT')
        raw_result=read(log,65536)
        result=json.loads(raw_result)
        receipt={'status':'PASS_GUARDED_FEATURE_ONLY_RUN','source_manifest_sha256':args.manifest_sha,
                 'result_sha256':hashlib.sha256(raw_result).hexdigest(),'result':result,'guard':returned}
        write_once(root/'result.json',receipt)
        print(json.dumps(receipt,sort_keys=True,allow_nan=False))
    finally:
        os.close(lockfd)


if __name__=='__main__':
    main()
