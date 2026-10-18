"""E59 fixed Linux source-byte hash. Never decode/import/execute inspected source."""
import hashlib
import json
import os
import re
import stat
import sys

PATH = '/temp/jiangchuanc/multimode_ate_phase4_20260825_A/00_framework/phase4_closure_driver_v2.py'
REFERENCE_SHA = '4394d366098c7c64614dced1cade709373b315fc3749a8f93404d5c496ecfb94'
MAX_SOURCE_BYTES = 128*1024
MAX_OUTPUT_BYTES = 16384
FALSE_FLAGS = ('source_content_decoded','source_imported_or_executed','referenced_files_opened',
    'remote_files_written','historical_freeze_certified','historically_deployed_execution_certified','training_release')


def require(ok,code):
    if not ok: raise ValueError(code)


def identity(info):
    return tuple(getattr(info,key) for key in
                 ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


def directory_identity(info):
    require(stat.S_ISDIR(info.st_mode),'ORDINARY_ANCESTOR')
    return (info.st_dev,info.st_ino,info.st_mode)


def regular(info):
    require(stat.S_ISREG(info.st_mode) and info.st_nlink==1
            and not getattr(info,'st_file_attributes',0)&0x400,'ORDINARY_SINGLE_LINK_FILE')


def hash_fixed(api=os):
    """Fixed descriptor-relative path only; API injection is for synthetic tests."""
    flags=api.O_RDONLY|api.O_DIRECTORY|api.O_NOFOLLOW
    descriptors=[]
    ancestors=[]
    source_fd=None
    try:
        parent=api.open('/',flags)
        descriptors.append(parent)
        directory_identity(api.fstat(parent))
        parts=PATH.strip('/').split('/')
        for name in parts[:-1]:
            before=api.stat(name,dir_fd=parent,follow_symlinks=False)
            expected=directory_identity(before)
            child=api.open(name,flags,dir_fd=parent)
            descriptors.append(child)
            require(directory_identity(api.fstat(child))==expected,'ANCESTOR_CHANGED')
            ancestors.append((parent,name,child,expected))
            parent=child
        before=api.stat(parts[-1],dir_fd=parent,follow_symlinks=False)
        regular(before)
        require(0<before.st_size<=MAX_SOURCE_BYTES,'SOURCE_BOUND')
        source_fd=api.open(parts[-1],api.O_RDONLY|api.O_NOFOLLOW|getattr(api,'O_NONBLOCK',0),dir_fd=parent)
        opened=api.fstat(source_fd)
        regular(opened)
        require(identity(before)==identity(opened),'OPEN_IDENTITY')
        count=0
        digest=hashlib.sha256()
        while count<=MAX_SOURCE_BYTES:
            chunk=api.read(source_fd,min(65536,MAX_SOURCE_BYTES+1-count))
            if not chunk:break
            count+=len(chunk)
            require(count<=MAX_SOURCE_BYTES,'SOURCE_BOUND')
            digest.update(chunk)
        after=api.fstat(source_fd)
        last=api.stat(parts[-1],dir_fd=parent,follow_symlinks=False)
        regular(after);regular(last)
        require(identity(before)==identity(opened)==identity(after)==identity(last)
                and count==opened.st_size,'READ_IDENTITY_OR_SIZE')
        for parent_fd,name,child,expected in ancestors:
            require(directory_identity(api.fstat(child))==expected
                    and directory_identity(api.stat(name,dir_fd=parent_fd,follow_symlinks=False))==expected,
                    'ANCESTOR_CHANGED')
        return count,digest.hexdigest()
    finally:
        if source_fd is not None:api.close(source_fd)
        for fd in reversed(descriptors):api.close(fd)


def response(byte_count,digest,resource):
    return dict(status='PASS_CURRENT_SOURCE_BYTE_IDENTITY',path=PATH,byte_count=byte_count,
        sha256=digest,reference_sha256=REFERENCE_SHA,matches_reference=digest==REFERENCE_SHA,
        resource=resource,**{key:False for key in FALSE_FLAGS})


def validate_response(result):
    keys={'status','path','byte_count','sha256','reference_sha256','matches_reference','resource',*FALSE_FLAGS}
    if type(result) is not dict or set(result)!=keys:return False
    if result['status']!='PASS_CURRENT_SOURCE_BYTE_IDENTITY' or result['path']!=PATH:return False
    if type(result['byte_count']) is not int or not 0<result['byte_count']<=MAX_SOURCE_BYTES:return False
    if type(result['sha256']) is not str or re.fullmatch('[a-f0-9]{64}',result['sha256']) is None:return False
    if result['reference_sha256']!=REFERENCE_SHA or type(result['matches_reference']) is not bool:return False
    if result['matches_reference']!=(result['sha256']==REFERENCE_SHA):return False
    if any(result[key] is not False for key in FALSE_FLAGS):return False
    resource=result['resource']
    return (type(resource) is dict and set(resource)=={'address_space_limit_bytes','cpu_limit_s','workers'}
        and all(type(resource[key]) is int for key in resource)
        and 0<resource['address_space_limit_bytes']<=512*1024*1024
        and 0<resource['cpu_limit_s']<=30 and resource['workers']==1)


def main():
    try:
        require(sys.platform=='linux' and len(sys.argv)==1,'LINUX_FIXED_STDIN_ONLY')
        import resource
        imposed={}
        for kind,cap,key in ((resource.RLIMIT_AS,512*1024*1024,'address_space_limit_bytes'),
                             (resource.RLIMIT_CPU,30,'cpu_limit_s')):
            soft,hard=resource.getrlimit(kind)
            bound=min([cap]+[value for value in (soft,hard) if value!=resource.RLIM_INFINITY])
            resource.setrlimit(kind,(bound,hard))
            imposed[key]=bound
        imposed['workers']=1
        count,digest=hash_fixed()
        result=response(count,digest,imposed)
        require(validate_response(result),'OUTPUT_SCHEMA')
        raw=json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=True)
        require(len(raw.encode('ascii'))+1<=MAX_OUTPUT_BYTES,'OUTPUT_BOUND')
        print(raw)
        return 0
    except Exception:
        print('{"status":"FAIL_CLOSED_DRIVER_IDENTITY","code":"FIXED_SOURCE_REJECTED"}')
        return 2


if __name__=='__main__':
    sys.exit(main())
