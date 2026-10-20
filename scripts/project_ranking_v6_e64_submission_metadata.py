"""Fixed mixed-launcher byte projection; only target submission metadata leaves the parser."""
import json
import os
import re
import stat
import sys

PATH = '/temp/jiangchuanc/multimode_ate_phase4_20260825_A/logs/phase4_closure_batch_v2_r1.launcher.log'
MAX_SOURCE_BYTES = 2*1024*1024
MAX_OUTPUT_BYTES = 16384
FALSE_FLAGS = ('non_target_metadata_exposed','timestamps_exposed','quality_or_runtime_values_exposed',
    'source_imported_or_executed','referenced_files_opened','remote_files_written',
    'historical_freeze_certified','historically_deployed_execution_certified','physical_call_certified',
    'costs_computed','training_release','job_execution_proved','global_absence_claimed')


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


def read_fixed(api=os):
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
        parts_read=[]
        while count<=MAX_SOURCE_BYTES:
            chunk=api.read(source_fd,min(65536,MAX_SOURCE_BYTES+1-count))
            if not chunk:break
            count+=len(chunk)
            require(count<=MAX_SOURCE_BYTES,'SOURCE_BOUND')
            parts_read.append(chunk)
        after=api.fstat(source_fd)
        last=api.stat(parts[-1],dir_fd=parent,follow_symlinks=False)
        regular(after);regular(last)
        require(identity(before)==identity(opened)==identity(after)==identity(last)
                and count==opened.st_size,'READ_IDENTITY_OR_SIZE')
        for parent_fd,name,child,expected in ancestors:
            require(directory_identity(api.fstat(child))==expected
                    and directory_identity(api.stat(name,dir_fd=parent_fd,follow_symlinks=False))==expected,
                    'ANCESTOR_CHANGED')
        return b''.join(parts_read)
    finally:
        if source_fd is not None:api.close(source_fd)
        for fd in reversed(descriptors):api.close(fd)



MAX_TARGET_ROWS=16
STAMP=rb'[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])'
SUBMIT=re.compile(STAMP+rb'\t(b20|b21|b22|wb_dma|aes_core|tv80|spi)\tCLOSURE\tSUBMIT\Z')
JOB=re.compile(rb'Job <([0-9]{1,20})> is submitted to (?:default )?queue <[A-Za-z0-9_.-]{1,64}>\.\Z')

def project_bytes(raw):
    require(type(raw) is bytes and 0<len(raw)<=MAX_SOURCE_BYTES,'INPUT_BOUND')
    rows=[];current=None
    for line in raw.split(b'\n'):
        if line.endswith(b'\r'):line=line[:-1]
        if b'\t' in line or re.match(rb'[0-9]{4}-[0-9]{2}-[0-9]{2}',line):
            current=None
            submit=SUBMIT.fullmatch(line)
            if submit and submit.group(1) in (b'aes_core',b'spi'):
                require(len(rows)<MAX_TARGET_ROWS,'TARGET_ROW_BOUND')
                current=dict(order=len(rows)+1,circuit='aes_core' if submit.group(1)==b'aes_core' else 'spi',
                    job_id=None,association='MISSING')
                rows.append(current)
        elif current is not None:
            job=JOB.fullmatch(line)
            if job:
                if current['association']=='MISSING':
                    current.update(job_id=job.group(1).decode('ascii'),association='UNIQUE')
                else:current.update(job_id=None,association='AMBIGUOUS')
    return rows

def response(raw,resource):
    rows=project_bytes(raw)
    status=('NO_MATCH_WITHIN_FIXED_SCOPE' if not rows else
        'PARTIAL_TARGET_SUBMISSION_METADATA' if any(r['association']!='UNIQUE' for r in rows) or {r['circuit'] for r in rows}!={'aes_core','spi'} else
        'PASS_TARGET_SUBMISSION_METADATA_OBSERVATIONS')
    return dict(status=status,path=PATH,byte_count=len(raw),target_rows=rows,
        evidence='LOG_ORDER_ONLY_NOT_EXECUTION_PROOF',resource=resource,
        **{key:False for key in FALSE_FLAGS})

def validate_response(result):
    keys={'status','path','byte_count','target_rows','evidence','resource',*FALSE_FLAGS}
    if type(result) is not dict or set(result)!=keys:return False
    if result['path']!=PATH or result['evidence']!='LOG_ORDER_ONLY_NOT_EXECUTION_PROOF':return False
    if type(result['byte_count']) is not int or not 0<result['byte_count']<=MAX_SOURCE_BYTES:return False
    if any(result[key] is not False for key in FALSE_FLAGS):return False
    rows=result['target_rows']
    if type(rows) is not list or len(rows)>MAX_TARGET_ROWS:return False
    for order,row in enumerate(rows,1):
        if type(row) is not dict or set(row)!={'order','circuit','job_id','association'}:return False
        if type(row['order']) is not int or row['order']!=order or row['circuit'] not in ('aes_core','spi'):return False
        if row['association']=='UNIQUE':
            if type(row['job_id']) is not str or re.fullmatch('[0-9]{1,20}',row['job_id']) is None:return False
        elif row['association'] in ('MISSING','AMBIGUOUS'):
            if row['job_id'] is not None:return False
        else:return False
    expected=('NO_MATCH_WITHIN_FIXED_SCOPE' if not rows else
        'PARTIAL_TARGET_SUBMISSION_METADATA' if any(r['association']!='UNIQUE' for r in rows) or {r['circuit'] for r in rows}!={'aes_core','spi'} else
        'PASS_TARGET_SUBMISSION_METADATA_OBSERVATIONS')
    if result['status']!=expected:return False
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
            resource.setrlimit(kind,(bound,hard));imposed[key]=bound
        imposed['workers']=1
        result=response(read_fixed(),imposed)
        require(validate_response(result),'OUTPUT_SCHEMA')
        raw=json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=True)
        require(len(raw.encode('ascii'))+1<=MAX_OUTPUT_BYTES,'OUTPUT_BOUND')
        print(raw);return 0
    except Exception:
        print('{"status":"FAIL_CLOSED_SUBMISSION_METADATA","code":"FIXED_SOURCE_REJECTED"}')
        return 2

if __name__=='__main__':
    sys.exit(main())
