import hashlib
import json
import os
import re
import stat
import sys

BASE='/temp/jiangchuanc/multimode_ate_phase4_20260825_A'
ROOTS=(BASE+'/logs',BASE+'/00_framework')
DRIVER=BASE+'/00_framework/phase4_closure_driver_v2.py'
REFERENCE_SHA='4394d366098c7c64614dced1cade709373b315fc3749a8f93404d5c496ecfb94'
STEMS=('phase4_closure_batch_v2_r1','phase4_closure_batch_v2')
TOKENS=frozenset(('sh','lsf','submit','log','out','err','status','stdout','stderr','bsub','job','o','e'))
MAX_ENTRIES=512
MAX_FILES=16
MAX_FILE_BYTES=2*1024*1024
MAX_TOTAL_BYTES=8*1024*1024
PER_KIND_CAP=8
MAX_OUTPUT=16384
FALSE_FLAGS=('nonanchor_line_values_decoded','status_values_decoded','source_or_launch_executed',
    'referenced_files_opened','driver_source_reread','remote_files_written','quality_or_runtime_values_exposed',
    'historical_immutability_certified','historical_execution_certified','physical_call_certified',
    'costs_computed','training_release')
JOB=re.compile(rb'Job <([0-9]{1,20})> is submitted to (?:default )?queue <[A-Za-z0-9_.-]{1,64}>\.\r?\Z')
SHA_LINE=re.compile(rb'([a-fA-F0-9]{64}) (?: |\*)'+re.escape(DRIVER.encode('ascii'))+rb'\r?\Z')


def require(ok,code):
    if not ok:raise ValueError(code)


def selected_name(name):
    if type(name) is not str or not name.isascii():return False
    for stem in STEMS:
        if name.startswith(stem+'.'):
            tokens=name[len(stem)+1:].split('.')
            return 1<=len(tokens)<=3 and all(token in TOKENS for token in tokens)
    return False


def status_only(name):
    return 'status' in name.split('.')[1:]


def content_allowed(name):
    suffix='.'.join(name.split('.')[1:])
    return suffix in ('sh','lsf','bsub','job')


def identity(info):
    return tuple(getattr(info,key) for key in
        ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


def directory(info):
    require(stat.S_ISDIR(info.st_mode),'ORDINARY_DIRECTORY')
    return (info.st_dev,info.st_ino,info.st_mode)


def regular(info):
    require(stat.S_ISREG(info.st_mode) and info.st_nlink==1
        and not getattr(info,'st_file_attributes',0)&0x400,'ORDINARY_SINGLE_LINK_FILE')


def open_scope(root,api):
    require(root in ROOTS,'FIXED_SCOPE')
    descriptors=[];ancestors=[]
    try:
        flags=api.O_RDONLY|api.O_DIRECTORY|api.O_NOFOLLOW
        parent=api.open('/',flags);descriptors.append(parent);directory(api.fstat(parent))
        for name in root.strip('/').split('/'):
            expected=directory(api.stat(name,dir_fd=parent,follow_symlinks=False))
            child=api.open(name,flags,dir_fd=parent);descriptors.append(child)
            require(directory(api.fstat(child))==expected,'ANCESTOR_CHANGED')
            ancestors.append((parent,name,child,expected));parent=child
        return parent,descriptors,ancestors
    except Exception:
        for fd in reversed(descriptors):api.close(fd)
        raise


def verify_ancestors(ancestors,api):
    for parent,name,child,expected in ancestors:
        require(directory(api.fstat(child))==expected
            and directory(api.stat(name,dir_fd=parent,follow_symlinks=False))==expected,'ANCESTOR_CHANGED')


def read_candidate(parent,name,before,remaining,api):
    regular(before)
    require(0<before.st_size<=MAX_FILE_BYTES and before.st_size<=remaining,'READ_BYTE_BOUND')
    fd=api.open(name,api.O_RDONLY|api.O_NOFOLLOW|getattr(api,'O_NONBLOCK',0),dir_fd=parent)
    try:
        opened=api.fstat(fd);regular(opened)
        require(identity(before)==identity(opened),'OPEN_IDENTITY')
        parts=[];count=0;digest=hashlib.sha256()
        cap=min(MAX_FILE_BYTES,remaining)
        while count<=cap:
            chunk=api.read(fd,min(65536,cap+1-count))
            if not chunk:break
            count+=len(chunk);require(count<=cap,'READ_BYTE_BOUND')
            parts.append(chunk);digest.update(chunk)
        after=api.fstat(fd);last=api.stat(name,dir_fd=parent,follow_symlinks=False)
        regular(after);regular(last)
        require(identity(before)==identity(opened)==identity(after)==identity(last)
            and count==opened.st_size,'READ_IDENTITY_OR_SIZE')
        return b''.join(parts),digest.hexdigest()
    finally:api.close(fd)


def project_bytes(raw,remaining=None):
    require(type(raw) is bytes and len(raw)<=MAX_FILE_BYTES,'PARSER_BOUND')
    if remaining is None:remaining={'SCHEDULER_SUBMISSION':PER_KIND_CAP,'DRIVER_SHA256':PER_KIND_CAP}
    anchors=[];recognized=0;emitted={'SCHEDULER_SUBMISSION':0,'DRIVER_SHA256':0}
    for ordinal,line in enumerate(raw.split(b'\n'),1):
        job=JOB.fullmatch(line);digest=SHA_LINE.fullmatch(line)
        if job:
            recognized+=1
            if emitted['SCHEDULER_SUBMISSION']<remaining['SCHEDULER_SUBMISSION']:
                anchors.append(dict(kind='SCHEDULER_SUBMISSION',logical_line=ordinal,job_id=job.group(1).decode('ascii')))
                emitted['SCHEDULER_SUBMISSION']+=1
        elif digest:
            recognized+=1
            if emitted['DRIVER_SHA256']<remaining['DRIVER_SHA256']:
                value=digest.group(1).lower().decode('ascii')
                anchors.append(dict(kind='DRIVER_SHA256',logical_line=ordinal,sha256=value,matches_reference=value==REFERENCE_SHA))
                emitted['DRIVER_SHA256']+=1
    return dict(driver_path_occurrences=raw.count(DRIVER.encode('ascii')),
        recognized_anchor_count=recognized,anchors_omitted=recognized-len(anchors),anchors=anchors)


def scan(api=os):
    roots=[];files=[];read_bytes=0
    emitted={'SCHEDULER_SUBMISSION':0,'DRIVER_SHA256':0}
    for root in ROOTS:
        parent,descriptors,ancestors=open_scope(root,api)
        try:
            root_identity=identity(api.fstat(parent));names=[]
            with api.scandir(parent) as entries:
                for entry in entries:
                    require(len(names)<MAX_ENTRIES,'DIRECTORY_ENTRY_BOUND')
                    names.append(entry.name)
            require(len(names)==len(set(names)),'DUPLICATE_NAME')
            selected=sorted(name for name in names if selected_name(name))
            require(len(files)+len(selected)<=MAX_FILES,'SELECTED_FILE_BOUND')
            roots.append(dict(root=root,entry_count=len(names),selected_file_count=len(selected)))
            for name in selected:
                before=api.stat(name,dir_fd=parent,follow_symlinks=False);regular(before)
                require(before.st_size>=0,'FILE_SIZE')
                row=dict(root=root,name=name,file_type='REGULAR_SINGLE_LINK',
                    role='LAUNCH_CODE' if content_allowed(name) else 'STATUS_METADATA_ONLY' if status_only(name) else 'NONCODE_METADATA_ONLY',
                    observed_byte_count=before.st_size,sha256=None,driver_path_occurrences=None,
                    recognized_anchor_count=0,anchors_omitted=0,anchors=[],anchors_scanned=False)
                if not content_allowed(name):
                    row['content_state']='METADATA_ONLY_NO_OPEN'
                elif before.st_size>MAX_FILE_BYTES:
                    row['content_state']='NOT_OPENED_SIZE_LIMIT'
                elif before.st_size>MAX_TOTAL_BYTES-read_bytes:
                    row['content_state']='NOT_OPENED_TOTAL_BUDGET'
                else:
                    if before.st_size==0:
                        fd=api.open(name,api.O_RDONLY|api.O_NOFOLLOW|getattr(api,'O_NONBLOCK',0),dir_fd=parent)
                        try:
                            opened=api.fstat(fd);regular(opened)
                            require(identity(opened)==identity(before),'OPEN_IDENTITY')
                            require(api.read(fd,1)==b'','EMPTY_CHANGED')
                            after=api.fstat(fd);regular(after)
                            last=api.stat(name,dir_fd=parent,follow_symlinks=False);regular(last)
                            require(identity(before)==identity(after)==identity(last),'READ_IDENTITY_OR_SIZE')
                        finally:api.close(fd)
                        raw=b'';digest=hashlib.sha256(raw).hexdigest()
                    else:
                        raw,digest=read_candidate(parent,name,before,MAX_TOTAL_BYTES-read_bytes,api)
                    read_bytes+=len(raw)
                    row['sha256']=digest
                    row['content_state']='HASHED_METADATA_PROJECTION'
                    row.update(project_bytes(raw,{key:PER_KIND_CAP-count for key,count in emitted.items()}))
                    row['anchors_scanned']=True
                    for anchor in row['anchors']:emitted[anchor['kind']]+=1
                if row['sha256'] is None:
                    last=api.stat(name,dir_fd=parent,follow_symlinks=False);regular(last)
                    require(identity(before)==identity(last),'SKIPPED_FILE_CHANGED')
                files.append(row)
            verify_ancestors(ancestors,api)
            require(identity(api.fstat(parent))==root_identity,'DIRECTORY_CHANGED')
        finally:
            for fd in reversed(descriptors):api.close(fd)
    return dict(status='PASS_FIXED_LAUNCH_METADATA_OBSERVATIONS' if files else 'NO_MATCH_WITHIN_FIXED_SCOPE',
        anchor_evidence='CODE_LITERALS_NOT_EXECUTION_PROOF',
        roots=roots,files=files,bytes_read=read_bytes,
        scope_incomplete_for_contents=any(row['sha256'] is None for row in files),
        scope_incomplete_for_anchors=any(row['sha256'] is None or row['anchors_omitted'] for row in files),
        global_absence_claimed=False,**{key:False for key in FALSE_FLAGS})


def validate_response(result):
    keys={'status','anchor_evidence','roots','files','bytes_read','scope_incomplete_for_contents','scope_incomplete_for_anchors','global_absence_claimed','resource',*FALSE_FLAGS}
    if type(result) is not dict or set(result)!=keys:return False
    if result['anchor_evidence']!='CODE_LITERALS_NOT_EXECUTION_PROOF':return False
    if result['global_absence_claimed'] is not False or any(result[k] is not False for k in FALSE_FLAGS):return False
    roots=result['roots'];files=result['files']
    if type(roots) is not list or len(roots)!=2 or type(files) is not list or len(files)>MAX_FILES:return False
    for item,root in zip(roots,ROOTS):
        if type(item) is not dict or set(item)!={'root','entry_count','selected_file_count'} or item['root']!=root:return False
        if any(type(item[k]) is not int for k in ('entry_count','selected_file_count')):return False
        if not 0<=item['selected_file_count']<=item['entry_count']<=MAX_ENTRIES:return False
    expected='PASS_FIXED_LAUNCH_METADATA_OBSERVATIONS' if files else 'NO_MATCH_WITHIN_FIXED_SCOPE'
    if result['status']!=expected:return False
    consumed=0;emitted={'SCHEDULER_SUBMISSION':0,'DRIVER_SHA256':0};ordering=[];incomplete=False;anchor_incomplete=False
    for row in files:
        if type(row) is not dict or set(row)!={'root','name','file_type','role','observed_byte_count','sha256','driver_path_occurrences',
            'recognized_anchor_count','anchors_omitted','anchors','content_state','anchors_scanned'}:return False
        if row['root'] not in ROOTS or not selected_name(row['name']) or row['file_type']!='REGULAR_SINGLE_LINK':return False
        ordering.append((ROOTS.index(row['root']),row['name']))
        hashed_status=status_only(row['name'])
        if row['role']!=('LAUNCH_CODE' if content_allowed(row['name']) else 'STATUS_METADATA_ONLY' if hashed_status else 'NONCODE_METADATA_ONLY'):return False
        n=row['observed_byte_count'];state=row['content_state'];anchors=row['anchors']
        if type(n) is not int or n<0 or type(anchors) is not list:return False
        if any(type(row[k]) is not int or row[k]<0 for k in ('recognized_anchor_count','anchors_omitted')):return False
        if row['recognized_anchor_count']!=len(anchors)+row['anchors_omitted'] or row['recognized_anchor_count']>n+1:return False
        if row['sha256'] is None:
            expected=('METADATA_ONLY_NO_OPEN' if not content_allowed(row['name']) else
                'NOT_OPENED_SIZE_LIMIT' if n>MAX_FILE_BYTES else 'NOT_OPENED_TOTAL_BUDGET')
            if state!=expected:return False
            if content_allowed(row['name']) and n<=MAX_FILE_BYTES and n<=MAX_TOTAL_BYTES-consumed:return False
            if anchors or row['driver_path_occurrences'] is not None or row['recognized_anchor_count']:return False
            if row['anchors_scanned'] is not False:return False
            incomplete=anchor_incomplete=True;continue
        if not content_allowed(row['name']) or n>MAX_FILE_BYTES or consumed+n>MAX_TOTAL_BYTES:return False
        if type(row['sha256']) is not str or re.fullmatch('[a-f0-9]{64}',row['sha256']) is None:return False
        consumed+=n
        if state!='HASHED_METADATA_PROJECTION' or row['anchors_scanned'] is not True:return False
        if type(row['driver_path_occurrences']) is not int or not 0<=row['driver_path_occurrences']<=n:return False
        lines=[]
        for anchor in anchors:
            if type(anchor) is not dict or type(anchor.get('logical_line')) is not int or not 1<=anchor['logical_line']<=n+1:return False
            lines.append(anchor['logical_line'])
            if anchor.get('kind')=='SCHEDULER_SUBMISSION':
                if set(anchor)!={'kind','logical_line','job_id'} or type(anchor['job_id']) is not str or re.fullmatch('[0-9]{1,20}',anchor['job_id']) is None:return False
            elif anchor.get('kind')=='DRIVER_SHA256':
                if set(anchor)!={'kind','logical_line','sha256','matches_reference'}:return False
                value=anchor['sha256']
                if type(value) is not str or re.fullmatch('[a-f0-9]{64}',value) is None:return False
                if type(anchor['matches_reference']) is not bool or anchor['matches_reference']!=(value==REFERENCE_SHA):return False
            else:return False
            emitted[anchor['kind']]+=1
        if lines!=sorted(set(lines)):return False
        if any(count>PER_KIND_CAP for count in emitted.values()):return False
        anchor_incomplete=anchor_incomplete or bool(row['anchors_omitted'])
    if ordering!=sorted(set(ordering)):return False
    if any(item['selected_file_count']!=sum(row['root']==item['root'] for row in files) for item in roots):return False
    if type(result['bytes_read']) is not int or result['bytes_read']!=consumed:return False
    if type(result['scope_incomplete_for_contents']) is not bool or result['scope_incomplete_for_contents']!=incomplete:return False
    if type(result['scope_incomplete_for_anchors']) is not bool or result['scope_incomplete_for_anchors']!=anchor_incomplete:return False
    resource=result['resource']
    return (type(resource) is dict and set(resource)=={'address_space_limit_bytes','cpu_limit_s','workers'}
        and all(type(v) is int for v in resource.values()) and 0<resource['address_space_limit_bytes']<=512*1024*1024
        and 0<resource['cpu_limit_s']<=30 and resource['workers']==1)


def main():
    try:
        require(sys.platform=='linux' and len(sys.argv)==1,'LINUX_FIXED_STDIN_ONLY')
        import resource
        imposed={}
        for kind,cap,key in ((resource.RLIMIT_AS,512*1024*1024,'address_space_limit_bytes'),(resource.RLIMIT_CPU,30,'cpu_limit_s')):
            soft,hard=resource.getrlimit(kind)
            bound=min([cap]+[v for v in (soft,hard) if v!=resource.RLIM_INFINITY])
            resource.setrlimit(kind,(bound,hard));imposed[key]=bound
        imposed['workers']=1
        result=scan();result['resource']=imposed
        require(validate_response(result),'OUTPUT_SCHEMA')
        raw=json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=True)
        require(len(raw.encode('ascii'))+1<=MAX_OUTPUT,'OUTPUT_BOUND')
        print(raw);return 0
    except Exception:
        print('{"status":"FAIL_CLOSED_LAUNCH_METADATA","code":"FIXED_SCOPE_REJECTED"}')
        return 2


if __name__=='__main__':
    sys.exit(main())
