"""Bounded explicit metadata reader. Import has no filesystem or remote action."""
import errno
import hashlib
import json
import os
import re
import socket
import stat
import sys

A_ROOT = '/temp/jiangchuanc/multimode_ate_phase4_20260825_A'
B_ROOT = '/ssd/cjc'
PROTECTED = B_ROOT+'/multimode_ate_gnn_v1'
FILE_LIMIT = 128*1024
TOTAL_LIMIT = 1024*1024
OUTPUT_LIMIT = 32768
MAX_FILES = 8
MAX_ENTRIES = 100
CODE_SUFFIXES = frozenset(('.py','.sh','.tcl','.lsf','.bsub','.job'))
META_WORDS = ('identity','feature','environment','model','schema','config')
DENY = ('blind','validation','outcome','metric','result','checkpoint','prediction','log')
RESOURCE_SIDECARS = frozenset(B_ROOT+'/gnn_model_ranking_v5_train_20261011_r2_iwls_'+c+
    '_20260824.stdout.log.memory.json' for c in ('aes_core','spi'))
JIT_SIDECARS = frozenset(B_ROOT+'/gnn_model_ranking_v5_train_20261011_r2/jit_admission_iwls_'+c+
    '_20260824.json' for c in ('aes_core','spi'))
JSON_KEYS = frozenset(('schema','schema_version','model_version','feature_version',
    'feature_names','feature_columns','graph_sha256','netlist_sha256','library_sha256',
    'common_fault_count','common_fault_universe_sha256','checkpoint_sha256','driver_sha256',
    'config_sha256','environment_sha256','memory_limit_bytes','workers','threads','family','seed',
    'source_root','output','freeze_loader_sha256','run_authorization_sha256','source_binding_sha256',
    'run_binding_review_sha256','address_space_limits','core_limits','peak_group_rss_bytes',
    'peak_combined_rss_bytes','rss_limit_bytes','address_space_bytes','combined_rss_limit_bytes'))
JSON_INTEGER_KEYS = frozenset(('common_fault_count','memory_limit_bytes','workers','threads','seed',
    'peak_group_rss_bytes','peak_combined_rss_bytes','rss_limit_bytes','address_space_bytes','combined_rss_limit_bytes'))
ENV_KEYS = frozenset((b'CIRCUIT',b'TOP_MODULE',b'F_CHAIN_COUNT',b'M_CHAIN_COUNT',
    b'H_CHAIN_COUNT',b'EXTERNAL_CHANNELS',b'TIMEPLATE_NS',b'CELL_LIBRARY'))
GUARDS = frozenset(('REQUEST','PATH_SCOPE','NAME_SCOPE','PROTECTED_PATH','DIRECTORY',
    'ANCESTOR_CHANGED','FILE_TYPE','FILE_BOUND','TOTAL_BOUND','FILE_CHANGED','SHORT_READ',
    'ENTRY_BOUND','DUPLICATE_ENTRY','PROC_IDENTITY','JSON_SYNTAX','JSON_BOUND','JSON_ASCII',
    'JSON_DUPLICATE','JSON_SELECTED_TYPE','JSON_SELECTED_VALUE','ENV_SELECTED_VALUE',
    'ENV_DUPLICATE','OUTPUT_BOUND','ACCESS_DENIED','MISSING','NOFOLLOW_REJECTED','OS_ERROR'))


class Guard(ValueError):
    def __init__(self, code):
        self.code = code if code in GUARDS else 'REQUEST'
        ValueError.__init__(self, self.code)


def require(ok, code):
    if not ok:
        raise Guard(code)


def safe_name(name):
    return (type(name) is str and re.fullmatch('[A-Za-z0-9_.-]{1,128}',name) is not None
        and name not in ('.','..'))


def forbidden(name):
    lowered=name.lower()
    return (any(word in lowered for word in DENY) or lowered.endswith(('.log','.out','.err',
        '.stdout','.stderr','.status')) or lowered in ('logs','runs','checkpoints'))


def file_kind(name, generic_manifest=False):
    if not safe_name(name) or forbidden(name):
        return None
    if name == 'config.env':
        return 'ENV'
    if os.path.splitext(name)[1] in CODE_SUFFIXES:
        return 'CODE_HASH_ONLY'
    if name.endswith('.json') and (generic_manifest and name=='manifest.json'
            or any(word in name.lower() for word in META_WORDS)):
        return 'JSON_METADATA'
    return None


def validate_path(role, path, inventory=False):
    require(role in ('A','B') and type(path) is str and len(path)<=1024,'REQUEST')
    require(path != PROTECTED and not path.startswith(PROTECTED+'/'),'PROTECTED_PATH')
    root=A_ROOT if role=='A' else B_ROOT
    require(path==root or path.startswith(root+'/'),'PATH_SCOPE')
    parts=path.split('/')[1:]
    require(all(safe_name(p) for p in parts),'NAME_SCOPE')
    if role=='B' and path in RESOURCE_SIDECARS:
        require(all(not forbidden(p) for p in parts[:-1]),'NAME_SCOPE')
        return 'JSON_METADATA'
    require(all(not forbidden(p) for p in parts),'NAME_SCOPE')
    relative=path[len(root):].strip('/')
    if role=='A':
        configs = [A_ROOT+'/10_circuits/'+c+'/01_config' for c in ('aes_core','spi')]
        if inventory:
            require(path in [A_ROOT+'/00_framework']+configs,'PATH_SCOPE')
            return 'DIRECTORY'
        if path.startswith(A_ROOT+'/00_framework/'):
            require(file_kind(parts[-1])=='CODE_HASH_ONLY','NAME_SCOPE')
            return 'CODE_HASH_ONLY'
        if path in [d+'/config.env' for d in configs]:
            return 'ENV'
        manifests=[A_ROOT+'/10_circuits/'+c+'/03_fault_universe/common_'+c+'_m16_phase4_v2/manifest.json'
                   for c in ('aes_core','spi')]
        require(path in manifests,'PATH_SCOPE')
        return 'JSON_METADATA'
    if inventory and path==B_ROOT:
        return 'DIRECTORY'
    require(relative and relative.split('/')[0].startswith('gnn_model'),'PATH_SCOPE')
    if inventory:
        return 'DIRECTORY'
    if path in JIT_SIDECARS:
        return 'JSON_METADATA'
    kind=file_kind(parts[-1])
    require(kind is not None and kind!='ENV','NAME_SCOPE')
    return kind


def identity(info):
    return tuple(getattr(info,k) for k in
        ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


def directory(info):
    require(stat.S_ISDIR(info.st_mode),'DIRECTORY')
    return info.st_dev,info.st_ino,info.st_mode


def regular(info):
    require(stat.S_ISREG(info.st_mode) and info.st_nlink==1
        and not getattr(info,'st_file_attributes',0)&0x400,'FILE_TYPE')


def open_directory(path, api):
    descriptors=[];ancestors=[]
    try:
        flags=api.O_RDONLY|api.O_DIRECTORY|api.O_NOFOLLOW
        parent=api.open('/',flags);descriptors.append(parent);directory(api.fstat(parent))
        for name in path.strip('/').split('/'):
            before=directory(api.stat(name,dir_fd=parent,follow_symlinks=False))
            child=api.open(name,flags,dir_fd=parent);descriptors.append(child)
            require(directory(api.fstat(child))==before,'ANCESTOR_CHANGED')
            ancestors.append((parent,name,child,before));parent=child
        return parent,descriptors,ancestors,identity(api.fstat(parent))
    except BaseException:
        for fd in reversed(descriptors):api.close(fd)
        raise


def verify_directory(fd, ancestors, before, api):
    for parent,name,child,expected in ancestors:
        require(directory(api.stat(name,dir_fd=parent,follow_symlinks=False))
            ==directory(api.fstat(child))==expected,'ANCESTOR_CHANGED')
    require(identity(api.fstat(fd))==before,'ANCESTOR_CHANGED')


def read_file(path, api, budget):
    parent,descriptors,ancestors,parent_before=open_directory(path.rsplit('/',1)[0],api)
    fd=None
    try:
        name=path.rsplit('/',1)[1]
        before=api.stat(name,dir_fd=parent,follow_symlinks=False);regular(before)
        require(0<=before.st_size<=FILE_LIMIT,'FILE_BOUND')
        require(before.st_size<=TOTAL_LIMIT-budget['bytes'],'TOTAL_BOUND')
        fd=api.open(name,api.O_RDONLY|api.O_NOFOLLOW|getattr(api,'O_NONBLOCK',0),dir_fd=parent)
        budget['files']+=1
        opened=api.fstat(fd);regular(opened)
        require(identity(before)==identity(opened),'FILE_CHANGED')
        chunks=[];size=0
        while size<before.st_size:
            chunk=api.read(fd,min(65536,before.st_size-size))
            require(type(chunk) is bytes and 0<len(chunk)<=before.st_size-size,'SHORT_READ')
            size+=len(chunk);budget['bytes']+=len(chunk);chunks.append(chunk)
        after=api.fstat(fd);last=api.stat(name,dir_fd=parent,follow_symlinks=False)
        regular(after);regular(last)
        require(identity(before)==identity(opened)==identity(after)==identity(last),'FILE_CHANGED')
        verify_directory(parent,ancestors,parent_before,api)
        return b''.join(chunks)
    finally:
        if fd is not None:api.close(fd)
        for item in reversed(descriptors):api.close(item)


def project_env(raw):
    result={}
    for line in raw.split(b'\n'):
        line=line.strip()
        if line.startswith(b'export '):line=line[7:]
        key,separator,value=line.partition(b'=')
        if not separator or key not in ENV_KEYS:continue
        require(key not in result,'ENV_DUPLICATE')
        value=value.strip()
        if len(value)>=2 and value[:1]==value[-1:] and value[:1] in (b'"',b"'"):
            value=value[1:-1]
        require(0<len(value)<=512 and all(32<=c<127 for c in value)
            and not any(c in value for c in (b'$',b'`',b';',b'"',b"'")),'ENV_SELECTED_VALUE')
        if key==b'CIRCUIT':require(value in (b'aes_core',b'spi'),'ENV_SELECTED_VALUE')
        elif key in (b'F_CHAIN_COUNT',b'M_CHAIN_COUNT',b'H_CHAIN_COUNT',b'EXTERNAL_CHANNELS'):
            require(re.fullmatch(rb'[1-9][0-9]{0,11}',value) is not None,'ENV_SELECTED_VALUE')
        elif key==b'TIMEPLATE_NS':
            require(re.fullmatch(rb'(?:0|[1-9][0-9]{0,8})(?:\.[0-9]{1,9})?',value) is not None
                and float(value)>0,'ENV_SELECTED_VALUE')
        result[key]=value
    return {key.decode('ascii'):value.decode('ascii') for key,value in result.items()}


def project_json(raw):
    """Byte grammar scan; only allowed top-level scalar/flat-list values decode."""
    require(type(raw) is bytes and len(raw)<=FILE_LIMIT,'JSON_BOUND')
    require(all(c<128 for c in raw),'JSON_ASCII')
    selected={};tokens=[0]
    def ws(i):
        while i<len(raw) and raw[i] in b' \t\r\n':i+=1
        return i
    def string(i):
        require(i<len(raw) and raw[i]==34,'JSON_SYNTAX');i+=1
        while i<len(raw):
            c=raw[i]
            if c==34:return i+1
            require(c>=32,'JSON_SYNTAX')
            if c==92:
                i+=1;require(i<len(raw),'JSON_SYNTAX')
                if raw[i]==117:
                    require(len(raw[i+1:i+5])==4 and all(c in b'0123456789abcdefABCDEF'
                        for c in raw[i+1:i+5]),'JSON_SYNTAX');i+=4
                else:require(raw[i] in b'"\\/bfnrt','JSON_SYNTAX')
            i+=1
        raise Guard('JSON_SYNTAX')
    def value(i,depth):
        tokens[0]+=1;require(depth<=16 and tokens[0]<=4096,'JSON_BOUND')
        i=ws(i);start=i;require(i<len(raw),'JSON_SYNTAX');kind=raw[i];flat=True
        if kind==34:i=string(i)
        elif kind in (123,91):
            closing=125 if kind==123 else 93
            keys=set();i=ws(i+1)
            if i<len(raw) and raw[i]==closing:return i+1,kind,kind==91
            while True:
                key=None
                if kind==123:
                    end=string(i);key=raw[i+1:end-1]
                    require(len(key)<=128 and b'\\' not in key,'JSON_SYNTAX')
                    require(key not in keys,'JSON_DUPLICATE');keys.add(key)
                    i=ws(end);require(i<len(raw) and raw[i]==58,'JSON_SYNTAX');i=ws(i+1)
                begin=i;i,child,child_flat=value(i,depth+1)
                flat=flat and child!=123 and child_flat
                if depth==0 and kind==123 and key in {k.encode('ascii') for k in JSON_KEYS}:
                    require(child!=123 and child_flat,'JSON_SELECTED_TYPE')
                    require(i-begin<=8192,'JSON_BOUND')
                    name=key.decode('ascii')
                    if name in ('feature_names','feature_columns','address_space_limits','core_limits'):
                        require(child==91,'JSON_SELECTED_TYPE')
                        if name in ('feature_names','feature_columns'):
                            cursor=begin+1
                            while cursor<i-1:
                                if raw[cursor]==34:cursor=string(cursor)
                                else:
                                    require(raw[cursor] in b' ,\t\r\n','JSON_SELECTED_TYPE');cursor+=1
                    elif name in JSON_INTEGER_KEYS:
                        require(child in b'-0123456789','JSON_SELECTED_TYPE')
                    else:require(child==34,'JSON_SELECTED_TYPE')
                    selected[name]=json.loads(raw[begin:i].decode('ascii'))
                i=ws(i);require(i<len(raw),'JSON_SYNTAX')
                if raw[i]==closing:return i+1,kind,flat if kind==91 else False
                require(raw[i]==44,'JSON_SYNTAX');i=ws(i+1)
        else:
            match=re.match(rb'(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)',raw[i:])
            require(match is not None,'JSON_SYNTAX');i+=len(match.group())
        return i,kind,flat
    require(raw.lstrip().startswith(b'{'),'JSON_SYNTAX')
    end,unused,unused_flat=value(0,0);require(ws(end)==len(raw),'JSON_SYNTAX')
    for key,value in selected.items():
        if key.endswith('_sha256'):
            require(type(value) is str and re.fullmatch('[a-f0-9]{64}',value) is not None,'JSON_SELECTED_VALUE')
        elif key in ('common_fault_count','memory_limit_bytes','workers','threads'):
            require(type(value) is int and 0<value<=2**63-1,'JSON_SELECTED_VALUE')
        elif key in ('seed','peak_group_rss_bytes','peak_combined_rss_bytes','rss_limit_bytes',
                     'address_space_bytes','combined_rss_limit_bytes'):
            require(type(value) is int and 0<=value<=2**63-1,'JSON_SELECTED_VALUE')
        elif key in ('address_space_limits','core_limits'):
            count=[0]
            def scalars(item,depth=0):
                count[0]+=1;require(count[0]<=128 and depth<=3,'JSON_BOUND')
                if type(item) is list:
                    require(len(item)<=64,'JSON_BOUND')
                    for child in item:scalars(child,depth+1)
                else:
                    require(item is None or type(item) is bool or type(item) is int and -1<=item<=2**63-1
                        or type(item) is str and len(item)<=256 and all(32<=ord(c)<127 for c in item),'JSON_SELECTED_VALUE')
            require(type(value) is list,'JSON_SELECTED_VALUE');scalars(value)
        elif key in ('feature_names','feature_columns'):
            require(type(value) is list and len(value)<=64 and all(type(v) is str and 0<len(v)<=128
                and all(32<=ord(c)<127 for c in v) for v in value),'JSON_SELECTED_VALUE')
        else:
            require(type(value) is str and 0<len(value)<=(1024 if key in ('source_root','output') else 256)
                and all(32<=ord(c)<127 for c in value),'JSON_SELECTED_VALUE')
    return selected


def inventory(role,path,api,budget):
    fd,descriptors,ancestors,before=open_directory(path,api)
    try:
        require(type(fd) is int and fd>=0,'PROC_IDENTITY')
        alias='/proc/self/fd/%d'%fd
        def verify_alias():
            require(identity(api.stat(alias,follow_symlinks=True))==identity(api.fstat(fd))==before,'PROC_IDENTITY')
        verify_alias();matches=[];seen=set();count=0
        with api.scandir(alias) as entries:
            for entry in entries:
                require(budget['entries']<MAX_ENTRIES,'ENTRY_BOUND')
                budget['entries']+=1;count+=1;name=entry.name
                require(type(name) is str and name not in seen,'DUPLICATE_ENTRY');seen.add(name)
                if not safe_name(name) or forbidden(name):continue
                root_entry=role=='B' and path==B_ROOT
                allowed=name.startswith('gnn_model') if root_entry else (
                    file_kind(name)=='CODE_HASH_ONLY' if role=='A' and path==A_ROOT+'/00_framework'
                    else name=='config.env' if role=='A' else file_kind(name) in ('CODE_HASH_ONLY','JSON_METADATA'))
                if not allowed:continue
                first=api.stat(name,dir_fd=fd,follow_symlinks=False)
                if root_entry:
                    directory(first);kind='DIRECTORY'
                else:
                    regular(first);kind='REGULAR_SINGLE_LINK'
                last=api.stat(name,dir_fd=fd,follow_symlinks=False)
                require(identity(first)==identity(last),'FILE_CHANGED')
                matches.append(dict(name=name,file_type=kind,bytes=first.st_size))
        verify_alias();verify_directory(fd,ancestors,before,api)
        return count,sorted(matches,key=lambda row:row['name'])
    finally:
        for item in reversed(descriptors):api.close(item)


def error_code(exc):
    if isinstance(exc,Guard):return exc.code
    if isinstance(exc,OSError):
        return {errno.ENOENT:'MISSING',errno.EACCES:'ACCESS_DENIED',errno.EPERM:'ACCESS_DENIED',
            errno.ELOOP:'NOFOLLOW_REJECTED'}.get(exc.errno,'OS_ERROR')
    return 'REQUEST'


def validate_request(role, paths, inventory_dirs):
    require(type(role) is str and role in ('A','B') and type(paths) is list and len(paths)<=MAX_FILES,'REQUEST')
    require(type(inventory_dirs) in (list,tuple) and len(inventory_dirs)<=8,'REQUEST')
    require(all(type(p) is str for p in paths) and len(set(paths))==len(paths),'REQUEST')
    require(all(type(p) is str for p in inventory_dirs) and len(set(inventory_dirs))==len(inventory_dirs),'REQUEST')
    for path in paths:validate_path(role,path)
    for path in inventory_dirs:validate_path(role,path,True)


def collect(role, paths, inventory_dirs=(), api=os):
    validate_request(role,paths,inventory_dirs)
    kinds=[validate_path(role,p) for p in paths]
    budget=dict(bytes=0,entries=0,files=0);files=[];directories=[]
    for path,kind in zip(paths,kinds):
        row=dict(path=path,status='READ',code=None,bytes=None,sha256=None,metadata={})
        try:
            raw=read_file(path,api,budget)
            metadata=project_env(raw) if kind=='ENV' else project_json(raw) if kind=='JSON_METADATA' else {}
            row.update(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),metadata=metadata)
        except Exception as exc:
            code=error_code(exc);row.update(status='MISSING' if code=='MISSING' else 'FAIL_CLOSED',code=code)
        files.append(row)
    for path in inventory_dirs:
        row=dict(path=path,status='LISTED',code=None,entries_seen=None,matches=[])
        try:
            count,matches=inventory(role,path,api,budget);row.update(entries_seen=count,matches=matches)
        except Exception as exc:
            code=error_code(exc);row.update(status='MISSING' if code=='MISSING' else 'FAIL_CLOSED',code=code)
        directories.append(row)
    complete=all(row['status']!='FAIL_CLOSED' for row in files+directories)
    result=dict(schema='prospective-metadata-read-v1',
        status='PASS_METADATA_ONLY' if complete else 'PARTIAL_METADATA_ONLY',
        role=role,host=host_identity(),resource=resource_identity(),paths=list(paths),
        inventory_dirs=list(inventory_dirs),files=files,inventories=directories,
        budget=dict(files_read=budget['files'],body_bytes=budget['bytes'],inventory_entries=budget['entries']),
        raw_bodies_returned=False,referenced_paths_opened=False,remote_writes=False,
        artifact_bytes_authenticated_by_sidecars=False,execution_ready=False,training_release=False)
    require(len(json.dumps(result,sort_keys=True,ensure_ascii=True).encode('ascii'))+1<=OUTPUT_LIMIT,'OUTPUT_BOUND')
    return result


def host_identity():
    hostname=socket.gethostname()
    require(type(hostname) is str and re.fullmatch('[A-Za-z0-9_.-]{1,128}',hostname) is not None,'REQUEST')
    return dict(hostname=hostname,python_version=list(sys.version_info[:3]),platform=sys.platform)


def resource_identity():
    result=dict(address_space_limit_bytes=None,cpu_limit_s=None,workers=1)
    try:
        import resource
        for kind,key in ((resource.RLIMIT_AS,'address_space_limit_bytes'),(resource.RLIMIT_CPU,'cpu_limit_s')):
            soft,unused=resource.getrlimit(kind)
            result[key]=None if soft==resource.RLIM_INFINITY else soft
    except ImportError:
        pass
    return result


def validate_response(result, request):
    """Pure strict gate; no imports of project code, paths or filesystem probes."""
    try:
        require(type(request) is dict and set(request)=={'role','paths','inventory_dirs'},'REQUEST')
        role=request['role'];paths=request['paths'];dirs=request['inventory_dirs']
        require(type(role) is str and role in ('A','B') and type(paths) is list and len(paths)<=MAX_FILES,'REQUEST')
        require(type(dirs) is list and len(dirs)<=8 and all(type(p) is str for p in paths+dirs),'REQUEST')
        require(len(set(paths))==len(paths) and len(set(dirs))==len(dirs),'REQUEST')
        kinds=[validate_path(role,p) for p in paths]
        for path in dirs:validate_path(role,path,True)
        flags={'raw_bodies_returned','referenced_paths_opened','remote_writes',
            'artifact_bytes_authenticated_by_sidecars','execution_ready','training_release'}
        require(type(result) is dict and set(result)=={'schema','status','role','host','resource','paths',
            'inventory_dirs','files','inventories','budget'}|flags,'REQUEST')
        require(result['schema']=='prospective-metadata-read-v1' and result['role']==role
            and result['paths']==paths and result['inventory_dirs']==dirs,'REQUEST')
        require(all(result[key] is False for key in flags),'REQUEST')
        host=result['host'];require(type(host) is dict and set(host)=={'hostname','python_version','platform'},'REQUEST')
        require(type(host['hostname']) is str and re.fullmatch('[A-Za-z0-9_.-]{1,128}',host['hostname']) is not None
            and host['platform']=='linux','REQUEST')
        require(type(host['python_version']) is list and len(host['python_version'])==3
            and all(type(v) is int and 0<=v<=999 for v in host['python_version']),'REQUEST')
        resources=result['resource'];require(type(resources) is dict and set(resources)=={
            'address_space_limit_bytes','cpu_limit_s','workers'},'REQUEST')
        require(type(resources['workers']) is int and resources['workers']==1,'REQUEST')
        for key,limit in (('address_space_limit_bytes',512*1024*1024),('cpu_limit_s',30)):
            require(type(resources[key]) is int and 0<resources[key]<=limit,'REQUEST')
        files=result['files'];inventories=result['inventories']
        require(type(files) is list and len(files)==len(paths) and type(inventories) is list
            and len(inventories)==len(dirs),'REQUEST')
        read_count=0;read_bytes=0;entry_count=0;failed=False
        for row,path,kind in zip(files,paths,kinds):
            require(type(row) is dict and set(row)=={'path','status','code','bytes','sha256','metadata'}
                and row['path']==path and type(row['metadata']) is dict,'REQUEST')
            if row['status']=='READ':
                require(row['code'] is None and type(row['bytes']) is int and 0<=row['bytes']<=FILE_LIMIT
                    and type(row['sha256']) is str and re.fullmatch('[a-f0-9]{64}',row['sha256']) is not None,'REQUEST')
                read_count+=1;read_bytes+=row['bytes'];metadata=row['metadata']
                if kind=='CODE_HASH_ONLY':require(metadata=={},'REQUEST')
                elif kind=='ENV':
                    require(all(type(k) is str and k.encode('ascii') in ENV_KEYS and type(v) is str
                        for k,v in metadata.items()),'REQUEST')
                    require(project_env(b'\n'.join(k.encode('ascii')+b'='+v.encode('ascii')
                        for k,v in metadata.items()))==metadata,'REQUEST')
                else:
                    require(set(metadata)<=JSON_KEYS and project_json(json.dumps(metadata,ensure_ascii=True,
                        allow_nan=False).encode('ascii'))==metadata,'REQUEST')
            else:
                require(row['status'] in ('MISSING','FAIL_CLOSED') and row['code'] in GUARDS
                    and (row['code']=='MISSING')==(row['status']=='MISSING') and row['bytes'] is None
                    and row['sha256'] is None and row['metadata']=={},'REQUEST')
                failed=failed or row['status']=='FAIL_CLOSED'
        for row,path in zip(inventories,dirs):
            require(type(row) is dict and set(row)=={'path','status','code','entries_seen','matches'}
                and row['path']==path and type(row['matches']) is list,'REQUEST')
            if row['status']=='LISTED':
                require(row['code'] is None and type(row['entries_seen']) is int
                    and 0<=len(row['matches'])<=row['entries_seen']<=MAX_ENTRIES,'REQUEST')
                entry_count+=row['entries_seen'];names=[]
                for match in row['matches']:
                    require(type(match) is dict and set(match)=={'name','file_type','bytes'}
                        and safe_name(match['name']) and not forbidden(match['name'])
                        and type(match['bytes']) is int and match['bytes']>=0,'REQUEST')
                    name=match['name'];names.append(name);root_entry=role=='B' and path==B_ROOT
                    if root_entry:require(name.startswith('gnn_model') and match['file_type']=='DIRECTORY','REQUEST')
                    else:
                        require(match['file_type']=='REGULAR_SINGLE_LINK','REQUEST')
                        require(file_kind(name)=='CODE_HASH_ONLY' if role=='A' and path==A_ROOT+'/00_framework'
                            else name=='config.env' if role=='A' else file_kind(name) in ('CODE_HASH_ONLY','JSON_METADATA'),'REQUEST')
                require(names==sorted(set(names)),'REQUEST')
            else:
                require(row['status'] in ('MISSING','FAIL_CLOSED') and row['code'] in GUARDS
                    and (row['code']=='MISSING')==(row['status']=='MISSING')
                    and row['entries_seen'] is None and not row['matches'],'REQUEST')
                failed=failed or row['status']=='FAIL_CLOSED'
        budget=result['budget'];require(type(budget) is dict and set(budget)=={'files_read','body_bytes','inventory_entries'},'REQUEST')
        require(all(type(v) is int for v in budget.values()) and read_count<=budget['files_read']<=len(paths)
            and read_bytes<=budget['body_bytes']<=TOTAL_LIMIT and entry_count<=budget['inventory_entries']<=MAX_ENTRIES,'REQUEST')
        if not any(row['status']=='FAIL_CLOSED' for row in files):
            require(budget['files_read']==read_count and budget['body_bytes']==read_bytes,'REQUEST')
        if not any(row['status']=='FAIL_CLOSED' for row in inventories):
            require(budget['inventory_entries']==entry_count,'REQUEST')
        require(result['status']==('PARTIAL_METADATA_ONLY' if failed else 'PASS_METADATA_ONLY'),'REQUEST')
        require(len(json.dumps(result,ensure_ascii=True,allow_nan=False).encode('ascii'))+1<=OUTPUT_LIMIT,'OUTPUT_BOUND')
        return True
    except (ValueError,TypeError,KeyError,UnicodeError,RecursionError,OverflowError):
        return False


def main(request):
    """Only an explicit reviewed parent-appended call runs; no CLI/default action."""
    try:
        require(type(request) is dict and set(request)=={'role','paths','inventory_dirs'},'REQUEST')
        require(sys.platform=='linux' and len(sys.argv)==1,'REQUEST')
        import resource
        import signal
        for kind,cap in ((resource.RLIMIT_AS,512*1024*1024),(resource.RLIMIT_CPU,30)):
            soft,hard=resource.getrlimit(kind)
            bound=min([cap]+[v for v in (soft,hard) if v!=resource.RLIM_INFINITY])
            resource.setrlimit(kind,(bound,hard))
        signal.alarm(50)
        result=collect(request['role'],request['paths'],request['inventory_dirs'])
        require(validate_response(result,request),'REQUEST')
        print(json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=True));return 0
    except Exception as exc:
        print(json.dumps(dict(status='FAIL_CLOSED_METADATA_REQUEST',code=error_code(exc)),sort_keys=True));return 2
