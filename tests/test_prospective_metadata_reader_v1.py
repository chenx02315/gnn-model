"""Synthetic bytes/FDs only. Never contact A/B or read their actual files."""
import copy
import errno
import hashlib
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

from scripts import read_prospective_metadata_v1 as p

A_CODE=p.A_ROOT+'/00_framework/driver.py'
A_ENV=p.A_ROOT+'/10_circuits/aes_core/01_config/config.env'
A_MANIFEST=p.A_ROOT+'/10_circuits/spi/03_fault_universe/common_spi_m16_phase4_v2/manifest.json'
B_JSON=p.B_ROOT+'/gnn_model_test/model_identity.json'
HOST=dict(hostname='synthetic-host',python_version=[3,6,8],platform='linux')
RESOURCE=dict(address_space_limit_bytes=512*1024*1024,cpu_limit_s=30,workers=1)


class Entries:
    def __init__(self,names):self.names=names
    def __enter__(self):return (types.SimpleNamespace(name=n) for n in self.names)
    def __exit__(self,*args):pass


class FakeFS:
    O_RDONLY,O_DIRECTORY,O_NOFOLLOW,O_NONBLOCK=0,1,2,4
    def __init__(self,files=None,dirs=None,extra=None,**options):
        self.options=options;self.nodes={'/':dict(kind='dir',names=[])}
        self.calls=[];self.opened=[];self.read_paths=[];self.closed=[];self.fds={};self.offsets={}
        self.next_fd=1;self.fstats={};self.stats={};self.alias_count=0
        for path in list(files or {})+list(dirs or []):
            current=''
            for name in path.strip('/').split('/'):
                parent=current or '/';current+='/'+name
                self.nodes.setdefault(current,dict(kind='dir',names=[]))
                if name not in self.nodes[parent]['names']:self.nodes[parent]['names'].append(name)
        for path,value in (files or {}).items():
            self.nodes[path]=dict(kind='file',data=value) if type(value) is bytes else dict(kind='file',**value)
        for path,names in (extra or {}).items():self.nodes[path]['names'].extend(names)
        self.ids={name:i+1 for i,name in enumerate(self.nodes)}
    def info(self,path):
        if path not in self.nodes:raise FileNotFoundError(errno.ENOENT,'PRIVATE_MISSING')
        node=self.nodes[path]
        return types.SimpleNamespace(st_dev=1,st_ino=self.ids[path],
            st_mode=node.get('mode',stat.S_IFDIR if node['kind']=='dir' else stat.S_IFREG),
            st_nlink=node.get('links',1),st_size=node.get('size',len(node.get('data',b''))),
            st_mtime_ns=1,st_ctime_ns=1,st_file_attributes=node.get('attrs',0))
    def full(self,name,dir_fd):return '/' if dir_fd is None else self.fds[dir_fd].rstrip('/')+'/'+name
    def stat(self,name,dir_fd=None,follow_symlinks=False):
        self.calls.append(('stat',name,dir_fd,follow_symlinks))
        if type(name) is str and name.startswith('/proc/self/fd/'):
            assert follow_symlinks is True and dir_fd is None
            if self.options.get('proc_missing'):raise FileNotFoundError(errno.ENOENT,'PRIVATE')
            if self.options.get('proc_denied'):raise PermissionError(errno.EACCES,'PRIVATE')
            self.alias_count+=1;fd=int(name.rsplit('/',1)[1]);value=self.info(self.fds[fd])
            if self.alias_count==self.options.get('proc_mismatch'):value.st_ino+=1
            return value
        assert follow_symlinks is False
        path=self.full(name,dir_fd);value=self.info(path)
        self.stats[path]=self.stats.get(path,0)+1
        if self.options.get('ancestor_swap')==path and self.stats[path]>1:value.st_ino+=1
        return value
    def fstat(self,fd):
        self.calls.append(('fstat',fd));path=self.fds[fd];value=self.info(path)
        self.fstats[path]=self.fstats.get(path,0)+1
        if self.options.get('mutate')==path and self.fstats[path]>1:value.st_mtime_ns+=1
        return value
    def open(self,name,flags,dir_fd=None):
        self.calls.append(('open',name,dir_fd));path=self.full(name,dir_fd);self.info(path)
        assert flags&self.O_NOFOLLOW
        if self.nodes[path]['kind']=='dir':assert flags&self.O_DIRECTORY
        fd=self.next_fd;self.next_fd+=1;self.fds[fd]=path;self.offsets[fd]=0;self.opened.append(path)
        return fd
    def read(self,fd,size):
        path=self.fds[fd];self.read_paths.append(path);offset=self.offsets[fd]
        data=self.nodes[path]['data'][offset:offset+size];self.offsets[fd]+=len(data)
        return data
    def close(self,fd):
        assert fd not in self.closed;self.closed.append(fd);del self.fds[fd]
    def scandir(self,alias):
        assert type(alias) is str
        fd=int(alias.rsplit('/',1)[1]);assert alias=='/proc/self/fd/%d'%fd
        return Entries(self.nodes[self.fds[fd]]['names'])


class ReaderTests(unittest.TestCase):
    def setUp(self):
        for name,value in (('host_identity',lambda:copy.deepcopy(HOST)),('resource_identity',lambda:dict(RESOURCE))):
            item=patch.object(p,name,value);item.start();self.addCleanup(item.stop)

    def collect(self,role,files,dirs=None,**options):
        fs=FakeFS(files,dirs=dirs,**options)
        request=dict(role=role,paths=list(files),inventory_dirs=list(dirs or []))
        result=p.collect(role,request['paths'],request['inventory_dirs'],fs)
        self.assertTrue(p.validate_response(result,request),result)
        self.assertEqual(fs.fds,{})
        return result,fs,request

    def test_protected_and_outside_requests_have_zero_io(self):
        fs=FakeFS()
        for role,path in (('B',p.PROTECTED+'/model_identity.json'),('B',p.B_ROOT+'/gnn_model/../multimode_ate_gnn_v1/x.py'),
                ('A','/tmp/driver.py'),('A',p.A_ROOT+'/10_circuits/tv80/01_config/config.env'),
                ('B',p.B_ROOT+'/other/model_identity.json')):
            with self.assertRaises(ValueError):p.collect(role,[path],api=fs)
        self.assertEqual(fs.calls,[])

    def test_name_denials_before_io_and_explicit_exceptions(self):
        fs=FakeFS()
        for name in ('worker_receipt.json','checkpoint.pt','manifest.json','result_model.json','model.log','model_BLIND.json'):
            with self.assertRaises(ValueError):p.collect('B',[p.B_ROOT+'/gnn_model_test/'+name],api=fs)
        for path in sorted(p.RESOURCE_SIDECARS|p.JIT_SIDECARS):
            self.assertEqual(p.validate_path('B',path),'JSON_METADATA')
        self.assertEqual(fs.calls,[])

    def test_code_body_hash_only_no_decode_or_reference_follow(self):
        raw=b'PRIVATE_QUALITY\xff\x00 open("/forbidden/reference")'
        result,fs,unused=self.collect('A',{A_CODE:raw})
        self.assertEqual(result['files'][0]['metadata'],{})
        self.assertEqual(result['files'][0]['sha256'],hashlib.sha256(raw).hexdigest())
        self.assertNotIn('PRIVATE',json.dumps(result))
        self.assertEqual(set(fs.read_paths),{A_CODE})

    def test_env_only_exact_fields_no_unknown_decode(self):
        raw=b'PRIVATE=\xffBLIND\nCIRCUIT=aes_core\nTOP_MODULE="aes_top"\nH_CHAIN_COUNT=64\nM_CHAIN_COUNT=16\nF_CHAIN_COUNT=4\nEXTERNAL_CHANNELS=8\nTIMEPLATE_NS=10.5\nCELL_LIBRARY=/declared/library.lib\n'
        result,fs,unused=self.collect('A',{A_ENV:raw})
        self.assertEqual(result['files'][0]['metadata']['CIRCUIT'],'aes_core')
        self.assertEqual(len(result['files'][0]['metadata']),8)
        self.assertNotIn('BLIND',json.dumps(result))
        self.assertEqual(set(fs.read_paths),{A_ENV})
        for invalid in (b'CIRCUIT=wb_dma',b'TOP_MODULE=$(command)',b'H_CHAIN_COUNT=1\nH_CHAIN_COUNT=2'):
            result,unused,unused=self.collect('A',{A_ENV:invalid})
            self.assertEqual(result['files'][0]['status'],'FAIL_CLOSED')

    def test_json_ignored_bodies_never_pass_json_decoder(self):
        raw=b'{"schema_version":"identity-v1","common_fault_count":17,"ignored":{"quality":"POISON_SECRET","metrics":[1,2]},"feature_names":["h_limit","m_limit"]}'
        original=p.json.loads;seen=[]
        def selected_only(value,*args,**kwargs):
            self.assertNotIn('POISON_SECRET',value);self.assertNotIn('metrics',value)
            seen.append(value);return original(value,*args,**kwargs)
        with patch.object(p.json,'loads',side_effect=selected_only):
            selected=p.project_json(raw)
        self.assertEqual(selected['common_fault_count'],17)
        self.assertEqual(len(seen),3)
        self.assertNotIn('ignored',selected)

    def test_json_selected_nested_maps_duplicates_and_wrong_types_fail(self):
        for raw in (b'{"feature_names":[{"quality":"POISON"}]}',b'{"schema":"a","schema":"b"}',
                b'{"workers":true}',b'{"graph_sha256":"bad"}',b'{"schema":1}',
                b'{"schema":"ok"} trailing',b'{"schema":"\xff"}',b'{"\\u0073chema":"x"}'):
            with self.assertRaises(ValueError):p.project_json(raw)
        with patch.object(p.json,'loads',side_effect=AssertionError('NO_WRONG_TYPE_DECODE')):
            for raw in (b'{"feature_names":[["POISON"]]}',b'{"feature_names":[123]}',
                    b'{"workers":true}',b'{"schema":["POISON"]}',b'{"address_space_limits":[{"quality":1}]}'):
                with self.assertRaises(ValueError):p.project_json(raw)

    def test_exact_resource_nested_lists_without_nested_jit_maps(self):
        path=sorted(p.RESOURCE_SIDECARS)[0]
        raw=json.dumps(dict(schema='memory-v1',family='toy',seed=20260824,
            address_space_limits=[[1,-1],[2,536870912]],core_limits=[0,0],
            peak_group_rss_bytes=23,threads=1,jit_probe={'metrics':'PRIVATE'})).encode()
        result,unused,unused=self.collect('B',{path:raw})
        meta=result['files'][0]['metadata']
        self.assertEqual(meta['address_space_limits'],[[1,-1],[2,536870912]])
        self.assertNotIn('jit_probe',meta)
        self.assertNotIn('PRIVATE',json.dumps(result))

    def test_missing_path_is_observation_and_uses_no_body_quota(self):
        fs=FakeFS(dirs=[A_CODE.rsplit('/',1)[0]])
        request=dict(role='A',paths=[A_CODE],inventory_dirs=[])
        result=p.collect('A',[A_CODE],api=fs)
        self.assertEqual(result['status'],'PASS_METADATA_ONLY')
        self.assertEqual(result['files'][0]['status'],'MISSING')
        self.assertEqual(result['budget'],dict(files_read=0,body_bytes=0,inventory_entries=0))
        self.assertTrue(p.validate_response(result,request))

    def test_file_size_symlink_multilink_reparse_and_identity_fail(self):
        for value,options in ((dict(data=b'x',size=p.FILE_LIMIT+1),{}),
                (dict(data=b'x',mode=stat.S_IFLNK),{}),(dict(data=b'x',links=2),{}),
                (dict(data=b'x',attrs=0x400),{}),(b'x',dict(mutate=A_CODE)),
                (b'x',dict(ancestor_swap='/temp'))):
            result,fs,unused=self.collect('A',{A_CODE:value},**options)
            self.assertEqual(result['files'][0]['status'],'FAIL_CLOSED')
            self.assertEqual(len(fs.closed),len(set(fs.closed)))

    def test_total_file_and_duplicate_request_bounds(self):
        files={p.A_ROOT+'/00_framework/x%d.py'%i:b'x'*p.FILE_LIMIT for i in range(8)}
        result,unused,unused=self.collect('A',files)
        self.assertEqual(result['budget']['body_bytes'],p.TOTAL_LIMIT)
        self.assertEqual(result['budget']['files_read'],8)
        fs=FakeFS()
        with self.assertRaises(ValueError):p.collect('A',list(files)+[A_CODE],api=fs)
        with self.assertRaises(ValueError):p.collect('A',[A_CODE,A_CODE],api=fs)
        self.assertEqual(fs.calls,[])

    def test_failed_projection_still_charges_actual_read_budget(self):
        result,unused,request=self.collect('B',{B_JSON:b'{"workers":false}'})
        self.assertEqual(result['status'],'PARTIAL_METADATA_ONLY')
        self.assertEqual(result['budget']['files_read'],1)
        self.assertEqual(result['budget']['body_bytes'],len(b'{"workers":false}'))
        self.assertTrue(p.validate_response(result,request))

    def test_python36_shallow_inventory_filters_before_stat(self):
        directory=p.A_ROOT+'/00_framework'
        fs=FakeFS({A_CODE:b'NEVER_OPEN'},extra={directory:['private.log','model.pt','bad\udcff']})
        result=p.collect('A',[],[directory],fs)
        self.assertEqual(result['budget']['inventory_entries'],4)
        self.assertEqual(result['inventories'][0]['matches'],[dict(name='driver.py',file_type='REGULAR_SINGLE_LINK',bytes=10)])
        self.assertEqual(fs.read_paths,[])
        self.assertFalse(any(call[0]=='stat' and call[1] in ('private.log','model.pt','bad\udcff') for call in fs.calls))
        self.assertTrue(p.validate_response(result,dict(role='A',paths=[],inventory_dirs=[directory])))

    def test_inventory_bound_proc_failures_and_no_excess_stat(self):
        directory=p.A_ROOT+'/00_framework'
        fs=FakeFS(dirs=[directory],extra={directory:['x%d.bin'%i for i in range(101)]})
        result=p.collect('A',[],[directory],fs)
        self.assertEqual(result['budget']['inventory_entries'],100)
        self.assertEqual(result['inventories'][0]['code'],'ENTRY_BOUND')
        self.assertFalse(any(call[0]=='stat' and call[1]=='x100.bin' for call in fs.calls))
        for options in ({'proc_missing':True},{'proc_denied':True},{'proc_mismatch':1},{'proc_mismatch':2}):
            fs=FakeFS(dirs=[directory],**options)
            result=p.collect('A',[],[directory],fs)
            self.assertNotEqual(result['inventories'][0]['status'],'LISTED')
            self.assertEqual(fs.fds,{})

    def test_strict_response_unknown_keys_counters_scope_and_flags(self):
        base,unused,request=self.collect('A',{A_CODE:b'x'})
        for key,value in (('extra_quality',1),('role','B'),('training_release',True),('status','UNKNOWN')):
            bad=copy.deepcopy(base);bad[key]=value;self.assertFalse(p.validate_response(bad,request))
        for key,value in (('files_read',True),('body_bytes',0),('inventory_entries',101)):
            bad=copy.deepcopy(base);bad['budget'][key]=value;self.assertFalse(p.validate_response(bad,request))
        bad=copy.deepcopy(base);bad['files'][0]['metadata']={'runtime':1}
        self.assertFalse(p.validate_response(bad,request))
        bad=copy.deepcopy(base);bad['resource']['cpu_limit_s']=31
        self.assertFalse(p.validate_response(bad,request))

    def test_import_isolated_has_no_filesystem_default_action(self):
        path=str(Path(p.__file__).resolve())
        code="import importlib.util; s=importlib.util.spec_from_file_location('p',%r); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); assert callable(m.main); assert callable(m.validate_request); assert not m.validate_response({},{}); print('IMPORT_ONLY')"%path
        child=subprocess.run([sys.executable,'-I','-S','-B','-c',code],capture_output=True,timeout=10)
        self.assertEqual(child.returncode,0,child.stderr)
        self.assertEqual(child.stdout.strip(),b'IMPORT_ONLY')

    def test_main_resource_caps_only_inside_explicit_call(self):
        result,unused,request=self.collect('A',{A_CODE:b'x'})
        limits=[];alarms=[]
        resource=types.SimpleNamespace(RLIMIT_AS=1,RLIMIT_CPU=2,RLIM_INFINITY=-1,
            getrlimit=lambda kind:(256*1024*1024,256*1024*1024) if kind==1 else (20,20),
            setrlimit=lambda kind,pair:limits.append((kind,pair)))
        signal=types.SimpleNamespace(alarm=lambda seconds:alarms.append(seconds))
        output=io.StringIO()
        with patch.dict(sys.modules,resource=resource,signal=signal),patch.object(p.sys,'platform','linux'),patch.object(p.sys,'argv',['-']),patch.object(p,'collect',return_value=result),patch('sys.stdout',output):
            self.assertEqual(p.main(request),0)
        self.assertEqual(limits,[(1,(256*1024*1024,256*1024*1024)),(2,(20,20))])
        self.assertEqual(alarms,[50])
        self.assertEqual(json.loads(output.getvalue())['schema'],'prospective-metadata-read-v1')


if __name__=='__main__':
    unittest.main()
