"""Synthetic E63 source bytes and fake SSH only; never read the inspected A source."""
import ast
import copy
import hashlib
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from scripts import hash_ranking_v6_e63_phase4_wrapper as p
from scripts import run_ranking_v6_e63_readonly as t


RESOURCE=dict(address_space_limit_bytes=512*1024*1024,cpu_limit_s=30,workers=1)


class FakeAPI:
    O_RDONLY,O_DIRECTORY,O_NOFOLLOW,O_NONBLOCK=0,1,2,4
    def __init__(self,data=b'NEVER_EXECUTE\xff',**options):
        self.data=data;self.options=options;self.fds={};self.next_fd=1
        self.opened=[];self.closed=[];self.reads=0;self.offset=0
        self.stat_calls={};self.fstat_calls={}
        self.paths=['/']
        current=''
        for component in p.PATH.strip('/').split('/'):
            current+='/'+component;self.paths.append(current)
    def info(self,path):
        source=path==p.PATH
        return types.SimpleNamespace(st_dev=1,st_ino=self.paths.index(path)+1,
            st_mode=stat.S_IFREG if source else stat.S_IFDIR,st_nlink=1,
            st_size=self.options.get('size',len(self.data)) if source else 1,
            st_mtime_ns=1,st_ctime_ns=1,st_file_attributes=0)
    def full(self,name,dir_fd):
        return '/' if dir_fd is None else self.fds[dir_fd].rstrip('/')+'/'+name
    def stat(self,name,dir_fd=None,follow_symlinks=False):
        assert follow_symlinks is False
        path=self.full(name,dir_fd);info=self.info(path)
        self.stat_calls[path]=self.stat_calls.get(path,0)+1
        if self.options.get('symlink')==path:info.st_mode=stat.S_IFLNK
        if path==p.PATH and self.options.get('hardlink'):info.st_nlink=2
        if self.options.get('ancestor_swap')==path and self.stat_calls[path]>1:info.st_ino+=1000
        return info
    def fstat(self,fd):
        path=self.fds[fd];info=self.info(path)
        self.fstat_calls[path]=self.fstat_calls.get(path,0)+1
        if path==p.PATH and self.options.get('unstable') and self.fstat_calls[path]>1:info.st_mtime_ns+=1
        if path==p.PATH and self.options.get('open_swap'):info.st_ino+=1000
        return info
    def open(self,name,flags,dir_fd=None):
        path=self.full(name,dir_fd)
        assert flags & self.O_NOFOLLOW
        if path!=p.PATH:assert flags & self.O_DIRECTORY
        self.opened.append(path)
        fd=self.next_fd;self.next_fd+=1;self.fds[fd]=path
        return fd
    def read(self,fd,size):
        assert self.fds[fd]==p.PATH
        self.reads+=1
        chunk=self.data[self.offset:self.offset+size]
        self.offset+=len(chunk)
        return chunk
    def close(self,fd):
        self.closed.append(fd);del self.fds[fd]


class FakeProcess:
    def __init__(self,stdout=b'',stderr=b'',code=0,timeout=False):
        self.stdin=io.BytesIO();self.stdout=io.BytesIO(stdout);self.stderr=io.BytesIO(stderr)
        self.returncode=code;self.timeout=timeout;self.waits=0;self.killed=False
    def wait(self,timeout=None):
        self.waits+=1
        if self.timeout and self.waits==1:raise subprocess.TimeoutExpired('synthetic',timeout)
        return self.returncode
    def kill(self):
        self.killed=True;self.returncode=-9


class WrapperIdentityTests(unittest.TestCase):
    def test_hash_only_binary_source_no_execution_or_contents_retained(self):
        api=FakeAPI()
        count,digest=p.hash_fixed(api)
        self.assertEqual((count,digest),(len(api.data),hashlib.sha256(api.data).hexdigest()))
        self.assertEqual(api.opened[-1],p.PATH)
        self.assertEqual(api.fds,{})
        result=p.response(count,digest,RESOURCE)
        self.assertTrue(p.validate_response(result))
        self.assertFalse(result['matches_reference'])
        self.assertNotIn('NEVER_EXECUTE',json.dumps(result))

    def test_exact_sibling_source_and_payload_cap(self):
        self.assertEqual(t.SOURCE.resolve(),Path(p.__file__).resolve())
        self.assertEqual(p.MAX_SOURCE_BYTES,16384)
        self.assertLessEqual(len(t.SOURCE.read_bytes()),16384)

    def test_matching_and_mismatching_hash_both_valid_observations(self):
        for digest in (p.REFERENCE_SHA,'a'*64):
            result=p.response(1,digest,RESOURCE)
            self.assertTrue(t.validate_response(json.dumps(result).encode()))
            self.assertEqual(result['matches_reference'],digest==p.REFERENCE_SHA)

    def test_symlink_source_or_ancestor_and_multiple_links_reject_before_read(self):
        for options in ({'symlink':p.PATH},{'symlink':'/temp'},{'hardlink':True}):
            api=FakeAPI(**options)
            with self.assertRaises(ValueError):p.hash_fixed(api)
            self.assertEqual(api.reads,0)
            self.assertEqual(api.fds,{})

    def test_source_byte_size_bound_before_read_and_growth(self):
        api=FakeAPI(size=p.MAX_SOURCE_BYTES+1)
        with self.assertRaisesRegex(ValueError,'SOURCE_BOUND'):p.hash_fixed(api)
        self.assertEqual(api.reads,0)
        api=FakeAPI(data=b'x'*(p.MAX_SOURCE_BYTES+1),size=p.MAX_SOURCE_BYTES)
        with self.assertRaisesRegex(ValueError,'SOURCE_BOUND'):p.hash_fixed(api)
        self.assertEqual(api.fds,{})

    def test_open_read_or_ancestor_identity_change_fails_closed(self):
        for options in ({'open_swap':True},{'unstable':True},{'ancestor_swap':'/temp'},{'size':1}):
            api=FakeAPI(**options)
            with self.assertRaises(ValueError):p.hash_fixed(api)
            self.assertEqual(api.fds,{})

    def test_exact_output_schema_flags_resource_and_reference_truth(self):
        base=p.response(10,'a'*64,RESOURCE)
        for key,value in (('path','/arbitrary/source.py'),('byte_count',True),('matches_reference',True),
                          ('source_content_decoded',True),('historical_freeze_certified',True),('extra_quality',1)):
            result=copy.deepcopy(base);result[key]=value
            self.assertFalse(p.validate_response(result))
        for resource in (dict(RESOURCE,workers=2),dict(RESOURCE,cpu_limit_s=31),
                         dict(RESOURCE,address_space_limit_bytes=512*1024*1024+1)):
            result=copy.deepcopy(base);result['resource']=resource
            self.assertFalse(p.validate_response(result))

    def test_fixed_path_no_runtime_path_argument_and_linux_argv_gate(self):
        self.assertEqual(p.PATH,'/temp/jiangchuanc/multimode_ate_phase4_20260825_A/00_framework/run_phase4_closure_batch_v2.sh')
        self.assertEqual(p.hash_fixed.__code__.co_varnames[:p.hash_fixed.__code__.co_argcount],('api',))
        # Static AST assertion only: never call payload main or inspect actual source.
        tree=ast.parse(Path(p.__file__).read_text(encoding='utf-8'))
        main=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='main')
        self.assertIn("sys.platform == 'linux'",ast.unparse(main))
        self.assertIn('len(sys.argv) == 1',ast.unparse(main))

    def test_transport_fixed_ssh_limits_zero_retry_and_no_dynamic_scope(self):
        self.assertEqual(t.COMMAND,['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
            '-o','ConnectTimeout=8','vnc.buptic.top','/usr/bin/python3 -I -S -B -'])
        self.assertEqual(t.LIMIT,16384);self.assertEqual(t.TIMEOUT,60)
        self.assertEqual(t.SOURCE.name,'hash_ranking_v6_e63_phase4_wrapper.py')
        self.assertFalse(t.validate_response(b'{}'))
        self.assertFalse(t.validate_response(b'x'*(t.LIMIT+1)))
        raw=json.dumps(p.response(1,'a'*64,RESOURCE)).encode()
        self.assertFalse(t.validate_response(raw[:-1]+b', "sha256":"bad"}'))

    def transport(self,proc):
        output=Path(t.__file__).resolve().parents[2]/'runtime_training_staging_20260928/v6_e63_wrapper_identity_synthetic'
        source=t.SOURCE.read_bytes();source_sha=hashlib.sha256(source).hexdigest()
        texts={};binary={}
        def write_text(path,value,**kwargs):texts[path.name]=value
        def write_bytes(path,value):binary[path.name]=value
        with patch.object(Path,'mkdir',autospec=True) as mkdir, \
             patch.object(Path,'write_text',autospec=True,side_effect=write_text), \
             patch.object(Path,'write_bytes',autospec=True,side_effect=write_bytes), \
             patch.object(t.subprocess,'Popen',return_value=proc) as popen, \
             patch('builtins.print'):
            code=t.run(source_sha,output)
        self.assertEqual(popen.call_count,1)
        self.assertEqual(mkdir.call_count,1)
        self.assertEqual(json.loads(texts['request.json'])['automatic_retries'],0)
        return code,json.loads(texts['transport.json']),binary

    def test_fake_transport_nonmatching_source_is_accepted_observation(self):
        raw=json.dumps(p.response(10,'a'*64,RESOURCE)).encode()
        code,result,_=self.transport(FakeProcess(stdout=raw))
        self.assertEqual(code,0)
        self.assertTrue(result['accepted_metadata_receipt'])
        self.assertFalse(result['remote_termination_verified'])

    def test_fake_transport_nonzero_stderr_or_timeout_fail_no_retry(self):
        raw=json.dumps(p.response(10,'a'*64,RESOURCE)).encode()
        for proc in (FakeProcess(stdout=raw,code=255),FakeProcess(stdout=raw,stderr=b'synthetic error'),
                     FakeProcess(stdout=raw,timeout=True)):
            code,result,_=self.transport(proc)
            self.assertEqual(code,2)
            self.assertFalse(result['accepted_metadata_receipt'])

    def test_fake_transport_output_overflow_caps_stream_and_fails(self):
        code,result,logs=self.transport(FakeProcess(stdout=b'x'*(t.LIMIT+1)))
        self.assertEqual(code,2)
        self.assertTrue(result['output_limit_exceeded'])
        self.assertEqual(len(logs['stdout.log']),t.LIMIT)

    def test_transport_bad_source_pin_or_output_path_never_starts_ssh(self):
        with patch.object(t.subprocess,'Popen',side_effect=AssertionError('NO_SSH')):
            with self.assertRaisesRegex(ValueError,'SHA_SHAPE'):t.run('bad','unused')
            with self.assertRaisesRegex(ValueError,'SHA_MISMATCH'):t.run('0'*64,'unused')
            source_sha=hashlib.sha256(t.SOURCE.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError,'RECEIPT_PATH'):
                t.run(source_sha,Path.cwd()/'outside_scope')

    def test_isolated_transport_validator_import_without_network_or_source_access(self):
        path=str(Path(t.__file__).resolve())
        raw=json.dumps(p.response(1,'a'*64,RESOURCE))
        code=(
            "import importlib.util,json,sys\n"
            "before=list(sys.path)\n"
            "spec=importlib.util.spec_from_file_location('synthetic_e63_transport',"+repr(path)+")\n"
            "m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)\n"
            "assert sys.path==before and sys.flags.isolated and sys.flags.no_site\n"
            "assert m.validate_response("+repr(raw)+".encode('ascii'))\n"
            "assert sys.path==before\n"
            "print(json.dumps({'validated':True}))\n"
        )
        with tempfile.TemporaryDirectory() as unrelated:
            result=subprocess.run([sys.executable,'-I','-S','-B','-c',code],
                                  cwd=unrelated,capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout),{'validated':True})


if __name__=='__main__':
    unittest.main()
