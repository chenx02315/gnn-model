"""Synthetic bytes, fake descriptors and one fake SSH only."""
import copy
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
from scripts import project_ranking_v6_e64_submission_metadata as p
from scripts import run_ranking_v6_e64_readonly as t
RESOURCE=dict(address_space_limit_bytes=512*1024*1024,cpu_limit_s=30,workers=1)
STAMP=b'2026-08-25T12:34:56+08:00'
def header(circuit=b'aes_core',tail=b'CLOSURE\tSUBMIT'):
    return STAMP+b'\t'+circuit+b'\t'+tail+b'\n'
def job(value=b'123'):
    return b'Job <'+value+b'> is submitted to queue <normal>.\n'

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



class SubmissionTests(unittest.TestCase):
    def test_binary_private_values_and_timestamp_never_exported(self):
        raw=b'PRIVATE_BLIND\xff\n'+header()+job()+header(b'spi')+job(b'0042')
        value=p.response(raw,RESOURCE)
        self.assertTrue(p.validate_response(value))
        self.assertEqual([r['job_id'] for r in value['target_rows']],['123','0042'])
        for secret in ('PRIVATE','2026-08-25T12:34:56','wb_dma'):
            self.assertNotIn(secret,json.dumps(value))

    def test_other_and_unknown_progress_clear_context(self):
        for circuit,tail in ((b'wb_dma',b'CLOSURE\tSUBMIT'),(b'BATCH',b'DONE\trc=0'),
                (b'aes_core',b'CLOSURE\tPASS'),(b'UNKNOWN',b'UNKNOWN\xff')):
            rows=p.project_bytes(header()+header(circuit,tail)+job())
            self.assertEqual(rows[0]['association'],'MISSING')

    def test_job_without_context_and_non_target_not_exported(self):
        rows=p.project_bytes(job()+header(b'wb_dma')+job(b'777')+header(b'spi')+job(b'8'))
        self.assertEqual(rows,[dict(order=1,circuit='spi',job_id='8',association='UNIQUE')])

    def test_retries_missing_and_duplicate_preserved(self):
        raw=header()+job()+job()+header()+header(b'spi')+job(b'2')
        value=p.response(raw,RESOURCE)
        self.assertEqual([r['association'] for r in value['target_rows']],['AMBIGUOUS','MISSING','UNIQUE'])
        self.assertIsNone(value['target_rows'][0]['job_id'])
        self.assertEqual(value['status'],'PARTIAL_TARGET_SUBMISSION_METADATA')

    def test_malformed_or_tab_boundary_cannot_stale_bind(self):
        for boundary in (b'2026-08-25BAD\n',b'unknown\tPRIVATE\n',b'2026-08-25T99:99:99BAD\n'):
            value=p.response(header()+boundary+job(),RESOURCE)
            self.assertEqual(value['target_rows'][0]['association'],'MISSING')
        value=p.response(header()+job(),RESOURCE)
        self.assertEqual(value['status'],'PARTIAL_TARGET_SUBMISSION_METADATA')
        self.assertTrue(p.validate_response(value))

    def test_full_lines_lf_crlf_and_strict_submit(self):
        raw=(header()+job()).replace(b'\n',b'\r\n')
        self.assertEqual(p.project_bytes(raw)[0]['job_id'],'123')
        raw=header()+b'prefix '+job()+job().rstrip()+b' extra\n'
        self.assertEqual(p.project_bytes(raw)[0]['association'],'MISSING')
        self.assertEqual(p.project_bytes(header(tail=b'CLOSURE\tSUBMIT extra')+job()),[])

    def test_bounds_and_no_match(self):
        for raw in (b'',b'x'*(p.MAX_SOURCE_BYTES+1),header()*17):
            with self.assertRaises(ValueError):p.project_bytes(raw)
        self.assertEqual(p.response(b'PRIVATE\xff',RESOURCE)['status'],'NO_MATCH_WITHIN_FIXED_SCOPE')

    def test_fixed_reader_binary_only_closes_once(self):
        api=FakeAPI(data=header()+job()+b'\xff')
        self.assertEqual(p.read_fixed(api),api.data)
        self.assertEqual(api.fds,{})
        self.assertEqual(len(api.closed),len(set(api.closed)))
        self.assertEqual(api.opened[-1],p.PATH)

    def test_fixed_reader_symlinks_links_bounds_and_changes(self):
        for options in ({'symlink':p.PATH},{'symlink':'/temp'},{'hardlink':True},
                {'size':p.MAX_SOURCE_BYTES+1},{'open_swap':True},{'unstable':True},{'ancestor_swap':'/temp'},{'size':1}):
            api=FakeAPI(**options)
            with self.assertRaises(ValueError):p.read_fixed(api)
            self.assertEqual(api.fds,{})
        api=FakeAPI(data=b'x'*(p.MAX_SOURCE_BYTES+1),size=p.MAX_SOURCE_BYTES)
        with self.assertRaises(ValueError):p.read_fixed(api)

    def test_strict_schema_and_false_flags(self):
        base=p.response(header()+job(),RESOURCE)
        for key,value in [('status','PASS'),('byte_count',True),('extra_quality',1)]+[(key,True) for key in p.FALSE_FLAGS]:
            bad=copy.deepcopy(base);bad[key]=value;self.assertFalse(p.validate_response(bad))
        for key,value in (('circuit','wb_dma'),('order',True),('job_id','-1'),('association','MISSING')):
            bad=copy.deepcopy(base);bad['target_rows'][0][key]=value;self.assertFalse(p.validate_response(bad))

    def test_isolated_source_binding_validator(self):
        self.assertEqual(t.SOURCE.resolve(),Path(p.__file__).resolve())
        self.assertLessEqual(len(t.SOURCE.read_bytes()),16384)
        raw=json.dumps(p.response(header()+job(),RESOURCE))
        code="import importlib.util; s=importlib.util.spec_from_file_location('t',%r); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); assert m.SOURCE.name=='project_ranking_v6_e64_submission_metadata.py'; assert m.validate_response(%r.encode())"%(str(Path(t.__file__).resolve()),raw)
        child=subprocess.run([sys.executable,'-I','-S','-B','-c',code],capture_output=True)
        self.assertEqual(child.returncode,0,child.stderr)

    def test_fake_transport_one_shot_failure_and_pin(self):
        source=t.SOURCE.read_bytes();sha=hashlib.sha256(source).hexdigest()
        output=Path(t.__file__).resolve().parents[2]/'runtime_training_staging_20260928/v6_e64_submission_metadata_synthetic'
        raw=json.dumps(p.response(header()+job(),RESOURCE)).encode()
        for proc,expected in ((FakeProcess(stdout=raw),0),(FakeProcess(stdout=raw,code=255),2),(FakeProcess(stdout=raw,stderr=b'fail'),2),(FakeProcess(stdout=raw,timeout=True),2),(FakeProcess(stdout=b'x'*(t.LIMIT+1)),2)):
            with patch.object(Path,'mkdir',autospec=True),patch.object(Path,'write_text',autospec=True),patch.object(Path,'write_bytes',autospec=True),patch.object(t.subprocess,'Popen',return_value=proc) as call,patch('builtins.print'):
                self.assertEqual(t.run(sha,output),expected);self.assertEqual(call.call_count,1)
        with patch.object(t.subprocess,'Popen') as call:
            with self.assertRaises(ValueError):t.run('0'*64,output)
            call.assert_not_called()

if __name__=='__main__':
    unittest.main()
