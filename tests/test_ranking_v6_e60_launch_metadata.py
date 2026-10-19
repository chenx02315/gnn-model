"""Synthetic E60 bytes/FDs/fake transport only; never actual A/log/source inputs."""
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

from scripts import project_ranking_v6_e60_launch_metadata as p
from scripts import run_ranking_v6_e60_readonly as t
from tests.test_ranking_v6_e59_driver_identity import FakeProcess

RESOURCE=dict(address_space_limit_bytes=512*1024*1024,cpu_limit_s=30,workers=1)
STEM=p.STEMS[0]


class Entries:
    def __init__(self,names):self.names=names
    def __enter__(self):return iter(types.SimpleNamespace(name=name) for name in self.names)
    def __exit__(self,*args):pass


class FakeFS:
    O_RDONLY,O_DIRECTORY,O_NOFOLLOW,O_NONBLOCK=0,1,2,4
    def __init__(self,files=None,extra=None,**options):
        self.options=options;self.nodes={'/':dict(kind='dir',names=[])}
        for root in p.ROOTS:
            current=''
            for name in root.strip('/').split('/'):
                parent=current or '/';current+='/'+name
                self.nodes.setdefault(current,dict(kind='dir',names=[]))
                if name not in self.nodes[parent]['names']:self.nodes[parent]['names'].append(name)
        for (root,name),value in (files or {}).items():
            path=root+'/'+name
            self.nodes[path]=dict(kind='file',data=value) if type(value) is bytes else dict(kind='file',**value)
            self.nodes[root]['names'].append(name)
        for root,names in (extra or {}).items():self.nodes[root]['names'].extend(names)
        self.ids={name:i+1 for i,name in enumerate(self.nodes)}
        self.fds={};self.offsets={};self.next_fd=1;self.opened=[];self.statted=[];self.read_paths=[]
        self.fstat_calls={}
    def full(self,name,dir_fd):
        return '/' if dir_fd is None else self.fds[dir_fd].rstrip('/')+'/'+name
    def info(self,path):
        node=self.nodes[path]
        return types.SimpleNamespace(st_dev=1,st_ino=self.ids[path],st_mode=node.get('mode',stat.S_IFDIR if node['kind']=='dir' else stat.S_IFREG),
            st_nlink=node.get('links',1),st_size=node.get('size',len(node.get('data',b''))),st_mtime_ns=1,st_ctime_ns=1,st_file_attributes=0)
    def stat(self,name,dir_fd=None,follow_symlinks=False):
        assert follow_symlinks is False
        path=self.full(name,dir_fd);self.statted.append(path);return self.info(path)
    def open(self,name,flags,dir_fd=None):
        path=self.full(name,dir_fd);assert flags&self.O_NOFOLLOW
        if self.nodes[path]['kind']=='dir':assert flags&self.O_DIRECTORY
        fd=self.next_fd;self.next_fd+=1;self.fds[fd]=path;self.offsets[fd]=0;self.opened.append(path);return fd
    def fstat(self,fd):
        path=self.fds[fd];value=self.info(path)
        self.fstat_calls[path]=self.fstat_calls.get(path,0)+1
        if path==self.options.get('unstable_file') and self.fstat_calls[path]>1:value.st_mtime_ns=2
        if path==self.options.get('unstable_directory') and self.fstat_calls[path]>2:value.st_mtime_ns=2
        return value
    def read(self,fd,size):
        path=self.fds[fd];self.read_paths.append(path)
        data=self.nodes[path].get('data',b'');offset=self.offsets[fd]
        chunk=data[offset:offset+size];self.offsets[fd]+=len(chunk);return chunk
    def scandir(self,fd):return Entries(self.nodes[self.fds[fd]]['names'])
    def close(self,fd):del self.fds[fd]


def result(fs):
    value=p.scan(fs);value['resource']=dict(RESOURCE)
    if not p.validate_response(value):raise AssertionError('SYNTHETIC_RESPONSE_INVALID')
    return value


class LaunchMetadataTests(unittest.TestCase):
    def test_exact_two_stems_suffix_token_grammar_only(self):
        for name in (STEM+'.sh',p.STEMS[1]+'.lsf',STEM+'.submit.log',STEM+'.job.o',STEM+'.stdout'):
            self.assertTrue(p.selected_name(name))
        for name in (STEM+'_other.log',STEM+'.123',STEM+'.submit.log.out.err',STEM+'.py','phase4_closure_driver_v2.py','../'+STEM+'.sh',STEM+'.log/extra'):
            self.assertFalse(p.selected_name(name))

    def test_only_full_line_submission_and_two_sha_forms_capture(self):
        sha=p.REFERENCE_SHA.encode();driver=p.DRIVER.encode()
        raw=(b'PRIVATE_QUALITY\xff\nJob <000123> is submitted to queue <normal>.\r\n'
             +sha+b'  '+driver+b'\n'+sha+b' *'+driver+b'\n'
             +b'prefix Job <99> is submitted to queue <normal>.\n'
             +sha+b' '+driver+b'\n'+sha+b'  '+driver+b' extra\n')
        value=p.project_bytes(raw)
        self.assertEqual(value['recognized_anchor_count'],3)
        self.assertEqual(value['anchors'][0]['job_id'],'000123')
        self.assertEqual([x['logical_line'] for x in value['anchors']],[2,3,4])
        self.assertTrue(all(x['matches_reference'] for x in value['anchors'][1:]))
        self.assertNotIn('PRIVATE',json.dumps(value))

    def test_namefilter_before_stat_driver_and_generic_logs_never_opened(self):
        files={(p.ROOTS[0],STEM+'.sh'):b'Job <77> is submitted to queue <normal>.\n',
               (p.ROOTS[0],STEM+'.log'):b'BLIND_PRIVATE_QUALITY\xff',
               (p.ROOTS[0],STEM+'.status'):b'PRIVATE_STATUS',
               (p.ROOTS[0],STEM+'.submit'):b'PRIVATE_SUBMIT\xff',
               (p.ROOTS[0],STEM+'.submit.log'):b'PRIVATE_SUBMIT_LOG\xff',
               (p.ROOTS[1],'phase4_closure_driver_v2.py'):b'NO_DRIVER_REREAD'}
        fs=FakeFS(files,extra={p.ROOTS[0]:['BLIND_driver.log','unrelated.tsv']})
        value=result(fs)
        self.assertNotIn(p.DRIVER,fs.statted)
        self.assertNotIn(p.ROOTS[0]+'/unrelated.tsv',fs.statted)
        for name in (STEM+'.log',STEM+'.status',STEM+'.submit',STEM+'.submit.log'):
            path=p.ROOTS[0]+'/'+name
            self.assertNotIn(path,fs.opened)
            row=next(x for x in value['files'] if x['name']==name)
            self.assertEqual(row['content_state'],'METADATA_ONLY_NO_OPEN')
            self.assertIsNone(row['sha256']);self.assertFalse(row['anchors_scanned'])
        self.assertEqual(next(row for row in value['files'] if row['name']==STEM+'.sh')['anchors'][0]['job_id'],'77')
        self.assertEqual(value['anchor_evidence'],'CODE_LITERALS_NOT_EXECUTION_PROOF')
        self.assertEqual(fs.fds,{})

    def test_no_match_is_only_fixed_scope_observation(self):
        value=result(FakeFS(extra={p.ROOTS[0]:['unrelated.log']}))
        self.assertEqual(value['status'],'NO_MATCH_WITHIN_FIXED_SCOPE')
        self.assertFalse(value['global_absence_claimed'])
        self.assertEqual(value['files'],[])

    def test_oversized_selected_code_preserves_metadata_without_open(self):
        name=STEM+'.sh';path=p.ROOTS[1]+'/'+name
        fs=FakeFS({(p.ROOTS[1],name):dict(data=b'',size=p.MAX_FILE_BYTES+1)})
        value=result(fs);row=value['files'][0]
        self.assertNotIn(path,fs.opened)
        self.assertEqual(row['content_state'],'NOT_OPENED_SIZE_LIMIT')
        self.assertEqual(row['observed_byte_count'],p.MAX_FILE_BYTES+1)
        self.assertTrue(value['scope_incomplete_for_contents'])
        self.assertTrue(value['scope_incomplete_for_anchors'])
        self.assertFalse(row['anchors_scanned'])

    def test_total_byte_budget_not_opened_and_marked(self):
        files={(p.ROOTS[1],STEM+'.'+suffix):b'x'*p.MAX_FILE_BYTES for suffix in ('sh','lsf','bsub','job')}
        files[(p.ROOTS[1],p.STEMS[1]+'.sh')]=b'x'*p.MAX_FILE_BYTES
        fs=FakeFS(files);value=result(fs)
        self.assertEqual(value['bytes_read'],p.MAX_TOTAL_BYTES)
        skipped=[row for row in value['files'] if row['sha256'] is None]
        self.assertEqual(len(skipped),1)
        self.assertEqual(skipped[0]['content_state'],'NOT_OPENED_TOTAL_BUDGET')
        self.assertNotIn(skipped[0]['root']+'/'+skipped[0]['name'],fs.opened)

    def test_hard_directory_and_selected_name_budgets_reject_not_truncate(self):
        fs=FakeFS(extra={p.ROOTS[0]:['unrelated_'+str(i) for i in range(513)]})
        with self.assertRaisesRegex(ValueError,'DIRECTORY_ENTRY_BOUND'):p.scan(fs)
        self.assertEqual(fs.fds,{})
        names=[STEM+'.'+token for token in sorted(p.TOKENS)]
        names+= [STEM+'.submit.'+token for token in sorted(p.TOKENS)[:4]]
        fs=FakeFS({(p.ROOTS[0],name):b'' for name in names})
        with self.assertRaisesRegex(ValueError,'SELECTED_FILE_BOUND'):p.scan(fs)
        self.assertEqual(fs.fds,{})

    def test_symlink_multiplelink_file_and_changed_source_or_directory_reject(self):
        name=STEM+'.sh';path=p.ROOTS[0]+'/'+name
        for options,node in (({},dict(data=b'x',mode=stat.S_IFLNK)),({},dict(data=b'x',links=2)),
                             ({'unstable_file':path},b'x'),({'unstable_directory':p.ROOTS[0]},b'x')):
            fs=FakeFS({(p.ROOTS[0],name):node},**options)
            with self.assertRaises(ValueError):p.scan(fs)
            self.assertEqual(fs.fds,{})

    def test_independent_anchor_caps_preserve_counts_and_incompleteness(self):
        raw=(b'Job <123> is submitted to queue <normal>.\n'*12
             +(p.REFERENCE_SHA+'  '+p.DRIVER+'\n').encode()*12)
        value=result(FakeFS({(p.ROOTS[0],STEM+'.sh'):raw}))
        row=value['files'][0]
        self.assertEqual(row['recognized_anchor_count'],24)
        self.assertEqual(row['anchors_omitted'],8)
        self.assertEqual(sum(x['kind']=='SCHEDULER_SUBMISSION' for x in row['anchors']),8)
        self.assertEqual(sum(x['kind']=='DRIVER_SHA256' for x in row['anchors']),8)
        self.assertFalse(value['scope_incomplete_for_contents'])
        self.assertTrue(value['scope_incomplete_for_anchors'])

    def test_strict_schema_scope_counts_anchor_shapes_and_no_false_certification(self):
        base=result(FakeFS({(p.ROOTS[0],STEM+'.sh'):b'Job <7> is submitted to queue <normal>.\n'}))
        for key,value in (('bytes_read',True),('global_absence_claimed',True),('historical_execution_certified',True),('extra_quality',1)):
            changed=copy.deepcopy(base);changed[key]=value
            self.assertFalse(p.validate_response(changed))
        changed=copy.deepcopy(base);changed['files'][0]['anchors'][0]['job_id']=7
        self.assertFalse(p.validate_response(changed))
        changed=copy.deepcopy(base);changed['roots'][0]['entry_count']=513
        self.assertFalse(p.validate_response(changed))
        changed=copy.deepcopy(base);changed['files'][0]['anchors_scanned']=False
        self.assertFalse(p.validate_response(changed))

    def test_transport_fake_single_process_zero_retry_limits_and_mismatch(self):
        raw=json.dumps(result(FakeFS())).encode()
        process=FakeProcess(stdout=raw)
        output=Path(t.__file__).resolve().parents[2]/'runtime_training_staging_20260928/v6_e60_launch_metadata_synthetic'
        payload=t.SOURCE.read_bytes()
        self.assertLessEqual(len(payload),t.LIMIT)
        captured={}
        def text(path,value,**kwargs):captured[path.name]=value
        with patch.object(Path,'mkdir',autospec=True),patch.object(Path,'write_text',autospec=True,side_effect=text), \
             patch.object(Path,'write_bytes',autospec=True),patch.object(t.subprocess,'Popen',return_value=process) as call,patch('builtins.print'):
            code=t.run(hashlib.sha256(payload).hexdigest(),output)
        self.assertEqual(code,0);self.assertEqual(call.call_count,1)
        self.assertEqual(json.loads(captured['request.json'])['automatic_retries'],0)
        self.assertEqual(t.TIMEOUT,60);self.assertEqual(t.LIMIT,16384)

    def test_transport_scope_and_reviewed_source_pin_fail_before_ssh(self):
        with patch.object(t.subprocess,'Popen',side_effect=AssertionError('NO_SSH')):
            with self.assertRaises(ValueError):t.run('bad','unused')
            with self.assertRaises(ValueError):t.run('0'*64,'unused')
        self.assertEqual(t.COMMAND[-2],'vnc.buptic.top')
        self.assertIn('StrictHostKeyChecking=yes',t.COMMAND)
        self.assertIn('BatchMode=yes',t.COMMAND)

    def test_isolated_validator_import_only_no_actual_payload_main(self):
        raw=json.dumps(result(FakeFS()))
        code=(
            "import importlib.util,json,sys\n"
            "before=list(sys.path)\n"
            "spec=importlib.util.spec_from_file_location('synthetic_e60',"+repr(str(Path(t.__file__).resolve()))+")\n"
            "m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)\n"
            "assert sys.path==before and sys.flags.isolated and sys.flags.no_site\n"
            "assert m.validate_response("+repr(raw)+".encode('ascii'))\n"
            "print(json.dumps({'ok':True}))\n"
        )
        with tempfile.TemporaryDirectory() as unrelated:
            output=subprocess.run([sys.executable,'-I','-S','-B','-c',code],cwd=unrelated,capture_output=True,text=True,timeout=15)
        self.assertEqual(output.returncode,0,output.stderr)
        self.assertEqual(json.loads(output.stdout),{'ok':True})


if __name__=='__main__':
    unittest.main()
