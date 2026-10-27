"""Virtual POSIX documentation tree and mocked transports; never contact A."""
import ast
import base64
import copy
import datetime
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from scripts import probe_tessent_docs_e132 as m
from scripts import acceptance_transport_e98 as control
from src.data import direct_tessent_acceptance_e104 as direct

BOOT = '3ebeb9bb-410c-476c-a000-5c625f590473'


class Tree(object):
    def __init__(self):
        self.nodes,self.handles,self.bodies,self.links = {},{},{},{}
        self.next_fd,self.next_ino = 100,1
        self.body_reads,self.entries_returned = [],0
        self.opened_paths = []
        self.scandir_arguments = []
        self.on_read = None
        for path in ('/','/cad','/cad/mentor',m.INSTALL_ROOT,m.INSTALL_ROOT+'/doc',m.INSTALL_ROOT+'/docs'):
            self.add(path,directory=True)
        self.add(m.INSTALL_ROOT+'/doc/manual.pdf',b'%PDF-1.4\n'+b'content'*10000)
        self.add(m.INSTALL_ROOT+'/docs/help.txt',b'official documentation fixture\n')

    def add(self,path,body=b'',directory=False,target=None):
        self.nodes[path] = SimpleNamespace(st_dev=1,st_ino=self.next_ino,
            st_mode=(stat.S_IFDIR if directory else stat.S_IFLNK if target is not None else stat.S_IFREG)|0o644,
            st_nlink=1,st_uid=0,st_size=len(body),st_mtime_ns=100,st_ctime_ns=100)
        self.next_ino += 1
        self.bodies[path] = body
        if target is not None:
            self.links[path] = target

    def path(self,name,dir_fd=None):
        if dir_fd is None:
            return name
        parent = self.handles[dir_fd][0]
        return parent.rstrip('/')+'/'+name

    def opened(self,path):
        fd = self.next_fd
        self.next_fd += 1
        self.handles[fd] = [path,0]
        return fd

    def open(self,name,flags,dir_fd=None):
        path = self.path(name,dir_fd)
        self.opened_paths.append(path)
        if path not in self.nodes:
            raise FileNotFoundError(path)
        info = self.nodes[path]
        if stat.S_ISLNK(info.st_mode) or (flags & m.os.O_DIRECTORY and not stat.S_ISDIR(info.st_mode)):
            raise OSError('NOFOLLOW_OR_DIRECTORY')
        return self.opened(path)

    def close(self,fd):
        self.handles.pop(fd)

    def dup(self,fd):
        return self.opened(self.handles[fd][0])

    def fstat(self,fd):
        return copy.copy(self.nodes[self.handles[fd][0]])

    def stat(self,name,dir_fd=None,follow_symlinks=False):
        if dir_fd is None and name.startswith('/proc/self/fd/'):
            return copy.copy(self.nodes[self.handles[int(name.rsplit('/',1)[1])][0]])
        path = self.path(name,dir_fd)
        if path not in self.nodes:
            raise FileNotFoundError(path)
        return copy.copy(self.nodes[path])

    def readlink(self,name,dir_fd=None):
        if dir_fd is None and name.startswith('/proc/self/fd/'):
            return self.handles[int(name.rsplit('/',1)[1])][0]
        return self.links[self.path(name,dir_fd)]

    def read(self,fd,count):
        path,offset = self.handles[fd]
        self.body_reads.append(path)
        raw = self.bodies[path][offset:offset+count]
        self.handles[fd][1] += len(raw)
        if self.on_read:
            self.on_read(path)
        return raw

    def scandir(self,alias):
        self.scandir_arguments.append(alias)
        if type(alias) is int:
            raise TypeError('simulated Python 3.6 scandir cannot accept integer FD')
        assert alias.startswith('/proc/self/fd/')
        fd = int(alias.rsplit('/',1)[1])
        path = self.handles[fd][0].rstrip('/')+'/'
        names = sorted(p[len(path):] for p in self.nodes if p.startswith(path) and '/' not in p[len(path):] and p != path)
        tree = self
        class Stream:
            def __enter__(self): return self
            def __exit__(self,*args): return False
            def close(self): pass
            def __iter__(self):
                for name in names:
                    tree.entries_returned += 1
                    yield SimpleNamespace(name=name)
        return Stream()


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.tree = Tree()
        self.authority = (Path(m.__file__).resolve().parents[1]/m.AUTH).read_bytes()
        self.domain = mock.Mock(peak=123)
        self.domain.sample.return_value = {}
        self.clock = mock.Mock(return_value=1001.0)
        patchers = [mock.patch.object(m.os,key,side_effect=getattr(self.tree,key)) for key in
            ('open','close','dup','fstat','stat','read','readlink','scandir')]
        patchers += [mock.patch.object(m.os,'getuid',return_value=1047,create=True),
            mock.patch.object(m.os,'O_DIRECTORY',0x100000,create=True),mock.patch.object(m.os,'O_NOFOLLOW',0x200000,create=True),
            mock.patch.object(m.os,'O_NONBLOCK',0x400000,create=True),
            mock.patch.object(m.os.path,'realpath',return_value=m.INSTALL_ROOT),
            mock.patch.object(m.sys,'platform','linux'),mock.patch.object(m.platform,'node',return_value='bupt-vncs2'),
            mock.patch.object(m.time,'monotonic',self.clock),mock.patch.object(direct,'Descendants',return_value=self.domain),
            mock.patch.object(direct.base,'_small',return_value=BOOT.encode('ascii'))]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(lambda:self.assertEqual(self.tree.handles,{}))

    def metadata(self):
        value = m.collect('metadata',dict(authority=base64.b64encode(self.authority).decode('ascii')),1000.0)
        self.assertTrue(value['capture_complete'],value['error'])
        return value

    def export(self,metadata,ids):
        raw = m.canonical(metadata)
        return m.collect('export',dict(authority=base64.b64encode(self.authority).decode('ascii'),
            metadata=base64.b64encode(raw).decode('ascii'),metadata_sha256=m.sha(raw),selected_ids=ids),1002.0)

    def test_metadata_reads_no_body_canonical_ids_and_bounded_scope(self):
        with mock.patch('subprocess.Popen') as spawn:
            value = self.metadata()
        spawn.assert_not_called()
        self.assertEqual(self.tree.body_reads,[])
        self.assertEqual(len(value['scan']['candidates']),2)
        self.assertEqual(value['root']['resolved'],m.INSTALL_ROOT)
        self.assertLessEqual(len(m.canonical(value)),65536)
        self.assertEqual(m.validate_metadata(m.canonical(value)),value)

    def test_doc_to_doc_symlink_allowed_but_bin_license_user_design_depth_and_outside_rejected(self):
        for name,target in (('bin.pdf','../bin/manual.pdf'),('lic.pdf','../license/manual.pdf'),
            ('u.pdf','../user/manual.pdf'),('d.pdf','../design/manual.pdf'),
            ('deep.pdf','../docs/a/b/c/manual.pdf'),('escape.pdf','/etc/passwd')):
            self.tree.add(m.INSTALL_ROOT+'/doc/'+name,target=target)
        self.tree.add(m.INSTALL_ROOT+'/doc/alias.txt',target='../docs/help.txt')
        value = self.metadata()
        logical = {r['logical_relative'] for r in value['scan']['candidates']}
        self.assertEqual(logical,{'doc/manual.pdf','docs/help.txt','doc/alias.txt'})
        self.assertEqual(self.tree.body_reads,[])
        changed = copy.deepcopy(value)
        changed['scan']['candidates'][0]['resolved_relative'] = 'bin/manual.pdf'
        with self.assertRaises(ValueError):
            m.validate_metadata(m.canonical(changed))

    def test_entry_limit_does_not_claim_document_absence_or_scan_more_than200(self):
        for i in range(250):
            self.tree.add(m.INSTALL_ROOT+'/doc/page%03d.html'%i,b'x')
        value = self.metadata()
        self.assertTrue(value['scan']['truncated'])
        self.assertLessEqual(value['scan']['scanned_entries'],200)
        self.assertLessEqual(self.tree.entries_returned,200)
        self.assertTrue(value['scan']['no_candidates_does_not_prove_installation_document_absence'])

    def test_simulated36_int_fd_failure_and_positive_string_alias_integration(self):
        with self.assertRaises(TypeError):
            m.os.scandir(7)
        self.tree.scandir_arguments.clear()
        with mock.patch.object(m.sys,'version_info',(3,6,8)):
            value = self.metadata()
        self.assertEqual(value['python_version'],[3,6,8])
        self.assertEqual(value['stage'],'COMPLETE')
        self.assertTrue(self.tree.scandir_arguments)
        self.assertTrue(all(type(arg) is str and arg.startswith('/proc/self/fd/') for arg in self.tree.scandir_arguments))

    def test_multiple_directories_share_global200_not200_per_directory(self):
        # Excluded extensions isolate the entry budget from the metadata byte cap.
        for directory in ('doc','docs'):
            for index in range(120):
                self.tree.add(m.INSTALL_ROOT+'/'+directory+'/excluded%03d.bin'%index,b'no document read')
        value = self.metadata()
        self.assertEqual(value['scan']['scanned_entries'],200)
        self.assertEqual(self.tree.entries_returned,200)
        self.assertGreaterEqual(value['scan']['scanned_directories'],2)
        self.assertTrue(value['scan']['truncated'])
        self.assertEqual(self.tree.body_reads,[])

    def test_fixed_stage_and_version_on_typeerror_without_exception_text_leakage(self):
        with mock.patch.object(m.sys,'version_info',(3,6,8)), \
                mock.patch.object(m,'scan_metadata',side_effect=TypeError('PRIVATE_TRACEBACK_OR_PATH')):
            value = m.collect('metadata',dict(authority=base64.b64encode(self.authority).decode('ascii')),1000.0)
        self.assertFalse(value['capture_complete'])
        self.assertEqual(value['python_version'],[3,6,8])
        self.assertEqual(value['stage'],'DOCUMENT_DIRECTORY_SCAN')
        self.assertEqual(value['error'],dict(type='TypeError',stage='DOCUMENT_DIRECTORY_SCAN',
            code='DOCUMENT_PROBE_FAILED_AT_DOCUMENT_DIRECTORY_SCAN'))
        self.assertNotIn('PRIVATE_TRACEBACK_OR_PATH',m.canonical(value).decode('ascii'))
        self.assertEqual(self.tree.body_reads,[])

    def test_export_complete_hash_base64_across_chunks_and_stable_snapshot(self):
        metadata = self.metadata()
        row = next(r for r in metadata['scan']['candidates'] if r['logical_relative'].endswith('.pdf'))
        value = self.export(metadata,[row['candidate_id']])
        self.assertTrue(value['capture_complete'],value['error'])
        exported = value['exports'][0]
        raw = self.tree.bodies[m.INSTALL_ROOT+'/doc/manual.pdf']
        self.assertEqual(base64.b64decode(exported['body_base64']),raw)
        self.assertEqual(exported['sha256'],m.sha(raw))
        self.assertEqual(value['probe_start_monotonic'],1000.0)
        self.assertEqual(value['probe_deadline_monotonic'],1300.0)

    def test_export_metadata_identity_mutation_stops_without_retry(self):
        metadata = self.metadata()
        row = metadata['scan']['candidates'][0]
        self.tree.nodes[m.INSTALL_ROOT+'/'+row['resolved_relative']].st_mtime_ns += 1
        value = self.export(metadata,[row['candidate_id']])
        self.assertFalse(value['capture_complete'])
        self.assertEqual(value['error']['code'],'SELECTED_DOCUMENT_SNAPSHOT_CHANGED')
        self.assertEqual(self.tree.body_reads,[])

    def test_special_documents_and_non_directory_intermediate_never_opened_or_read(self):
        root_fd,root = m.open_root()
        try:
            for kind in (stat.S_IFCHR,stat.S_IFBLK,stat.S_IFIFO,stat.S_IFSOCK):
                path = m.INSTALL_ROOT+'/doc/special.pdf'
                self.tree.add(path,b'not a regular document')
                self.tree.nodes[path].st_mode = kind|0o644
                self.tree.opened_paths.clear()
                with self.subTest(kind=kind),self.assertRaisesRegex(ValueError,'NAMED_DOCUMENT_OR_DIRECTORY_TYPE_REQUIRED'):
                    m.resolve_doc(root_fd,root,'doc/special.pdf')
                self.assertNotIn(path,self.tree.opened_paths)
                self.assertNotIn(path,self.tree.body_reads)
            path = m.INSTALL_ROOT+'/doc/notdirectory'
            self.tree.add(path,b'ordinary file, not a directory')
            self.tree.opened_paths.clear()
            with self.assertRaisesRegex(ValueError,'NAMED_DOCUMENT_OR_DIRECTORY_TYPE_REQUIRED'):
                m.resolve_doc(root_fd,root,'doc/notdirectory/manual.pdf')
            self.assertNotIn(path,self.tree.opened_paths)
            self.assertNotIn(path,self.tree.body_reads)
        finally:
            m.os.close(root_fd)

    def test_memory_child_and_total300deadline_guard(self):
        metadata = self.metadata()
        ids = [metadata['scan']['candidates'][0]['candidate_id']]
        self.clock.return_value = 1301.0
        self.assertFalse(self.export(metadata,ids)['capture_complete'])
        self.clock.return_value = 1001.0
        self.domain.peak = 536870913
        self.assertFalse(self.export(metadata,ids)['capture_complete'])
        self.domain.peak = 0
        self.domain.sample.return_value = {1:'child'}
        self.assertFalse(self.export(metadata,ids)['capture_complete'])
        self.assertEqual(self.tree.body_reads,[])


class LocalTests(unittest.TestCase):
    def metadata_fixture(self):
        root_info = dict(st_dev=1,st_ino=1,st_mode=stat.S_IFDIR|0o755,st_nlink=1,st_uid=0,st_size=0,st_mtime_ns=1,st_ctime_ns=1)
        root = dict(logical=m.INSTALL_ROOT,resolved=m.INSTALL_ROOT,identity=root_info)
        raw = b'%PDF-fixture\n'
        file_info = dict(root_info,st_ino=2,st_mode=stat.S_IFREG|0o644,st_size=len(raw))
        row = m.candidate(root,'doc/manual.pdf','doc/manual.pdf',SimpleNamespace(**file_info))
        value = dict(schema=m.SCHEMA,mode='metadata',capture_complete=True,error=None,hostname='bupt-vncs2',uid=1047,
            python_version=[3,6,8],stage='COMPLETE',
            boot_id=BOOT,remote_start_monotonic=1000.0,remote_end_monotonic=1001.0,probe_start_monotonic=1000.0,
            probe_deadline_monotonic=1300.0,root=root,exports=[],sampled_peak_rss_swap_bytes=0,filesystem_writes=0,
            child_launches=0,environment_reads=0,tessent_launches=0,training_runs=0,coverage_semantics_proven=False,
            old_experiment_clock_changed=False,training_release=False,scan=dict(candidates=[row],scanned_entries=1,
            scanned_directories=1,rejected_entries=0,truncated=False,depth_limited=False,scan_complete_within_fixed_scope=True,
            fixed_document_roots=list(m.DOC_ROOTS),no_candidates_does_not_prove_installation_document_absence=True))
        return m.canonical(value),row,raw

    def first(self,plan):
        now = datetime.datetime.now(datetime.timezone.utc)
        started = m.time.monotonic()
        return dict(local_utc_deadline=(now+datetime.timedelta(seconds=300)).isoformat(timespec='microseconds'),
            local_monotonic_start=started,local_monotonic_deadline=started+300,
            local_clock_domain=dict(pid=m.os.getpid(),host=m.platform.node(),
                monotonic_implementation=m.time.get_clock_info('monotonic').implementation),
            source_sha256=plan['source_sha256'],protocol_sha256=plan['protocol_sha256'],authorization_sha256=m.AUTH_SHA,
            host_fingerprint='cached-A')

    def test_authority_unicode_and_offline_preparation_ast(self):
        with mock.patch.object(control,'load_transport',side_effect=AssertionError('NO NETWORK')):
            plan = m.prepare_metadata()
        authority = json.loads((Path(m.__file__).resolve().parents[1]/m.AUTH).read_bytes())
        self.assertEqual(authority['user_reply'],'\u6279\u51c6 **E132 \u65b0\u6587\u6863\u6838\u9a8c\u6574\u5305**')
        self.assertNotIn('\ufffd',authority['user_reply'])
        self.assertEqual(plan['authorization_sha256'],m.AUTH_SHA)
        self.assertTrue(plan['protocol']['protocol_review_is_not_future_selection_review'])
        for path in (Path(m.__file__),Path(__file__)):
            ast.parse(path.read_text(),feature_version=(3,6))
        ast.parse(plan['payload'].decode('ascii'),feature_version=(3,6))
        self.assertEqual(plan['source_sha256']['documentation_scandir_compat_e132'],m.HELPER_SHA)
        self.assertEqual(len(plan['source_sha256']),16)

    def test_sensitive_extension_root_and_depth_rejections(self):
        for path in ('bin/a.pdf','doc/license.pdf','doc/secret.txt','doc/a.key','doc/a/b/c/d.pdf',
                     'doc/../bin/a.pdf','docs//a.pdf','/doc/a.pdf','share/help/a/b/c/d.pdf'):
            self.assertFalse(m.allowed(path),path)
        self.assertTrue(m.allowed('doc/a/b/manual.pdf'))
        self.assertTrue(m.allowed('share/doc/pdf/manual.pdf'))

    def test_selection_count_total_bytes_and_unknown_ids(self):
        row = dict(candidate_id='a',identity=dict(st_size=20*1048576))
        metadata = dict(scan=dict(candidates=[row,dict(row,candidate_id='b')]))
        for ids in ([],['unknown'],['a','a'],['a','b'],['a']*4):
            with self.assertRaises(ValueError):
                m.select_candidates(metadata,ids)

    def test_protocol_review_before_transport_and_raw_before_validation_once(self):
        with tempfile.TemporaryDirectory() as temp:
            staging = Path(temp)
            plan = {k:'a'*64 for k in m.PROTOCOL_KEYS}
            plan.update(payload=b'inert',payload_sha256='b'*64,source_sha256={},mode='metadata')
            review = staging/'review.json'
            review.write_bytes(m.canonical(dict(status='PASS',protocol_reviewed={k:plan[k] for k in m.PROTOCOL_KEYS},
                metadata_payload_sha256=plan['payload_sha256'],future_selection_not_yet_reviewed=True)))
            helper = mock.Mock()
            helper.verify_cached_host.return_value = 'cached-A'
            helper.transport.return_value = dict(stdout=b'invalid raw',stderr=b'stderr',exit_code=0,
                timeout=False,overflow=False,write_failed=False,threads_incomplete=False)
            phase = staging/m.PHASE_NAME
            def validate(raw):
                self.assertEqual((phase/'metadata/stdout.json').read_bytes(),b'invalid raw')
                self.assertTrue((phase/'metadata/transport.json').is_file())
                raise ValueError('MOCK_REJECT')
            with mock.patch.object(m,'prepare_metadata',return_value=plan),mock.patch.object(control,'STAGING',staging), \
                    mock.patch.object(control,'load_transport',return_value=helper), \
                    mock.patch.object(control,'execute_phase',side_effect=AssertionError('OLD GRANT')), \
                    mock.patch.object(m,'validate_metadata',side_effect=validate):
                with self.assertRaisesRegex(ValueError,'MOCK_REJECT'):
                    m.execute_metadata(review,plan['payload_sha256'])
                with self.assertRaises(FileExistsError):
                    m.execute_metadata(review,plan['payload_sha256'])
            self.assertEqual(helper.transport.call_count,1)

    def test_export_exact_root_selection_and_all_sha_verified_before_any_decoded_write(self):
        metadata,row,body = self.metadata_fixture()
        plan = m.prepare_export(metadata,[row['candidate_id']])
        meta_value = m.validate_metadata(metadata)
        export = dict(meta_value,mode='export',remote_start_monotonic=1002.0,remote_end_monotonic=1003.0,scan=None,
            exports=[dict(candidate_id=row['candidate_id'],bytes=len(body),sha256='0'*64,
                          whole_file_hashed=True,body_base64=base64.b64encode(body).decode('ascii'))])
        with tempfile.TemporaryDirectory() as temp:
            staging = Path(temp)
            phase = staging/m.PHASE_NAME
            (phase/'metadata').mkdir(parents=True)
            (phase/'start.json').write_bytes(m.canonical(self.first(plan)))
            (phase/'metadata/stdout.json').write_bytes(metadata)
            (phase/'metadata/validated.json').write_bytes(m.canonical(dict(metadata_sha256=m.sha(metadata))))
            protocol_path,selection_path = staging/'protocol.json',staging/'selection.json'
            protocol_path.write_bytes(m.canonical(dict(status='PASS',protocol_reviewed={k:plan[k] for k in m.PROTOCOL_KEYS},
                future_selection_not_yet_reviewed=True)))
            selection_path.write_bytes(m.canonical(dict(status='PASS',reviewer_role='PARENT_EXACT_POST_METADATA_SELECTION',
                selected_ids=[row['candidate_id']],selection_reviewed=plan['selection_manifest'],
                export_payload_sha256=plan['payload_sha256'],selection_manifest_sha256=plan['selection_manifest_sha256'])))
            helper = mock.Mock()
            helper.verify_cached_host.return_value = 'cached-A'
            helper.transport.return_value = dict(stdout=m.canonical(export),stderr=b'',exit_code=0,
                timeout=False,overflow=False,write_failed=False,threads_incomplete=False)
            with mock.patch.object(control,'STAGING',staging),mock.patch.object(control,'load_transport',return_value=helper), \
                    mock.patch.object(control,'execute_phase',side_effect=AssertionError('OLD GRANT')):
                with self.assertRaisesRegex(ValueError,'FULL_EXPORTED_DOCUMENT_SHA'):
                    m.execute_export(metadata,selection_path,protocol_path,plan['payload_sha256'])
                self.assertTrue((phase/'export/stdout.json').is_file())
                self.assertTrue((phase/'export/transport.json').is_file())
                self.assertFalse((phase/'export'/(row['candidate_id']+'.pdf')).exists())
                with self.assertRaises(FileExistsError):
                    m.execute_export(metadata,selection_path,protocol_path,plan['payload_sha256'])
            self.assertEqual(helper.transport.call_count,1)

    def test_local_monotonic_and_utc_both_expire_and_same_process_required(self):
        first = self.first(dict(source_sha256={},protocol_sha256='x'))
        first['local_clock_domain']['pid'] += 1
        with self.assertRaisesRegex(ValueError,'SAME_LOCAL_PROCESS'):
            m._remaining(first)
        first = self.first(dict(source_sha256={},protocol_sha256='x'))
        first['local_monotonic_start'] = m.time.monotonic()-301
        first['local_monotonic_deadline'] = first['local_monotonic_start']+300
        with self.assertRaisesRegex(ValueError,'MONOTONIC_PROBE_DEADLINE'):
            m._remaining(first)
        first = self.first(dict(source_sha256={},protocol_sha256='x'))
        first['local_utc_deadline'] = (datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(seconds=1)).isoformat(timespec='microseconds')
        with self.assertRaisesRegex(ValueError,'300_SECONDS_EXPIRED'):
            m._remaining(first)

    def test_import_exec_is_inert_and_export_protocol_matches_metadata_preapproval(self):
        source = Path(m.__file__).read_bytes()
        with mock.patch.object(m.os,'open',side_effect=AssertionError('NO FILE ACCESS')), \
                mock.patch('subprocess.Popen',side_effect=AssertionError('NO CHILD')):
            exec(compile(source,'<inert-doc-source-import>','exec'),{'__name__':'inert_docs','__file__':m.__file__})
        metadata,row,body = self.metadata_fixture()
        initial = m.prepare_metadata()
        dynamic = m.prepare_export(metadata,[row['candidate_id']])
        self.assertEqual({k:initial[k] for k in m.PROTOCOL_KEYS},{k:dynamic[k] for k in m.PROTOCOL_KEYS})
        self.assertEqual(dynamic['selection_manifest']['metadata_sha256'],m.sha(metadata))


if __name__ == '__main__':
    unittest.main()
