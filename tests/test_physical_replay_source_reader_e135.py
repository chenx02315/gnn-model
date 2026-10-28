"""Synthetic virtual FS only; no remote, real source read or tool launch."""
import ast
import base64
import copy
from pathlib import Path
import stat
import unittest
from unittest import mock

from src.data import physical_replay_source_reader_e135 as m
from src.data import prospective_acceptance_materializer_v1 as anchored
from tests.test_hf_credit_artifact_reader_e134 import Files


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.bodies = [b'synthetic STIL\n',b'%PDF-synthetic\n'+bytes(range(256))*300]
        self.fs = Files(m.FILES,self.bodies)
        for record in m.FILES:
            self.fs.info[record['path']].st_uid = record['uid']
        self.tick = mock.Mock()
        for patch in (
            mock.patch.object(anchored,'_directory',side_effect=self.fs.directory),
            mock.patch.object(m.os,'stat',side_effect=self.fs.stat),
            mock.patch.object(m.os,'fstat',side_effect=self.fs.fstat),
            mock.patch.object(m.os,'open',side_effect=self.fs.open),
            mock.patch.object(m.os,'read',side_effect=self.fs.read),
            mock.patch.object(m.os,'close',side_effect=self.fs.close),
            mock.patch.object(m.os,'O_NOFOLLOW',131072,create=True),
            mock.patch.object(m.os,'O_NONBLOCK',262144,create=True)):
            patch.start()
            self.addCleanup(patch.stop)
        self.addCleanup(lambda:self.assertEqual(self.fs.handles,{}))

    def receipt(self):
        return dict(schema=m.SCHEMA,files=[m.read_file(r,self.tick) for r in m.FILES],
            source_provenance_authenticated=False,semantics_verified=False,execution_ready=False)

    def test_default_authority_denies_before_any_io(self):
        with mock.patch.object(anchored,'_directory') as directory:
            with self.assertRaisesRegex(ValueError,'NO_FROZEN_E135_AUTHORITY'):
                m.collect(b'',b'',self.tick)
        directory.assert_not_called()
        self.tick.assert_not_called()

    def test_hash_only_pattern_full_pdf_no_launch_scan_or_write(self):
        with mock.patch('subprocess.Popen') as spawn,mock.patch.object(m.os,'scandir') as scan:
            value = self.receipt()
        spawn.assert_not_called()
        scan.assert_not_called()
        self.assertNotIn('body_base64',value['files'][0])
        for row,body in zip(value['files'],self.bodies):
            self.assertEqual(row['sha256'],m.sha(body))
            self.assertEqual(row['bytes'],len(body))
        self.assertEqual(base64.b64decode(value['files'][1]['body_base64']),self.bodies[1])
        self.assertEqual(m.validate_receipt(m.canonical(value)),value)
        self.assertEqual(self.fs.opened,[r['path'] for r in m.FILES])

    def test_wrong_path_and_preopen_type_link_owner_size(self):
        with self.assertRaisesRegex(ValueError,'EXACT_SOURCE_RECORD'):
            m.read_file(dict(m.FILES[0],path='/arbitrary'),self.tick)
        for record in m.FILES:
            info = self.fs.info[record['path']]
            for key,bad in [('st_mode',x) for x in (stat.S_IFLNK,stat.S_IFCHR,stat.S_IFBLK,stat.S_IFIFO,stat.S_IFSOCK,stat.S_IFDIR)]+[
                    ('st_nlink',2),('st_uid',999),('st_size',record['cap']+1),('st_size',0)]:
                old = getattr(info,key)
                setattr(info,key,bad)
                with self.assertRaises(ValueError):
                    m.read_file(record,self.tick)
                setattr(info,key,old)
        self.assertEqual(self.fs.opened,[])

    def test_short_read_growth_and_identity_mutation(self):
        record = m.FILES[0]
        path = record['path']
        self.fs.body[path] = b''
        with self.assertRaisesRegex(ValueError,'SHORT_OR_INVALID_READ'):
            m.read_file(record,self.tick)
        self.fs.body[path] = self.bodies[0]+b'grew'
        with self.assertRaisesRegex(ValueError,'SOURCE_GREW'):
            m.read_file(record,self.tick)
        self.fs.body[path] = self.bodies[0]
        self.fs.read_hook = lambda p:setattr(self.fs.info[p],'st_mtime_ns',101)
        with self.assertRaisesRegex(ValueError,'SOURCE_IDENTITY_CHANGED'):
            m.read_file(record,self.tick)

    def test_parent_replacement_and_open_race(self):
        record = m.FILES[0]
        parent = record['path'].rsplit('/',1)[0]
        self.fs.read_hook = lambda p:setattr(self.fs.info[parent],'st_ino',999)
        with self.assertRaisesRegex(ValueError,'HELD_PARENT_CHANGED'):
            m.read_file(record,self.tick)
        self.fs.read_hook = None
        original = self.fs.open
        def replaced(*args,**kwargs):
            fd = original(*args,**kwargs)
            self.fs.info[record['path']].st_ino += 1
            return fd
        with mock.patch.object(m.os,'open',side_effect=replaced):
            with self.assertRaisesRegex(ValueError,'OPEN_IDENTITY_CHANGED'):
                m.read_file(record,self.tick)

    def test_streaming_short_chunks_base64_and_guard_abort(self):
        original = self.fs.read
        with mock.patch.object(m.os,'read',side_effect=lambda fd,n:original(fd,min(n,7))):
            value = self.receipt()
        self.assertEqual(base64.b64decode(value['files'][1]['body_base64']),self.bodies[1])
        self.assertGreater(self.tick.call_count,100)
        self.tick.side_effect = ValueError('DEADLINE_OR_MEMORY')
        with self.assertRaisesRegex(ValueError,'DEADLINE_OR_MEMORY'):
            m.read_file(m.FILES[0],self.tick)

    def test_fresh_parent_anchor_and_missing_source(self):
        record = m.FILES[0]
        directory = self.fs.directory
        calls = [0]
        def changed_parent(path):
            calls[0] += 1
            if calls[0] == 2:
                self.fs.info[path].st_ino += 1
            return directory(path)
        with mock.patch.object(anchored,'_directory',side_effect=changed_parent):
            with self.assertRaisesRegex(ValueError,'PARENT_ANCHOR_CHANGED'):
                m.read_file(record,self.tick)
        del self.fs.info[record['path']]
        with self.assertRaises(FileNotFoundError):
            m.read_file(record,self.tick)

    def test_collect_authority_checked_first_and_injected_guard_midstream(self):
        with mock.patch.object(m,'check_authority') as authority:
            value = m.collect(b'synthetic-auth',b'synthetic-proposal',self.tick)
        authority.assert_called_once_with(b'synthetic-auth',b'synthetic-proposal')
        self.assertEqual(len(value['files']),2)
        self.tick.side_effect = [None,None,ValueError('RESOURCE_STOP')]
        with self.assertRaisesRegex(ValueError,'RESOURCE_STOP'):
            m.read_file(m.FILES[1],self.tick)

    def test_read_flags_and_chunk_bound(self):
        original_open,original_read = self.fs.open,self.fs.read
        with mock.patch.object(m.os,'open',side_effect=original_open) as opened,\
                mock.patch.object(m.os,'read',side_effect=original_read) as read:
            m.read_file(m.FILES[1],self.tick)
        self.assertEqual(opened.call_args[0][1],m.os.O_RDONLY|m.os.O_NOFOLLOW|m.os.O_NONBLOCK)
        self.assertTrue(all(0 < call[0][1] <= 65536 for call in read.call_args_list))

    def test_receipt_wrong_digest_body_caps_and_identity_rejected(self):
        value = self.receipt()
        cases = []
        for index,key,bad in [(0,'sha256','not-a-hash'),(0,'body_base64','YQ=='),
                (1,'sha256','0'*64),(1,'body_base64','YQ=='),(1,'bytes',m.FILES[1]['cap']+1),
                (0,'path','/wrong'),(0,'whole_file_hashed',False)]:
            changed = copy.deepcopy(value)
            changed['files'][index][key] = bad
            cases.append(changed)
        changed = copy.deepcopy(value)
        changed['files'][1]['identity']['st_uid'] = 1047
        cases.append(changed)
        for changed in cases:
            with self.assertRaises(ValueError):
                m.validate_receipt(m.canonical(changed))
        with mock.patch.object(m,'MAX_RESPONSE',10):
            with self.assertRaisesRegex(ValueError,'RESPONSE_CAP'):
                m.validate_receipt(m.canonical(value))

    def test_authority_hash_reply_schema_and_scope(self):
        repo = Path(__file__).resolve().parents[1]
        proposal = (repo/'contracts/physical_f_pattern_replay_proposal_e135_v1.json').read_bytes()
        self.assertEqual(m.sha(proposal),m.PROPOSAL_SHA)
        plan = m.decode(proposal)
        auth = dict(schema='physical-f-pattern-replay-authorization-e135-v1',approval_source='explicit_user_reply',
            user_reply='\u6279\u51c6 E135 \u6574\u5305',user_authorization_received=True,
            proposal_sha256=m.PROPOSAL_SHA,approved_scope=plan['scope_if_granted'])
        raw = m.canonical(auth)
        with mock.patch.object(m,'AUTH_SHA',m.sha(raw)):
            m.check_authority(raw,proposal)
            with self.assertRaises(ValueError):
                m.check_authority(raw+b' ',proposal)
        for key,bad in [('user_reply','approved'),('schema','old'),('user_authorization_received',False),('approved_scope',{})]:
            changed = dict(auth,**{key:bad})
            raw = m.canonical(changed)
            with mock.patch.object(m,'AUTH_SHA',m.sha(raw)):
                with self.assertRaises(ValueError):
                    m.check_authority(raw,proposal)
        self.assertEqual(self.fs.opened,[])

    def test_source_ast36_and_import_inert(self):
        source = Path(m.__file__).read_bytes()
        ast.parse(source.decode('utf-8'),feature_version=(3,6))
        ast.parse(Path(__file__).read_text(encoding='utf-8'),feature_version=(3,6))
        with mock.patch('builtins.open') as opened,mock.patch('subprocess.Popen') as spawn:
            namespace = {}
            exec(compile(source,'<inert-e135>','exec'),namespace)
        opened.assert_not_called()
        spawn.assert_not_called()
        self.assertIsNone(namespace['AUTH_SHA'])
        self.assertNotIn('execute',namespace)
        self.assertNotIn('prepare',namespace)


if __name__ == '__main__':
    unittest.main()
