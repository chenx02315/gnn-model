"""Virtual anchored IO only; large-file cases prove admission, not a real 2GiB hash."""
import ast
import copy
import errno
from pathlib import Path
import stat
import unittest
from unittest import mock
from src.data import physical_engine_evidence_e137 as m
from tests.test_generation_failure_readback_e122 import Files as BaseFiles


class Files(BaseFiles):
    def __init__(self):
        self.info,self.body,self.handles={},{},{};self.next_fd,self.next_ino=100,10
        self.opened,self.read_hook=[],None
        self.add('/',directory=True)
        for path in m.PATHS:
            parts=path.split('/')[1:]
            for i in range(1,len(parts)):
                parent='/'+'/'.join(parts[:i])
                if parent not in self.info:self.add(parent,directory=True)
            self.add(path,raw=b'synthetic installed engine',directory=path in m.selector.TCL.values())
        for info in self.info.values():
            info.st_uid=0
            info.st_mode=stat.S_IFMT(info.st_mode)|0o755
    def resolve(self,name,dir_fd):
        return name if dir_fd is None else self.handles[dir_fd][0].rstrip('/')+'/'+name
    def stat(self,name,dir_fd=None,follow_symlinks=False):
        path=self.resolve(name,dir_fd)
        if path not in self.info:raise FileNotFoundError(errno.ENOENT,'missing')
        return copy.copy(self.info[path])
    def open(self,name,flags,dir_fd=None):
        path=self.resolve(name,dir_fd)
        if path not in self.info:raise FileNotFoundError(errno.ENOENT,'missing')
        self.opened.append(path)
        return self.handle(path)


class Tests(unittest.TestCase):
    def setUp(self):
        self.fs=Files()
        self.pins={p:(len(self.fs.body[p]),m.sha(self.fs.body[p])) for p in m.CHAIN}
        for patch in (mock.patch.object(m,'PINS',self.pins),mock.patch.object(m.os,'stat',side_effect=self.fs.stat),
            mock.patch.object(m.os,'fstat',side_effect=self.fs.fstat),mock.patch.object(m.os,'open',side_effect=self.fs.open),
            mock.patch.object(m.os,'read',side_effect=self.fs.read),mock.patch.object(m.os,'close',side_effect=self.fs.close),
            mock.patch.object(m.os,'O_DIRECTORY',65536,create=True),mock.patch.object(m.os,'O_NOFOLLOW',131072,create=True),
            mock.patch.object(m.os,'O_NONBLOCK',262144,create=True)):
            patch.start();self.addCleanup(patch.stop)
        self.addCleanup(lambda:self.assertEqual(self.fs.handles,{}))

    def test_default_trust_denies_before_any_clock_callback_or_filesystem(self):
        callback=mock.Mock()
        with self.assertRaisesRegex(ValueError,'ENGINE_EVIDENCE_TRUST_NOT_FROZEN'):
            m.collect(b'',b'',b'','',{},callback,callback,callback)
        callback.assert_not_called();self.assertEqual(self.fs.opened,[])

    def test_exact_all_paths_hashes_and_no_bodies_or_directory_walk(self):
        total=[0]
        with mock.patch.object(m.os,'scandir') as scan:
            rows={p:m.sample_path(p,mock.Mock(),total) for p in m.PATHS}
        scan.assert_not_called()
        self.assertEqual(set(rows),set(m.PATHS))
        for p,row in rows.items():
            if p in m.selector.TCL.values():self.assertIsNone(row['sha256'])
            else:self.assertEqual(row['sha256'],m.sha(self.fs.body[p]))
        self.assertNotIn('body_base64',m.canonical(rows).decode('ascii'))
        with self.assertRaisesRegex(ValueError,'ENGINE_FINITE_PATH_ONLY'):m.sample_path('/other',mock.Mock(),[0])

    def test_real_enoent_only_missing_errors_not_absence(self):
        path=m.selector.ENGINE['64'];del self.fs.info[path]
        self.assertEqual(m.sample_path(path,mock.Mock(),[0]),dict(state='MISSING'))
        original=self.fs.stat
        def denied(name,dir_fd=None,follow_symlinks=False):
            if self.fs.resolve(name,dir_fd)==path:raise PermissionError(errno.EACCES,'denied')
            return original(name,dir_fd,follow_symlinks)
        with mock.patch.object(m.os,'stat',side_effect=denied):
            with self.assertRaises(PermissionError):m.sample_path(path,mock.Mock(),[0])

    def test_unsafe_leaves_and_parents_never_opened_as_files(self):
        path=m.selector.ENGINE['64'];info=self.fs.info[path]
        for key,value in [('st_mode',stat.S_IFLNK|0o755),('st_mode',stat.S_IFIFO|0o755),('st_uid',1047),('st_nlink',2),('st_mode',stat.S_IFREG|0o777)]:
            old=getattr(info,key);setattr(info,key,value);self.fs.opened.clear()
            with self.assertRaises(ValueError):m.sample_path(path,mock.Mock(),[0])
            self.assertNotIn(path,self.fs.opened);setattr(info,key,old)
        self.fs.info['/cad'].st_uid=1047
        with self.assertRaisesRegex(ValueError,'ENGINE_PARENT_TYPE_OWNER_PERMISSIONS'):
            m.sample_path(path,mock.Mock(),[0])

    def test_mutation_short_tick_and_large_metadata_admission(self):
        path=m.selector.ENGINE['64'];original=self.fs.body[path]
        self.fs.body[path]=b''
        with self.assertRaisesRegex(ValueError,'ENGINE_SHORT_READ'):m.sample_path(path,mock.Mock(),[0])
        self.fs.body[path]=original
        self.fs.read_hook=lambda p:setattr(self.fs.info[p],'st_ctime_ns',101)
        with self.assertRaisesRegex(ValueError,'ENGINE_OBJECT_CHANGED'):m.sample_path(path,mock.Mock(),[0])
        self.fs.read_hook=None
        with self.assertRaisesRegex(ValueError,'STOP'):m.sample_path(path,mock.Mock(side_effect=ValueError('STOP')),[0])
        self.fs.info[path].st_size=134217729
        with mock.patch.object(m.os,'read',side_effect=ValueError('STREAM_STARTED')):
            with self.assertRaisesRegex(ValueError,'STREAM_STARTED'):m.sample_path(path,mock.Mock(),[0])
        self.fs.info[path].st_size=2147483649;self.fs.opened.clear()
        with self.assertRaisesRegex(ValueError,'ENGINE_HASH_BYTE_LIMIT'):m.sample_path(path,mock.Mock(),[0])
        self.assertNotIn(path,self.fs.opened)

    def test_fresh_parent_swapped_inode_not_accepted(self):
        path=m.selector.ENGINE['64'];parent=path.rsplit('/',1)[0]
        replacement=parent+'_replacement';self.fs.add(replacement,directory=True)
        self.fs.info[replacement].st_uid=0;self.fs.info[replacement].st_mode=stat.S_IFDIR|0o755
        changed=[False];original=m._directory
        def directory(p):
            if p==parent and changed[0]:return self.fs.directory(replacement)
            return original(p)
        self.fs.read_hook=lambda p:changed.__setitem__(0,True)
        with mock.patch.object(m,'_directory',side_effect=directory):
            with self.assertRaisesRegex(ValueError,'ENGINE_NAMED_PARENT_REPLACED'):m.sample_path(path,mock.Mock(),[0])

    def test_full_collect_with_frozen_synthetic_context_has_honest_flags(self):
        repo=Path(__file__).absolute().parents[1]
        authority=(repo/'contracts/physical_f_clean_replay_authorization_e137.json').read_bytes()
        context=m.canonical(dict(role='execution',authorization_sha256=m.ACTUAL_AUTH_SHA256,
            boot_id='3ebeb9bb-410c-476c-a000-5c625f590473',package_start=1000.,package_end=4600.,connection_start=2000.,utc_end=9000.))
        packet=m.canonical(dict(role='execution',authorization_sha256=m.ACTUAL_AUTH_SHA256,
            context_sha256=m.sha(context),selector_sha256=m.SELECTOR_SHA256))
        with mock.patch.object(m,'AUTH_SHA256',m.ACTUAL_AUTH_SHA256),mock.patch.object(m,'CONTEXT_SHA256',m.sha(context)),\
                mock.patch.object(m,'PACKET_SHA256',m.sha(packet)),mock.patch.object(m.selector,'__source_sha256__',m.SELECTOR_SHA256,create=True),\
                mock.patch.object(m.selector,'_validate_plan'),mock.patch.object(m.selector,'redact_plan',return_value={'redacted':True}),\
                mock.patch.object(m.selector,'classify',return_value={'status':'CONDITIONALLY_SELECTED'}):
            value=m.collect(authority,packet,context,'3ebeb9bb-410c-476c-a000-5c625f590473',{},mock.Mock(),lambda:2001.,lambda:5000.)
            self.assertEqual(set(value['files']),set(m.PATHS))
            self.assertTrue(value['physical_metadata_observed']);self.assertFalse(value['engine_identity_authenticated'])
            self.assertFalse(value['memory_enforcement_verified']);self.assertFalse(value['execution_ready'])
            calls=[0]
            def after_minute():
                calls[0]+=1
                return 2001. if calls[0]==1 else 2062.
            extended=m.collect(authority,packet,context,'3ebeb9bb-410c-476c-a000-5c625f590473',{},mock.Mock(),after_minute,lambda:5000.)
            self.assertTrue(extended['physical_metadata_observed'])
            with self.assertRaisesRegex(ValueError,'ENGINE_EVIDENCE_DEADLINE'):
                m.collect(authority,packet,context,'3ebeb9bb-410c-476c-a000-5c625f590473',{},mock.Mock(),lambda:4400.,lambda:5000.)
            with self.assertRaisesRegex(ValueError,'ENGINE_ORIGINAL_RUNTIME_BOOT'):
                m.collect(authority,packet,context,'wrong',{},mock.Mock(),lambda:2001.,lambda:5000.)
            with self.assertRaisesRegex(ValueError,'ENGINE_EVIDENCE_DEADLINE'):
                m.collect(authority,packet,context,'3ebeb9bb-410c-476c-a000-5c625f590473',{},mock.Mock(),lambda:4600.,lambda:5000.)
            # Isolate original package end: a later connection would still have
            # time left at 4600, but it cannot renew the package's original end.
            later=m.decode(context);later['connection_start']=4000.
            later_context=m.canonical(later)
            later_packet=m.canonical(dict(role='execution',authorization_sha256=m.ACTUAL_AUTH_SHA256,
                context_sha256=m.sha(later_context),selector_sha256=m.SELECTOR_SHA256))
            with mock.patch.object(m,'CONTEXT_SHA256',m.sha(later_context)),mock.patch.object(m,'PACKET_SHA256',m.sha(later_packet)):
                with self.assertRaisesRegex(ValueError,'ENGINE_EVIDENCE_DEADLINE'):
                    m.collect(authority,later_packet,later_context,'3ebeb9bb-410c-476c-a000-5c625f590473',{},mock.Mock(),lambda:4600.,lambda:5000.)


class SourceTests(unittest.TestCase):
    def test_ast36_inert_pins(self):
        raw=Path(m.__file__).read_bytes();ast.parse(raw.decode('utf-8'),feature_version=(3,6))
        ast.parse(Path(__file__).read_text(encoding='utf-8'),feature_version=(3,6))
        with mock.patch('builtins.open') as opened:
            scope=dict(__package__='src.data');exec(compile(raw,'<inert-evidence>','exec'),scope)
        opened.assert_not_called();self.assertIsNone(scope['CONTEXT_SHA256'])
        self.assertEqual(m.MAX_FILE,2147483648);self.assertEqual(m.MAX_TOTAL,4294967296)
