"""Simulated Python 3.6 scandir contract only, not measured Linux evidence."""
import ast
import copy
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest import mock

from src.data import documentation_scandir_compat_e132 as m


class Host(object):
    def __init__(self,count=1000):
        self.snapshot = dict(st_dev=1,st_ino=20,st_mode=stat.S_IFDIR|0o755,st_nlink=2,
            st_uid=0,st_size=4096,st_mtime_ns=50,st_ctime_ns=50)
        self.info = dict(self.snapshot)
        self.target = '/cad/mentor/tessent2021_2/doc/pdf'
        self.alias_info = None
        self.handles = {7}
        self.count,self.yielded,self.closed_streams = count,0,0
        self.scandir_arguments,self.closed_fds,self.alias_reads = [],[],[]
        self.on_next = None
        self.name = None

    def dup(self,fd):
        if fd not in self.handles:
            raise OSError('BAD_FD')
        self.handles.add(31)
        return 31

    def fstat(self,fd):
        if fd not in self.handles:
            raise OSError('BAD_FD')
        return SimpleNamespace(**self.info)

    def readlink(self,path):
        assert path == '/proc/self/fd/31'
        self.alias_reads.append(path)
        return self.target

    def stat(self,path,follow_symlinks=False):
        assert path == '/proc/self/fd/31' and follow_symlinks is True
        return SimpleNamespace(**(self.alias_info if self.alias_info is not None else self.info))

    def close(self,fd):
        self.handles.remove(fd)
        self.closed_fds.append(fd)

    def scandir(self,arg):
        self.scandir_arguments.append(arg)
        if type(arg) is int:
            raise TypeError('scandir: expected path string, not int (simulated 3.6)')
        assert arg == '/proc/self/fd/31'
        host = self
        class Stream(object):
            def __iter__(self): return self
            def __next__(self):
                if host.yielded >= host.count:
                    raise StopIteration
                host.yielded += 1
                if host.on_next:
                    host.on_next()
                return SimpleNamespace(name=host.name if host.name is not None else 'manual_%d.pdf'%host.yielded)
            def close(self): host.closed_streams += 1
        return Stream()


class Tests(unittest.TestCase):
    def setUp(self):
        self.host = Host()
        self.tick = mock.Mock()
        for name in ('dup','fstat','readlink','stat','close','scandir'):
            patch = mock.patch.object(m.os,name,side_effect=getattr(self.host,name))
            patch.start()
            self.addCleanup(patch.stop)
        patch = mock.patch.object(m.sys,'platform','linux')
        patch.start()
        self.addCleanup(patch.stop)
        self.addCleanup(lambda:self.assertEqual(self.host.handles,{7}))

    def iterator(self,**kwargs):
        args = dict(directory_fd=7,expected_identity=self.host.snapshot,
            verified_installation_root='/cad/mentor/tessent2021_2',logical_relative='doc/pdf',
            resolved_relative='doc/pdf',tick=self.tick)
        args.update(kwargs)
        return m.BoundedDocumentNames(**args)

    def test_simulated36_integer_fd_fails_but_owned_string_alias_streams200_never201(self):
        with self.assertRaises(TypeError):
            m.os.scandir(7)
        with mock.patch.object(m.os,'listdir',side_effect=AssertionError('NO MATERIALIZATION')), \
                mock.patch.object(m.os,'chdir',side_effect=AssertionError('NO CHDIR')), \
                mock.patch.object(m.os,'open',side_effect=AssertionError('NO OTHER OPENS')), \
                mock.patch.object(m.os,'read',side_effect=AssertionError('NO BODY READS')):
            with self.iterator() as names:
                output = list(names)
        self.assertEqual(len(output),200)
        self.assertEqual(self.host.yielded,200)
        self.assertEqual(self.host.scandir_arguments,[7,'/proc/self/fd/31'])
        self.assertTrue(names.truncated)
        self.assertFalse(names.exhausted)
        self.assertTrue(names.post_identity_verified)
        self.assertEqual(self.host.closed_fds,[31])
        self.assertEqual(self.host.closed_streams,1)

    def test_smaller_remaining_budget_and_exact200_conservatively_truncated(self):
        with self.iterator(limit=3) as names:
            self.assertEqual(len(list(names)),3)
        self.assertEqual(self.host.yielded,3)
        self.assertTrue(names.truncated)

    def test_exhaustion_and_early_stop_both_check_identity_and_close_owned_dup_only(self):
        self.host.count = 2
        with self.iterator() as names:
            self.assertEqual(list(names),['manual_1.pdf','manual_2.pdf'])
        self.assertTrue(names.exhausted)
        self.assertFalse(names.truncated)
        self.assertTrue(names.post_identity_verified)
        self.host.yielded = 0
        with self.iterator() as early:
            self.assertEqual(next(early),'manual_1.pdf')
        self.assertFalse(early.exhausted)
        self.assertFalse(early.truncated)
        self.assertTrue(early.post_identity_verified)

    def test_source_fd_closed_after_dup_does_not_switch_alias_to_reused_source(self):
        with self.iterator(limit=1) as names:
            self.host.handles.remove(7)
            self.assertEqual(next(names),'manual_1.pdf')
            self.host.handles.add(7)
        self.assertTrue(names.post_identity_verified)

    def test_non_directory_stale_snapshot_or_alias_escape_never_scans(self):
        for mutate in (lambda:self.host.info.update(st_mode=stat.S_IFREG|0o644),
                       lambda:self.host.info.update(st_ino=999),
                       lambda:setattr(self.host,'target','/cad/mentor/tessent2021_2/bin'),
                       lambda:setattr(self.host,'target','/cad/mentor/tessent2021_2/doc/pdf (deleted)')):
            self.host.info = dict(self.host.snapshot)
            self.host.target = '/cad/mentor/tessent2021_2/doc/pdf'
            mutate()
            with self.assertRaises(ValueError):
                with self.iterator():
                    pass
        self.assertEqual(self.host.scandir_arguments,[])

    def test_alias_stat_mismatch_and_mutation_during_next_fail_closed(self):
        self.host.alias_info = dict(self.host.snapshot,st_ino=999)
        with self.assertRaisesRegex(ValueError,'ALIAS_IDENTITY_CHANGED'):
            with self.iterator():
                pass
        self.host.alias_info = None
        def mutate(): self.host.info['st_mtime_ns'] += 1
        self.host.on_next = mutate
        with self.assertRaisesRegex(ValueError,'PINNED_DOCUMENT_DIRECTORY_CHANGED'):
            with self.iterator() as names:
                next(names)
        self.assertEqual(self.host.yielded,1)

    def test_post_mutation_or_callback_exception_retains_cleanup(self):
        with self.assertRaisesRegex(ValueError,'PINNED_DOCUMENT_DIRECTORY_CHANGED'):
            with self.iterator() as names:
                next(names)
                self.host.info['st_ctime_ns'] += 1
        self.host.info = dict(self.host.snapshot)
        with self.assertRaisesRegex(RuntimeError,'CALLER_STOP'):
            with self.iterator():
                raise RuntimeError('CALLER_STOP')
        self.assertEqual(self.host.closed_streams,2)

    def test_scope_depth_sensitive_name_and_budget_constructor_rejections(self):
        for kwargs in (dict(logical_relative='bin'),dict(resolved_relative='license'),
            dict(resolved_relative='doc/a/b/c'),dict(logical_relative='doc/../bin'),
            dict(resolved_relative='docs/secret'),dict(verified_installation_root='/home/user/install'),
            dict(limit=0),dict(limit=201),dict(directory_fd=True)):
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):
                self.iterator(**kwargs)
        self.assertEqual(self.host.scandir_arguments,[])

    def test_entry_name_is_one_component_and_iterator_cannot_reenter(self):
        self.host.name = '../escape'
        obj = self.iterator()
        with self.assertRaisesRegex(ValueError,'SAFE_SINGLE_DOCUMENT_ENTRY_NAME'):
            with obj as names:
                next(names)
        with self.assertRaisesRegex(ValueError,'ONE_DOCUMENT_DIRECTORY_ITERATION'):
            with obj:
                pass

    def test_source_ast36_inert_import_and_e131_unchanged(self):
        raw = Path(m.__file__).read_bytes()
        ast.parse(raw.decode('utf-8'),feature_version=(3,6))
        ast.parse(Path(__file__).read_text(),feature_version=(3,6))
        with mock.patch.object(m.os,'open',side_effect=AssertionError('INERT IMPORT')):
            exec(compile(raw,'<inert-e132-helper>','exec'),{'__name__':'inert_e132'})
        import hashlib
        repo = Path(m.__file__).resolve().parents[2]
        self.assertEqual(hashlib.sha256((repo/'scripts/probe_tessent_docs_e131.py').read_bytes()).hexdigest(),
            'bcbc66b54c171ca1cb3b955b189aa85f91c1e77c4b44e61a5539d976d66a168e')


if __name__ == '__main__':
    unittest.main()
