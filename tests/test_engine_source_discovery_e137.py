import stat
import unittest
from unittest import mock
from src.data import engine_source_discovery_e137 as m
from tests.test_hf_credit_artifact_reader_e134 import Files


class Tests(unittest.TestCase):
    def setUp(self):
        self.bodies = [b'#!/bin/ksh\nsynthetic helper '+bytes([65+i]) for i in range(2)]
        self.fs = Files([dict(path=p) for p in m.PATHS],self.bodies)
        for path in m.PATHS:
            self.fs.info[path].st_uid = 0
        for patch in (mock.patch.object(m.anchored,'_directory',side_effect=self.fs.directory),
            mock.patch.object(m.os,'stat',side_effect=self.fs.stat),mock.patch.object(m.os,'fstat',side_effect=self.fs.fstat),
            mock.patch.object(m.os,'read',side_effect=self.fs.read),mock.patch.object(m.os,'open',side_effect=self.fs.open),
            mock.patch.object(m.os,'close',side_effect=self.fs.close),mock.patch.object(m.os,'O_NOFOLLOW',131072,create=True),
            mock.patch.object(m.os,'O_NONBLOCK',262144,create=True)):
            patch.start();self.addCleanup(patch.stop)
        self.addCleanup(lambda:self.assertEqual(self.fs.handles,{}))

    def test_two_full_hash_bodies(self):
        rows = [m.read_file(p,mock.Mock(),[0]) for p in m.PATHS]
        raw = m.canonical(dict(schema=m.SCHEMA,files=rows,simulation_budget_changed=False))
        self.assertEqual(m.validate(raw)[1],self.bodies)
        rows[1]['sha256'] = '0'*64
        with self.assertRaisesRegex(ValueError,'FULL_HELPER_SHA'):
            m.validate(m.canonical(dict(schema=m.SCHEMA,files=rows,simulation_budget_changed=False)))

    def test_path_special_uid_links_size_rejected_before_open(self):
        with self.assertRaisesRegex(ValueError,'FIXED_HELPER_ONLY'):
            m.read_file('/other',mock.Mock(),[0])
        info = self.fs.info[m.PATHS[0]]
        for key,bad in [('st_mode',stat.S_IFLNK),('st_mode',stat.S_IFIFO),('st_uid',1047),('st_nlink',2),('st_size',2097153)]:
            old = getattr(info,key);setattr(info,key,bad)
            with self.assertRaises(ValueError):m.read_file(m.PATHS[0],mock.Mock(),[0])
            setattr(info,key,old)
        self.assertEqual(self.fs.opened,[])

    def test_short_mutation_parent_and_guard(self):
        p = m.PATHS[0];self.fs.body[p] = b''
        with self.assertRaisesRegex(ValueError,'SHORT_HELPER'):m.read_file(p,mock.Mock(),[0])
        self.fs.body[p] = self.bodies[0]
        self.fs.read_hook = lambda q:setattr(self.fs.info[q],'st_ctime_ns',101)
        with self.assertRaisesRegex(ValueError,'HELPER_CHANGED'):m.read_file(p,mock.Mock(),[0])
        self.fs.read_hook = None
        with self.assertRaisesRegex(ValueError,'STOP'):m.read_file(p,mock.Mock(side_effect=ValueError('STOP')),[0])

    def test_fresh_parent_replacement(self):
        original = self.fs.directory;calls = [0]
        def directory(path):
            calls[0] += 1
            if calls[0] == 2:self.fs.info[path].st_ino += 1
            return original(path)
        with mock.patch.object(m.anchored,'_directory',side_effect=directory):
            with self.assertRaisesRegex(ValueError,'PARENT_REPLACED'):m.read_file(m.PATHS[0],mock.Mock(),[0])
