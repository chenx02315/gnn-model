"""Native raw join and native fixed exporter over an owned virtual FS."""
import ast
import copy
import importlib
from pathlib import Path
import unittest
from unittest import mock
from src.data import physical_e138_readback_runtime as m

REPO=Path(__file__).resolve().parents[1]


class Tests(unittest.TestCase):
    def patch(self,*args,**kwargs):
        patch=mock.patch.object(*args,**kwargs);value=patch.start();self.addCleanup(patch.stop);return value

    def setUp(self):
        self.sources={name:(REPO/'src/data'/(name+'.py')).read_bytes() for name in m.REQUIRED}
        from tests.test_physical_e138_role2_join import Tests as JoinTests
        self.case=JoinTests();self.addCleanup(self.case.doCleanups);self.case.setUp()
        self.package=copy.deepcopy(self.case.package);self.fs=self.case.case.fs
        self.now,self.utc=1100.,self.case.case.utc
        self.domain=mock.Mock(peak=1234);self.domain.sample.return_value={}
        self.frozen=dict(source_sha256={name:m.sha(raw) for name,raw in self.sources.items()},
            source_order=tuple(sorted(self.sources)),join_freeze=copy.deepcopy(self.case.frozen))
        self.patch(m,'FROZEN',self.frozen);self.patch(m,'_USED',False)
        self.patch(m.contract,'LOADED_SOURCE_ORDER',self.frozen['source_order'])
        for name,pin in self.frozen['source_sha256'].items():
            self.patch(importlib.import_module('src.data.'+name),'__source_sha256__',pin,create=True)
        self.patch(m.time,'monotonic',side_effect=lambda:self.now);self.patch(m.time,'time',side_effect=lambda:self.utc)
        self.patch(m.platform,'node',return_value='bupt-vncs2');self.patch(m.platform,'system',return_value='Linux')
        self.patch(m.os,'getuid',return_value=1047,create=True)
        self.factory=self.patch(m.runtime.legacy.direct,'Descendants',return_value=self.domain)
        self.patch(m.runtime.legacy.process,'_boot_id',return_value=self.case.receipt['boot_id'])
        self.patch(m.os,'open',side_effect=self.fs.open);self.patch(m.os,'read',side_effect=self.fs.read)
        self.patch(m.os,'O_NOFOLLOW',131072,create=True);self.patch(m.os,'O_NONBLOCK',262144,create=True)
        for index,path in enumerate(m.export_origin.OUTPUTS):
            parent=path.rsplit('/',1)[0]
            if parent not in self.fs.info:self.fs.add(parent,directory=True)
            self.fs.add(path,raw=('synthetic artifact %d'%index).encode('ascii'))

    def collect(self,started=1100.):return m.collect(self.package,self.sources,started)

    def test_default_and_source_drift_reject_before_compile_or_callbacks(self):
        with mock.patch.object(m,'FROZEN',None),mock.patch('builtins.compile') as compile:
            with self.assertRaisesRegex(ValueError,'EXTERNAL_FREEZE_REQUIRED'):self.collect()
        compile.assert_not_called();self.factory.assert_not_called()
        sources=dict(self.sources);sources[m.SELF]+=b' '
        with mock.patch('builtins.compile') as compile:
            with self.assertRaisesRegex(ValueError,'SOURCE_BYTES'):m.collect(self.package,sources,1100.)
        compile.assert_not_called();self.assertEqual(self.fs.opened,[])

    def test_native_join_and_export_full_fixed35_without_process_or_writes(self):
        old_freeze=copy.deepcopy(m.join_origin.FREEZE);old_used=m.export_origin._USED
        with mock.patch('subprocess.Popen') as spawn,mock.patch.object(m.os,'mkdir') as mkdir:
            result=self.collect()
        spawn.assert_not_called();mkdir.assert_not_called()
        self.assertEqual([row['path'] for row in result['files']],list(m.export_origin.OUTPUTS))
        self.assertEqual(self.fs.opened,list(m.export_origin.OUTPUTS));self.assertFalse(result['execution_ready'])
        self.assertEqual(m.join_origin.FREEZE,old_freeze);self.assertEqual(m.export_origin._USED,old_used)
        with self.assertRaisesRegex(ValueError,'EXTERNAL_FREEZE_REQUIRED'):self.collect()

    def test_bad_native_raw_join_never_constructs_domain_or_opens_fs(self):
        self.package['role2_stdout']+=b'forged'
        with self.assertRaisesRegex(ValueError,'JOIN_RAW_PIN'):self.collect()
        self.factory.assert_not_called();self.assertEqual(self.fs.opened,[])
        self.assertTrue(m._USED)

    def test_role3_original_start_deadline_includes_prior_work(self):
        self.now=1160.
        with self.assertRaisesRegex(ValueError,'CONNECTION_DEADLINE'):self.collect(started=1100.)
        self.factory.assert_not_called();self.assertEqual(self.fs.opened,[])

    def test_sampler_peak_and_children_not_confused_with_bytes(self):
        self.domain.peak=536870913
        result=self.collect()
        self.assertEqual(result['error_code'],'ROLE3_MEMORY_OR_CHILD_STOP')
        self.assertIsNone(result['partial_result']);self.assertEqual(self.fs.opened,[])

    def test_child_set_is_rejected_and_sampler_exception_does_not_become_zero(self):
        self.domain.sample.return_value={99:object()}
        result=self.collect();self.assertEqual(result['error_code'],'ROLE3_MEMORY_OR_CHILD_STOP')
        self.assertEqual(self.fs.opened,[])

    def test_unknown_sampler_exception_redacted(self):
        self.domain.sample.side_effect=OSError('PRIVATE_SENTINEL')
        result=self.collect()
        self.assertEqual(result['error_code'],'ROLE3_CAPABILITY_OR_IO_FAILED')
        self.assertNotIn(b'PRIVATE_SENTINEL',m.canonical(result));self.assertIsNone(result['partial_result'])

    def test_partial_frame_contains_only_completed_ordered_prefix(self):
        target=m.export_origin.OUTPUTS[1]
        def mutate(path):
            if path==target:self.fs.info[path].st_ctime_ns+=1
        self.fs.read_hook=mutate;result=self.collect()
        self.assertEqual(result['error_code'],'ROLE3_OUTPUT_CHANGED')
        self.assertEqual([row['path'] for row in result['partial_result']['files']],[m.export_origin.OUTPUTS[0]])
        self.assertFalse(result['durable_publication_verified'])

    def test_legitimate_result_over6mib_within_role3_bound(self):
        path=next(p for p in m.export_origin.OUTPUTS if p.endswith('faults.rpt'))
        self.fs.body[path]=b'x'*(6291456+100);self.fs.info[path].st_size=len(self.fs.body[path])
        result=self.collect();raw=m.canonical(result)
        self.assertGreater(len(raw),6291456);self.assertLess(len(raw),m.export_origin.MAX_RESPONSE)
        self.assertEqual(len(result['files']),35)

    def test_final_close_failure_keeps_error_not_success(self):
        original=self.fs.close
        def close(fd):
            root=self.fs.handles[fd][0]==m.contract.ROOT
            original(fd)
            if root:raise OSError('PRIVATE_SENTINEL')
        with mock.patch.object(m.os,'close',side_effect=close):result=self.collect()
        self.assertEqual(result['status'],'STOPPED_FIRST_FAILURE')
        self.assertNotIn(b'PRIVATE_SENTINEL',m.canonical(result))

    def test_failed_error_frame_serialization_is_not_retried_or_leaked(self):
        with mock.patch.object(m,'canonical',side_effect=OSError('PRIVATE_SENTINEL')) as encode:
            result=self.collect()
        self.assertEqual(result['error_code'],'E138_READBACK_ERROR_FRAME_FAILED')
        self.assertIsNone(result['partial_result']);self.assertNotIn('PRIVATE_SENTINEL',str(result))
        self.assertEqual(encode.call_count,2)  # original value then error frame, no third retry

    def test_error_frame_crossing_original_deadline_drops_all_bodies(self):
        self.domain.sample.side_effect=OSError('PRIVATE_SENTINEL');original=m.canonical
        def encode(value):
            raw=original(value)
            if value.get('schema')=='e138-readback-partial-failure-v1':self.now=1160.
            return raw
        with mock.patch.object(m,'canonical',side_effect=encode):result=self.collect()
        self.assertEqual(result['error_code'],'E138_READBACK_CONNECTION_DEADLINE')
        self.assertIsNone(result['partial_result'])

    def test_unknown_exception_argument_equality_is_never_invoked(self):
        compared=mock.Mock()
        class Hostile(object):
            def __eq__(self,other):
                compared();raise OSError('PRIVATE_SENTINEL')
        with mock.patch.object(m,'canonical',side_effect=ValueError(Hostile())):
            result=self.collect()
        compared.assert_not_called()
        self.assertEqual(result['error_code'],'E138_READBACK_ERROR_FRAME_FAILED')
        self.assertIsNone(result['partial_result'])

    def test_python36_syntax(self):
        ast.parse(Path(m.__file__).read_text(encoding='utf-8'),feature_version=(3,6))


if __name__=='__main__':unittest.main()
