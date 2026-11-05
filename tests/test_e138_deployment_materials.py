"""Temporary synthetic files only. No real cache/network/vendor reads or writes."""
import json
from pathlib import Path
import pickle
import tempfile
import unittest
from unittest import mock

from scripts import e138_deployment_materials as m


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.repo=Path(self.tmp.name)
        (self.repo/'src/data').mkdir(parents=True)

    def module(self,name,raw):
        path=self.repo/'src/data'/(name+'.py');path.write_bytes(raw);return path

    def test_bounded_exact_hash_read(self):
        path=self.module('one',b'PRIVATE_SYNTHETIC_BODY')
        self.assertEqual(m._read(path,64,m.sha(b'PRIVATE_SYNTHETIC_BODY')),b'PRIVATE_SYNTHETIC_BODY')
        with self.assertRaisesRegex(m.MaterialFailure,'PIN_MISMATCH'):m._read(path,64,'0'*64)
        with self.assertRaisesRegex(m.MaterialFailure,'SIZE'):m._read(path,2)

    def test_missing_fixed_file_has_no_private_exception_text(self):
        with self.assertRaises(m.MaterialFailure) as caught:m._read(self.repo/'missing',64)
        self.assertEqual(str(caught.exception),'MISSING_OR_REFUSED_FIXED_FILE')
        self.assertIsNone(caught.exception.__cause__)

    def test_topological_transitive_sources_python36_without_execution(self):
        self.module('root',b'from . import middle\nraise RuntimeError("MUST_NOT_EXECUTE")\n')
        self.module('middle',b'from .leaf import value\n')
        self.module('leaf',b'value=1\n')
        result=m._closure(self.repo,{'root'})
        self.assertEqual(result['source_order'],('leaf','middle','root'))
        self.assertEqual(set(result['sources']),{'leaf','middle','root'})
        for name,raw in result['sources'].items():self.assertEqual(result['source_sha256'][name],m.sha(raw))

    def test_declared_dependency_pin_checked_after_closure(self):
        self.module('root',b'from . import leaf\nSOURCE_PINS={"leaf":"'+b'0'*64+b'"}\n')
        self.module('leaf',b'value=1\n')
        with self.assertRaisesRegex(m.MaterialFailure,'DEPENDENCY_PIN'):m._closure(self.repo,{'root'})

    def test_dynamic_roster_seeds_not_just_imports(self):
        # Synthetic mirrors of the pure roster declarations; no production pins
        # or public prepare() test-mode override is installed.
        self.module('one',b'value=1\n');self.module('dynamic_only',b'value=2\n')
        result=m._closure(self.repo,{'one','dynamic_only'})
        self.assertEqual(set(result['sources']),{'one','dynamic_only'})

    def test_unhandled_project_import_cannot_be_silently_external(self):
        self.module('root',b'from scripts import helper\n')
        with self.assertRaisesRegex(m.MaterialFailure,'UNSUPPORTED_PROJECT_IMPORT'):
            m._closure(self.repo,{'root'})

    def test_declared_missing_target_or_malformed_pin_fails(self):
        self.module('root',b'DEPENDENCY_SHA256={"missing":"'+b'0'*64+b'"}\n')
        with self.assertRaisesRegex(m.MaterialFailure,'DEPENDENCY_TARGET_OR_PIN_INVALID'):
            m._closure(self.repo,{'root'})

    def test_unresolved_native_pin_dictionary_is_not_silently_skipped(self):
        self.module('root',b'SOURCE_PINS={"leaf":unknown.pin}\n')
        with self.assertRaisesRegex(m.MaterialFailure,'UNRESOLVED_NATIVE_PIN_DECLARATION'):
            m._closure(self.repo,{'root'})

    def test_native_module_alias_tuple_and_nested_import_alias_checked(self):
        leaf=b'value=1\n'
        middle=b'from . import leaf as original\n'
        self.module('leaf',leaf);self.module('middle',middle)
        root=('from . import middle as sampler\nSOURCE_PINS=((sampler,"%s"),(sampler.original,"%s"))\n'
              %(m.sha(middle),m.sha(leaf))).encode('ascii')
        self.module('root',root)
        result=m._closure(self.repo,{'root'})
        self.assertEqual(result['dependency_checks'],2)
        self.module('root',root.replace(m.sha(leaf).encode('ascii'),b'0'*64))
        with self.assertRaisesRegex(m.MaterialFailure,'MODULE_ALIAS_PIN_MISMATCH'):
            m._closure(self.repo,{'root'})
        self.module('root',b'from . import leaf\nDEPENDENCY_SHA256={"leaf":"bad"}\n')
        self.module('leaf',b'value=1\n')
        with self.assertRaisesRegex(m.MaterialFailure,'DEPENDENCY_TARGET_OR_PIN_INVALID'):
            m._closure(self.repo,{'root'})

    def test_source_cycle_missing_module_and_python_new_syntax_rejected(self):
        self.module('one',b'from . import two\n');self.module('two',b'from . import one\n')
        with self.assertRaisesRegex(m.MaterialFailure,'CYCLE'):m._closure(self.repo,{'one'})
        with self.assertRaisesRegex(m.MaterialFailure,'MISSING'):m._closure(self.repo,{'absent'})
        self.module('modern',b'match value:\n case 1: pass\n')
        with self.assertRaisesRegex(m.MaterialFailure,'PYTHON36'):m._closure(self.repo,{'modern'})

    def test_source_count_cap(self):
        names=['n%d'%index for index in range(96)]
        self.module('root',('from . import '+','.join(names)+'\n').encode('ascii'))
        for name in names:self.module(name,b'value=1\n')
        with self.assertRaisesRegex(m.MaterialFailure,'MODULE_CAP'):m._closure(self.repo,{'root'})

    def test_source_total_cap(self):
        names=['n%d'%index for index in range(18)]
        self.module('root',('from . import '+','.join(names)+'\n').encode('ascii'))
        for name in names:self.module(name,b'x="'+b'x'*240000+b'"\n')
        with self.assertRaisesRegex(m.MaterialFailure,'TOTAL_CAP'):m._closure(self.repo,{'root'})

    def test_source_per_module_cap(self):
        self.module('large',b'x'*262145)
        with self.assertRaisesRegex(m.MaterialFailure,'SIZE'):m._closure(self.repo,{'large'})

    def test_prepare_missing_cache_no_alternate_search_or_private_serialization(self):
        seen=[]
        def absent(path,cap,pin=None):
            seen.append(path)
            raise m.MaterialFailure('MISSING_OR_REFUSED_FIXED_FILE')
        with mock.patch.object(m,'_read',side_effect=absent),mock.patch('subprocess.Popen') as spawn:
            result=m.prepare()
        spawn.assert_not_called()
        summary=result.public_summary()
        self.assertEqual(summary['status'],'MISSING_OR_INVALID_FIXED_MATERIALS')
        self.assertTrue(any('v6_e137_engine_source_supplement_r1' in str(p) for p in seen))
        self.assertFalse(any('authority' in p.name or 'proposal' in p.name for p in seen))
        self.assertNotIn('PRIVATE_SYNTHETIC_BODY',json.dumps(summary))
        with self.assertRaisesRegex(m.MaterialFailure,'NOT_READY'):result.private_bytes()
        with self.assertRaisesRegex(TypeError,'NOT_SERIALIZABLE'):pickle.dumps(result)
        self.assertIn('PRIVATE_RAM_ONLY',repr(result))


if __name__=='__main__':unittest.main()
