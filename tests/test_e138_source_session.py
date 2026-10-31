"""Synthetic modules prove all-byte verification and registry rollback."""
import ast
import base64
import hashlib
from pathlib import Path
import sys
import types
import unittest
from unittest import mock
from scripts import e138_source_session as m


class Tests(unittest.TestCase):
    def configure(self,bodies):
        rows=[dict(name=name,sha256=hashlib.sha256(raw).hexdigest(),body_base64=base64.b64encode(raw).decode()) for name,raw in bodies]
        for patch in (mock.patch.object(m,'FROZEN_SOURCE_SHA256',{row['name']:row['sha256'] for row in rows}),
                mock.patch.object(m,'FROZEN_SOURCE_ORDER',tuple(row['name'] for row in rows))):
            patch.start();self.addCleanup(patch.stop)
        return rows

    def snapshot(self):return {k:v for k,v in sys.modules.items() if k=='src' or k.startswith('src.')}

    def test_default_denial_before_compile_or_registry_changes(self):
        before=self.snapshot()
        with mock.patch('builtins.compile') as compile:
            with self.assertRaisesRegex(ValueError,'E138_SOURCE_FREEZE_REQUIRED'):
                with m.source_session([]):self.fail('must not enter')
        compile.assert_not_called();self.assertEqual(before,self.snapshot())

    def test_all_hashes_verified_before_any_compile(self):
        rows=self.configure([('a',b'VALUE=1'),('b',b'VALUE=2')]);rows[1]['body_base64']='eA=='
        before=self.snapshot()
        with mock.patch('builtins.compile') as compile:
            with self.assertRaisesRegex(ValueError,'E138_SOURCE_BODY_PIN_OR_BOUND'):
                with m.source_session(rows):self.fail('must not enter')
        compile.assert_not_called();self.assertEqual(before,self.snapshot())

    def test_complete_clear_no_cached_child_resolution_and_restore(self):
        rows=self.configure([('a',b'VALUE=123'),('b',b'from . import a\nVALUE=a.VALUE')])
        poison=types.ModuleType('src.data.unreviewed_cached');poison.VALUE='PRIVATE'
        with mock.patch.dict(sys.modules,{'src.data.unreviewed_cached':poison}):
            before=self.snapshot()
            with m.source_session(rows) as loaded:
                self.assertNotIn('src.data.unreviewed_cached',sys.modules)
                self.assertEqual(loaded['b'].VALUE,123)
                self.assertEqual(loaded['a'].__source_sha256__,rows[0]['sha256'])
            self.assertEqual(before,self.snapshot())

    def test_cached_missing_dependency_cannot_rescue_bad_closure(self):
        rows=self.configure([('x',b'from . import missing')])
        with mock.patch.dict(sys.modules,{'src.data.missing':types.ModuleType('src.data.missing')}):
            before=self.snapshot()
            with self.assertRaises(ImportError):
                with m.source_session(rows):self.fail('must not enter')
            self.assertEqual(before,self.snapshot())
        self.assertFalse(m._ACTIVE)

    def test_exec_body_exception_and_body_exception_both_restore_registry(self):
        before=self.snapshot();rows=self.configure([('a',b'raise RuntimeError("synthetic")')])
        with self.assertRaises(RuntimeError):
            with m.source_session(rows):pass
        self.assertEqual(before,self.snapshot());self.assertFalse(m._ACTIVE)
        rows=self.configure([('a',b'VALUE=1')])
        with self.assertRaises(RuntimeError):
            with m.source_session(rows):raise RuntimeError('caller body')
        self.assertEqual(before,self.snapshot());self.assertFalse(m._ACTIVE)

    def test_exact_order_extra_duplicate_and_reentrancy(self):
        rows=self.configure([('a',b'VALUE=1'),('b',b'VALUE=2')])
        for bad in (list(reversed(rows)),rows+[rows[0]],[rows[0],rows[0]]):
            with self.assertRaises(ValueError):
                with m.source_session(bad):pass
        with m.source_session(rows):
            with self.assertRaisesRegex(ValueError,'E138_SOURCE_SESSION_NONREENTRANT'):
                with m.source_session(rows):pass

    def test_python36_syntax_and_no_transport(self):
        ast.parse(Path(m.__file__).read_text(encoding='utf-8'),feature_version=(3,6))
        rows=self.configure([('a',b'VALUE=1')])
        with mock.patch('subprocess.Popen') as spawn,mock.patch('builtins.open') as opened:
            with m.source_session(rows):pass
        spawn.assert_not_called();opened.assert_not_called()

    def native_bodies(self,roots):
        root=Path(__file__).resolve().parents[1]/'src/data'
        bodies=[];seen=set();active=set()
        def visit(name):
            if name in seen:return
            self.assertNotIn(name,active);active.add(name)
            raw=(root/(name+'.py')).read_bytes();deps=set()
            for node in ast.walk(ast.parse(raw.decode('utf-8'))):
                if isinstance(node,ast.ImportFrom):
                    if node.level==1:
                        deps.update([node.module.split('.')[0]] if node.module else [v.name for v in node.names])
                    elif node.module=='src.data':deps.update(v.name for v in node.names)
                    elif node.module and node.module.startswith('src.data.'):deps.add(node.module.split('.')[2])
            for dep in sorted(deps):visit(dep)
            active.remove(name);seen.add(name);bodies.append((name,raw))
        for name in roots:visit(name)
        return bodies

    def test_actual_native_component_closure_loads_in_one_clean_session(self):
        bodies=self.native_bodies(('physical_replay_capture_e138','physical_runtime_bootstrap_e138',
            'physical_engine_evidence_e138','physical_e138_root_receipt','physical_e138_role3_export','physical_e138_role2_join'))
        rows=self.configure(bodies);before=self.snapshot()
        with mock.patch('builtins.open') as opened,mock.patch('subprocess.Popen') as spawn:
            with m.source_session(rows) as loaded:
                self.assertEqual(set(loaded),{name for name,raw in bodies})
                self.assertIsNone(loaded['physical_replay_capture_e138'].AUTH_SHA)
                self.assertIsNone(loaded['physical_e138_runtime_primitives'].FACTORY_FREEZE)
                self.assertEqual(loaded['physical_e138_root_receipt'].ROOT,loaded['physical_e138_contract'].ROOT)
        opened.assert_not_called();spawn.assert_not_called();self.assertEqual(before,self.snapshot())

    def test_full_synthetic_assembler_executes_inside_fresh_source_session(self):
        # Fixture preparation reads existing local code/E128 Tcl only. Runtime
        # physical backends remain virtual/mocked exactly as the assembler suite.
        from tests import test_physical_e138_batch_assembler as fixture
        from tests import test_physical_replay_capture_e138 as capture_fixture
        from tests import test_physical_replay_source_inventory_e135 as inventory_fixture
        roots=set(fixture.m.COMPONENTS.values())|set(fixture.m.ORIGINS.values())|set(fixture.m.INPUT_SOURCES.values())|set(fixture.m.contract.REQUIRED_SOURCES)|{'physical_e138_batch_assembler'}
        rows=self.configure(self.native_bodies(roots))
        before=self.snapshot()
        with m.source_session(rows) as loaded:
            with mock.patch.object(fixture,'m',loaded['physical_e138_batch_assembler']), \
                    mock.patch.object(capture_fixture,'m',loaded['physical_replay_capture_e138']), \
                    mock.patch.object(inventory_fixture,'inv',loaded['physical_replay_source_inventory_e135']), \
                    mock.patch.object(inventory_fixture,'core',loaded['physical_replay_source_reader_e135']), \
                    mock.patch('subprocess.Popen') as spawn:
                case=fixture.NativeFlowTests()
                try:
                    case.setUp()
                    # Use the real loader's complete verified roster and actual
                    # insertion order, not the standalone fixture's subset.
                    case.sources={row['name']:base64.b64decode(row['body_base64'],validate=True) for row in rows}
                    manifest=case.frozen['source_sha256'];manifest.clear()
                    manifest.update({name:hashlib.sha256(raw).hexdigest() for name,raw in case.sources.items()})
                    case.frozen['source_order']=tuple(loaded)
                    case.patch(loaded['physical_e138_contract'],'LOADED_SOURCE_ORDER',tuple(loaded))
                    result=case.run_flow()
                    self.assertIsNotNone(result['owned_root'],result)
                    self.assertEqual(result['worker_response']['launch_debit'],1)
                    self.assertFalse(result['execution_ready'])
                finally:case.doCleanups()
                spawn.assert_not_called()
        self.assertEqual(before,self.snapshot())
