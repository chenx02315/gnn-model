"""Actual function namespaces and pure path checks; no remote/real STIL IO."""
from pathlib import Path
import unittest
from unittest import mock
from src.data import physical_e138_dependency_binding as m

REPO=Path(__file__).resolve().parents[1]
SELECTOR=(REPO/'src/data/physical_engine_selector_e137.py').read_bytes()
STIL=(REPO/'src/data/physical_stil_dependencies_e137.py').read_bytes()


class Tests(unittest.TestCase):
    def setUp(self):
        from tests.test_physical_e138_contract import ContractTests
        self.case=ContractTests();self.addCleanup(self.case.doCleanups);self.case.setUp()
        self.frozen=dict(authorization_sha256=self.case.frozen['authorization_sha256'],
            proposal_sha256=self.case.frozen['proposal_sha256'],adapter_source_sha256='a'*64)
        for patch in (mock.patch.object(m,'FREEZE',self.frozen),mock.patch.object(m,'__source_sha256__','a'*64,create=True)):
            patch.start();self.addCleanup(patch.stop)

    def bind(self):return m.bind(SELECTOR,STIL,self.case.package['authority'],self.case.package['proposal'])

    def test_default_and_drift_reject_before_compile(self):
        with mock.patch('builtins.compile') as compile:
            with mock.patch.object(m,'FREEZE',None):
                with self.assertRaises(ValueError):self.bind()
            with self.assertRaisesRegex(ValueError,'E138_DEPENDENCY_ORIGIN_PIN'):
                m.bind(SELECTOR,STIL+b' ',self.case.package['authority'],self.case.package['proposal'])
        compile.assert_not_called()

    def test_all_functions_share_new_private_namespace_and_old_module_unchanged(self):
        from src.data import physical_engine_selector_e137 as old_selector
        from src.data import physical_stil_dependencies_e137 as old_stil
        before=(old_selector.RUN_ROOT,old_stil.ROOT,old_stil.PATTERN,old_stil.FIXED)
        with mock.patch('builtins.open') as opened,mock.patch('subprocess.Popen') as spawn:
            result=self.bind()
        opened.assert_not_called();spawn.assert_not_called()
        selector,stil=result['selector'],result['stil']
        for name in ('verify','_allowlist','_chunks','_parent_check'):
            self.assertIs(getattr(stil,name).__globals__,vars(stil))
        self.assertIs(selector._argv.__globals__,vars(selector))
        self.assertEqual(selector.RUN_ROOT,m.contract.ROOT)
        self.assertEqual(selector.ROOT,old_selector.ROOT)
        self.assertEqual(selector.CANDIDATES,old_selector.CANDIDATES)
        self.assertEqual(before,(old_selector.RUN_ROOT,old_stil.ROOT,old_stil.PATTERN,old_stil.FIXED))
        self.assertFalse(result['binding']['execution_ready'])

    def test_actual_nested_selector_path_validation_rejects_old_output_root(self):
        selector=self.bind()['selector']
        argv=[selector.LAUNCHER,'-shell','-log',m.contract.ROOT+'/tool.log','-dofile',m.contract.ROOT+'/code/replay.tcl']
        self.assertEqual(selector._argv(argv),'')
        argv[3]='/temp/jiangchuanc/multimode_ate_physical_f_replay_e135_recipe_r2/tool.log'
        with self.assertRaisesRegex(ValueError,'FIXED_REPLAY_PATH_OPTION'):selector._argv(argv)

    def test_actual_stil_allowlist_new_root_and_no_old_path_io(self):
        stil=self.bind()['stil']
        rows=list(stil.FIXED)+[dict(path=stil.ROOT+'/tsdb/file%d'%i,bytes=(3759776 if i==0 else 0),sha256='b'*64) for i in range(19)]
        rows.sort(key=lambda row:row['path'])
        self.assertEqual(len(stil._allowlist(stil.PATTERN,rows)[0]),22)
        with mock.patch.object(stil.anchored,'_directory') as directory:
            with self.assertRaisesRegex(ValueError,'E137_EXACT_CLONED_ALLOWLIST'):
                stil._allowlist('/old/inputs/tester.stil',rows)
        directory.assert_not_called()

    def test_full_verifier_dispatch_with_virtual_files_uses_new_paths(self):
        from tests import test_physical_stil_dependencies_e137 as fixtures
        stil=self.bind()['stil']
        patch=mock.patch.object(fixtures,'m',stil)
        patch.start();self.addCleanup(patch.stop)
        case=fixtures.DependenciesTests();self.addCleanup(case.doCleanups);case.setUp()
        result=case.run_verify()
        self.assertEqual(result['status'],'PASS')
        self.assertEqual(result['files_verified'],22)
        self.assertEqual(result['parsed_files'],[m.contract.ROOT+'/inputs/tester.stil'])
        self.assertFalse(result['execution_ready'])
