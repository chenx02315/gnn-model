"""Real candidate control flow, simulated operations only. E137 stays frozen."""
import ast
import hashlib
from pathlib import Path
import unittest
from unittest import mock
from src.data import physical_e138_batch_candidate as m


class AdmissionTests(unittest.TestCase):
    def test_unreleased_before_io_clock_process_or_private_callbacks(self):
        with mock.patch.object(m.time,'monotonic') as clock, mock.patch.object(m,'_private') as private, \
                mock.patch.object(m.execution.direct,'Descendants') as domain, mock.patch('builtins.open') as opened:
            result=m.execute({'authority':b'old E137 grant'},0.)
        for call in (clock,private,domain,opened):call.assert_not_called()
        self.assertEqual(result['diagnostic']['stage_attempted'],'ADMISSION')
        self.assertEqual(result['diagnostic']['error_code'],'E138_FREEZE_NOT_CONFIGURED')
        self.assertIsNone(result['owned_root'])

    def test_real_synthetic_contract_pass_still_cannot_release_candidate(self):
        from tests.test_physical_e138_contract import ContractTests
        fixture=ContractTests();self.addCleanup(fixture.doCleanups);fixture.setUp()
        with mock.patch.object(m.time,'monotonic') as clock, mock.patch.object(m,'_execute') as work:
            result=m.execute(fixture.package,0.)
        clock.assert_not_called();work.assert_not_called()
        self.assertEqual(result['diagnostic']['error_code'],'E138_REMOTE_PACKAGE_UNRELEASED')

    def test_frozen_e137_source_and_python36_candidate_syntax(self):
        old=Path(m.__file__).with_name('physical_e137_batch_execution.py').read_bytes()
        self.assertEqual(hashlib.sha256(old).hexdigest(),m.BASE_E137_SOURCE_SHA256)
        ast.parse(Path(m.__file__).read_text(encoding='utf-8'),feature_version=(3,6))


class FlowTests(unittest.TestCase):
    def setUp(self):
        from tests import test_physical_e137_batch_execution as fixtures
        self.fixture_module=fixtures
        patch=mock.patch.object(fixtures,'m',m)
        patch.start();self.addCleanup(patch.stop)
        self.case=fixtures.FlowTests()
        self.addCleanup(self.case.doCleanups);self.case.setUp()

    def fail(self,*args,**kwargs):
        raise ValueError('SENTINEL_ENV_SCRIPT_AND_PRIVATE_PATH')

    def run_failure(self,stage,debit=0,constructed=False):
        result=m.execute(self.case.package,2000.)
        self.assertEqual(result['schema'],'e138-batch-candidate-failure-v1')
        diagnostic=result['diagnostic']
        self.assertEqual(diagnostic['stage_attempted'],stage)
        self.assertEqual(diagnostic['launch_debit'],debit)
        self.assertEqual(diagnostic['instance_sha256'] is not None,constructed)
        self.assertIsNone(result['owned_root']);self.assertFalse(diagnostic['cleanup_verified'])
        self.assertNotIn(b'SENTINEL',m.canonical(result))
        return result

    def test_admission_failure_is_now_observable(self):
        m.admission.side_effect=self.fail
        self.run_failure('ADMISSION');self.case.services._observer.assert_not_called()

    def test_host_clock_failure_is_now_observable(self):
        m.platform.node.return_value='wrong-host'
        result=self.run_failure('HOST_CLOCK')
        self.assertEqual(result['diagnostic']['error_code'],'BATCH_FIXED_HOST_PLATFORM')

    def test_bootstrap_failure_is_now_observable(self):
        self.case.boot.bootstrap.side_effect=self.fail
        self.run_failure('BOOTSTRAP')

    def test_launch_spec_failure_is_now_observable(self):
        with mock.patch.object(m,'_launch',side_effect=self.fail):self.run_failure('LAUNCH_SPEC')

    def test_engine_collection_failure_is_now_observable(self):
        self.case.sampler.collect.side_effect=self.fail
        self.run_failure('ENGINE_COLLECTION')

    def test_instance_build_failure_is_now_observable(self):
        original=m.canonical
        def reject_spec(value):
            if type(value) is dict and 'launch' in value:self.fail()
            return original(value)
        with mock.patch.object(m,'canonical',side_effect=reject_spec):self.run_failure('INSTANCE_BUILD')

    def test_root_services_failure_does_not_lose_constructed_instance(self):
        self.case.root.tracked_services.side_effect=self.fail
        self.run_failure('ROOT_SERVICES',constructed=True)

    def test_initial_intent_failure_does_not_claim_durability(self):
        self.case.services._storage.return_value[0].side_effect=self.fail
        self.assertFalse(self.run_failure('INITIAL_INTENT',constructed=True)['diagnostic']['evidence_durability_verified'])

    def test_root_create_failure_has_no_owned_receipt(self):
        self.case.files.directory.side_effect=self.fail
        self.run_failure('ROOT_CREATE',constructed=True)

    def test_source_copy_failure(self):
        m.execution._source_recheck.side_effect=self.fail
        self.run_failure('SOURCE_COPY',constructed=True)

    def test_recipe_write_failure(self):
        m.execution.io._publish.side_effect=self.fail
        self.run_failure('RECIPE_WRITE',constructed=True)

    def test_dependency_failure(self):
        m._verify_dependencies.side_effect=self.fail
        self.run_failure('DEPENDENCIES',constructed=True)

    def test_selfcheck_failure(self):
        self.case.services.run_selftests.side_effect=self.fail
        self.run_failure('SELFCHECKS',constructed=True)

    def test_prelaunch_failure(self):
        m.execution._closure_recheck.side_effect=self.fail
        self.run_failure('PRELAUNCH_RECHECK',constructed=True)

    def test_launch_intent_write_failure_preserves_consumed_debit(self):
        def publish(name,*args,**kwargs):
            if name=='launch_intent.json':self.fail()
        self.case.files.publish.side_effect=publish
        self.run_failure('LAUNCH_DEBIT',debit=1,constructed=True)
        self.case.services._observer.assert_not_called()

    def test_deadline_before_launch_debit_does_not_consume_it(self):
        original=m.diagnostics.DiagnosticState.checkpoint
        def checkpoint(state,stage):
            original(state,stage)
            if stage=='LAUNCH_DEBIT':m.time.monotonic.return_value=4400.
        with mock.patch.object(m.diagnostics.DiagnosticState,'checkpoint',checkpoint):
            self.run_failure('LAUNCH_DEBIT',debit=0,constructed=True)
        self.case.services._observer.assert_not_called()

    def test_observer_failure_preserves_consumed_debit_no_retry(self):
        self.case.services._observer.side_effect=self.fail
        self.run_failure('TOOL_OBSERVATION',debit=1,constructed=True)
        result=m.execute(self.case.package,2000.)
        self.assertEqual(result['diagnostic']['stage_attempted'],'ADMISSION')
        self.assertEqual(self.case.services._observer.call_count,1)

    def test_raw_write_failure_and_receipt_failure_do_not_invent_cleanup(self):
        def publish(name,*args,**kwargs):
            if name=='observation.json':self.fail()
        self.case.files.publish.side_effect=publish
        self.run_failure('RAW_PUBLICATION',debit=1,constructed=True)
        self.case.root_session.emit.assert_not_called()

    def test_final_receipt_failure(self):
        self.case.root_session.emit.side_effect=self.fail
        self.run_failure('ROOT_RECEIPT',debit=1,constructed=True)

    def test_successful_synthetic_flow_keeps_one_observer_and_no_repeat(self):
        result=m.execute(self.case.package,2000.)
        self.assertIsNotNone(result['owned_root'])
        self.assertEqual(result['worker_response']['launch_debit'],1)
        self.assertEqual(self.case.services._observer.call_count,1)
        self.assertEqual(self.case.boot.bootstrap.call_count,1)
        self.assertEqual(self.case.services.run_selftests.call_count,1)
        second=m.execute(self.case.package,2000.)
        self.assertEqual(second['diagnostic']['stage_attempted'],'ADMISSION')
        self.assertEqual(self.case.services._observer.call_count,1)
        # The rejection is a separate response, not a replacement of the first.
        self.assertEqual(result['worker_response']['launch_debit'],1)
