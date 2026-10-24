"""E98 queue lease, review chain and isolated root adapter; mocks only."""
import ast
import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock
from contextlib import ExitStack

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / 'scripts/run_acceptance_job_e98.py'
SPEC = importlib.util.spec_from_file_location('entry_e98_test', str(PATH))
m = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(m)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')


def bundle_chain(review_age=20):
    permit = dict(schema='e98-queue-permit-v1', job_id=123,
        authorization_sha256=m.AUTH_SHA256, code_manifest_sha256='a' * 64,
        recipe_sha256='b' * 64, registration_review_sha256='', pre_resume_review_sha256='',
        resume_intent_sha256='', issued_at_epoch=10000, queue_start_lease_seconds=86400)
    receipts = []
    for stage in ('registration', 'pre_resume'):
        receipt = dict(schema='e98-independent-review-v1', stage=stage, job_id=123,
            passed=True, independent=True, reviewer='external-reviewer',
            reviewed_at_epoch=10000-review_age, authorization_sha256=m.AUTH_SHA256,
            code_manifest_sha256='a' * 64, recipe_sha256='b' * 64,
            registration_evidence_sha256='c' * 64, observation_sha256='d' * 64)
        raw = canonical(receipt); receipts.append(raw)
        permit[stage + '_review_sha256'] = m.sha(raw)
    intent = {key: permit[key] for key in ('job_id', 'issued_at_epoch', 'authorization_sha256',
        'code_manifest_sha256', 'recipe_sha256', 'registration_review_sha256',
        'pre_resume_review_sha256', 'queue_start_lease_seconds')}
    intent.update(schema='e98-resume-intent-v1', observation_sha256='d' * 64,
        registration_evidence_sha256='c' * 64, resume_attempt_consumed=True, automatic_retries=0)
    raw_intent = canonical(intent); permit['resume_intent_sha256'] = m.sha(raw_intent)
    return permit, receipts[0], receipts[1], raw_intent


class E98Tests(unittest.TestCase):
    def validation(self, permit, now=20000, changes=None):
        env = dict(LSB_JOBID='123', LSB_JOBINDEX='0', LSB_DJOB_NUMPROC='1', LSB_MCPU_HOSTS='bupt-vncs2 1')
        if changes:
            env.update(changes)
            env = {k: v for k, v in env.items() if v is not None}
        with mock.patch.object(m.time, 'time', return_value=now), \
                mock.patch.object(m.sys, 'platform', 'linux'), \
                mock.patch.object(m.platform, 'node', return_value='bupt-vncs2'), \
                mock.patch.dict(m.os.environ, env, clear=True):
            m.validate_permit(permit)

    def test_hours_queued_are_accepted(self):
        permit, *chain = bundle_chain()
        self.validation(permit, now=50000)
        m.validate_review_chain(permit, *chain)

    def test_lease_boundary_expired_and_future(self):
        permit = bundle_chain()[0]
        self.validation(permit, now=96400)
        for now in (96401, 9999):
            with self.assertRaisesRegex(m.EntryError, 'LEASE'):
                self.validation(permit, now=now)

    def test_review_old_at_resume_rejected_despite_current_lease(self):
        permit, *chain = bundle_chain(review_age=301)
        self.validation(permit)
        with self.assertRaisesRegex(m.EntryError, 'FRESH_REVIEW_AT_RESUME'):
            m.validate_review_chain(permit, *chain)

    def test_review_boundary_is_300_seconds(self):
        permit, *chain = bundle_chain(review_age=300)
        m.validate_review_chain(permit, *chain)

    def test_permit_exact_keys_types_job_and_pins(self):
        for key, value in (('job_id', True), ('authorization_sha256', '0' * 64),
                           ('schema', 'e97-resume-permit-v1'), ('recipe_sha256', 'BAD'),
                           ('queue_start_lease_seconds', True), ('queue_start_lease_seconds', 86401)):
            permit = bundle_chain()[0]; permit[key] = value
            with self.assertRaises(m.EntryError):
                self.validation(permit)

    def test_array_multiple_or_missing_worker_evidence_rejected(self):
        for changes in ({'LSB_JOBINDEX': '1'}, {'LSB_DJOB_NUMPROC': '2'},
                        {'LSB_DJOB_NUMPROC': None}, {'LSB_MCPU_HOSTS': None},
                        {'LSB_MCPU_HOSTS': 'bupt-vncs2 2'}, {'LSB_JOBID': '124'},
                        {'LSB_MCPU_HOSTS': 'other 1'}):
            with self.assertRaises(m.EntryError):
                self.validation(bundle_chain()[0], changes=changes)

    def test_review_and_intent_bytes_actually_hashed(self):
        permit, reg, pre, intent = bundle_chain()
        for chain in ((reg+b' ', pre, intent), (reg, pre+b' ', intent), (reg, pre, intent+b' ')):
            with self.assertRaisesRegex(m.EntryError, 'REVIEW_CHAIN_PIN'):
                m.validate_review_chain(permit, *chain)

    def test_review_binding_and_independence_not_boolean_only(self):
        for key, item in (('job_id', 124), ('job_id', True), ('independent', False),
                          ('recipe_sha256', '0' * 64), ('observation_sha256', '0' * 64)):
            permit, reg, pre, intent = bundle_chain()
            changed = json.loads(pre.decode('ascii')); changed[key] = item
            pre = canonical(changed); permit['pre_resume_review_sha256'] = m.sha(pre)
            body = json.loads(intent.decode('ascii')); body['pre_resume_review_sha256'] = m.sha(pre)
            intent = canonical(body); permit['resume_intent_sha256'] = m.sha(intent)
            with self.assertRaises(m.EntryError):
                m.validate_review_chain(permit, reg, pre, intent)

    def test_intent_retry_and_lease_binding(self):
        for key, item in (('automatic_retries', 1), ('resume_attempt_consumed', False),
                          ('queue_start_lease_seconds', 86401), ('issued_at_epoch', 10001)):
            permit, reg, pre, raw = bundle_chain(); intent = json.loads(raw.decode('ascii'))
            intent[key] = item; raw = canonical(intent); permit['resume_intent_sha256'] = m.sha(raw)
            with self.assertRaises(m.EntryError):
                m.validate_review_chain(permit, reg, pre, raw)

    def test_no_secret_in_fixed_failure_envelope(self):
        secret = '/private/license/SECRET=abc'
        record = m.safe_failure('KERNEL_PREFLIGHT', RuntimeError(secret))
        self.assertNotIn(secret, canonical(record).decode('ascii'))
        self.assertEqual(record['code'], 'STAGE_FAILED')
        self.assertEqual(m.safe_failure('KERNEL_PREFLIGHT', RuntimeError('APPROVED_HARD_CAP'))['code'],
                         'APPROVED_HARD_CAP')

    def recipe_fixture(self):
        recipe = types.ModuleType('isolated_recipe')
        exec(compile((ROOT / 'src/data/prospective_tessent_acceptance_v1.py').read_bytes(), '<recipe>', 'exec'),
             recipe.__dict__)
        materializer = types.SimpleNamespace(compiler=recipe,
            RECIPE_SHA256='67c927c315354adf9ad09466fa679e46c3417d64065d0cb44819af8a3e65271e')
        e85 = (ROOT / m.E85).read_bytes(); e93 = (ROOT / m.E93).read_bytes()
        original = recipe.compile_acceptance(e85, e93, recipe.E85_SHA256, recipe.E93_SHA256)
        recipe.ROOT = m.E98_ACCEPTANCE_ROOT
        rebound = recipe.compile_acceptance(e85, e93, recipe.E85_SHA256, recipe.E93_SHA256)
        recipe.ROOT = original['root']
        return recipe, materializer, e85, e93, original, rebound

    def test_e98_adapter_new_sha_and_all_output_paths_no_writes(self):
        recipe, materializer, e85, e93, old, new = self.recipe_fixture()
        with mock.patch.object(m.os, 'open') as opened, mock.patch.object(m.os, 'mkdir') as mkdir:
            plan = m.bind_e98_recipe(recipe, materializer, e85, e93, new['recipe_sha256'])
            opened.assert_not_called(); mkdir.assert_not_called()
        self.assertNotEqual(old['recipe_sha256'], plan['recipe_sha256'])
        self.assertEqual(materializer.RECIPE_SHA256, plan['recipe_sha256'])
        self.assertEqual(materializer.compiler.ROOT, m.E98_ACCEPTANCE_ROOT)
        for item in plan['items']:
            for key in ('future_scratch', 'tcl_path', 'cwd', 'translated_status_path',
                        'translation_manifest_path', 'isolated_tsdb_copy'):
                self.assertTrue(item[key].startswith(m.E98_ACCEPTANCE_ROOT + '/'))
            self.assertNotIn(old['root'].encode('ascii'), item['tcl_bytes'])
            self.assertNotIn(b'multimode_ate_acceptance_e97_', item['tcl_bytes'])
        # Materializer's bundle root and the coordinator journal share this root.
        self.assertTrue((recipe.ROOT + '/coordinator_events.jsonl').startswith(m.E98_ACCEPTANCE_ROOT + '/'))

    def test_adapter_wrong_recipe_pin_rejected_before_initialization(self):
        recipe, materializer, e85, e93, _, _ = self.recipe_fixture()
        with self.assertRaisesRegex(m.EntryError, 'E98_RECIPE_PIN'):
            m.bind_e98_recipe(recipe, materializer, e85, e93, '0' * 64)
        self.assertEqual(materializer.RECIPE_SHA256, '67c927c315354adf9ad09466fa679e46c3417d64065d0cb44819af8a3e65271e')

    def test_real_initializer_and_ledger_fd_use_only_new_acceptance_root(self):
        from src.data import prospective_acceptance_materializer_v1 as materializer
        recipe, _, e85, e93, _, new = self.recipe_fixture()
        instance = types.SimpleNamespace(root_fd=None, scratch_fd=None, failed=False,
            authorization={}, recipe=new, _preflight=lambda: {}, _owned_bundle=lambda: None)
        with mock.patch.object(materializer, 'compiler', recipe), \
                mock.patch.object(materializer, 'RECIPE_SHA256',
                    '67c927c315354adf9ad09466fa679e46c3417d64065d0cb44819af8a3e65271e'), \
                mock.patch.object(materializer, '_directory', return_value=100) as directory, \
                mock.patch.object(materializer, '_mkdir', side_effect=[101, 102]) as mkdir, \
                mock.patch.object(materializer, '_publish'), \
                mock.patch.object(materializer.os, 'close'), \
                mock.patch.object(materializer.os, 'dup', return_value=103) as dup:
            m.bind_e98_recipe(recipe, materializer, e85, e93, new['recipe_sha256'])
            materializer.Materializer.initialize_bundle(instance)
            self.assertEqual(materializer.Materializer.journal_directory_fd(instance), 103)
            directory.assert_called_once_with('/temp/jiangchuanc')
            self.assertEqual(mkdir.call_args_list, [
                mock.call(100, 'multimode_ate_acceptance_e98_20261024_r1'), mock.call(101, 'scratch')])
            dup.assert_called_once_with(101)

    def execute_failure(self, duplicate=False, identity_failure=False):
        permit, *chain = bundle_chain()
        events = []; fake_sys = types.SimpleNamespace(modules={}, meta_path=[])
        preflight = types.SimpleNamespace(collect_preflight=mock.Mock(side_effect=RuntimeError('license=SECRET')))
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(m, 'validate_permit',
                side_effect=m.EntryError('ACTUAL_SINGLE_WORKER_ENV_REQUIRED') if identity_failure else None))
            stack.enter_context(mock.patch.object(m, 'sys', fake_sys))
            stack.enter_context(mock.patch.object(m, '_directory', return_value=10))
            stack.enter_context(mock.patch.object(m, 'verify_bundle', return_value={}))
            stack.enter_context(mock.patch.object(m, '_read', side_effect=chain))
            stack.enter_context(mock.patch.object(m.os, 'O_DIRECTORY', 1, create=True))
            stack.enter_context(mock.patch.object(m.os, 'O_NOFOLLOW', 2, create=True))
            stack.enter_context(mock.patch.object(m.os, 'mkdir'))
            stack.enter_context(mock.patch.object(m.os, 'fsync'))
            stack.enter_context(mock.patch.object(m.os, 'open', return_value=11))
            stack.enter_context(mock.patch.object(m.os, 'close'))
            imported = stack.enter_context(mock.patch.object(m.importlib, 'import_module', return_value=preflight))
            def record(fd, name, body, cap=131072):
                events.append((name, body))
                if duplicate and name == 'e98_worker_start.json':
                    raise FileExistsError()
            stack.enter_context(mock.patch.object(m, '_write_record', side_effect=record))
            with self.assertRaises((RuntimeError, FileExistsError, m.EntryError)):
                m.execute(permit, m.ROOT)
        return events, imported, preflight

    def test_kernel_failure_consumes_start_persists_safe_code_no_coordinator(self):
        events, imported, preflight = self.execute_failure()
        self.assertEqual([name for name, _ in events], ['e98_worker_start.json', 'failure.json'])
        self.assertEqual(events[-1][1]['stage'], 'KERNEL_PREFLIGHT')
        self.assertNotIn('SECRET', canonical(events[-1][1]).decode('ascii'))
        self.assertEqual(imported.call_count, 1)
        preflight.collect_preflight.assert_called_once()

    def test_duplicate_worker_marker_never_preflights_or_retries(self):
        events, imported, preflight = self.execute_failure(duplicate=True)
        self.assertEqual(len(events), 1)
        imported.assert_not_called(); preflight.collect_preflight.assert_not_called()

    def test_runtime_identity_failure_also_consumes_authenticated_start(self):
        events, imported, preflight = self.execute_failure(identity_failure=True)
        self.assertEqual([name for name, _ in events], ['e98_worker_start.json', 'failure.json'])
        self.assertEqual(events[-1][1]['stage'], 'WORKER_IDENTITY')
        self.assertEqual(events[-1][1]['code'], 'ACTUAL_SINGLE_WORKER_ENV_REQUIRED')
        imported.assert_not_called(); preflight.collect_preflight.assert_not_called()

    def pipeline(self, passed):
        permit, *chain = bundle_chain(); events = []
        preflight = types.SimpleNamespace(collect_preflight=mock.Mock(
            side_effect=lambda *args: events.append('kernel') or {'memory_preflight_passed': True}))
        coordinator = types.SimpleNamespace(recipes=object(), AUTH_SCHEMA='auth', SCOPE='scope',
            run_package=mock.Mock(return_value={'status': 'FOUR_CASES_ONLY'}))
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(m, 'validate_permit'))
            stack.enter_context(mock.patch.object(m, 'sys', types.SimpleNamespace(modules={}, meta_path=[])))
            stack.enter_context(mock.patch.object(m, '_directory', return_value=10))
            stack.enter_context(mock.patch.object(m, 'verify_bundle', return_value={m.E85: b'85', m.E93: b'93'}))
            stack.enter_context(mock.patch.object(m, '_read', side_effect=chain))
            stack.enter_context(mock.patch.object(m.os, 'O_DIRECTORY', 1, create=True))
            stack.enter_context(mock.patch.object(m.os, 'O_NOFOLLOW', 2, create=True))
            for name in ('mkdir', 'fsync', 'close'):
                stack.enter_context(mock.patch.object(m.os, name))
            stack.enter_context(mock.patch.object(m.os, 'open', return_value=11))
            stack.enter_context(mock.patch.object(m.time, 'monotonic', side_effect=[100, 200]))
            stack.enter_context(mock.patch.object(m.importlib, 'import_module', side_effect=[
                preflight, coordinator, object(), types.SimpleNamespace(LICENSE_KEYS=())]))
            stack.enter_context(mock.patch.object(m, '_write_record', side_effect=lambda fd, name, body, cap=131072:
                events.append(name)))
            stack.enter_context(mock.patch.object(m, '_gate', side_effect=lambda *args:
                events.append('six_tests') or {'passed': passed}))
            adapter = stack.enter_context(mock.patch.object(m, 'bind_e98_recipe',
                return_value={'recipe_sha256': permit['recipe_sha256']}))
            if passed:
                result = m.execute(permit, m.ROOT)
                self.assertEqual(result['status'], 'FOUR_CASES_ONLY')
                self.assertEqual(coordinator.run_package.call_args[1]['package_deadline'], 2800)
                self.assertEqual(coordinator.run_package.call_count, 1)
                adapter.assert_called_once()
            else:
                with self.assertRaisesRegex(m.EntryError, 'SYNTHETIC_GATE_FAILED'):
                    m.execute(permit, m.ROOT)
                adapter.assert_not_called(); coordinator.run_package.assert_not_called()
        return events

    def test_success_pipeline_keeps_original_2700_deadline_and_one_package(self):
        self.assertEqual(self.pipeline(True), ['e98_worker_start.json', 'kernel', 'six_tests', 'gate.json'])

    def test_failed_linux_gate_retains_record_and_never_binds_or_launches(self):
        self.assertEqual(self.pipeline(False), [
            'e98_worker_start.json', 'kernel', 'six_tests', 'gate.json', 'failure.json'])

    def test_snapshot_members_stay_fixed_and_python36(self):
        self.assertEqual(len(m.FILES), 23)
        self.assertIn('scripts/run_acceptance_job_e98.py', m.FILES)
        self.assertNotIn('scripts/run_acceptance_job_e97.py', m.FILES)
        self.assertIn('tests/test_prospective_acceptance_linux_e97.py', m.FILES)
        kwargs = {'feature_version': (3, 6)} if sys.version_info >= (3, 8) else {}
        ast.parse(PATH.read_text(), **kwargs)


if __name__ == '__main__':
    unittest.main()
