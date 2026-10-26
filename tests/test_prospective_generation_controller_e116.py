"""Full 78-task composition with mocks only; no real process or A input IO."""
import ast
import copy
import json
from pathlib import Path
import unittest
from unittest import mock

from src.data import prospective_generation_controller_e116 as m


class FakeMaker(object):
    def __init__(self, raw85, raw88, raw93, common, incremental, authorize):
        self.authorize = authorize
        self.common = {row['circuit']: row['files'] for row in json.loads(raw88.decode('ascii'))['roots']}
        self.e85 = json.loads(raw85.decode('ascii'))
        self.sources = m.material.recipe.freeze_sources(common, incremental)
        self.published, self.actions, self.directories = {}, [], set()
        self.failure_task = None
        self.fail_initialize = False
        self.closed = False

    def initialize_bundle(self):
        self.authorize({})
        self.actions.append('initialize')
        if self.fail_initialize:
            raise ValueError('MOCK_INITIALIZATION_FAILURE')

    def _mkdir(self, path):
        if path in self.directories:
            raise FileExistsError()
        self.directories.add(path)

    def _publish(self, path, raw):
        if path in self.published:
            raise FileExistsError()
        self.published[path] = raw
        return dict(path=path, bytes=len(raw), sha256=m.sha(raw))

    def prepare_translation(self, freeze, binding):
        self.authorize({})
        self.actions.append(binding['task_uid'])
        if self.failure_task == binding['task_uid']:
            raise ValueError('MOCK_PREPARATION_FAILURE')
        return dict(prereq_dir=m.ROOT + '/mock-translation')

    def materialize_attempt(self, freeze, binding):
        self.authorize({})
        self.actions.append(binding['task_uid'])
        if self.failure_task == binding['task_uid']:
            raise ValueError('MOCK_PREPARATION_FAILURE')
        run = binding['request']['run_uid']
        return dict(prereq_dir=m.ROOT + '/' + freeze['circuit'] + '/runs/' + run +
                    '/attempts/_prereq/' + binding['task_uid'])

    def close(self):
        self.closed = True


class Domain(object):
    peak = 123
    def sample(self):
        return {}


class Tests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]
        self.authority = (self.root / 'contracts/prospective_acquisition_authorization_e111_20261026.json').read_bytes()
        self.e112 = (self.root.parent / 'runtime_training_staging_20260928/v6_e112_preparation_20261026_r1/stdout.json').read_bytes()
        manifests = self.root / 'data/manifests'
        self.raws = [(manifests / ('ranking_v6_' + key + '_input_observation_20261023_r1.json')).read_bytes()
                     for key in ('e85', 'e88', 'e93')]
        self.common = (self.root / 'src/data/templates/e108_common_base.tcl').read_bytes()
        self.incremental = (self.root / 'src/data/templates/e108_incremental_base.tcl').read_bytes()
        self.initials, self.order, self.observations = [], [], []
        self.observer_failure = None
        self.monitor = mock.Mock()
        self.monitor.sample.return_value = dict(root=m.ROOT, sidecar=m.SIDECAR,
            sidecar_accounted=True, threshold_bytes=m.DIRECTORY_LIMIT, sampled_named_bytes=200)
        self.selftest_cases = [dict(case=name, passed=True, cleaned=True, authenticated_claim=True,
                                   actual_linux_process=True) for name in ('success', 'timeout', 'setsid_child')]
        self.patchers = [
            mock.patch.object(m.material, 'Materializer', FakeMaker),
            mock.patch.object(m.material, '_hash_file', return_value=dict(
                path=m.material.pins.LAUNCHER, bytes=3658, sha256=m.material.pins.LAUNCHER_SHA256)),
            mock.patch.object(m.runtime, 'prepare_runtime', return_value=({'PATH': '/usr/bin:/bin'}, {'schema': 'mock-runtime'})),
            mock.patch.object(m.process.direct, 'Descendants', return_value=Domain()),
            mock.patch.object(m.process, '_check_worker'),
            mock.patch.object(m.process, '_boot_id', return_value=m.BOOT_ID),
            mock.patch.object(m.process, 'observe_tessent', side_effect=self.observe),
            mock.patch.object(m.sys, 'platform', 'linux'),
            mock.patch.object(m.platform, 'node', return_value='bupt-vncs2'),
            mock.patch.object(m.os, 'getuid', return_value=1047, create=True),
            mock.patch.object(m.time, 'monotonic', return_value=m.PACKAGE_START + 100)]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.controller = self.construct()

    def construct(self, authority=None, e112=None, gates=None):
        return m.Controller(self.authority if authority is None else authority,
            self.e112 if e112 is None else e112, *(self.raws + [self.common, self.incremental, {},
            self.initial, self.selftests, self.monitor, self.artifacts, self.translation,
            dict(implementation_review_passed_claim=True, independent_review_passed_claim=True)
            if gates is None else gates]))

    def initial(self, raw):
        if self.initials:
            raise FileExistsError()
        self.initials.append(raw)
        self.order.append('initial')
        return dict(path=m.SIDECAR, bytes=len(raw), sha256=m.sha(raw))

    def selftests(self, ctx):
        self.order.append('selftests')
        ctx['sample']()
        return copy.deepcopy(self.selftest_cases)

    def result(self, binding):
        raw = m.canonical(dict(task_uid=binding['task_uid'], binding_sha256=binding['binding_sha256']))
        return raw, dict(binding_sha256=binding['binding_sha256'], validation_passed=True,
                         output_authenticated_claim=True)

    def artifacts(self, binding, freeze, envelope, observed, ctx):
        self.order.append(('artifacts', binding['task_uid']))
        ctx['sample']()
        return self.result(binding)

    def translation(self, binding, freeze, prep, parent_reference, ctx):
        self.order.append(('translation', binding['task_uid']))
        self.assertIsInstance(parent_reference, bytes)
        self.assertEqual(ctx['end'], m.PACKAGE_END)
        ctx['sample']()
        return self.result(binding)

    def observe(self, launch, end, domain, output_budget, on_spawn, monitor):
        self.order.append(('observe', launch['launch_spec_sha256']))
        identity = dict(schema=m.process.IDENTITY_SCHEMA, boot_id=m.BOOT_ID,
            launch_spec_sha256=launch['launch_spec_sha256'], environment_sha256=launch['environment_sha256'],
            effective_envelope_sha256=launch['effective_envelope_sha256'])
        identity['identity_sha256'] = m.sha(m.canonical(identity))
        self.assertIs(on_spawn(identity), True)
        result = dict(schema=m.process.SCHEMA, launch_spec_sha256=launch['launch_spec_sha256'],
            environment_sha256=launch['environment_sha256'], effective_envelope_sha256=launch['effective_envelope_sha256'],
            launch_attempted=True, known_process_handle=True, returncode=0, failure=self.observer_failure,
            cleaned=True, output=b'MOCK_PREFIX', spawn_identity=identity,
            spawn_identity_persisted_claim=True, physical_process_identity_observed=True)
        self.observations.append(result)
        return result

    def test_full_fixed_78_tasks_exact_budgets_and_no_training(self):
        with mock.patch('subprocess.Popen') as spawn:
            result = self.controller.run()
            spawn.assert_not_called()
        self.assertEqual(result['status'], 'FIXED_78_TASKS_COLLECTED', result['error'])
        self.assertEqual(result['counts'], dict(tessent_debited=48, translation_debited=30,
            selftest_cases_reserved=3, selftest_cases_accepted=3, committed_tasks=78))
        self.assertEqual(len(self.observations), 48)
        self.assertEqual(len([x for x in self.order if type(x) is tuple and x[0] == 'translation']), 30)
        self.assertEqual(self.order[:2], ['initial', 'selftests'])
        self.assertEqual(result['original_package_start'], m.PACKAGE_START)
        self.assertEqual(result['original_package_deadline'], m.PACKAGE_END)
        self.assertEqual(result['package_elapsed_seconds'], 100)
        self.assertFalse(result['full_session_cost_qualified'])
        self.assertEqual(result['training_runs'], 0)
        self.assertFalse(result['training_release'])
        self.assertTrue(self.controller.maker.closed)

    def test_every_intent_debit_exists_before_any_task_preparation(self):
        maker = self.controller.maker
        original_tessent, original_translation = maker.materialize_attempt, maker.prepare_translation
        def check(operation, freeze, binding):
            intents = [json.loads(raw.decode('ascii')) for path, raw in maker.published.items()
                       if path.endswith('_intent.json') and '/task_' in path]
            self.assertTrue(any(row['task_uid'] == binding['task_uid'] for row in intents))
            row = next(row for row in intents if row['task_uid'] == binding['task_uid'])
            key = 'tessent_debited' if binding['kind'] == 'TESSENT' else 'translation_debited'
            self.assertGreater(row['counts'][key], 0)
            return operation(freeze, binding)
        maker.materialize_attempt = lambda freeze, binding: check(original_tessent, freeze, binding)
        maker.prepare_translation = lambda freeze, binding: check(original_translation, freeze, binding)
        self.assertEqual(self.controller.run()['status'], 'FIXED_78_TASKS_COLLECTED')

    def test_wrong_actual_raw_pins_or_review_gates_reject_before_operations(self):
        for kwargs in ({'authority': self.authority + b' '}, {'e112': self.e112 + b' '}, {'gates': {}}):
            with self.assertRaises(ValueError):
                self.construct(**kwargs)
        self.assertEqual(self.initials, [])

    def test_expired_or_wrong_boot_never_resets_clock_or_creates_root(self):
        with mock.patch.object(m.time, 'monotonic', return_value=m.PACKAGE_END + 1):
            result = self.controller.run()
        self.assertEqual(result['status'], 'STOPPED_FIRST_FAILURE')
        self.assertEqual(self.initials, [])
        self.assertEqual(self.controller.maker.actions, [])
        other = self.construct()
        with mock.patch.object(m.process, '_boot_id', return_value='other-boot'):
            result = other.run()
        self.assertEqual(result['error']['code'], 'ORIGINAL_BOOT_CHANGED')
        self.assertEqual(self.initials, [])

    def test_initialization_failure_keeps_sidecar_and_setup_cost_no_retry(self):
        self.controller.maker.fail_initialize = True
        result = self.controller.run()
        self.assertEqual(len(self.initials), 1)
        self.assertEqual(result['status'], 'STOPPED_FIRST_FAILURE')
        self.assertIsNotNone(result['initialization_start_monotonic'])
        self.assertEqual(result['counts']['tessent_debited'], 0)
        with self.assertRaisesRegex(ValueError, 'ONE_VERSION_NO_RESUME'):
            self.controller.run()
        second = self.construct()
        self.assertEqual(second.run()['status'], 'STOPPED_FIRST_FAILURE')
        self.assertEqual(second.maker.actions, [])

    def test_preparation_failure_debit_not_refunded_stops_whole_package(self):
        first = self.controller.plan['phases'][0]['tasks'][0]['task_uid']
        self.controller.maker.failure_task = first
        result = self.controller.run()
        self.assertEqual(result['counts']['tessent_debited'], 1)
        self.assertEqual(result['counts']['translation_debited'], 0)
        self.assertEqual(result['counts']['committed_tasks'], 0)
        self.assertEqual(len(self.observations), 0)
        self.assertEqual(result['failed_task_uid'], first)

    def test_observer_failure_published_before_rejection_preserves_raw_prefix(self):
        self.observer_failure = 'CASE_TIMEOUT'
        result = self.controller.run()
        self.assertEqual(result['status'], 'STOPPED_FIRST_FAILURE')
        self.assertEqual(self.controller.last_observation['output'], b'MOCK_PREFIX')
        published = self.controller.maker.published
        self.assertEqual(published[m.ROOT + '/journal/task_000_stdout.log'], b'MOCK_PREFIX')
        self.assertIn(m.ROOT + '/journal/task_000_observation.json', published)
        self.assertNotIn(m.ROOT + '/journal/task_000_ack.json', published)
        self.assertEqual(result['counts']['tessent_debited'], 1)

    def test_deadline_expiring_inside_observer_does_not_drop_observation(self):
        original = self.observe
        with mock.patch.object(m.time, 'monotonic', return_value=m.PACKAGE_START + 100) as clock:
            def overdue(*args):
                observed = original(*args)
                clock.return_value = m.PACKAGE_END + 1
                return observed
            with mock.patch.object(m.process, 'observe_tessent', side_effect=overdue):
                result = self.controller.run()
        self.assertEqual(result['error']['code'], 'ORIGINAL_PACKAGE_CLOCK_EXPIRED_OR_INVALID')
        self.assertEqual(self.controller.maker.published[m.ROOT + '/journal/task_000_stdout.log'], b'MOCK_PREFIX')
        self.assertIn(m.ROOT + '/journal/task_000_observation.json', self.controller.maker.published)
        self.assertEqual(result['counts']['committed_tasks'], 0)

    def test_log_publication_failure_keeps_raw_observation_and_stops(self):
        original = self.controller.maker._publish
        def fail(path, raw):
            if path.endswith('_stdout.log'):
                raise OSError('private-output-path')
            return original(path, raw)
        self.controller.maker._publish = fail
        result = self.controller.run()
        self.assertEqual(result['status'], 'STOPPED_FIRST_FAILURE')
        self.assertEqual(self.controller.last_observation['output'], b'MOCK_PREFIX')
        self.assertEqual(result['counts']['committed_tasks'], 0)
        self.assertNotIn('private-output-path', repr(result))
        path = m.ROOT + '/journal/task_000_observation.json'
        body = json.loads(self.controller.maker.published[path].decode('ascii'))
        self.assertEqual(body['returncode'], 0)
        self.assertTrue(body['cleaned'])
        self.assertFalse(body['stdout_publication_acknowledged'])
        self.assertEqual(body['stdout_expected']['sha256'], m.sha(b'MOCK_PREFIX'))

    def test_observer_end_clock_error_cannot_prevent_durable_metadata(self):
        original = self.controller._event
        def fail(phase):
            if phase == 'observer_end':
                raise OSError('clock-end-error')
            return original(phase)
        self.controller._event = fail
        result = self.controller.run()
        self.assertEqual(result['error']['code'], 'OBSERVER_END_CLOCK_UNAVAILABLE')
        published = self.controller.maker.published
        body = json.loads(published[m.ROOT + '/journal/task_000_observation.json'].decode('ascii'))
        self.assertEqual(body['returncode'], 0)
        self.assertTrue(body['cleaned'])
        self.assertEqual(body['observer_end_clock_error'], 'OSError')
        self.assertEqual(published[m.ROOT + '/journal/task_000_stdout.log'], b'MOCK_PREFIX')
        self.assertIn(m.ROOT + '/journal/task_000_stdout_ack.json', published)
        self.assertEqual(result['counts']['committed_tasks'], 0)

    def test_ack_publication_failure_never_commits_or_retries(self):
        original = self.controller.maker._publish
        def fail(path, raw):
            if path.endswith('_ack.json') and not path.endswith('_stdout_ack.json'):
                raise OSError()
            return original(path, raw)
        self.controller.maker._publish = fail
        result = self.controller.run()
        self.assertEqual(result['counts']['committed_tasks'], 0)
        self.assertEqual(result['counts']['tessent_debited'], 1)
        self.assertEqual(len(self.observations), 1)
        self.assertIn(m.ROOT + '/journal/task_000_reference.json', self.controller.maker.published)

    def test_synthetic_observation_schema_cannot_be_a_real_e113_observation(self):
        original = self.observe
        def synthetic(*args):
            result = original(*args)
            result['schema'] = 'synthetic-backend'
            return result
        with mock.patch.object(m.process, 'observe_tessent', side_effect=synthetic):
            result = self.controller.run()
        self.assertEqual(result['error']['code'], 'TESSENT_OBSERVATION_REJECTED')
        self.assertEqual(result['counts']['committed_tasks'], 0)

    def test_failed_artifact_validation_never_ack_or_next_task(self):
        self.controller.read_artifacts = lambda *args: (b'{}', dict(validation_passed=False))
        result = self.controller.run()
        self.assertEqual(result['error']['code'], 'ARTIFACT_VALIDATION_REQUIRED')
        self.assertEqual(result['counts']['committed_tasks'], 0)
        self.assertEqual(len(self.observations), 1)

    def test_translation_failure_debits_before_callback_and_stops(self):
        def fail(*args):
            self.assertEqual(self.controller.counts['translation_debited'], 1)
            raise ValueError('MOCK_TRANSLATION_FAILURE')
        self.controller.run_translation = fail
        result = self.controller.run()
        self.assertEqual(result['counts']['translation_debited'], 1)
        self.assertEqual(result['counts']['tessent_debited'], 1)
        self.assertEqual(result['counts']['committed_tasks'], 1)
        self.assertTrue(any(row['phase'] == 'translation_worker_interval_start'
                            for row in result['failed_operation_events']))

    def test_three_selftests_must_be_actual_claimed_clean_successes(self):
        self.selftest_cases[1]['cleaned'] = False
        result = self.controller.run()
        self.assertEqual(result['error']['code'], 'THREE_ACTUAL_LINUX_SELFTESTS_REQUIRED')
        self.assertEqual(result['counts']['selftest_cases_reserved'], 3)
        self.assertEqual(result['counts']['tessent_debited'], 0)
        self.assertEqual(len(self.observations), 0)

    def test_directory_monitor_requires_sidecar_and_exact_8gib(self):
        self.monitor.sample.return_value['sidecar_accounted'] = False
        result = self.controller.run()
        self.assertEqual(result['error']['code'], 'DIRECTORY_SAMPLE_REJECTED')
        self.assertEqual(result['counts']['tessent_debited'], 0)

    def test_callback_cannot_escape_task_journal(self):
        def bad(*args):
            args[-1]['persist']('../escape', b'bad')
        self.controller.read_artifacts = bad
        result = self.controller.run()
        self.assertEqual(result['error']['code'], 'CALLBACK_PUBLICATION_SCOPE')
        self.assertEqual(result['counts']['committed_tasks'], 0)

    def test_changed_launcher_blocks_before_any_tessent_without_refund(self):
        with mock.patch.object(m.material, '_hash_file', return_value=dict(
                path=m.material.pins.LAUNCHER, bytes=3658, sha256='0'*64)):
            summary = self.controller.run()
        self.assertEqual(summary['status'], 'STOPPED_FIRST_FAILURE')
        self.assertEqual(summary['error']['code'], 'FRESH_LAUNCHER_IDENTITY_CHANGED')
        self.assertEqual(summary['counts']['tessent_debited'], 1)
        self.assertEqual(len(self.observations), 0)
        self.assertEqual(summary['counts']['committed_tasks'], 0)

    def test_source_python36(self):
        for path in ('src/data/prospective_generation_controller_e116.py',
                     'tests/test_prospective_generation_controller_e116.py'):
            ast.parse((self.root / path).read_text(), feature_version=(3, 6))
