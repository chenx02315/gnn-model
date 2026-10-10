"""Synthetic callback fixtures only: no ML, real artifacts, or remote I/O."""
from copy import deepcopy
from dataclasses import replace
from threading import Event, Thread
import unittest

from src.models import ranking_v5_serial_matrix as matrix
from src.models import ranking_v4_memory_guard as guard


ROOT = '/ssd/cjc/gnn_model_ranking_v5_train_20261010_r1'


def parent_receipt():
    return dict(status='PASS_BOUNDED_WORKER', memory_policy=guard.policy(),
                initial_available_bytes=12*guard.GIB, effective_total_bytes=16*guard.GIB,
                reserve_bytes=4*guard.GIB, sample_count=2, peak_group_rss_bytes=100,
                peak_combined_rss_bytes=200, exit_code=0, process_group=123,
                elapsed_seconds=0.5)


def reviewed(task):
    receipt = parent_receipt()
    return matrix.ReviewedTask(task, receipt, deepcopy(receipt), dict(
        status=matrix.READBACK_STATUS, family=task.family, seed=task.seed,
        log_record_count=122, file_sha256={name: 'a'*64 for name in matrix._FILES},
        formal_training_authorized_by_this_function=False,
        new_formal_18_fit_release=False, parent_sampled_rss_enforcement_proven=False), True)


class SerialMatrixTests(unittest.TestCase):
    def setUp(self):
        self.tasks = matrix.build_train_matrix(ROOT)
        self.controller = matrix.SerialTrainMatrix(ROOT, self.tasks)

    def run_matrix(self, execute=lambda task: task, review=reviewed):
        return self.controller.run(execute_once=execute, review_independently=review)

    def test_exact_order_eighteen_and_alternating_independent_review(self):
        events = []
        def execute(task):
            events.append(('execute', task))
            return task
        def review(task):
            events.append(('review', task))
            return reviewed(task)
        result = self.run_matrix(execute, review)
        self.assertEqual(len(set(self.tasks)), 18)
        self.assertEqual([(task.family, task.seed) for task in self.tasks],
                         [(family, seed) for family in matrix.FAMILIES for seed in matrix.SEEDS])
        self.assertEqual(events, [(kind, task) for task in self.tasks for kind in ('execute', 'review')])
        self.assertEqual(result.status, 'PASS_SERIAL_CONTROL_CALLBACKS_ONLY')
        self.assertEqual(result.completed, self.tasks)
        self.assertIsNone(result.failed)
        self.assertEqual(result.remaining, ())
        for name in ('actual_fits_proven', 'production_runtime_proven',
                     'formal_training_authorized_by_this_function', 'new_formal_18_fit_release'):
            self.assertIs(getattr(result, name), False)
        with self.assertRaisesRegex(RuntimeError, 'NO_RETRY'):
            self.run_matrix(execute, review)
        self.assertEqual(len(events), 36)

    def test_retained_input_mutation_cannot_change_canonical_plan(self):
        original = matrix.build_train_matrix(ROOT)
        object.__setattr__(self.tasks[0], 'family', 'UNEXPECTED_FAMILY')
        object.__setattr__(self.tasks[0], 'roles', ('BLIND',))
        seen = []
        result = self.run_matrix(lambda task: seen.append(task) or task)
        self.assertEqual(tuple(seen), original)
        self.assertEqual(result.completed, original)

    def test_public_state_mutation_is_isolated(self):
        exposed = self.controller.state
        object.__setattr__(exposed.remaining[0], 'output', '/ssd/cjc/multimode_ate_gnn_v1')
        object.__setattr__(exposed, 'status', 'FORGED')
        self.assertEqual(self.controller.state.remaining, self.tasks)
        self.assertEqual(self.controller.state.status, 'READY_CALLBACK_PLAN_ONLY')
        result = self.run_matrix()
        object.__setattr__(result.completed[0], 'roles', ('BLIND',))
        self.assertEqual(self.controller.state.completed, self.tasks)

    def test_execute_argument_mutation_rejected_before_review(self):
        calls = []
        def execute(task):
            object.__setattr__(task, 'output', '/ssd/cjc/multimode_ate_gnn_v1')
            object.__setattr__(task, 'roles', ('BLIND',))
            return task
        result = self.run_matrix(execute, lambda task: calls.append(task))
        self.assertEqual(result.status, 'STOPPED_NO_RETRY')
        self.assertEqual(result.failed, self.tasks[0])
        self.assertEqual(calls, [])

    def test_review_argument_mutation_rejected_against_canonical_plan(self):
        def review(task):
            object.__setattr__(task, 'family', 'UNEXPECTED_FAMILY')
            object.__setattr__(task, 'roles', ('BLIND',))
            return reviewed(task)
        result = self.run_matrix(review=review)
        self.assertEqual(result.status, 'STOPPED_NO_RETRY')
        self.assertEqual(result.failed, self.tasks[0])
        self.assertEqual(result.completed, ())

    def test_execute_and_review_arguments_are_distinct(self):
        retained = []
        def execute(task):
            retained.append(task)
            return task
        def review(task):
            self.assertIsNot(task, retained[-1])
            object.__setattr__(retained[-1], 'roles', ('BLIND',))
            return reviewed(task)
        result = self.run_matrix(execute, review)
        self.assertEqual(result.completed, self.tasks)

    def test_missing_extra_duplicate_and_out_of_order_rejected_preexecution(self):
        bad_plans = [self.tasks[:-1], self.tasks + (self.tasks[0],),
                     (self.tasks[0],) + self.tasks[:-1], tuple(reversed(self.tasks))]
        for tasks in bad_plans:
            with self.subTest(tasks=tasks), self.assertRaises(ValueError):
                matrix.SerialTrainMatrix(ROOT, tasks)

    def test_task_contamination_and_root_rejection(self):
        for change in (dict(family='s13207'), dict(seed=True), dict(seed=20260824.0),
                       dict(seed=20260827), dict(seed='20260824'), dict(output=ROOT),
                       dict(roles=('TRAIN', 'TEST')), dict(roles=('VAL',)), dict(roles=['TRAIN'])):
            tasks = list(self.tasks); tasks[0] = replace(tasks[0], **change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                matrix.SerialTrainMatrix(ROOT, tasks)
        for root in ('/ssd/cjc/multimode_ate_gnn_v1', ROOT+'/../x', ROOT+'/', ROOT+' ',
                     ROOT.replace('/', '\\'), None, 'x'*3000):
            with self.subTest(root=root), self.assertRaises(ValueError):
                matrix.build_train_matrix(root)

    def test_execute_failure_stops_immediately_zero_retry(self):
        calls, reviews = [], []
        def execute(task):
            calls.append(task)
            if task == self.tasks[3]:
                raise OSError('synthetic only')
            return task
        def review(task):
            reviews.append(task)
            return reviewed(task)
        result = self.run_matrix(execute, review)
        self.assertEqual(result.status, 'STOPPED_NO_RETRY')
        self.assertEqual(result.completed, self.tasks[:3])
        self.assertEqual(result.failed, self.tasks[3])
        self.assertEqual(result.failed_index, 3)
        self.assertEqual(result.failure_kind, 'OSError')
        self.assertEqual(result.remaining, self.tasks[4:])
        self.assertEqual(calls, list(self.tasks[:4]))
        self.assertEqual(reviews, list(self.tasks[:3]))
        with self.assertRaisesRegex(RuntimeError, 'NO_RETRY'):
            self.run_matrix(execute, review)
        self.assertEqual(calls, list(self.tasks[:4]))

    def test_review_exception_stops(self):
        def review(task):
            raise ValueError('synthetic readback failure')
        result = self.run_matrix(review=review)
        self.assertEqual(result.completed, ())
        self.assertEqual(result.failed_index, 0)
        self.assertEqual(result.remaining, self.tasks[1:])

    def test_execution_binding_rejected_before_review(self):
        for execution in (None, {'status': 'PASS'}, self.tasks[1],
                          replace(self.tasks[0], output=ROOT),
                          replace(self.tasks[0], seed=float(self.tasks[0].seed))):
            controller = matrix.SerialTrainMatrix(ROOT, self.tasks)
            reviews = []
            result = controller.run(execute_once=lambda task: execution,
                                    review_independently=lambda task: reviews.append(task))
            self.assertEqual(result.status, 'STOPPED_NO_RETRY')
            self.assertEqual(reviews, [])

    def test_exact_review_binding_and_real_guard_validation(self):
        original = reviewed(self.tasks[0])
        bad_results = [None, {'status': matrix.READBACK_STATUS},
                       replace(original, task=self.tasks[1]),
                       replace(original, task=replace(original.task, output=ROOT)),
                       replace(original, task=replace(original.task, seed=float(original.task.seed)))]
        for field, bad in (('status', 'PASS'), ('sample_count', 0), ('exit_code', False),
                           ('peak_combined_rss_bytes', guard.RSS_CAP+1), ('unknown', 1)):
            receipt = deepcopy(original.guard_returned_receipt); receipt[field] = bad
            bad_results.append(replace(original, guard_returned_receipt=receipt,
                                       guard_reread_receipt=deepcopy(receipt)))
        mismatch = deepcopy(original.guard_reread_receipt); mismatch['process_group'] = 124
        bad_results.append(replace(original, guard_reread_receipt=mismatch))
        for value in bad_results:
            controller = matrix.SerialTrainMatrix(ROOT, self.tasks)
            result = controller.run(execute_once=lambda task: task,
                                    review_independently=lambda task: value)
            self.assertEqual(result.status, 'STOPPED_NO_RETRY')
            self.assertEqual(result.completed, ())

    def test_readback_strict_schema_binding_and_held_replay_required(self):
        original = reviewed(self.tasks[0])
        mutations = [(field, bad) for field, bad in (
            ('status', 'PASS'), ('family', self.tasks[3].family), ('seed', True),
            ('seed', float(original.task.seed)), ('log_record_count', True),
            ('log_record_count', 121), ('new_formal_18_fit_release', True),
            ('formal_training_authorized_by_this_function', 0),
            ('parent_sampled_rss_enforcement_proven', True),
            ('file_sha256', {'model.pt': 'a'*64}), ('unknown', None))]
        bad_results = []
        for field, bad in mutations:
            artifact = deepcopy(original.artifact_check); artifact[field] = bad
            bad_results.append(replace(original, artifact_check=artifact))
        for field in original.artifact_check:
            artifact = deepcopy(original.artifact_check); del artifact[field]
            bad_results.append(replace(original, artifact_check=artifact))
        artifact = deepcopy(original.artifact_check); artifact['file_sha256']['model.pt'] = 'A'*64
        bad_results.append(replace(original, artifact_check=artifact))
        bad_results += [replace(original, held_labels_replayed=bad) for bad in (False, 1, 'true', None)]
        for value in bad_results:
            controller = matrix.SerialTrainMatrix(ROOT, self.tasks)
            result = controller.run(execute_once=lambda task: task,
                                    review_independently=lambda task: value)
            self.assertEqual(result.status, 'STOPPED_NO_RETRY')
            self.assertEqual(result.failed_index, 0)

    def test_reentry_rejected_and_outer_failure_stops(self):
        def execute(task):
            return self.run_matrix()
        result = self.run_matrix(execute)
        self.assertEqual(result.status, 'STOPPED_NO_RETRY')
        self.assertEqual(result.failure_kind, 'RuntimeError')
        self.assertEqual(result.remaining, self.tasks[1:])

    def test_concurrent_call_rejected_on_same_instance(self):
        entered, release = Event(), Event()
        outputs = []
        def execute(task):
            entered.set()
            if not release.wait(5):
                raise TimeoutError('test coordination')
            return task
        thread = Thread(target=lambda: outputs.append(self.run_matrix(execute)))
        thread.start()
        try:
            self.assertTrue(entered.wait(5))
            with self.assertRaisesRegex(RuntimeError, 'BUSY'):
                self.run_matrix()
        finally:
            release.set(); thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(outputs[0].completed, self.tasks)

    def test_async_and_same_callback_rejected_without_execution(self):
        async def asynchronous(task):
            return task
        class AsyncCallable:
            async def __call__(self, task):
                return task
        for callback in (asynchronous, AsyncCallable(), None):
            with self.assertRaisesRegex(ValueError, 'CALLBACKS'):
                self.run_matrix(execute=callback)
        with self.assertRaisesRegex(ValueError, 'CALLBACKS'):
            self.run_matrix(execute=reviewed, review=reviewed)
        self.assertEqual(self.controller.state.status, 'READY_CALLBACK_PLAN_ONLY')

    def test_returned_awaitable_is_rejected_and_never_awaited(self):
        class Awaitable:
            def __await__(self):
                raise AssertionError('must never be awaited')
        for execute, review in ((lambda task: Awaitable(), reviewed),
                                (lambda task: task, lambda task: Awaitable())):
            controller = matrix.SerialTrainMatrix(ROOT, self.tasks)
            result = controller.run(execute_once=execute, review_independently=review)
            self.assertEqual(result.status, 'STOPPED_NO_RETRY')

    def test_interrupt_records_failure_and_propagates_without_retry(self):
        def execute(task):
            raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.run_matrix(execute)
        self.assertEqual(self.controller.state.failure_kind, 'KeyboardInterrupt')
        self.assertEqual(self.controller.state.failed, self.tasks[0])
        with self.assertRaisesRegex(RuntimeError, 'NO_RETRY'):
            self.run_matrix()


if __name__ == '__main__':
    unittest.main()
