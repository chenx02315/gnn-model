"""Finite serial callback controller: implementation only, not a runtime release.

No subprocess, file/package reads, Torch imports, automatic retries or authority
are provided. Actual parent bootstrap, authenticated prelaunch envelopes, user
authorization and the existing external resource guard remain prerequisites.
The independent review callback must authenticate/reread guard evidence and
artifacts against independently trusted expectations, using the existing parent
receipt and artifact readback validators. A worker's self-report is NOT such an
expectation. The controller cannot authenticate callback provenance or enforce
resources. Its local dataclasses are adapter values, not a new release schema.
Family/seed/output binding is NOT complete fit-identity security: independently
pinned request/head-recipe/fold-manifest/fitting-UID/held-UID contexts must be
established by a future trusted outer parent before execution. This component
neither invents these pins nor derives them from worker/log self-reports.

Only one invocation per controller is allowed, including after failure. The
lock prevents concurrent/reentrant calls on that instance, not independent
controllers/processes. External parent coordination remains required. Completed
tasks mean reviewed callback completion only, never formal training/metrics.
"""
from dataclasses import dataclass
import inspect
import re
from threading import Lock

from src.models.ranking_v5_parent_guard_receipt import validate_parent_guard_receipt


FAMILIES = ('iwls_aes_core', 'iscas89_s13207', 'iscas89_s15850',
            'iscas89_s35932', 'iscas89_s38417', 'iwls_spi')
SEEDS = (20260824, 20260825, 20260826)
ROOT_PATTERN = r'/ssd/cjc/gnn_model_ranking_v5_train_[0-9]{8}_r[1-9][0-9]*'
GUARD_STATUS = 'PASS_PARENT_GUARD_RECEIPT_IMPLEMENTATION_ONLY'
READBACK_STATUS = 'PASS_TRAIN_ARTIFACT_READBACK_INTEGRITY_ONLY'
_READBACK_FIELDS = frozenset(('status', 'family', 'seed', 'log_record_count',
    'file_sha256', 'formal_training_authorized_by_this_function',
    'new_formal_18_fit_release', 'parent_sampled_rss_enforcement_proven'))
_FILES = frozenset(('model.pt', 'fitting.jsonl', 'freeze.json', 'worker_receipt.json'))


def _require(condition, code):
    if not condition:
        raise ValueError('V5_SERIAL_MATRIX_' + code)


@dataclass(frozen=True, slots=True)
class TrainTask:
    family: str
    seed: int
    output: str
    roles: tuple = ('TRAIN',)


@dataclass(frozen=True, slots=True)
class ReviewedTask:
    """Independent adapter result; all fields need trusted external provenance.

    ``task`` binds the exact output reviewed, as the existing readback summary
    does not contain an output field. ``held_labels_replayed`` must come from
    independently authenticated/reread boundary evidence, NOT a worker claim.
    """
    task: TrainTask
    guard_returned_receipt: dict
    guard_reread_receipt: dict
    artifact_check: dict
    held_labels_replayed: bool


@dataclass(frozen=True, slots=True)
class MatrixState:
    status: str
    completed: tuple
    failed: object
    remaining: tuple
    failure_kind: object = None
    failed_index: object = None
    formal_training_authorized_by_this_function: bool = False
    new_formal_18_fit_release: bool = False
    production_runtime_proven: bool = False
    actual_fits_proven: bool = False


def build_train_matrix(source_root):
    """Pure lexical construction in family-major, then seed-major order."""
    _require(type(source_root) is str and len(source_root) <= 2048
             and re.fullmatch(ROOT_PATTERN, source_root) is not None, 'SOURCE_ROOT')
    return tuple(TrainTask(family, seed, source_root + '_' + family + '_' + str(seed))
                 for family in FAMILIES for seed in SEEDS)


def validate_train_matrix(source_root, tasks):
    """Require exactly the immutable, ordered 18 TRAIN tasks before callbacks."""
    expected = build_train_matrix(source_root)
    _require(type(tasks) in (list, tuple) and len(tasks) == 18, 'TASK_COUNT')
    for task, wanted in zip(tasks, expected):
        _require(type(task) is TrainTask, 'TASK_TYPE')
        _require(type(task.family) is str and task.family == wanted.family, 'FAMILY_ORDER')
        _require(type(task.seed) is int and task.seed == wanted.seed, 'SEED_ORDER')
        _require(type(task.output) is str and task.output == wanted.output, 'OUTPUT_BINDING')
        _require(type(task.roles) is tuple and task.roles == ('TRAIN',)
                 and all(type(role) is str for role in task.roles), 'ROLES')
    return tuple(TrainTask(task.family, task.seed, task.output) for task in tasks)


def _task(plan):
    return TrainTask(*plan)


def _binding(task, plan, code):
    _require(type(task) is TrainTask and type(task.family) is str
             and type(task.seed) is int and type(task.output) is str
             and type(task.roles) is tuple
             and all(type(role) is str for role in task.roles)
             and (task.family, task.seed, task.output) == plan
             and task.roles == ('TRAIN',), code)


def _review(plan, result):
    _require(type(result) is ReviewedTask and type(result.task) is TrainTask, 'REVIEW_TYPE')
    _binding(result.task, plan, 'REVIEW_TASK_BINDING')
    task = _task(plan)
    guard = validate_parent_guard_receipt(result.guard_returned_receipt,
                                         result.guard_reread_receipt)
    _require(guard['status'] == GUARD_STATUS, 'GUARD_REJECTED')
    artifact = result.artifact_check
    _require(type(artifact) is dict and set(artifact) == _READBACK_FIELDS, 'READBACK_SCHEMA')
    _require(type(artifact['status']) is str and artifact['status'] == READBACK_STATUS
             and type(artifact['family']) is str and artifact['family'] == task.family
             and type(artifact['seed']) is int and artifact['seed'] == task.seed
             and type(artifact['log_record_count']) is int and artifact['log_record_count'] == 122
             and all(artifact[k] is False for k in (
                 'formal_training_authorized_by_this_function', 'new_formal_18_fit_release',
                 'parent_sampled_rss_enforcement_proven')), 'READBACK_REJECTED')
    pins = artifact['file_sha256']
    _require(type(pins) is dict and set(pins) == _FILES and all(
        type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None
        for value in pins.values()), 'READBACK_PINS')
    _require(result.held_labels_replayed is True, 'HELD_REPLAY_REQUIRED')


class SerialTrainMatrix:
    """Single-use finite orchestration with injected synchronous callbacks.

    execute_once(task) must return only after its externally guarded child exits
    (including all group members); it returns exactly the bound TrainTask as a
    local consistency receipt, not as fit proof. No worker result is forwarded.
    review_independently(task) must reread/check trustworthy evidence, not use
    the execution return as authorization. Passing different callables is only
    an accidental-wiring check, not independent-review authentication.
    """
    def __init__(self, source_root, tasks):
        validated = validate_train_matrix(source_root, tasks)
        # Canonical primitive values are never passed to either callback or state.
        self._plan = tuple((task.family, task.seed, task.output) for task in validated)
        self._lock = Lock()
        self._attempted = False
        self._state = MatrixState('READY_CALLBACK_PLAN_ONLY', (), None,
                                  tuple(_task(plan) for plan in self._plan))

    @property
    def state(self):
        value = self._state
        return MatrixState(value.status,
                           tuple(TrainTask(t.family, t.seed, t.output) for t in value.completed),
                           None if value.failed is None else TrainTask(
                               value.failed.family, value.failed.seed, value.failed.output),
                           tuple(TrainTask(t.family, t.seed, t.output) for t in value.remaining),
                           value.failure_kind, value.failed_index)

    def run(self, *, execute_once, review_independently):
        _require(callable(execute_once) and callable(review_independently)
                 and execute_once is not review_independently
                 and not any(inspect.iscoroutinefunction(callback)
                             or inspect.isasyncgenfunction(callback)
                             or inspect.iscoroutinefunction(getattr(callback, '__call__', None))
                             or inspect.isasyncgenfunction(getattr(callback, '__call__', None))
                             for callback in (execute_once, review_independently)), 'CALLBACKS')
        if not self._lock.acquire(blocking=False):
            raise RuntimeError('V5_SERIAL_MATRIX_BUSY')
        try:
            if self._attempted:
                raise RuntimeError('V5_SERIAL_MATRIX_ALREADY_ATTEMPTED_NO_RETRY')
            self._attempted = True
            completed = []
            for index, plan in enumerate(self._plan):
                task = _task(plan)
                self._state = MatrixState('RUNNING_CALLBACK_PLAN_ONLY', tuple(completed),
                                          None, tuple(_task(p) for p in self._plan[index:]))
                try:
                    executed = execute_once(_task(plan))
                    _binding(executed, plan, 'EXECUTION_TASK_BINDING')
                    _review(plan, review_independently(_task(plan)))
                except BaseException as error:
                    self._state = MatrixState('STOPPED_NO_RETRY', tuple(completed), task,
                                              tuple(_task(p) for p in self._plan[index+1:]),
                                              type(error).__name__[:64], index)
                    if not isinstance(error, Exception):
                        raise
                    return self.state
                completed.append(task)
            self._state = MatrixState('PASS_SERIAL_CONTROL_CALLBACKS_ONLY',
                                      tuple(completed), None, ())
            return self.state
        finally:
            self._lock.release()
