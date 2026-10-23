"""Pure, volatile E84 intent-to-E81 request binding; never a real collector.

All output bytes and live-ACK/authentication claims are caller supplied. This
module neither opens artifacts nor establishes their OS provenance, durable
acknowledgement, process completion, resource admission, or training release.
"""
import hashlib
import json

from src.data import prospective_acquisition_pilot_v1 as pilot
from src.data import prospective_request_features_v1 as features
from src.data import prospective_tessent_stage_v1 as stage

SCHEMA = 'prospective-acquisition-binding-v1'
RECEIPT_KEYS = {'task_uid', 'binding_sha256', 'output_sha256', 'status',
                'live_acknowledged_claim', 'output_authenticated_claim'}
MAX_OUTPUT_BYTES = 1024 * 1024


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def clone(value):
    return json.loads(canonical(value).decode('ascii'))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _signed(body, field):
    return dict(body, **{field: sha(canonical(body))})


class Binder(object):
    """One circuit, exact ordered slots; no I/O, retry, recovery, or launcher."""
    def __init__(self, plan, circuit, freeze=None, run_uid=None):
        pilot.validate_plan(plan)
        require(type(circuit) is str and circuit in pilot.CIRCUITS,
                'CIRCUIT')
        phase = next(row for row in plan['phases'] if row['circuit'] == circuit)
        if freeze is not None:
            require(stage.safe_uid(run_uid), 'RUN_UID')
            checked = features.build_features(freeze)
            require(freeze['circuit'] == circuit and
                    checked['feature_schema_id'] == features.FEATURE_SCHEMA_ID,
                    'FREEZE_CIRCUIT_OR_SCHEMA')
            require(freeze['requested_roster'] == phase['requested_roster'] and
                    freeze['roster_sha256'] == phase['roster_sha256'] and
                    freeze['requested_max_h'] == phase['requested_max_h'] and
                    freeze['requested_max_m'] == phase['requested_max_m'],
                    'FREEZE_PILOT_ROSTER')
        else:
            require(run_uid is None, 'RUN_UID_WITHOUT_FREEZE')
        self._plan = clone(plan)
        self._phase = clone(phase)
        self._freeze = None if freeze is None else clone(freeze)
        self._run_uid = run_uid
        self._cursor = 0
        self._receipts = {}

    def snapshot(self):
        return clone(dict(schema=SCHEMA, plan_sha256=self._plan['plan_sha256'],
                          circuit=self._phase['circuit'], next_slot=self._cursor,
                          task_count=len(self._phase['tasks']),
                          receipts=[self._receipts[row['task_uid']]
                                    for row in self._phase['tasks'][:self._cursor]],
                          volatile_only=True, os_authenticated=False,
                          durable_ack_verified=False, execution_ready=False,
                          training_release=False))

    def _next(self, task_uid):
        require(self._cursor < len(self._phase['tasks']), 'PLAN_FINISHED')
        node = self._phase['tasks'][self._cursor]
        require(type(task_uid) is str and task_uid == node['task_uid'],
                'EXACT_NEXT_TASK')
        return node

    def bind_next(self, task_uid):
        node = self._next(task_uid)
        parent_uid = node['parent_result_task_uid']
        parent = None if parent_uid is None else self._receipts.get(parent_uid)
        require(parent_uid is None or parent is not None, 'PARENT_NOT_ACKNOWLEDGED')
        translation_uid = None
        translation = None
        if node['kind'] == 'TRANSLATION':
            require(parent_uid is not None and node['depends_on'] == [parent_uid] and
                    node['target_mode'] in ('M', 'F'), 'TRANSLATION_LINEAGE')
            target_mode = node['target_mode']
            request = None
            recipe = None
        else:
            require(node['kind'] == 'TESSENT' and node['stage'] in ('H', 'M', 'F'),
                    'TASK_KIND_OR_STAGE')
            target_mode = node['stage']
            if target_mode == 'H':
                require(parent_uid is None and node['depends_on'] == [], 'H_PARENT')
            else:
                require(len(node['depends_on']) == 2 and
                        node['depends_on'][0] == parent_uid,
                        'INCREMENTAL_DEPENDENCIES')
                translation_uid = node['depends_on'][1]
                translation = self._receipts.get(translation_uid)
                require(translation is not None and
                        translation['kind'] == 'TRANSLATION' and
                        translation['parent_task_uid'] == parent_uid and
                        translation['parent_result_sha256'] == parent['output_sha256'] and
                        translation['target_mode'] == target_mode and
                        translation['action_uid'] == node['action_uid'],
                        'EXACT_TRANSLATION_NOT_ACKNOWLEDGED')
            request = None
            recipe = None
            if self._freeze is not None:
                request = dict(run_uid=self._run_uid, action_uid=node['action_uid'],
                               attempt_uid=task_uid, stage=target_mode,
                               stage_index=node['stage_index'],
                               freeze_sha256=self._freeze['freeze_sha256'],
                               control=clone(node['control']),
                               parent_attempt_uid=parent_uid,
                               parent_result_sha256=(None if parent is None else
                                                     parent['output_sha256']))
                recipe = stage.compile_stage(self._freeze, request)
            if target_mode != 'H' and recipe is not None:
                required = recipe['required_tasks']
                require(len(required) == 1 and
                        required[0]['parent_attempt_uid'] == parent_uid and
                        required[0]['parent_result_sha256'] == parent['output_sha256'] and
                        required[0]['target_mode'] == target_mode,
                        'RECIPE_PARENT_BINDING')
        if parent is not None:
            require(parent['action_uid'] == node['action_uid'] and
                    parent['circuit'] == self._phase['circuit'] and
                    parent['task_uid'] == parent_uid and
                    parent['kind'] == 'TESSENT', 'EXACT_PARENT_ACTION')
        body = dict(schema=SCHEMA, plan_sha256=self._plan['plan_sha256'],
                    freeze_sha256=(None if self._freeze is None else
                                   self._freeze['freeze_sha256']),
                    circuit=self._phase['circuit'], slot=self._cursor,
                    previous_receipt_sha256=(None if self._cursor == 0 else
                        self._receipts[self._phase['tasks'][self._cursor - 1]['task_uid']]
                        ['receipt_sha256']),
                    task_uid=task_uid, action_uid=node['action_uid'],
                    kind=node['kind'], target_mode=target_mode,
                    parent_task_uid=parent_uid,
                    parent_result_sha256=(None if parent is None else
                                          parent['output_sha256']),
                    parent_receipt_sha256=(None if parent is None else
                                           parent['receipt_sha256']),
                    translation_task_uid=translation_uid,
                    translation_result_sha256=(None if translation is None else
                                               translation['output_sha256']),
                    translation_receipt_sha256=(None if translation is None else
                                                translation['receipt_sha256']),
                    control=(None if node['kind'] == 'TRANSLATION' else
                             clone(node['control'])),
                    request=request, recipe=recipe,
                    compilation_ready=recipe is not None,
                    caller_claims_not_os_proof=True,
                    execution_ready=False, training_release=False)
        return _signed(body, 'binding_sha256')

    def commit_next(self, binding, receipt, output_bytes):
        require(type(binding) is dict and type(binding.get('task_uid')) is str,
                'BINDING_SCHEMA')
        expected = self.bind_next(binding['task_uid'])
        require(set(binding) == set(expected), 'BINDING_CHANGED')
        try:
            same = canonical(binding) == canonical(expected)
        except (TypeError, ValueError, UnicodeError):
            same = False
        require(same, 'BINDING_CHANGED')
        require(type(receipt) is dict and set(receipt) == RECEIPT_KEYS,
                'RECEIPT_SCHEMA')
        require(type(output_bytes) is bytes and
                0 < len(output_bytes) <= MAX_OUTPUT_BYTES, 'OUTPUT_BYTES_BOUND')
        require(receipt['task_uid'] == expected['task_uid'] and
                receipt['binding_sha256'] == expected['binding_sha256'] and
                type(receipt['output_sha256']) is str and
                receipt['output_sha256'] == sha(output_bytes) and
                receipt['status'] == 'SUCCESS' and
                receipt['live_acknowledged_claim'] is True and
                receipt['output_authenticated_claim'] is True,
                'UNVERIFIED_OR_MISMATCHED_RECEIPT')
        record = dict(receipt, schema=SCHEMA, circuit=expected['circuit'],
                      action_uid=expected['action_uid'], kind=expected['kind'],
                      target_mode=expected['target_mode'],
                      parent_task_uid=expected['parent_task_uid'],
                      parent_result_sha256=expected['parent_result_sha256'],
                      parent_receipt_sha256=expected['parent_receipt_sha256'],
                      translation_task_uid=expected['translation_task_uid'],
                      translation_result_sha256=expected['translation_result_sha256'],
                      translation_receipt_sha256=expected['translation_receipt_sha256'],
                      previous_receipt_sha256=expected['previous_receipt_sha256'],
                      receipt_sha256=sha(canonical(receipt)),
                      caller_claims_not_os_proof=True)
        self._receipts[expected['task_uid']] = clone(record)
        self._cursor += 1
        return clone(record)
