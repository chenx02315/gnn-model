"""One-shot E84 acquisition composition, never a deployment/consent mechanism.

Real I/O callbacks are trusted deployment dependencies, not synthetic backends.
All receipts retain caller-claim boundaries. No training/BLIND/LSF capability.
The package clock is the original E112 boot-monotonic clock, never restarted.
"""
import copy
import json
import math
import os
import platform
import re
import sys
import time

from . import prospective_generation_materializer_e111 as material
from . import prospective_generation_process_e113 as process
from . import prospective_generation_supervision_e109 as launches
from . import prospective_runtime_adapter_e114 as runtime

SCHEMA = 'prospective-generation-controller-e116-v1'
AUTH_SHA256 = 'c11a7a29418680a3506f8bc9b7e6f5fcd564887a6c58b436f2e3ec83601b1ba9'
E112_SHA256 = 'fd09999da5355c8b66fb0bbae0e6f495544bbf578df8894b01ac5fc8685864ae'
BOOT_ID = '3ebeb9bb-410c-476c-a000-5c625f590473'
PACKAGE_START = 2332488.679409259
PACKAGE_END = 2382888.679409259
DIRECTORY_LIMIT = 8589934592
ROOT = material.recipe.ROOT
SIDECAR = ROOT + '.initial_intent.json'
require, sha, canonical = material.require, material.sha, material.canonical


def _json(raw, pin, cap, label):
    require(type(raw) is bytes and len(raw) <= cap and sha(raw) == pin, label + '_PIN')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=material.pins._pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE_JSON')))


class Controller(object):
    def __init__(self, raw_authority, raw_e112, raw_e85, raw_e88, raw_e93,
                 common_base_bytes, incremental_base_bytes, runtime_values,
                 persist_initial_intent, selftests, monitor, read_artifacts,
                 run_translation, review_gates):
        self.authority = _json(raw_authority, AUTH_SHA256, 65536, 'ACTUAL_AUTHORIZATION')
        self.preparation = _json(raw_e112, E112_SHA256, 1048576, 'ACTUAL_E112')
        prep = self.preparation
        require(prep.get('schema') == 'e112-readonly-preparation-v1' and prep.get('capture_complete') is True and
                prep.get('error') is None and prep.get('hostname') == 'bupt-vncs2' and prep.get('uid') == 1047 and
                prep.get('boot_id') == BOOT_ID and prep.get('remote_start_monotonic') == PACKAGE_START,
                'ACTUAL_PREPARATION_OR_CLOCK')
        require(type(review_gates) is dict and set(review_gates) ==
                {'implementation_review_passed_claim', 'independent_review_passed_claim'} and
                all(value is True for value in review_gates.values()), 'IMPLEMENTATION_REVIEW_GATES')
        for callback in (persist_initial_intent, selftests, read_artifacts, run_translation):
            require(callable(callback), 'TRUSTED_CALLBACK_REQUIRED')
        require(callable(getattr(monitor, 'sample', None)), 'DIRECTORY_MONITOR_REQUIRED')
        self.persist_initial_intent, self.selftests = persist_initial_intent, selftests
        self.monitor, self.read_artifacts, self.run_translation = monitor, read_artifacts, run_translation
        self.runtime_values, self.runtime_receipt = runtime.prepare_runtime(runtime_values,
            prep['runtime_profile'], material.pins.LAUNCHER_SHA256)
        self.plan = material.recipe.pilot.build_plan()
        self.maker = material.Materializer(raw_e85, raw_e88, raw_e93,
            common_base_bytes, incremental_base_bytes, self._admit_materialization)
        self.review_gates = dict(review_gates)
        self.domain = None
        self.started = self.failed = self.journal_ready = False
        self.active_intent = None
        self.counts = dict(tessent_debited=0, translation_debited=0, selftest_cases_reserved=0,
                           selftest_cases_accepted=0, committed_tasks=0)
        self.events, self.task_records = [], []
        self.last_observation = self.last_reference = self.summary = None

    def _clock(self):
        now = time.monotonic()
        require(type(now) in (int, float) and math.isfinite(now) and
                PACKAGE_START <= now < PACKAGE_END, 'ORIGINAL_PACKAGE_CLOCK_EXPIRED_OR_INVALID')
        require(process._boot_id() == BOOT_ID, 'ORIGINAL_BOOT_CHANGED')
        return now

    def sample(self):
        self._clock()
        process._check_worker(self.domain)
        self.domain.sample()  # E104 already includes this worker plus descendants.
        if self.journal_ready:
            observed = self.monitor.sample()
            require(type(observed) is dict and observed.get('root') == ROOT and
                    observed.get('sidecar') == SIDECAR and observed.get('sidecar_accounted') is True and
                    observed.get('threshold_bytes') == DIRECTORY_LIMIT and
                    type(observed.get('sampled_named_bytes')) is int and
                    0 <= observed['sampled_named_bytes'] <= DIRECTORY_LIMIT, 'DIRECTORY_SAMPLE_REJECTED')
        self._clock()

    def _admit_materialization(self, request):
        require(self.active_intent is not None and not self.failed, 'PERSISTED_INTENT_REQUIRED')
        self.sample()
        return True

    def _publish(self, name, raw):
        require(self.journal_ready and type(name) is str and
                re.fullmatch(r'[A-Za-z0-9_.-]{1,160}', name) is not None and name not in ('.', '..') and
                type(raw) is bytes and len(raw) <= 16777216, 'JOURNAL_PUBLICATION_SCOPE')
        return self.maker._publish(ROOT + '/journal/' + name, raw)

    def _record(self, name, body):
        raw = canonical(body) + b'\n'
        return self._publish(name, raw)

    def _event(self, phase):
        require(len(self.events) < 128, 'EVENT_BOUND')
        # End-of-operation evidence must survive an expired package deadline.
        now = time.monotonic()
        require(type(now) in (int, float) and math.isfinite(now), 'EVENT_CLOCK_INVALID')
        self.events.append(dict(phase=phase, monotonic=now))

    def _context(self, prefix):
        def persist(name, raw):
            require(type(name) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,96}', name) is not None and
                    name not in ('.', '..'), 'CALLBACK_PUBLICATION_SCOPE')
            return self._publish(prefix + '_callback_' + name, raw)
        return dict(end=PACKAGE_END, root=ROOT, sample=self.sample, persist=persist,
                    events=copy.deepcopy(self.events))

    def _selftest_gate(self):
        self.counts['selftest_cases_reserved'] = 3
        self._record('selftest_intent.json', dict(cases=['success', 'timeout', 'setsid_child'],
            reserved_cases=3, counts=dict(self.counts), deadline=PACKAGE_END))
        cases = self.selftests(self._context('selftest'))
        self._record('selftest_observation.json', dict(cases=cases))
        require(type(cases) is list and len(cases) == 3 and
                [case.get('case') for case in cases] == ['success', 'timeout', 'setsid_child'] and
                all(type(case) is dict and all(case.get(field) is True for field in
                    ('passed', 'cleaned', 'authenticated_claim', 'actual_linux_process')) for case in cases),
                'THREE_ACTUAL_LINUX_SELFTESTS_REQUIRED')
        self.counts['selftest_cases_accepted'] = 3
        self.sample()

    def _callback_result(self, result, binding):
        require(type(result) is tuple and len(result) == 2, 'ARTIFACT_CALLBACK_RESULT')
        raw, metadata = result
        require(type(raw) is bytes and 0 < len(raw) <= 1048576 and type(metadata) is dict and
                metadata.get('binding_sha256') == binding['binding_sha256'] and
                metadata.get('validation_passed') is True and metadata.get('output_authenticated_claim') is True and
                len(canonical(metadata)) <= 262144, 'ARTIFACT_VALIDATION_REQUIRED')
        return raw, metadata

    def _task(self, binder, freeze, node, index, references):
        binding = binder.bind_next(node['task_uid'])
        self.events = []
        self._event('task_start_before_intent')
        key, cap = ('tessent_debited', 48) if node['kind'] == 'TESSENT' else ('translation_debited', 30)
        require(self.counts[key] < cap, 'ATTEMPT_BUDGET_EXHAUSTED')
        self.counts[key] += 1  # No refund, including preparation/spawn failures.
        prefix = 'task_%03d' % index
        self._record(prefix + '_intent.json', dict(schema=SCHEMA, task_uid=node['task_uid'],
            binding=binding, freeze_sha256=freeze['freeze_sha256'], counts=dict(self.counts),
            original_package_start=PACKAGE_START, deadline=PACKAGE_END, automatic_retries=0))
        self.active_intent = node['task_uid']
        self._event('intent_persisted')
        self.sample()
        self._event('preparation_start')
        if node['kind'] == 'TRANSLATION':
            prep = self.maker.prepare_translation(freeze, binding)
            self._event('preparation_end')
            self.sample()
            self._event('translation_worker_interval_start')
            value = self.run_translation(binding, freeze, prep,
                references[binding['parent_task_uid']], self._context(prefix))
            self._event('translation_worker_interval_end')
            raw, metadata = self._callback_result(value, binding)
            self.last_reference = raw
            self._record(prefix + '_translation_observation.json', dict(metadata=metadata,
                reference_sha256=sha(raw), events=copy.deepcopy(self.events)))
            self.sample()
        else:
            prep = self.maker.materialize_attempt(freeze, binding)
            self._event('preparation_end')
            envelope = material.recipe.compile_execution(freeze, binding, self.maker.sources)
            self.sample()
            launcher = material._hash_file(material.pins.LAUNCHER, self.maker.e85['binary']['bytes'])
            require(launcher == dict(path=material.pins.LAUNCHER,
                    bytes=self.maker.e85['binary']['bytes'], sha256=material.pins.LAUNCHER_SHA256),
                    'FRESH_LAUNCHER_IDENTITY_CHANGED')
            self.sample()
            # Existing owned prerequisite is separate from Tcl's absent output dir.
            cwd = prep['prereq_dir']
            launch = launches.prepare_launch(freeze, binding, self.maker.sources, self.runtime_values, cwd)
            self._record(prefix + '_preparation.json', dict(input_receipt=prep, fresh_launcher=launcher,
                effective_envelope_sha256=envelope['envelope_sha256'], launch_spec_sha256=launch['launch_spec_sha256'],
                environment_sha256=launch['environment_sha256'], events=copy.deepcopy(self.events)))
            self.sample()
            spawned = [None]
            def on_spawn(identity):
                require(spawned[0] is None and type(identity) is dict and
                        identity.get('schema') == process.IDENTITY_SCHEMA and identity.get('boot_id') == BOOT_ID and
                        identity.get('launch_spec_sha256') == launch['launch_spec_sha256'] and
                        identity.get('environment_sha256') == launch['environment_sha256'] and
                        identity.get('effective_envelope_sha256') == envelope['envelope_sha256'] and
                        sha(canonical({k: v for k, v in identity.items() if k != 'identity_sha256'})) ==
                        identity.get('identity_sha256'), 'BOUND_SPAWN_IDENTITY_REQUIRED')
                self._record(prefix + '_spawn_identity.json', identity)
                spawned[0] = copy.deepcopy(identity)
                return True
            self._event('observer_start')
            observed = process.observe_tessent(launch, PACKAGE_END, self.domain, [16777216], on_spawn, self)
            self.last_observation = observed  # Retain raw prefix even if publication fails.
            end_clock_error = None
            try:
                self._event('observer_end')
            except BaseException as exc:
                end_clock_error = type(exc).__name__
            output = observed['output']
            require(type(output) is bytes and len(output) <= 16777216, 'OBSERVER_OUTPUT_BOUND')
            expected_log = dict(path=ROOT + '/journal/' + prefix + '_stdout.log',
                                bytes=len(output), sha256=sha(output))
            observation_body = {k: v for k, v in observed.items() if k != 'output'}
            observation_receipt = self._record(prefix + '_observation.json', dict(observation_body,
                stdout_expected=expected_log, stdout_publication_acknowledged=False,
                observer_end_clock_error=end_clock_error, events=copy.deepcopy(self.events)))
            log = self._publish(prefix + '_stdout.log', output)
            require(log == expected_log, 'STDOUT_PUBLICATION_RECEIPT_MISMATCH')
            self._record(prefix + '_stdout_ack.json', dict(stdout_receipt=log,
                observation_receipt=observation_receipt, stdout_publication_acknowledged=True))
            require(end_clock_error is None, 'OBSERVER_END_CLOCK_UNAVAILABLE')
            require(observed.get('returncode') == 0 and observed.get('failure') is None and
                    observed.get('schema') == process.SCHEMA and observed.get('launch_attempted') is True and
                    observed.get('known_process_handle') is True and
                    observed.get('launch_spec_sha256') == launch['launch_spec_sha256'] and
                    observed.get('environment_sha256') == launch['environment_sha256'] and
                    observed.get('effective_envelope_sha256') == envelope['envelope_sha256'] and
                    observed.get('spawn_identity') == spawned[0] and spawned[0] is not None and
                    observed.get('cleaned') is True and observed.get('spawn_identity_persisted_claim') is True and
                    observed.get('physical_process_identity_observed') is True, 'TESSENT_OBSERVATION_REJECTED')
            self.sample()
            self._event('artifact_read_start')
            raw, metadata = self._callback_result(self.read_artifacts(binding, freeze, envelope,
                observed, self._context(prefix)), binding)
            self._event('artifact_read_end')
        self.last_reference = raw
        reference_receipt = self._publish(prefix + '_reference.json', raw)
        self._record(prefix + '_artifact_metadata.json', metadata)
        receipt = dict(task_uid=binding['task_uid'], binding_sha256=binding['binding_sha256'],
            output_sha256=sha(raw), status='SUCCESS', live_acknowledged_claim=True,
            output_authenticated_claim=True)
        self.sample()
        self._record(prefix + '_ack.json', dict(receipt, reference_receipt=reference_receipt,
            events=copy.deepcopy(self.events), counts=dict(self.counts),
            claims_are_not_independent_durability_attestation=True))
        binder.commit_next(binding, receipt, raw)
        references[node['task_uid']] = raw
        self.counts['committed_tasks'] += 1
        self.task_records.append(dict(task_uid=node['task_uid'], output_sha256=sha(raw),
                                     binding_sha256=binding['binding_sha256']))
        self.active_intent = None

    def run(self):
        require(not self.started, 'ONE_VERSION_NO_RESUME')
        self.started = True
        run_start, setup_start, setup_end = None, None, None
        error = None
        try:
            require(sys.platform.startswith('linux') and platform.node() == 'bupt-vncs2' and
                    os.getuid() == 1047, 'FIXED_HOST_UID_PLATFORM')
            self.domain = process.direct.Descendants()
            self.sample()
            run_start = setup_start = self._clock()
            initial = canonical(dict(schema=SCHEMA, root=ROOT, sidecar=SIDECAR,
                authorization_sha256=AUTH_SHA256, e112_sha256=E112_SHA256,
                original_package_start=PACKAGE_START, deadline=PACKAGE_END, boot_id=BOOT_ID,
                initialization_start=setup_start, versions_max=1, automatic_retries=0,
                review_gates=self.review_gates, review_gates_authenticated=False)) + b'\n'
            receipt = self.persist_initial_intent(initial)
            require(receipt == dict(path=SIDECAR, bytes=len(initial), sha256=sha(initial)), 'INITIAL_INTENT_PERSISTENCE_REQUIRED')
            self.active_intent = 'INITIALIZE_FIXED_INPUTS'
            self.maker.initialize_bundle()
            self.maker._mkdir(ROOT + '/journal')
            self.journal_ready = True
            setup_end = time.monotonic()
            self._record('initialization.json', dict(initial_intent_receipt=receipt,
                setup_start_monotonic=setup_start, setup_end_monotonic=setup_end,
                setup_cost_excluded_from_process_interval=True, runtime_compatibility=self.runtime_receipt))
            self.sample()
            self._selftest_gate()
            references, index = {}, 0
            for phase in self.plan['phases']:
                circuit = phase['circuit']
                freeze = material.recipe.requests.freeze_acquisition(self.plan, circuit,
                    material.pins.COUNTS[circuit], self.maker.common[circuit]['manifest.json']['sha256'])
                run_uid = 'e116-' + circuit
                binder = material.recipe.bindings.Binder(self.plan, circuit, freeze, run_uid)
                self._record(circuit + '_freeze.json', freeze)
                for node in phase['tasks']:
                    self._task(binder, freeze, node, index, references)
                    index += 1
            require(self.counts['tessent_debited'] == 48 and self.counts['translation_debited'] == 30 and
                    self.counts['committed_tasks'] == 78, 'EXACT_78_TASK_COMPLETION')
            self.sample()
        except BaseException as exc:
            self.failed = True
            error = dict(type=type(exc).__name__, code=str(exc) if type(exc) is ValueError else 'PACKAGE_OPERATION_FAILED')
        try:
            ended = time.monotonic()
        except BaseException as exc:
            ended = None
            self.failed = True
            error = error or dict(type=type(exc).__name__, code='FINAL_CLOCK_UNAVAILABLE')
        if setup_start is not None and setup_end is None:
            setup_end = ended
        self.summary = dict(schema=SCHEMA, status='STOPPED_FIRST_FAILURE' if self.failed else 'FIXED_78_TASKS_COLLECTED',
            error=error, counts=dict(self.counts), root=ROOT, sidecar=SIDECAR, boot_id=BOOT_ID,
            original_package_start=PACKAGE_START, original_package_deadline=PACKAGE_END,
            controller_start_monotonic=run_start, controller_end_monotonic=ended,
            initialization_start_monotonic=setup_start, initialization_end_monotonic=setup_end,
            package_elapsed_seconds=(ended - PACKAGE_START if type(ended) in (int, float) and
                                     math.isfinite(ended) and ended >= PACKAGE_START else None),
            failed_task_uid=self.active_intent if self.failed else None, completed_tasks=list(self.task_records),
            failed_operation_events=copy.deepcopy(self.events) if self.failed else [],
            full_session_cost_qualified=False, actual_atpg_runtime_ns=None, automatic_retries=0,
            memory_sampling_is_hard_guarantee=False, directory_sampling_is_quota=False,
            training_release=False, execution_ready=False, training_runs=0, lsf_used=False)
        if self.journal_ready:
            try:
                self._record('package_summary.json', self.summary)
            except BaseException as exc:
                self.failed = True
                self.summary.update(status='STOPPED_FIRST_FAILURE', summary_publication_error=type(exc).__name__)
        self.maker.close()
        return copy.deepcopy(self.summary)
