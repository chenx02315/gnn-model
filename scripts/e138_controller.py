"""Bounded, default-disabled E138 orchestration. No live transport is installed.

RELEASE is an independently installed local review, never candidate data. An
injected adapter is trusted test machinery, NOT host authentication or consent.
No resume, retries, grant discovery, SSH, or scientific-success assertion.
"""
import copy
import datetime
import json
from pathlib import Path
import time
import types

from scripts import e138_packet as packet
from scripts import e138_reviewed_envelope as envelope
from scripts import e138_controller_clock as clock
from scripts import e138_phase_store as storage
from src.data import physical_e138_contract as contract
from src.data import physical_e138_role2_join as joiner
from src.data import physical_e138_role3_export as exporter

AUTHORIZATION_SHA256 = None
PROPOSAL_SHA256 = None
RELEASE = None
ROLES = storage.ROLES
LIMITS = dict(capture=60, execution=2400, readback=60)
require = contract.require
canonical, sha = packet.canonical, packet.sha


def _private_function(function, **bindings):
    namespace = dict(function.__globals__, **bindings)
    return types.FunctionType(function.__code__, namespace)


class Controller:
    """Single original phase, three consumed connections, trusted local staging.

    Adapter.send receives exact reviewed payload/command plus an explicit timeout
    and host identity. Only simulation adapters are currently supported. Adapter
    exceptions consume the intent and produce a terminal bounded transport record.
    RELEASE binds adapter source, native validator sources and each exact review.
    Python monkeypatching is outside this trusted-process threat boundary.
    """
    def __init__(self, staging, authority, proposal, adapter):
        # This check precedes file reads, clocks, store creation and callbacks.
        f = RELEASE
        require(type(f) is dict and contract._hex(AUTHORIZATION_SHA256) and
                contract._hex(PROPOSAL_SHA256), 'E138_CONTROLLER_NO_RELEASE')
        require(set(f) == {'authorization_sha256', 'proposal_sha256', 'adapter_source_sha256',
                           'host', 'native_source_sha256', 'roles'} and
                f['authorization_sha256'] == AUTHORIZATION_SHA256 and
                f['proposal_sha256'] == PROPOSAL_SHA256, 'E138_CONTROLLER_RELEASE_PINS')
        contract.check_authority(authority, proposal, AUTHORIZATION_SHA256, PROPOSAL_SHA256)
        require(type(f['roles']) is dict and set(f['roles']) == set(ROLES) and
                type(f['host']) is str and f['host'] == 'bupt-vncs2' and
                getattr(adapter, 'scope', None) == 'LOCAL_SIMULATION_ONLY',
                'E138_CONTROLLER_ADAPTER_SCOPE')
        import inspect
        adapter_raw = Path(inspect.getfile(type(adapter))).read_bytes()
        require(sha(adapter_raw) == f['adapter_source_sha256'], 'E138_CONTROLLER_ADAPTER_SOURCE')
        modules = (packet, envelope, clock, storage, contract, joiner, exporter)
        require(set(f['native_source_sha256']) == {m.__name__ for m in modules} and
                all(sha(Path(m.__file__).read_bytes()) == f['native_source_sha256'][m.__name__]
                    for m in modules), 'E138_CONTROLLER_NATIVE_SOURCE')
        self.freeze = copy.deepcopy(f)
        self.authority, self.proposal, self.adapter = authority, proposal, adapter
        self.store = storage.PhaseStore(staging, AUTHORIZATION_SHA256, PROPOSAL_SHA256)
        self.start = self.store.create()
        self.index, self.terminal, self.original_clock = 0, False, None

    def _stop(self, reason):
        self.terminal = True
        if not self.store._closed:
            self.store.close(reason)

    def install_review(self, role, independently_frozen_descriptor):
        """Trusted local reviewer API, NOT a candidate/remote entrypoint.

        Review occurs after earlier raw outputs exist; installation never resets
        the original clock. Caller must independently review full packet bytes.
        This method does not assert reviewer identity or grant consent.
        """
        require(not self.terminal and self.index < 3 and role == ROLES[self.index] and
                self.freeze['roles'][role] is None,
                'E138_CONTROLLER_REVIEW_INSTALL_ORDER')
        self.store.remaining()
        require(type(independently_frozen_descriptor) is dict and
                set(independently_frozen_descriptor) == {'packet', 'review_sha256'} and
                contract._hex(independently_frozen_descriptor['review_sha256']),
                'E138_CONTROLLER_REVIEW_DESCRIPTOR')
        self.freeze['roles'][role] = copy.deepcopy(independently_frozen_descriptor)

    def _prepare(self, material, review_raw):
        role = ROLES[self.index]
        pinned = self.freeze['roles'][role]
        require(type(pinned) is dict and set(pinned) == {'packet', 'review_sha256'} and
                type(review_raw) is bytes and sha(review_raw) == pinned['review_sha256'],
                'E138_CONTROLLER_REVIEW_PIN')
        require(type(material) is dict and set(material) == {'template', 'inputs', 'sources',
                'worker_raw', 'loader_raw', 'envelope_raw'}, 'E138_CONTROLLER_MATERIAL')
        plan = _private_function(packet.prepare, EXPECTED=pinned['packet'])(**material)
        expected = dict(projection=plan['projection'], projection_sha256=plan['projection_sha256'],
                        payload_sha256=sha(plan['payload']), remote_command=plan['remote_command'],
                        host=self.freeze['host'], scope='LOCAL_SIMULATION_ONLY')
        require(review_raw == canonical(expected) and plan['projection']['role'] == role and
                plan['projection']['authorization_sha256'] == self.freeze['authorization_sha256'] and
                plan['projection']['proposal_sha256'] == self.freeze['proposal_sha256'],
                'E138_CONTROLLER_EXACT_REVIEW')
        inputs = material['inputs']
        require(inputs.get('authority') == self.authority and inputs.get('proposal') == self.proposal,
                'E138_CONTROLLER_AUTHORITY_JOIN')
        if role != 'capture':
            require(inputs.get('original_clock') == self.original_clock, 'E138_CONTROLLER_ORIGINAL_CLOCK_JOIN')
        if role == 'execution':
            require(inputs.get('role1_response') == (self.store.phase/'capture/stdout.raw').read_bytes(),
                    'E138_CONTROLLER_CAPTURE_RAW_JOIN')
        if role == 'readback':
            root = self.store.phase / 'execution'
            for key, filename in (('role2_stdout', 'stdout.raw'), ('role2_stderr', 'stderr.raw'),
                                  ('role2_transport', 'transport.json'), ('role2_intent', 'intent.json')):
                require(inputs.get(key) == (root / filename).read_bytes(), 'E138_CONTROLLER_ROLE2_PERSISTED_JOIN')
            intent = envelope.intent(role, sha(plan['payload']))
            frozen, package = envelope.derive(material['template'], inputs, intent, sha(plan['payload']))
            # Native raw receipt/cleanup validation, never a supplied owned bool.
            _private_function(joiner.join, FREEZE=frozen['readback']['join_freeze'])(package)
        return plan

    def run_role(self, material, review_raw):
        require(not self.terminal and self.index < 3, 'E138_CONTROLLER_TERMINAL')
        try:
            self.store.remaining()
            plan = self._prepare(material, review_raw)
            role = ROLES[self.index]
            timeout = min(LIMITS[role], self.store.remaining() - 10)
            require(timeout > 0, 'E138_CONTROLLER_RESERVE')
            intent = self.store.reserve(role, sha(plan['payload']))
            require(intent == envelope.intent(role, sha(plan['payload'])) and
                    (self.store.phase / role / 'intent.json').read_bytes() == canonical(intent),
                    'E138_CONTROLLER_PERSISTED_INTENT')
            timeout = min(LIMITS[role], self.store.remaining() - 10)
            require(timeout > 0, 'E138_CONTROLLER_RESERVE')
            try:
                result = self.adapter.send(host=self.freeze['host'], role=role,
                    payload=plan['payload'], remote_command=plan['remote_command'], timeout=timeout)
            except BaseException:
                result = dict(stdout=b'', stderr=b'', exit_code=None, timeout=False,
                              overflow=False, write_failed=False, threads_incomplete=True)
            def validate(raw, stderr, transport):
                if role == 'capture':
                    now = time.monotonic()
                    utc = datetime.datetime.now(datetime.timezone.utc).timestamp()
                    self.original_clock = clock.build(raw, (self.store.phase/'start.json').read_bytes(),
                        sha(plan['payload']), self.authority, self.proposal,
                        self.freeze['authorization_sha256'], self.freeze['proposal_sha256'],
                        now, utc, self.start['domain'])
                    storage.write_new(self.store.phase/'original_clock.json', self.original_clock)
                elif role == 'execution':
                    value = contract.decode(raw)
                    require(type(value) is dict and set(value) == {'role', 'worker_response',
                        'owned_root', 'cleanup_observation', 'execution_ready'} and
                        value['role'] == role and value['execution_ready'] is False and
                        type(value['owned_root']) is dict, 'E138_CONTROLLER_ROLE2_FRAME')
                else:
                    value = json.loads(raw.decode('utf-8'), object_pairs_hook=contract._pairs,
                        parse_constant=contract._nonfinite, parse_float=contract._finite_float)
                    if value.get('schema') == 'e138-readback-partial-failure-v1':
                        require(False, 'E138_CONTROLLER_READBACK_PARTIAL')
                    exporter.validate_result(value, complete=True)
                return canonical(dict(role=role, raw_sha256=sha(raw),
                    remote_authentication_proven=False, execution_ready=False,
                    scope='LOCAL_SIMULATION_ONLY'))
            receipt = self.store.record(result, validate)
            self.index += 1
            if self.index == 3:
                self._stop('CONTROLLER_STOP')
            return receipt
        except BaseException:
            failed = True
        if failed:
            try:
                self._stop('CONTROLLER_STOP')
            except BaseException:
                self.terminal = True
            raise ValueError('E138_CONTROLLER_STOPPED_FIRST_FAILURE') from None
