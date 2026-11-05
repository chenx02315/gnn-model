"""Bounded, default-disabled simulation and pinned E138 orchestration.

RELEASE is an independently installed local review, never candidate data. An
injected adapter is trusted test machinery, NOT host authentication or consent.
Pinned transport requires separate factory admission. No resume, retries, grant
discovery, or scientific-success assertion. No grant is installed by this code.
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
PINNED_RELEASE = None
ROLES = storage.ROLES
LIMITS = dict(capture=60, execution=2400, readback=60)
require = contract.require
canonical, sha = packet.canonical, packet.sha


def local_source_closure():
    """Inspect the complete repository-local static import closure, not stdlib.

    Includes package initializers. Dynamic remote source compilation is bound
    separately by the reviewed packet; this is not a Python execution sandbox.
    Caller must establish release authority before invoking this filesystem API.
    """
    import ast
    import importlib.util
    root = Path(__file__).resolve().parents[1]
    pending = ['scripts.e138_controller','scripts.run_prospective_metadata_v1']
    seen = {}
    def location(name):
        stem = root.joinpath(*name.split('.'))
        for path in (stem.with_suffix('.py'), stem/'__init__.py'):
            if path.is_file(): return path
        return None
    while pending:
        name = pending.pop()
        if name in seen: continue
        path = location(name)
        if path is None: continue
        raw = path.read_bytes()
        require(len(raw) <= 1048576, 'E138_CONTROLLER_LOCAL_SOURCE_BOUND')
        seen[name] = sha(raw)
        parts = name.split('.')
        for count in range(1,len(parts)):
            pending.append('.'.join(parts[:count]))
        package = name if path.name == '__init__.py' else name.rpartition('.')[0]
        for node in ast.walk(ast.parse(raw)):
            if isinstance(node,ast.Import):
                pending.extend(alias.name for alias in node.names)
            elif isinstance(node,ast.ImportFrom):
                target = (importlib.util.resolve_name('.'*node.level+(node.module or ''),package)
                          if node.level else node.module)
                if target:
                    pending.append(target)
                    pending.extend(target+'.'+alias.name for alias in node.names if alias.name != '*')
    return seen


def _private_function(function, **bindings):
    namespace = dict(function.__globals__, **bindings)
    return types.FunctionType(function.__code__, namespace)


class Controller:
    """Single original phase, three consumed connections, trusted local staging.

    Adapter.send receives exact reviewed payload/command plus an explicit timeout
    and host identity. __init__ accepts simulation adapters only; create_pinned
    constructs the exact separately pinned transport with no caller adapter.
    Adapter
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
        self._pinned_mode = False

    @classmethod
    def create_pinned(cls, staging, authority, proposal):
        """Separate production-shaped admission; defaults still deny all IO.

        No caller adapter can substitute for the exact pinned transport class.
        Both controller and transport grants require independent installation.
        No endpoint is contacted here; constructor compilation consumes the
        original local package clock, which is never restarted.
        """
        f = PINNED_RELEASE
        require(type(f) is dict and contract._hex(AUTHORIZATION_SHA256) and
                contract._hex(PROPOSAL_SHA256), 'E138_CONTROLLER_NO_PINNED_RELEASE')
        require(set(f) == {'authorization_sha256','proposal_sha256','adapter_source_sha256',
                'host','host_key','helper_sha256','scope','local_source_sha256','roles'} and
                f['authorization_sha256'] == AUTHORIZATION_SHA256 and
                f['proposal_sha256'] == PROPOSAL_SHA256, 'E138_CONTROLLER_PINNED_RELEASE')
        contract.check_authority(authority,proposal,AUTHORIZATION_SHA256,PROPOSAL_SHA256)
        closure = local_source_closure()
        require(type(f['local_source_sha256']) is dict and closure == f['local_source_sha256'] and
                closure.get('scripts.e138_pinned_transport') == f['adapter_source_sha256'],
                'E138_CONTROLLER_PINNED_SOURCE_CLOSURE')
        # Verify source bytes before importing newly reachable adapter code.
        from scripts import e138_pinned_transport as pinned
        require(f['host'] == pinned.HOST and f['host_key'] == pinned.HOST_KEY and
                f['helper_sha256'] == pinned.HELPER_SHA256 and
                f['scope'] == pinned.PinnedTransport.scope and
                type(f['roles']) is dict and set(f['roles']) == set(ROLES),
                'E138_CONTROLLER_PINNED_IDENTITY')
        instance = cls.__new__(cls)
        instance.freeze = copy.deepcopy(f)
        instance.authority, instance.proposal = authority,proposal
        instance.store = storage.PhaseStore(staging,AUTHORIZATION_SHA256,PROPOSAL_SHA256)
        instance.start = instance.store.create()
        instance.index, instance.terminal, instance.original_clock = 0,False,None
        instance._pinned_mode = True
        failed = False
        try:
            instance.adapter = pinned.PinnedTransport(authority,proposal)
            require(type(instance.adapter) is pinned.PinnedTransport,
                    'E138_CONTROLLER_PINNED_ADAPTER_TYPE')
            instance._adapter_type = pinned.PinnedTransport
            instance.store.remaining()
            return instance
        except BaseException:
            failed = True
        if failed:
            try: instance._stop('CONTROLLER_STOP')
            except BaseException: instance.terminal = True
            raise ValueError('E138_CONTROLLER_PINNED_CONSTRUCTION_FAILED') from None

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
                        host=self.freeze['host'], scope=(self.freeze['scope'] if self._pinned_mode else 'LOCAL_SIMULATION_ONLY'))
        if self._pinned_mode:
            expected.update(host_key=self.freeze['host_key'],helper_sha256=self.freeze['helper_sha256'],
                adapter_source_sha256=self.freeze['adapter_source_sha256'],
                local_source_sha256=self.freeze['local_source_sha256'])
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

    def _persist_native(self, result, role, origin='NATIVE_ADAPTER_RETURN'):
        """Save bounded raw prefixes and all native fields BEFORE projection.

        Malformed/non-JSON field values get a bounded invalid-type marker, never
        repr/private exception text. Valid native receipts retain every field.
        Projection is explicitly labelled; the full receipt is never overwritten.
        """
        directory = self.store.phase/role
        values = result if type(result) is dict else {}
        saved = {}
        projected = {}
        bounded = True
        remaining_cap = storage.CAPS[role]
        for name in ('stdout','stderr'):
            cap = remaining_cap
            value = values.get(name)
            raw = value[:cap] if type(value) is bytes else b''
            bounded = bounded and type(value) is bytes and len(value) <= cap
            storage.write_new(directory/('native_'+name+'.raw'),raw)
            remaining_cap -= len(raw)
            saved[name] = dict(file='native_'+name+'.raw',bytes=len(raw),sha256=sha(raw),
                original_bytes=len(value) if type(value) is bytes else None,
                prefix_only=type(value) is not bytes or len(value)>cap)
            projected[name] = raw if name == 'stdout' else raw[:65536]
            if name == 'stderr' and type(value) is bytes and len(value)>65536:
                bounded = False
        for name in ('exit_code','timeout','overflow','write_failed','threads_incomplete','remote_termination_verified'):
            value = values.get(name)
            if name not in values:
                saved[name] = {'missing':True}
            elif (name == 'exit_code' and (value is None or (type(value) is int and abs(value)<2**31))) or (name != 'exit_code' and type(value) is bool):
                saved[name] = value
            else:
                saved[name] = {'invalid_native_field':True}
        exact = set(values) == storage.RESULT_KEYS|{'remote_termination_verified'}
        storage.write_new(directory/'native_transport.json',canonical(dict(
            schema='e138-full-native-transport-v1',result=saved,exact_native_keys=exact,
            receipt_origin=origin,native_result_received=origin=='NATIVE_ADAPTER_RETURN',
            phase_store_projection='EXPLICIT_SEVEN_KEY_PROJECTION_NOT_FULL_NATIVE_RECEIPT')))
        valid = exact and bounded and origin=='NATIVE_ADAPTER_RETURN' and values.get('remote_termination_verified') is False
        code = values.get('exit_code')
        valid_code = code is None or (type(code) is int and abs(code)<2**31)
        valid = valid and valid_code
        projected['exit_code'] = code if valid_code else None
        for name in ('timeout','overflow','write_failed','threads_incomplete'):
            value = values.get(name)
            valid = valid and type(value) is bool
            projected[name] = value if type(value) is bool else True
        if not valid: projected['threads_incomplete'] = True
        return projected

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
            if self._pinned_mode:
                require(type(self.adapter) is self._adapter_type and
                        local_source_closure() == self.freeze['local_source_sha256'],
                        'E138_CONTROLLER_PINNED_ADAPTER_OR_SOURCE_DRIFT')
            timeout = min(LIMITS[role], self.store.remaining() - 10)
            require(timeout > 0, 'E138_CONTROLLER_RESERVE')
            origin = 'NATIVE_ADAPTER_RETURN'
            try:
                result = self.adapter.send(host=self.freeze['host'], role=role,
                    payload=plan['payload'], remote_command=plan['remote_command'], timeout=timeout)
            except BaseException:
                origin = 'LOCAL_ADAPTER_EXCEPTION'
                result = dict(stdout=b'', stderr=b'', exit_code=None, timeout=False,
                              overflow=False, write_failed=False, threads_incomplete=True)
            if self._pinned_mode:
                result = self._persist_native(result,role,origin)
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
                    scope=self.freeze['scope'] if self._pinned_mode else 'LOCAL_SIMULATION_ONLY'))
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
