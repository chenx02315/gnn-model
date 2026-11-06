"""Scoped fixed-local E139 graph/configuration; NOT an entry or release.

FROZEN pins local code only, never authorization or review. All external packet,
controller and transport gates remain None. No simulation constructor support.
Private references must stay within this single-worker session. Trusted Python
mutation is outside the threat model. Closing terminalizes tracked controllers
without filesystem, network or clock operations; it does not revoke raw refs.
"""
import base64
import copy
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import stat
import sys
import threading
import types

from scripts import e139_native_graph_candidate as native
from scripts import e139_packet_candidate as packet_candidate

FROZEN = None
_LOCK = threading.Lock()
REPO = Path(__file__).resolve().parents[1]
SELF = 'scripts/e139_local_source_session.py'
SCRIPT_ORDER = ('e138_phase_store', 'e138_reviewed_envelope', 'e138_controller_clock',
                'e138_packet', 'e138_source_session', 'e138_pinned_transport', 'e138_controller')
SCRIPT_PINS = {
    'e138_controller': '0748c3fb9b8c4144de938066e1fa1bd5da2deab994e617742f0970624f4100dd',
    'e138_phase_store': '1852ad7622c5e3b6eeee1541cb0965869dccd468884fe883b190c2fa29b32f75',
    'e138_controller_clock': '4049a59c12b75c46a8235b9be32db85a24acff3dee3541a6a502c20d69d585d1',
    'e138_pinned_transport': '7116e26ab66ae951c7eb8ab51e41eee99d6a397238ec277bb868719fd8b90693',
    'e138_reviewed_envelope': '6b46afad88f3894e1798dd9703781ba676a865f3dea88a4dce8b4b677867d7db',
    'e138_source_session': 'e98ca167923c0d0e964578b42877c7d61043317dfaaa2e5cf9c0eef4854987cc',
    'e138_packet': 'cef358fc68fa56894bb7f84d8fbcdaf6e871e99540f540b43aa5646ab34db826',
}
SUPPORT_PINS = {
    'scripts/run_prospective_metadata_v1.py': 'e0b1e62352781f96dc7d0e5a2a1a27e7f278b63c8aaaa07dbd946c1795c0f434',
    'scripts/e139_source_derivation.py': '15d024613ced492c3d9371ed18b850d4b98226b474828d1006c208f57b21d40f',
    'scripts/e139_contract_bootstrap_candidate.py': 'a4990b27e84a175651efe847a1193ea16399b411fc1dbe1b827b7e8ce0126624',
    'scripts/e139_runtime_identity_candidate.py': '0647022da7ef24b55734f70b4a258be64ca2ed7aa40e5f85945a485b86bba5ad',
    'scripts/e139_native_graph_candidate.py': '30ef062e6ccc3a5ee8910d089a2f779c49bc7c6ee7f834447fab7712f64268ea',
    'scripts/e139_packet_candidate.py': '4838bec6a14b064bce638d5c61e142b121527bcc930511ea475cbbc0cdb43f51',
}
BINDINGS = {
    'schema': 'e139-local-source-session-bindings-v1',
    'phase_store.PHASE': 'v6_e139_clean_F_replay_r1',
    'packet.SOURCE_BYTES': 'EXACT_KEY_scripts.e138_packet_EFFECTIVE_RAM_BYTES',
    'controller.local_source_closure': 'FIXED_ORIGINS_RECHECKED_THEN_EFFECTIVE_MAP_PLUS_BINDING_CLOSURE',
    'controller.simulation_constructor': 'UNSUPPORTED',
    'controller.create_pinned/run_role': 'SESSION_ALIVE_GUARDED_TRACKED_TERMINAL_ON_CLOSE',
    'transport.__file__': 'VERIFIED_ORIGIN_LOCATOR_FOR_FIXED_HELPER_ONLY_NOT_CODE_IDENTITY',
    'package_parents': 'SYNTHETIC_EMPTY_PATH_PREVENTS_DISK_IMPORT_FALLBACK',
    'external_release_installed': False,
}


def _require(ok, code):
    if not ok:
        raise ValueError(code)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _hex(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def origin_manifest(adapter_sha256):
    """Expected fixed roster; caller supplies independently reviewed SELF pin.

    A self-referential literal source hash is impossible. This parameter only
    expresses a proposed snapshot; it neither installs FROZEN nor reviews it.
    """
    _require(_hex(adapter_sha256), 'E139_SESSION_ADAPTER_PIN')
    pins = dict(SUPPORT_PINS)
    pins[SELF] = adapter_sha256
    pins.update({'scripts/' + name + '.py': pin for name, pin in SCRIPT_PINS.items()})
    pins.update({'src/data/' + row['name'] + '.py': row['sha256'] for row in native.specification()['origins']})
    return pins


def effective_maps():
    return ({row['name']: row['effective_sha256'] for row in native.specification()['origins']},
            dict(SCRIPT_PINS, e138_packet=packet_candidate.EFFECTIVE_SHA256))


def binding_digest():
    return _sha(json.dumps(BINDINGS, sort_keys=True, ensure_ascii=True,
                           separators=(',', ':'), allow_nan=False).encode('ascii'))


def _admit():
    f = FROZEN
    _require(type(f) is dict and set(f) == {'origin_sha256', 'effective_native_sha256',
             'effective_script_sha256', 'adapter_sha256', 'binding_sha256'}, 'E139_SESSION_NO_SOURCE_FREEZE')
    _require(_hex(f['adapter_sha256']) and f['origin_sha256'] == origin_manifest(f['adapter_sha256']),
             'E139_SESSION_ORIGIN_MANIFEST')
    _require(f['binding_sha256'] == binding_digest(), 'E139_SESSION_BINDING_DIGEST')
    pins, scripts = effective_maps()
    _require(f['effective_native_sha256'] == pins and f['effective_script_sha256'] == scripts,
             'E139_SESSION_EFFECTIVE_MANIFEST')
    return copy.deepcopy(f)


def _read_origins(frozen):
    result = {}
    for relative, pin in frozen['origin_sha256'].items():
        # Roster equality above disallows unknown paths; reject symlink/reparse
        # parents too, not just leaves. No alternate paths or cache discovery.
        path = REPO / relative
        try:
            path.resolve().relative_to(REPO.resolve())
        except ValueError:
            raise ValueError('E139_SESSION_PATH_ESCAPE') from None
        leaf = path.lstat()
        _require(stat.S_ISREG(leaf.st_mode), 'E139_SESSION_REGULAR_FILE')
        current = path
        while current != REPO:
            info = current.lstat()
            _require(not current.is_symlink() and not getattr(info, 'st_file_attributes', 0) & 1024,
                     'E139_SESSION_LINK_OR_REPARSE')
            current = current.parent
        with path.open('rb') as stream:
            raw = stream.read(1048577)
        _require(0 < len(raw) <= 1048576 and _sha(raw) == pin, 'E139_SESSION_ORIGIN_DRIFT')
        result[relative] = raw
    return result


class Session:
    def __init__(self, frozen, origins, native_bytes, script_bytes):
        self._frozen, self._native, self._scripts = frozen, native_bytes, script_bytes
        self._alive, self._controllers = True, []
        self.modules = {}
        self.binding_manifest = copy.deepcopy(BINDINGS)

    def _check(self):
        _require(self._alive, 'E139_SESSION_CLOSED')

    def local_source_closure(self):
        self._check()
        self._check_bindings()
        _read_origins(self._frozen)
        _require({n: _sha(v) for n, v in self._native.items()} == self._frozen['effective_native_sha256'] and
                 {n: _sha(v) for n, v in self._scripts.items()} == self._frozen['effective_script_sha256'],
                 'E139_SESSION_EFFECTIVE_DRIFT')
        closure = {'src.data.' + name: _sha(raw) for name, raw in self._native.items()}
        closure.update({'scripts.' + name: _sha(raw) for name, raw in self._scripts.items()})
        closure.update({path[:-3].replace('/', '.'): pin for path, pin in self._frozen['origin_sha256'].items()
                        if path in SUPPORT_PINS or path == SELF})
        closure['bindings.e139_local_source_session'] = self._frozen['binding_sha256']
        return closure

    def _check_bindings(self):
        s, n = self.modules, self.native_modules
        c = n['physical_e138_contract']
        _require(self.binding_manifest == BINDINGS and binding_digest() == self._frozen['binding_sha256'] and
            s['e138_phase_store'].PHASE == BINDINGS['phase_store.PHASE'] == c.PHASE == native.pair.PHASE_NEW and
            c.ROOT == native.pair.ROOT_NEW and s['e138_packet'].SOURCE_BYTES is self._packet_provider and
            s['e138_controller'].local_source_closure == self.local_source_closure and
            s['e138_controller'].Controller is self._controller_type and
            s['e138_controller'].contract is c and s['e138_controller'].require is c.require and
            all(getattr(s['e138_controller'], alias) is s[name] for alias, name in
                (('packet','e138_packet'), ('envelope','e138_reviewed_envelope'),
                 ('clock','e138_controller_clock'), ('storage','e138_phase_store'))) and
            s['e138_controller_clock'].contract is c and
            s['e138_controller_clock'].capture is n['physical_replay_capture_e138'] and
            s['e138_controller_clock'].runtime is n['physical_e138_runtime_primitives'] and
            s['e138_pinned_transport'].contract is c and
            s['e138_pinned_transport'].envelope is s['e138_reviewed_envelope'],
            'E139_SESSION_BINDING_DRIFT')

    def _bind(self):
        modules = self.modules
        modules['e138_phase_store'].PHASE = BINDINGS['phase_store.PHASE']
        def source_bytes(key):
            self._check()
            _require(type(key) is str and key == 'scripts.e138_packet', 'E139_SESSION_PACKET_SOURCE_KEY')
            _require(_sha(self._scripts['e138_packet']) == self._frozen['effective_script_sha256']['e138_packet'],
                     'E139_SESSION_EFFECTIVE_DRIFT')
            return self._scripts['e138_packet']
        modules['e138_packet'].SOURCE_BYTES = source_bytes
        self._packet_provider = source_bytes
        controller = modules['e138_controller']
        controller.local_source_closure = self.local_source_closure
        original = controller.Controller
        session = self
        class ScopedController(original):
            def __init__(self, *args, **kwargs):
                session._check()
                raise ValueError('E139_SESSION_SIMULATION_UNSUPPORTED')
            @classmethod
            def create_pinned(cls, *args, **kwargs):
                session._check()
                instance = original.create_pinned.__func__(cls, *args, **kwargs)
                session._controllers.append(instance)
                return instance
            def run_role(self, *args, **kwargs):
                session._check()
                return original.run_role(self, *args, **kwargs)
        controller.Controller = ScopedController
        self._controller_type = ScopedController

    def close(self):
        self._alive = False
        for instance in self._controllers:
            instance.terminal = True
            if hasattr(instance, 'adapter'):
                instance.adapter._terminal = True


@contextmanager
def local_session():
    frozen = _admit()  # Default denial before IO, lock, compile or registry.
    _require(_LOCK.acquire(blocking=False), 'E139_SESSION_SINGLE_ACTIVE')
    saved = None
    session = None
    native_entered = False
    try:
        origins = _read_origins(frozen)
        native_bytes = native.build({name: origins['src/data/' + name + '.py'] for name in native.SOURCE_ORDER}).private_sources()
        script_bytes = {name: origins['scripts/' + name + '.py'] for name in SCRIPT_ORDER}
        script_bytes['e138_packet'] = packet_candidate.build(script_bytes['e138_packet']).private_sources()[packet_candidate.KEY]
        _require({n: _sha(v) for n, v in native_bytes.items()} == frozen['effective_native_sha256'] and
                 {n: _sha(v) for n, v in script_bytes.items()} == frozen['effective_script_sha256'], 'E139_SESSION_EFFECTIVE_DRIFT')
        compiled = {n: compile(raw, '<e139-local-' + n + '>', 'exec') for n, raw in script_bytes.items()}
        session = Session(frozen, origins, native_bytes, script_bytes)
        saved = {n: mod for n, mod in sys.modules.items() if n == 'scripts' or n.startswith('scripts.')}
        for name in saved:
            del sys.modules[name]
        parent = types.ModuleType('scripts'); parent.__path__ = []; sys.modules['scripts'] = parent
        for name in SCRIPT_ORDER:
            # Load the private native graph BEFORE the first native consumer.
            if name == 'e138_controller_clock':
                loader = types.ModuleType('_e139_local_native_loader')
                exec(compiled['e138_source_session'], loader.__dict__)
                loader.FROZEN_SOURCE_SHA256 = frozen['effective_native_sha256']
                loader.FROZEN_SOURCE_ORDER = native.SOURCE_ORDER
                rows = [dict(name=n, sha256=frozen['effective_native_sha256'][n],
                             body_base64=base64.b64encode(native_bytes[n]).decode('ascii')) for n in native.SOURCE_ORDER]
                native_context = loader.source_session(rows)
                session.native_modules = native_context.__enter__()
                native_entered = True
            module = types.ModuleType('scripts.' + name); module.__package__ = 'scripts'
            if name == 'e138_pinned_transport':
                module.__file__ = str(REPO / 'scripts/e138_pinned_transport.py')
            sys.modules[module.__name__] = module; setattr(parent, name, module)
            exec(compiled[name], module.__dict__)
            module.__source_sha256__ = frozen['effective_script_sha256'][name]
            session.modules[name] = module
        session._bind()
        yield session
    finally:
        try:
            if session is not None:
                session.close()
        finally:
            try:
                if native_entered:
                    native_context.__exit__(None, None, None)
            finally:
                try:
                    if saved is not None:
                        for name in list(sys.modules):
                            if name == 'scripts' or name.startswith('scripts.'):
                                del sys.modules[name]
                        sys.modules.update(saved)
                finally:
                    _LOCK.release()
