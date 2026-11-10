"""Thin LOCAL E140 adaptation of the pinned E139 scoped-session algorithm.

No grant, source freeze or controller release is installed by import. __file__
is the genuine adapter origin locator, NOT the effective private-code identity;
the latter is pinned independently and included in configuration/closure data.
Private native/script source loading, lifetime guards and cleanup remain the
reviewed algorithm. Trusted Python object mutation is not an adversarial sandbox.
"""
import copy
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import threading
import types

from scripts import e139_local_source_session as origin
from scripts import e140_native_graph_candidate as native
from scripts.e139_source_derivation import derive

FROZEN = None
_LOCK = threading.Lock()
REPO = Path(__file__).resolve().parents[1]
SELF = 'scripts/e140_local_source_session.py'
KEY = 'scripts.e139_local_source_session'
ORIGIN_SHA256 = 'a38a4c743a5bfd8d8c62530022ff4857af50aa6c7eb0c1a503aa1ac6926af1a0'
EFFECTIVE_SHA256 = 'c44fd740b9b711d1c9a28126092bd2014b5f4e787cfe5aa9bc698813937f7cdd'
EXTRA_SUPPORT = {
    'scripts/e139_local_source_session.py': ORIGIN_SHA256,
    'scripts/e140_native_graph_candidate.py': 'a1bd104d00d66d80d0bd5da18dd6bf22f1d2e731049711276c0dc31ff674936a',
    'scripts/bootstrap_builtins_repair_candidate.py': '898da047ee67ab33928c082bcfcf73ca7cd8cbebe93cf2d320f146698e2a5112',
}
_SUPPORT_TEXT = ''.join('    ' + repr(path) + ': ' + repr(pin) + ',\n' for path,pin in EXTRA_SUPPORT.items())
REPLACEMENTS = (
    ('from scripts import e139_native_graph_candidate as native', 'from scripts import e140_native_graph_candidate as native', 1),
    ("SELF = 'scripts/e139_local_source_session.py'", "SELF = 'scripts/e140_local_source_session.py'", 1),
    ('SUPPORT_PINS = {\n', 'SUPPORT_PINS = {\n' + _SUPPORT_TEXT, 1),
    ("'schema': 'e139-local-source-session-bindings-v1',", "'schema': 'e140-local-source-session-bindings-v1',\n    'effective_session_code_sha256': E140_SESSION_CODE_SHA256,", 1),
    ("'v6_e139_clean_F_replay_r1'", "'v6_e140_clean_F_replay_r1'", 1),
    ('native.pair.PHASE_NEW', 'native.PHASE', 1),
    ('native.pair.ROOT_NEW', 'native.ROOT', 1),
    ("row['sha256'] for row in native.specification()['origins']",
     "row['sha256'] for row in native.previous.specification()['origins']", 1),
    ("closure['bindings.e139_local_source_session'] = self._frozen['binding_sha256']",
     "closure['bindings.e140_local_source_session'] = self._frozen['binding_sha256']\n"
     "        closure['effective.scripts.e140_local_source_session'] = E140_SESSION_CODE_SHA256", 1),
)


def specification():
    return dict(schema='e139-source-derivation-v1',
        origins=[dict(name=KEY,sha256=ORIGIN_SHA256,effective_sha256=EFFECTIVE_SHA256)],
        rules=[dict(source=KEY,old_hex=old.encode('ascii').hex(),new_hex=new.encode('ascii').hex(),count=count)
               for old,new,count in REPLACEMENTS])


def build(raw):
    """Pure finite byte derivation; does not compile, read or install anything."""
    return derive({KEY:raw},specification())


def effective_maps():
    return ({row['name']:row['effective_sha256'] for row in native.specification()['origins']},
            dict(origin.SCRIPT_PINS,e138_packet=origin.packet_candidate.EFFECTIVE_SHA256))


def origin_manifest(adapter_sha256):
    pins = origin.origin_manifest(adapter_sha256)
    pins.update(EXTRA_SUPPORT)
    pins[SELF] = adapter_sha256
    return pins


def bindings():
    return dict(origin.BINDINGS,schema='e140-local-source-session-bindings-v1',
                effective_session_code_sha256=EFFECTIVE_SHA256,
                **{'phase_store.PHASE':native.PHASE})


def binding_digest():
    return hashlib.sha256(json.dumps(bindings(),sort_keys=True,ensure_ascii=True,
                          separators=(',',':'),allow_nan=False).encode('ascii')).hexdigest()


def _admit():
    f = FROZEN
    origin._require(type(f) is dict and set(f)=={'origin_sha256','effective_native_sha256',
        'effective_script_sha256','adapter_sha256','binding_sha256'},'E140_SESSION_NO_SOURCE_FREEZE')
    origin._require(origin._hex(f['adapter_sha256']) and f['origin_sha256']==origin_manifest(f['adapter_sha256']),
                    'E140_SESSION_ORIGIN_MANIFEST')
    pins,scripts = effective_maps()
    origin._require(f['effective_native_sha256']==pins and f['effective_script_sha256']==scripts and
                    f['binding_sha256']==binding_digest(),'E140_SESSION_EFFECTIVE_OR_BINDING_MANIFEST')
    return copy.deepcopy(f)


@contextmanager
def local_session():
    frozen = _admit()  # Default denial before source read, compile or registry.
    origin._require(_LOCK.acquire(blocking=False),'E140_SESSION_SINGLE_ACTIVE')
    try:
        with (REPO/'scripts/e139_local_source_session.py').open('rb') as stream:
            raw = stream.read(65537)
        result = build(raw)
        module = types.ModuleType('_e140_exact_private_source_session')
        module.__file__ = __file__  # Genuine origin locator; effective SHA above.
        module.E140_SESSION_CODE_SHA256 = EFFECTIVE_SHA256
        exec(compile(result.private_sources()[KEY],'<e140-derived-source-session>','exec'),module.__dict__)
        origin._require(module.BINDINGS==bindings() and module.binding_digest()==frozen['binding_sha256'],
                        'E140_SESSION_DERIVED_BINDING_CONSISTENCY')
        module.FROZEN = frozen
        with module.local_session() as session:
            yield session
    finally:
        _LOCK.release()
