"""Fixed LOCAL E140 public facade. No installed authority or automatic run.

The private backend is an exact finite derivation of the reviewed E139 wrapper,
not a reconfiguration of historical globals. One context owns one staged clock.
Extra sources live in the entry manifest, not the controller's core closure;
trusted-local check-to-send races are not an adversarial sandbox guarantee.
"""
import copy
from contextlib import contextmanager
from pathlib import Path
import threading
import types

from scripts import run_physical_f_clean_replay_e139 as old
from scripts import e140_public_entry_derivation as derivation
from scripts import e140_entry_candidate as candidate
from scripts import e140_local_materials as materials
from scripts import e140_local_source_session as session_source

AUTH_SHA256 = REVIEW_PINS = SOURCE_FREEZE = None
PROPOSAL_SHA256 = candidate.PROPOSAL_SHA256
REPO = Path(__file__).resolve().parents[1]
SELF = 'scripts/run_physical_f_clean_replay_e140.py'
_FIXED_REPO = REPO
_LOCK = threading.Lock()
SUPPORT_PINS = dict(old.SUPPORT_PINS, **{
    'scripts/run_physical_f_clean_replay_e139.py': derivation.ORIGIN_SHA256,
    'scripts/e140_public_entry_derivation.py': '9d286c9894e55e55a1cb43ac740a2b714666ee79868bfd38b6e573743e3c18fb',
    'scripts/e140_entry_candidate.py': '9d3f8c69b2f52fdbd4d0e3030b9cd38effbc67c8f2474357798039eefa38e5e6',
    'scripts/e140_local_materials.py': '58d62bb987147eae4f14c68d35f8a4588cd5e4e6447e82a363bb81de4ab10489',
    'scripts/e140_local_source_session.py': '6c99f49bf45715a40df0591d841a0d3274463e8e72b57e058092a3c488dd87eb',
})
BINDINGS = dict(old.BINDINGS, schema='e140-fixed-public-entry-bindings-v1',
    effective_wrapper_sha256=derivation.EFFECTIVE_SHA256,
    materials='FIXED_E140_LOCAL_MATERIALS_PLUS_BOUNDED_OWNED_EVIDENCE_READER',
    grant='EXACT_NEW_E140_PATH_PIN_CANONICAL_ASCII_NO_GENERATION')


def require(ok, code):
    if not ok: raise ValueError(code)


def binding_digest():
    return materials.origin.sha(materials.origin.contract.canonical(BINDINGS))


def origin_manifest(self_sha256):
    require(session_source.origin._hex(self_sha256), 'E140_PUBLIC_SELF_PIN')
    return dict(SUPPORT_PINS, **{SELF:self_sha256})


def _admit():
    require(REPO == _FIXED_REPO and session_source.REPO == REPO, 'E140_PUBLIC_ROOT_DRIFT')
    require(session_source.origin._hex(AUTH_SHA256) and PROPOSAL_SHA256 == candidate.PROPOSAL_SHA256,
            'E140_PUBLIC_AUTHORITY_PINS_REQUIRED')
    f=SOURCE_FREEZE
    require(type(f) is dict and set(f)=={'session','origin_sha256','effective_entry_sha256','binding_sha256'},
            'E140_PUBLIC_SOURCE_FREEZE_REQUIRED')
    origins=f['origin_sha256']
    require(type(origins) is dict and origins==origin_manifest(origins.get(SELF)) and
        f['effective_entry_sha256']==candidate.EFFECTIVE_SHA256 and f['binding_sha256']==binding_digest(),
        'E140_PUBLIC_SOURCE_OR_BINDING_FREEZE')
    s=f['session']; native,scripts=session_source.effective_maps()
    require(type(s) is dict and set(s)=={'origin_sha256','effective_native_sha256','effective_script_sha256','adapter_sha256','binding_sha256'} and
        s['origin_sha256']==session_source.origin_manifest(s['adapter_sha256']) and
        s['effective_native_sha256']==native and s['effective_script_sha256']==scripts and
        s['binding_sha256']==session_source.binding_digest(), 'E140_PUBLIC_SESSION_FREEZE')
    require(REVIEW_PINS is None or (type(REVIEW_PINS) is dict and set(REVIEW_PINS)<={'capture'} and
        all(session_source.origin._hex(p) for p in REVIEW_PINS.values())), 'E140_PUBLIC_REVIEW_PINS')
    return copy.deepcopy(f),AUTH_SHA256,copy.deepcopy(REVIEW_PINS)


class _Run:
    def __init__(self, owner, run): self._owner,self._run=owner,run
    def __repr__(self): return '<E140 PRIVATE STAGED RUN>'
    def __reduce_ex__(self, protocol): raise TypeError('E140_PRIVATE_NOT_SERIALIZABLE')
    def execute(self, prepared, record):
        self._owner._check(); return self._run.execute(prepared,record)
    def prepare_execution(self):
        self._owner._check(); return self._run.prepare_execution()
    def prepare_readback(self):
        self._owner._check(); return self._run.prepare_readback()


class Entry:
    def __repr__(self): return '<E140 FIXED PRIVATE ENTRY; no automatic run>'
    def __reduce_ex__(self, protocol): raise TypeError('E140_PRIVATE_NOT_SERIALIZABLE')
    def _check(self):
        require(self._alive, 'E140_PUBLIC_ENTRY_CLOSED')
        require(REPO==_FIXED_REPO and AUTH_SHA256==self._auth and SOURCE_FREEZE==self._freeze and
            REVIEW_PINS==self._reviews and PROPOSAL_SHA256==candidate.PROPOSAL_SHA256 and
            binding_digest()==self._freeze['binding_sha256'], 'E140_PUBLIC_FRONT_CONFIGURATION_DRIFT')
        self._backend._check()
    def prepare_capture(self):
        self._check(); return self._backend.prepare_capture()
    def install_review_pin(self, role, externally_reviewed_record_sha256):
        self._check(); return self._backend.install_review_pin(role,externally_reviewed_record_sha256)
    def public_source_manifest(self):
        self._check(); return self._backend.public_source_manifest()
    def start(self, prepared, independent_record_raw):
        self._check(); return _Run(self,self._backend.start(prepared,independent_record_raw))


@contextmanager
def open_entry():
    f,auth,reviews=_admit()  # Default denial before read/compile/lock.
    require(_LOCK.acquire(blocking=False),'E140_PUBLIC_SINGLE_ACTIVE')
    front=None
    try:
        raw=materials.origin._read(REPO/'scripts/run_physical_f_clean_replay_e139.py',65536,derivation.ORIGIN_SHA256)
        effective=derivation.build(raw).private_sources()[derivation.KEY]
        backend=types.ModuleType('_e140_fixed_public_backend')
        backend.E140_CANDIDATE=candidate
        backend.E140_MATERIALS=types.SimpleNamespace(prepare=materials.prepare,READY=materials.READY,
            sha=materials.origin.sha,canonical=materials.origin.contract.canonical)
        backend.E140_SESSION=session_source
        backend.E140_REPO=REPO
        backend.E140_SUPPORT_PINS=dict(SUPPORT_PINS)
        backend.E140_WRAPPER_SHA=derivation.EFFECTIVE_SHA256
        exec(compile(effective,'<e140-effective-public-wrapper>','exec'),backend.__dict__)
        require(backend.BINDINGS==BINDINGS,'E140_PUBLIC_DERIVED_BINDING_DRIFT')
        backend.AUTH_SHA256,backend.REVIEW_PINS,backend.SOURCE_FREEZE=auth,copy.deepcopy(reviews),copy.deepcopy(f)
        with backend.open_entry() as entry:
            front=Entry(); front._alive=True
            front._backend,front._auth,front._freeze,front._reviews=entry,auth,f,reviews
            try: yield front
            finally: front._alive=False
    finally:
        if front is not None: front._alive=False
        _LOCK.release()
