"""Fixed local E139 entry binding. No CLI, automatic run, or installed grant.

open_entry() keeps one reviewed private source session alive for preparation,
independent review and explicitly requested staged operations. Source pins are
not authority. Trusted-process isolation is not a malicious Python sandbox.
"""
import copy
from contextlib import contextmanager
from pathlib import Path
import stat
import threading
import types

from scripts import e139_entry_candidate as candidate
from scripts import e139_local_materials as materials
from scripts import e139_local_source_session as session_source

AUTH_SHA256 = None
REVIEW_PINS = None
SOURCE_FREEZE = None
PROPOSAL_SHA256 = '4b8a915f06482f25425c71b07c6eba8c002c1455b59e28023ce5e0a806bd75a1'
REPO = Path(__file__).resolve().parents[1]
STAGING = REPO.parent / 'runtime_training_staging_20260928'
_FIXED_REPO, _FIXED_STAGING = REPO, STAGING
SELF = 'scripts/run_physical_f_clean_replay_e139.py'
_LOCK = threading.Lock()
SUPPORT_PINS = {
    'scripts/e139_entry_candidate.py': 'd13ae39dd83c80d4802ab6555a4e0b0392ae45727fcd3a8e52fa5d11089ed5fa',
    'scripts/run_physical_f_clean_replay_e138.py': candidate.ORIGIN_SHA256,
    'scripts/e139_local_materials.py': 'd71176afd458e6941ff875e5eb7037fc39f7718a9ce30633e907a02f0f071d91',
    'scripts/e138_deployment_materials.py': '61d361b920c33a859263d08d3ddce1a5d44265c370961061927f1524953490f9',
    'scripts/worker_e138_batch.py': 'e2f93af4d816237038121dec5ba830b3c6427a602dcf1afd6146b9d164bc8d95',
}
BINDINGS = dict(schema='e139-fixed-public-entry-bindings-v1',
    materials='FIXED_E139_LOCAL_MATERIALS_PLUS_BOUNDED_OWNED_EVIDENCE_READER',
    source_bytes=list(candidate.SOURCE_KEYS),
    source_manifest='VERIFIED_SESSION_PLUS_EFFECTIVE_ENTRY_EXTRA_ORIGINS_AND_BINDING_CONFIG',
    entry_repo='FIXED_REPO_NOT_EFFECTIVE_FILE_IDENTITY',
    entry_staging='FIXED_SIBLING_RUNTIME_TRAINING_STAGING_20260928',
    lifetime='ONE_SOURCE_SESSION_STALE_OPERATIONS_DENIED',
    reviews='TRUSTED_PARENT_ONE_INSTALL_PER_CURRENT_ROLE_NO_CANDIDATE_PIN_LEARNING',
    grant='EXACT_NEW_E139_PATH_PIN_CANONICAL_ASCII_NO_GENERATION')


def require(ok, code):
    if not ok:
        raise ValueError(code)


def binding_digest():
    return materials.sha(materials.canonical(BINDINGS))


def origin_manifest(self_sha256):
    """Proposed fixed snapshot only; never installs/reviews any source freeze."""
    require(session_source._hex(self_sha256), 'E139_PUBLIC_SELF_PIN')
    return dict(SUPPORT_PINS, **{SELF: self_sha256})


def _admit():
    require(REPO == _FIXED_REPO and STAGING == _FIXED_STAGING and session_source.REPO == _FIXED_REPO,
            'E139_PUBLIC_FIXED_ROOT_DRIFT')
    require(session_source._hex(AUTH_SHA256) and
            PROPOSAL_SHA256 == candidate.PROPOSAL_SHA256, 'E139_PUBLIC_AUTHORITY_PINS_REQUIRED')
    frozen = SOURCE_FREEZE
    require(type(frozen) is dict and set(frozen) ==
            {'session', 'origin_sha256', 'effective_entry_sha256', 'binding_sha256'},
            'E139_PUBLIC_SOURCE_FREEZE_REQUIRED')
    origins = frozen['origin_sha256']
    require(type(origins) is dict and origins == origin_manifest(origins.get(SELF)),
            'E139_PUBLIC_ORIGIN_MANIFEST')
    require(frozen['effective_entry_sha256'] == candidate.EFFECTIVE_SHA256 and
            frozen['binding_sha256'] == binding_digest(), 'E139_PUBLIC_EFFECTIVE_OR_BINDING_PIN')
    # Reproduce the existing five-field admission without installing globals yet.
    f = frozen['session']
    require(type(f) is dict and set(f) == {'origin_sha256', 'effective_native_sha256',
            'effective_script_sha256', 'adapter_sha256', 'binding_sha256'}, 'E139_PUBLIC_SESSION_FREEZE')
    native, scripts = session_source.effective_maps()
    require(f['origin_sha256'] == session_source.origin_manifest(f['adapter_sha256']) and
            f['effective_native_sha256'] == native and f['effective_script_sha256'] == scripts and
            f['binding_sha256'] == session_source.binding_digest(), 'E139_PUBLIC_SESSION_FREEZE')
    require(REVIEW_PINS is None or (type(REVIEW_PINS) is dict and set(REVIEW_PINS) <=
            {'capture'} and all(session_source._hex(p) for p in REVIEW_PINS.values())),
            'E139_PUBLIC_REVIEW_PINS')
    return copy.deepcopy(frozen), AUTH_SHA256, copy.deepcopy(REVIEW_PINS)


def _bounded_read(path, cap, pin, root):
    """Fixed callers only; reject links/reparse parents and bounded-read drift."""
    require(type(cap) is int and 0 < cap <= 25165824, 'E139_PUBLIC_READ_CAP')
    path = Path(path)
    require(path.is_absolute() and path == root / path.relative_to(root), 'E139_PUBLIC_PATH')
    current = path
    while current != root.parent:
        info = current.lstat()
        require(not current.is_symlink() and not getattr(info, 'st_file_attributes', 0) & 1024,
                'E139_PUBLIC_LINK_OR_REPARSE')
        if current == path:
            require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= cap, 'E139_PUBLIC_FILE_SIZE')
            size = info.st_size
        current = current.parent
    with path.open('rb') as stream:
        raw = stream.read(cap + 1)
    require(len(raw) == size and 0 < len(raw) <= cap and
            (pin is None or materials.sha(raw) == pin), 'E139_PUBLIC_FILE_PIN_OR_SIZE')
    return raw


class _Facade:
    def __init__(self, owner):
        self._owner = owner

    def prepare(self):
        self._owner._check()
        prepared = materials.prepare()
        require(prepared.public_summary()['status'] == materials.READY, 'E139_PUBLIC_MATERIALS_NOT_READY')
        return prepared

    def _read(self, path, cap, pin=None):
        owner = self._owner
        owner._check()
        path = Path(path)
        grants = {
            REPO / 'contracts/physical_f_clean_replay_authorization_e139.json': owner._auth,
            REPO / 'contracts/physical_f_clean_replay_proposal_e139_v1.json': PROPOSAL_SHA256}
        if path in grants:
            require(pin == grants[path] and cap == 65536, 'E139_PUBLIC_GRANT_READ_PIN')
            raw = _bounded_read(path, cap, pin, REPO)
            if path.name == 'physical_f_clean_replay_authorization_e139.json':
                c = owner._entry.contract
                require(raw.isascii() and raw == c.canonical(c.decode(raw)), 'E139_PUBLIC_CANONICAL_ASCII_GRANT')
            return raw
        phase = STAGING / session_source.native.pair.PHASE_NEW
        allowed = {phase / 'original_clock.json'}
        allowed.update(phase / role / name for role in ('capture', 'execution', 'readback')
            for name in ('accepted.json', 'native_transport.json', 'stdout.raw', 'stderr.raw',
                         'transport.json', 'intent.json'))
        owned = any(getattr(c.store, '_created', False) and c.store.phase == phase
                    for c in owner._session._controllers)
        require(path in allowed and owned, 'E139_PUBLIC_UNOWNED_OR_UNKNOWN_PATH')
        require(pin is None or session_source._hex(pin), 'E139_PUBLIC_EVIDENCE_PIN')
        return _bounded_read(path, cap, pin, STAGING)


class _Run:
    def __init__(self, owner, run):
        self._owner, self._run = owner, run

    def __repr__(self):
        return '<E139 PRIVATE STAGED RUN; no automatic next role>'

    def __reduce_ex__(self, protocol):
        raise TypeError('E139_PUBLIC_PRIVATE_NOT_SERIALIZABLE')

    def prepare_execution(self):
        self._owner._check()
        return self._run.prepare_execution()

    def prepare_readback(self):
        self._owner._check()
        return self._run.prepare_readback()

    def execute(self, prepared, independent_record_raw):
        self._owner._check()
        return self._run.execute(prepared, independent_record_raw)


class Entry:
    def __repr__(self):
        return '<E139 FIXED PRIVATE ENTRY; no automatic run>'

    def __reduce_ex__(self, protocol):
        raise TypeError('E139_PUBLIC_PRIVATE_NOT_SERIALIZABLE')

    def _check(self):
        require(self._alive, 'E139_PUBLIC_ENTRY_CLOSED')
        require(REPO == _FIXED_REPO and STAGING == _FIXED_STAGING and session_source.REPO == _FIXED_REPO,
                'E139_PUBLIC_FIXED_ROOT_DRIFT')
        require(AUTH_SHA256 == self._auth and SOURCE_FREEZE == self._frozen and
                REVIEW_PINS == self._reviews and binding_digest() == self._frozen['binding_sha256'],
                'E139_PUBLIC_CONFIGURATION_DRIFT')
        self._session.local_source_closure()
        for path, pin in self._frozen['origin_sha256'].items():
            _bounded_read(REPO / path, 1048576, pin, REPO)
        require(self._entry.SOURCE_BYTES is self._provider and
                self._entry.SOURCE_MANIFEST is self._manifest_provider and
                self._entry.materials is self._facade and self._entry.AUTH_SHA256 == self._auth and
                self._entry.PROPOSAL_SHA256 == PROPOSAL_SHA256 and self._entry.REVIEW_PINS == self._installed_reviews and
                self._entry._repo is self._repo_provider and self._entry._staging is self._staging_provider and
                materials.sha(self._entry_bytes) == self._frozen['effective_entry_sha256'],
                'E139_PUBLIC_PROVIDER_BINDING_DRIFT')

    def _source_bytes(self, key):
        self._check()
        require(type(key) is str and key in candidate.SOURCE_KEYS, 'E139_PUBLIC_SOURCE_KEY')
        raw = self._sources[key]
        require(materials.sha(raw) == self._source_pins[key], 'E139_PUBLIC_EFFECTIVE_SOURCE_DRIFT')
        return raw

    def _manifest(self):
        self._check()
        result = self._session.local_source_closure()
        result.update({p[:-3].replace('/', '.'): pin for p, pin in self._frozen['origin_sha256'].items()})
        result[candidate.KEY] = self._frozen['effective_entry_sha256']
        result['bindings.e139_public_entry'] = self._frozen['binding_sha256']
        return result

    def public_source_manifest(self):
        return copy.deepcopy(self._manifest())

    def prepare_capture(self):
        self._check()
        return self._entry.prepare_capture()

    def install_review_pin(self, role, externally_reviewed_record_sha256):
        """Trusted parent installs an independently reviewed record digest once.

        Never pass a digest learned from an alleged candidate PASS. Installation
        neither reviews a packet nor advances a role, starts a clock or runs it.
        Future-role records can only be installed after actual prior outputs.
        """
        self._check()
        require(type(role) is str and role in ('capture', 'execution', 'readback') and
                session_source._hex(externally_reviewed_record_sha256), 'E139_PUBLIC_REVIEW_PIN_TYPE')
        require(role not in self._installed_reviews, 'E139_PUBLIC_REVIEW_PIN_ALREADY_INSTALLED')
        if role == 'capture':
            require(not self._start_attempted and self._run is None, 'E139_PUBLIC_REVIEW_ROLE_ORDER')
        else:
            require(self._run is not None, 'E139_PUBLIC_REVIEW_ROLE_ORDER')
            controller = self._run._run._controller
            require(any(controller is c for c in self._session._controllers) and
                    not controller.terminal and controller.index == ('capture', 'execution', 'readback').index(role),
                    'E139_PUBLIC_REVIEW_ROLE_ORDER')
        # Verify the exact authority/proposal still exist at the fixed pinned
        # paths. This is read-only and does not reset/create any phase or clock.
        self._entry._grant()
        self._installed_reviews[role] = externally_reviewed_record_sha256
        self._entry.REVIEW_PINS = copy.deepcopy(self._installed_reviews)

    def start(self, prepared, independent_record_raw):
        self._check()
        require('capture' in self._installed_reviews, 'E139_PUBLIC_REVIEW_PIN_REQUIRED')
        require(not self._start_attempted and self._run is None, 'E139_PUBLIC_START_ALREADY_ATTEMPTED')
        self._start_attempted = True
        self._run = _Run(self, self._entry.start(prepared, independent_record_raw))
        return self._run


@contextmanager
def open_entry():
    frozen, auth, reviews = _admit()  # No file IO, compile, lock or grant read before denial.
    require(_LOCK.acquire(blocking=False), 'E139_PUBLIC_SINGLE_ACTIVE')
    previous = session_source.FROZEN
    handle = None
    try:
        require(previous is None, 'E139_PUBLIC_SESSION_ALREADY_CONFIGURED')
        origins = {p: _bounded_read(REPO / p, 1048576, pin, REPO)
                   for p, pin in frozen['origin_sha256'].items()}
        entry_bytes = candidate.build(origins['scripts/run_physical_f_clean_replay_e138.py']).private_sources()[candidate.KEY]
        session_source.FROZEN = frozen['session']
        with session_source.local_session() as session:
            handle = Entry()
            handle._alive = True
            handle._frozen, handle._auth, handle._reviews = frozen, auth, reviews
            handle._installed_reviews = copy.deepcopy(reviews) if reviews is not None else {}
            handle._run, handle._start_attempted = None, False
            handle._session, handle._entry_bytes = session, entry_bytes
            handle._sources = {'scripts.worker_e138_batch': origins['scripts/worker_e138_batch.py'],
                **{'scripts.' + n: session._scripts[n] for n in
                   ('e138_source_session', 'e138_reviewed_envelope', 'e138_packet')}}
            handle._source_pins = {'scripts.worker_e138_batch': SUPPORT_PINS['scripts/worker_e138_batch.py'],
                **{'scripts.' + n: frozen['session']['effective_script_sha256'][n] for n in
                   ('e138_source_session', 'e138_reviewed_envelope', 'e138_packet')}}
            handle._facade = _Facade(handle)
            entry = types.ModuleType('_e139_fixed_private_entry')
            entry.E139_MATERIALS = handle._facade
            exec(compile(entry_bytes, '<e139-reviewed-effective-entry>', 'exec'), entry.__dict__)
            handle._entry = entry
            handle._provider, handle._manifest_provider = handle._source_bytes, handle._manifest
            handle._repo_provider, handle._staging_provider = lambda: REPO, lambda: STAGING
            entry.SOURCE_BYTES, entry.SOURCE_MANIFEST = handle._provider, handle._manifest_provider
            entry._repo, entry._staging = handle._repo_provider, handle._staging_provider
            entry.AUTH_SHA256, entry.REVIEW_PINS = auth, copy.deepcopy(handle._installed_reviews)
            handle._check()
            try:
                yield handle
            finally:
                handle._alive = False
    finally:
        if handle is not None:
            handle._alive = False
        session_source.FROZEN = previous
        _LOCK.release()
