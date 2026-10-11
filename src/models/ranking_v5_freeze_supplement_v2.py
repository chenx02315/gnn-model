"""Pure authenticated supplemental loading, not a launch or authorization.

The caller must independently establish the original sealed core context and
approve these exact source pins. This adds NEW module names only, never patches
old core modules. No disk discovery, package reads, ML invocation, or release.
"""
from contextlib import contextmanager
import hashlib
import sys
from types import ModuleType

FILES = (
    'src/models/ranking_v5_freeze_codec_v2.py',
    'src/models/ranking_v5_real_artifact_store_v2.py',
    'src/models/ranking_v5_single_fit_worker_v2.py',
    'src/models/ranking_v5_train_artifact_readback_v2.py',
    'src/models/ranking_v5_independent_fit_context_v2.py',
    'src/models/ranking_v5_parent_artifact_candidate_v2.py',
)
SOURCE_MAX_BYTES = 65536
SOURCE_TOTAL_MAX_BYTES = 256 * 1024


def _require(ok, code):
    if not ok:
        raise ValueError('V5_FREEZE_SUPPLEMENT_' + code)


def validate_sources(sources, trusted_sha256):
    """Authenticate all fixed bytes before compiling even the first module."""
    _require(type(sources) is dict and type(trusted_sha256) is dict
             and set(sources) == set(trusted_sha256) == set(FILES), 'SOURCE_SET')
    sources, trusted_sha256 = dict(sources), dict(trusted_sha256)
    total = 0
    for path in FILES:
        raw, pin = sources[path], trusted_sha256[path]
        _require(type(raw) is bytes and 0 < len(raw) <= SOURCE_MAX_BYTES, 'SOURCE_BOUND')
        total += len(raw)
        _require(total <= SOURCE_TOTAL_MAX_BYTES, 'SOURCE_TOTAL_BOUND')
        _require(type(pin) is str and len(pin) == 64
                 and all(c in '0123456789abcdef' for c in pin)
                 and hashlib.sha256(raw).hexdigest() == pin, 'SOURCE_SHA')
    return sources


@contextmanager
def authenticated_supplements(sources, trusted_sha256):
    """Yield explicit new modules within an already-owned sealed namespace.

    Namespace markers are a prerequisite, not an OS sandbox or consent proof.
    The original fence, parent guard, trust/release and CLI binding must still
    be established by the external caller. No old CLI alias is created here.
    """
    frozen = validate_sources(sources, trusted_sha256)
    package = sys.modules.get('src.models')
    _require(type(package) is ModuleType and package.__dict__.get('__path__') == []
             and getattr(package.__dict__.get('__spec__'), 'origin', None)
                 == 'sealed://namespace/src.models', 'CORE_CONTEXT_REQUIRED')
    names = {path: path[:-3].replace('/', '.') for path in FILES}
    for name in names.values():
        _require(name not in sys.modules and name.rsplit('.', 1)[1] not in package.__dict__,
                 'PRELOADED_SUPPLEMENT')
    loaded = {}
    try:
        for path in FILES:
            name = names[path]
            module = ModuleType(name)
            module.__file__ = 'sealed-freeze-v2://' + path
            module.__package__ = 'src.models'
            loaded[name] = module
            sys.modules[name] = module
            setattr(package, name.rsplit('.', 1)[1], module)
            exec(compile(frozen[path], module.__file__, 'exec'), module.__dict__)
        yield {path: loaded[names[path]] for path in FILES}
    finally:
        # Remove only our own identities, never unrelated/replaced user objects.
        for name, module in reversed(tuple(loaded.items())):
            if sys.modules.get(name) is module:
                del sys.modules[name]
            short = name.rsplit('.', 1)[1]
            if package.__dict__.get(short) is module:
                delattr(package, short)


if __name__ == '__main__':
    raise SystemExit('V5_FREEZE_SUPPLEMENT_CLI_CLOSED')
