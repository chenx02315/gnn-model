"""Pinned effective-byte packet compiler adapter; no controller or transport.

Historical compiler origin stays untouched. Its self-read is replaced by an
exact-key RAM source provider, bound to the same verified bytes compiled here.
EXPECTED remains None: loading is not authority, review, or permission to run a
packet. The caller must install independently reviewed exact input/source pins.
"""
import hashlib
import types

from scripts.e139_source_derivation import derive

KEY = 'scripts.e138_packet'
ORIGIN_SHA256 = 'cef358fc68fa56894bb7f84d8fbcdaf6e871e99540f540b43aa5646ab34db826'
EFFECTIVE_SHA256 = '5c1e2ed157ef4e9a1a067c655ea52b00377c82866e623b7bdff29d40f0f402ef'
REPLACEMENTS = (
    ('EXPECTED=None', 'EXPECTED=None\nSOURCE_BYTES=None', 1),
    ('compiler=Path(__file__).read_bytes()',
     "require(callable(SOURCE_BYTES),'E139_PACKET_SOURCE_PROVIDER_REQUIRED')\n    compiler=SOURCE_BYTES('scripts.e138_packet')", 1),
    ("'e138-exact-packet-projection-v1'", "'e139-exact-packet-projection-v1'", 1),
)


def specification():
    return dict(schema='e139-source-derivation-v1',
        origins=[dict(name=KEY, sha256=ORIGIN_SHA256, effective_sha256=EFFECTIVE_SHA256)],
        rules=[dict(source=KEY, old_hex=old.encode('ascii').hex(),
                    new_hex=new.encode('ascii').hex(), count=count)
               for old, new, count in REPLACEMENTS])


def build(origin_raw):
    return derive({KEY: origin_raw}, specification())


def compiler(effective_raw):
    """Compile exactly pinned bytes privately, with a verified self-byte view.

    Not installed into sys.modules. No fake __file__ or path substitution. A
    caller-supplied different compiler/source provider is never accepted here.
    Trusted Python callers can mutate objects; this is not an adversarial-code
    sandbox, and external EXPECTED/review integrity remains required.
    """
    if type(effective_raw) is not bytes or len(effective_raw) > 65536 or \
            hashlib.sha256(effective_raw).hexdigest() != EFFECTIVE_SHA256:
        raise ValueError('E139_PACKET_EFFECTIVE_SOURCE_PIN')
    module = types.ModuleType('_e139_verified_packet_private')
    exec(compile(effective_raw, '<e139-verified-packet>', 'exec'), module.__dict__)
    def source_bytes(key):
        if type(key) is not str or key != KEY:
            raise ValueError('E139_PACKET_EXACT_SOURCE_KEY')
        return effective_raw
    module.SOURCE_BYTES = source_bytes
    return module
