"""Finite effective entry bytes only: no compiler, grant, provider install or run.

Compatibility import/module names and diagnostic labels deliberately remain.
The trusted private script session must supply E139_MATERIALS before import,
then install SOURCE_BYTES and SOURCE_MANIFEST against reviewed effective pins.
These seams are not an API for accepting untrusted arbitrary callbacks.
"""
from scripts.e139_source_derivation import derive

KEY = 'scripts.run_physical_f_clean_replay_e138'
ORIGIN_SHA256 = '1308ce76ecaa9048c88b250152c500bb3dab99256ca132dc6b2f4a325e5729cd'
EFFECTIVE_SHA256 = 'eb07035f6550574dc70a124372f653cc13e2e266a318254e49f782c2a7da8f25'
PROPOSAL_SHA256 = '4b8a915f06482f25425c71b07c6eba8c002c1455b59e28023ce5e0a806bd75a1'
SOURCE_KEYS = ('scripts.worker_e138_batch', 'scripts.e138_source_session',
               'scripts.e138_reviewed_envelope', 'scripts.e138_packet')
_OLD_ENTRY_SOURCES = '''def _entry_sources():
    # Controller closure covers its transport/helper/static native validators;
    # preparation and this entrypoint are separately committed by exact request.
    names=('scripts/run_physical_f_clean_replay_e138.py','scripts/e138_deployment_materials.py',
           'scripts/worker_e138_batch.py','scripts/e138_source_session.py')
    return {name:sha(materials._read(_repo()/name,262144)) for name in names}'''
_NEW_ENTRY_SOURCES = '''def _entry_sources():
    require(callable(SOURCE_MANIFEST),'E139_ENTRY_SOURCE_MANIFEST_REQUIRED')
    return SOURCE_MANIFEST()'''
REPLACEMENTS = (
    ('from scripts import e138_deployment_materials as materials', 'materials=E139_MATERIALS', 1),
    ("AUTH_SHA256='bcaa8da7adc2e61daa35ccd50ce42dfd4131de180c7f3ca3adbbc86e8403dd74'",
     'AUTH_SHA256=None\nSOURCE_BYTES=None\nSOURCE_MANIFEST=None', 1),
    ("PROPOSAL_SHA256='6e4d52d540aa3c776f7d443a1a14f0764ab90fa11657585d8d6c1b6c8acd0b4b'",
     "PROPOSAL_SHA256='" + PROPOSAL_SHA256 + "'", 1),
    ('physical_f_clean_replay_authorization_e138.json', 'physical_f_clean_replay_authorization_e139.json', 1),
    ('physical_f_clean_replay_proposal_e138_v1.json', 'physical_f_clean_replay_proposal_e139_v1.json', 1),
    ('def _grant():\n    repo=_repo()',
     "def _grant():\n    require(contract._hex(AUTH_SHA256) and contract._hex(PROPOSAL_SHA256),"
     "'E139_ENTRY_AUTHORITY_PINS_REQUIRED')\n    repo=_repo()", 1),
    (_OLD_ENTRY_SOURCES, _NEW_ENTRY_SOURCES, 1),
    ("worker=materials._read(_repo()/'scripts/worker_e138_batch.py',65536)",
     "require(callable(SOURCE_BYTES),'E139_ENTRY_SOURCE_BYTES_REQUIRED')\n    worker=SOURCE_BYTES('scripts.worker_e138_batch')", 1),
    ("loader=materials._read(_repo()/'scripts/e138_source_session.py',65536)",
     "loader=SOURCE_BYTES('scripts.e138_source_session')", 1),
    ("env=materials._read(_repo()/'scripts/e138_reviewed_envelope.py',65536)",
     "env=SOURCE_BYTES('scripts.e138_reviewed_envelope')", 1),
    ('sha(materials._read(Path(packet.__file__),65536))', "sha(SOURCE_BYTES('scripts.e138_packet'))", 1),
    ("'e138-independent-exact-packet-review-request-v1'", "'e139-independent-exact-packet-review-request-v1'", 1),
    ("'e138-independent-exact-packet-review-v1'", "'e139-independent-exact-packet-review-v1'", 1),
    ("        private_clock=_private_capture_clock(prepared)\n"
     "        run_role=controller._private_function(controller.Controller.run_role,clock=private_clock)\n"
     "        c.run_role=types.MethodType(run_role,c)",
     "        clock=controller.clock\n"
     "        source_pins=prepared._descriptor['packet']['source_sha256']\n"
     "        require(clock.contract is contract and clock.capture.contract is contract and\n"
     "            clock.runtime.contract is contract and\n"
     "            clock.build.__globals__.get('contract') is contract and\n"
     "            clock.build.__globals__.get('capture') is clock.capture and\n"
     "            clock.build.__globals__.get('runtime') is clock.runtime and\n"
     "            getattr(contract,'__source_sha256__',None)==source_pins['physical_e138_contract'] and\n"
     "            getattr(clock.capture,'__source_sha256__',None)==source_pins['physical_replay_capture_e138'] and\n"
     "            getattr(clock.runtime,'__source_sha256__',None)==source_pins['physical_e138_runtime_primitives'],\n"
     "            'E139_ENTRY_SESSION_CLOCK_SOURCE_JOIN')", 1),
)


def specification():
    return dict(schema='e139-source-derivation-v1',
        origins=[dict(name=KEY, sha256=ORIGIN_SHA256, effective_sha256=EFFECTIVE_SHA256)],
        rules=[dict(source=KEY, old_hex=old.encode('ascii').hex(),
                    new_hex=new.encode('ascii').hex(), count=count)
               for old, new, count in REPLACEMENTS])


def build(origin_raw):
    """Pure exact byte derivation; does not compile or configure the entry."""
    return derive({KEY: origin_raw}, specification())
