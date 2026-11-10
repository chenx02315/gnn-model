"""Pure finite E140 wrapper derivation. No callback installation or dispatch."""
from scripts.e139_source_derivation import derive

KEY = 'scripts.run_physical_f_clean_replay_e139'
ORIGIN_SHA256 = 'a602a74a3d99b73a12931a48db8ebec1c76a87eaac1ed42061f17f65aecb1e87'
EFFECTIVE_SHA256 = 'dc9a52943a99967980d405eb3eeaedfc563b8cfbf3e2e5b4a115c352f81ec19a'
_SUPPORT = '''SUPPORT_PINS = {
    'scripts/e139_entry_candidate.py': 'd13ae39dd83c80d4802ab6555a4e0b0392ae45727fcd3a8e52fa5d11089ed5fa',
    'scripts/run_physical_f_clean_replay_e138.py': candidate.ORIGIN_SHA256,
    'scripts/e139_local_materials.py': 'd71176afd458e6941ff875e5eb7037fc39f7718a9ce30633e907a02f0f071d91',
    'scripts/e138_deployment_materials.py': '61d361b920c33a859263d08d3ddce1a5d44265c370961061927f1524953490f9',
    'scripts/worker_e138_batch.py': 'e2f93af4d816237038121dec5ba830b3c6427a602dcf1afd6146b9d164bc8d95',
}'''
REPLACEMENTS = (
    ('from scripts import e139_entry_candidate as candidate', 'candidate=E140_CANDIDATE', 1),
    ('from scripts import e139_local_materials as materials', 'materials=E140_MATERIALS', 1),
    ('from scripts import e139_local_source_session as session_source', 'session_source=E140_SESSION', 1),
    ('entry.E139_MATERIALS = handle._facade', 'entry.E140_MATERIALS = handle._facade', 1),
    ('REPO = Path(__file__).resolve().parents[1]', 'REPO = E140_REPO', 1),
    ("SELF = 'scripts/run_physical_f_clean_replay_e139.py'", "SELF = 'scripts/run_physical_f_clean_replay_e140.py'", 1),
    (_SUPPORT, 'SUPPORT_PINS = E140_SUPPORT_PINS', 1),
    ("'4b8a915f06482f25425c71b07c6eba8c002c1455b59e28023ce5e0a806bd75a1'", "'43bd32db6e629e7c558c165f4f5d0f08d01100ee9e6055a79a99a4c88ffa0b9e'", 1),
    ("schema='e139-fixed-public-entry-bindings-v1'", "schema='e140-fixed-public-entry-bindings-v1', effective_wrapper_sha256=E140_WRAPPER_SHA", 1),
    ('FIXED_E139_LOCAL_MATERIALS_PLUS_BOUNDED_OWNED_EVIDENCE_READER', 'FIXED_E140_LOCAL_MATERIALS_PLUS_BOUNDED_OWNED_EVIDENCE_READER', 1),
    ('EXACT_NEW_E139_PATH_PIN_CANONICAL_ASCII_NO_GENERATION', 'EXACT_NEW_E140_PATH_PIN_CANONICAL_ASCII_NO_GENERATION', 1),
    ('physical_f_clean_replay_authorization_e139.json', 'physical_f_clean_replay_authorization_e140.json', 2),
    ('physical_f_clean_replay_proposal_e139_v1.json', 'physical_f_clean_replay_proposal_e140_v1.json', 1),
    ('session_source.native.pair.PHASE_NEW', 'session_source.native.PHASE', 1),
    ('session_source._hex', 'session_source.origin._hex', 5),
    ("result['bindings.e139_public_entry'] = self._frozen['binding_sha256']",
     "result['bindings.e140_public_entry'] = self._frozen['binding_sha256']\n        result['effective.scripts.e140_public_entry'] = E140_WRAPPER_SHA", 1),
    ('<E139 FIXED PRIVATE ENTRY;', '<E140 FIXED PRIVATE ENTRY;', 1),
    ('<E139 PRIVATE STAGED RUN;', '<E140 PRIVATE STAGED RUN;', 1),
)


def specification():
    return dict(schema='e139-source-derivation-v1',
        origins=[dict(name=KEY, sha256=ORIGIN_SHA256, effective_sha256=EFFECTIVE_SHA256)],
        rules=[dict(source=KEY, old_hex=a.encode('ascii').hex(), new_hex=b.encode('ascii').hex(), count=c)
               for a,b,c in REPLACEMENTS])


def build(raw):
    return derive({KEY:raw}, specification())
