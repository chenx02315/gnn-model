"""LOCAL finite E140 entry candidate; no compiler/dispatch or grant creation."""
from scripts import e139_entry_candidate as previous
from scripts.e139_source_derivation import derive

KEY = previous.KEY
SOURCE_KEYS = previous.SOURCE_KEYS
ORIGIN_SHA256 = previous.EFFECTIVE_SHA256
EFFECTIVE_SHA256 = '431c9d160800a314fd19797e63c00614c74625ddcb7889f92297879fbd92ab0d'
PROPOSAL_SHA256 = '43bd32db6e629e7c558c165f4f5d0f08d01100ee9e6055a79a99a4c88ffa0b9e'
REPLACEMENTS = (
    ('materials=E139_MATERIALS', 'materials=E140_MATERIALS', 1),
    ("PROPOSAL_SHA256='" + previous.PROPOSAL_SHA256 + "'", "PROPOSAL_SHA256='" + PROPOSAL_SHA256 + "'", 1),
    ('physical_f_clean_replay_authorization_e139.json', 'physical_f_clean_replay_authorization_e140.json', 1),
    ('physical_f_clean_replay_proposal_e139_v1.json', 'physical_f_clean_replay_proposal_e140_v1.json', 1),
    ("'e139-independent-exact-packet-review-request-v1'", "'e140-independent-exact-packet-review-request-v1'", 1),
    ("'e139-independent-exact-packet-review-v1'", "'e140-independent-exact-packet-review-v1'", 1),
)


def specification():
    return dict(schema='e139-source-derivation-v1',
        origins=[dict(name=KEY, sha256=ORIGIN_SHA256, effective_sha256=EFFECTIVE_SHA256)],
        rules=[dict(source=KEY, old_hex=a.encode('ascii').hex(), new_hex=b.encode('ascii').hex(), count=c)
               for a, b, c in REPLACEMENTS])


def build(original_entry_raw):
    """Exact original E138 entry -> frozen E139 lifetime fix -> E140 identity."""
    prior = previous.build(original_entry_raw)
    return derive(prior.private_sources(), specification())
