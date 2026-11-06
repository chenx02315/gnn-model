"""Pure two-module identity migration candidate; NOT a runnable E139 graph.

Historical module keys and E138 diagnostic codes remain compatibility labels.
Only listed bytes change. No imports/compilation of the derived modules, grant
creation, registry mutation, file IO or dispatch occurs here. Downstream actual
source maps must pin effective bytes, not the origin identities below.
"""
import copy

from scripts.e139_source_derivation import derive

CONSUMED_E138_AUTH = 'bcaa8da7adc2e61daa35ccd50ce42dfd4131de180c7f3ca3adbbc86e8403dd74'
ROOT_OLD = '/temp/jiangchuanc/multimode_ate_physical_f_replay_e138_r1'
ROOT_NEW = '/temp/jiangchuanc/multimode_ate_physical_f_replay_e139_r1'
PHASE_OLD = 'v6_e138_clean_F_replay_r1'
PHASE_NEW = 'v6_e139_clean_F_replay_r1'
CONTRACT = 'physical_e138_contract'
BOOTSTRAP = 'physical_runtime_bootstrap_e138'

# Exact quoted literals, not a global identifier/version replacement. Keeping
# compatibility keys avoids pretending that the rest of the graph migrated.
_COMMON = (
    (repr(ROOT_OLD), repr(ROOT_NEW), 1),
    (repr(PHASE_OLD), repr(PHASE_NEW), 1),
    ("'e138-fixed-f-replay-proposal-v1'", "'e139-fixed-f-replay-proposal-v1'", 1),
    ("'e138-explicit-whole-package-authorization-v1'", "'e139-explicit-whole-package-authorization-v1'", 1),
)
REPLACEMENTS = {
    CONTRACT: _COMMON + (
        ("'E138'", "'E139'", 5),
        ("'e138-fixed-f-replay-policy-v1'", "'e139-fixed-f-replay-policy-v1'", 1),
        ("'e138-authority-consistency-only-v1'", "'e139-authority-consistency-only-v1'", 1),
        ("'e138-contract-consistency-only-v1'", "'e139-contract-consistency-only-v1'", 1),
        ("OLD_AUTH_SHA256='49f000fe45de6cfc029ad8a9c1ead5e09edd24321de6062039d638436cce4969'",
         "OLD_AUTH_SHA256='" + CONSUMED_E138_AUTH + "'", 1),
    ),
    BOOTSTRAP: _COMMON + (
        ("'E138'", "'E139'", 2),
        ("'e138-private-runtime-bootstrap-v1'", "'e139-private-runtime-bootstrap-v1'", 2),
        ('AUTH_SHA256 != OLD_E137_AUTH_SHA256)',
         "AUTH_SHA256 not in (OLD_E137_AUTH_SHA256,'" + CONSUMED_E138_AUTH + "'))", 1),
    ),
}
ORIGIN_PINS = {
    CONTRACT: '19bdaaf461de3ff424df57cf8e263f80efd57fa2a67a9929d5f89c4188f917f6',
    BOOTSTRAP: '8a8d95802d4a5b52958511bfaf8f3e7c2a34b82460c335b701e69f3b7a3de238',
}
EFFECTIVE_PINS = {
    CONTRACT: '6236ade200957cfc5476c726dc2fda45231806552291952d9cc1fd8778088730',
    BOOTSTRAP: 'aefa865fcedfc19d2e03a1cd081eff4c1168358a505b7b251c24684df1f8d11f',
}


def specification():
    """Return an independent copy of the finite, reviewable migration plan."""
    return copy.deepcopy(dict(
        schema='e139-source-derivation-v1',
        origins=[dict(name=name, sha256=ORIGIN_PINS[name],
                      effective_sha256=EFFECTIVE_PINS[name])
                 for name in (CONTRACT, BOOTSTRAP)],
        rules=[dict(source=name, old_hex=old.encode('ascii').hex(),
                    new_hex=new.encode('ascii').hex(), count=count)
               for name in (CONTRACT, BOOTSTRAP)
               for old, new, count in REPLACEMENTS[name]],
    ))


def build(sources):
    """Only derive the exact two frozen sources; no executable graph release."""
    return derive(sources, specification())
