"""LOCAL source repair candidate only; no grant, new package/root or entry.

The frozen E139 effective bootstrap is the immediate origin, not a historical
file to overwrite. Nine explicit builtins bind the trusted pinned E127 function;
this namespace is not a sandbox. Modern implicit-builtins behavior is not proof
that the target interpreter shared it. This candidate does not reopen E139.
"""
from scripts.e139_source_derivation import derive

KEY = 'physical_runtime_bootstrap_e138'
HISTORICAL_ORIGIN_SHA256 = '8a8d95802d4a5b52958511bfaf8f3e7c2a34b82460c335b701e69f3b7a3de238'
ORIGIN_SHA256 = 'aefa865fcedfc19d2e03a1cd081eff4c1168358a505b7b251c24684df1f8d11f'
EFFECTIVE_SHA256 = 'ad019f0ef4910d12be465b8caa41ac27f32befefc3ac659ae104c7e07680658a'
BUILTIN_NAMES = ('repr', 'min', 'len', 'type', 'bytes', 'dict', 'set', 'Exception', 'ValueError')
REPLACEMENTS = (
    ('import base64\n', 'import base64\nimport builtins\n', 1),
    ('namespace=dict(base64=base64,',
     'namespace=dict(__builtins__=dict((name,getattr(builtins,name)) for name in '
     + repr(BUILTIN_NAMES) + '),base64=base64,', 1),
)


def specification():
    return dict(schema='e139-source-derivation-v1',
        origins=[dict(name=KEY, sha256=ORIGIN_SHA256, effective_sha256=EFFECTIVE_SHA256)],
        rules=[dict(source=KEY, old_hex=old.encode('ascii').hex(),
                    new_hex=new.encode('ascii').hex(), count=count) for old, new, count in REPLACEMENTS])


def build(e139_effective_bootstrap):
    """Return exact effective bytes/manifest; no IO, compilation or loading."""
    return derive({KEY: e139_effective_bootstrap}, specification())
