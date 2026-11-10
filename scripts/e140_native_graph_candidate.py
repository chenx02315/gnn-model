"""Pure LOCAL E140 native graph candidate; no grant, loader or entry.

56 original fixed sources -> frozen E139 graph -> reviewed nine-builtins
bootstrap repair -> finite E140 identity rules. All effective pins are fixed
constants, not learned on admission. Legacy module keys/errors remain; dormant
batch_candidate.execute is still E137 compatibility code, NOT an E140 entry.
Nothing here reopens terminal E139 or authorizes another connection.
"""
from scripts import e139_native_graph_candidate as previous
from scripts import bootstrap_builtins_repair_candidate as repair
from scripts.e139_source_derivation import derive, DerivationResult

SOURCE_ORDER = previous.SOURCE_ORDER
ROOT = '/temp/jiangchuanc/multimode_ate_physical_f_replay_e140_r1'
PHASE = 'v6_e140_clean_F_replay_r1'
CONTRACT = previous.pair.CONTRACT
BOOTSTRAP = previous.pair.BOOTSTRAP
E137_AUTH = '49f000fe45de6cfc029ad8a9c1ead5e09edd24321de6062039d638436cce4969'
E138_AUTH = 'bcaa8da7adc2e61daa35ccd50ce42dfd4131de180c7f3ca3adbbc86e8403dd74'
E139_AUTH = '9e8b899d529983e29493ea253b32c58e543afca307b7e6bff6be8e599fd37e54'
CONTRACT_EFFECTIVE_SHA256 = '2f780b36d6c7e652280163e2c485f285603555447ee7394f545a7c53b4aafc72'

COMMON = (
    ("'/temp/jiangchuanc/multimode_ate_physical_f_replay_e139_r1'", repr(ROOT), 1),
    ("'v6_e139_clean_F_replay_r1'", repr(PHASE), 1),
    ("'e139-fixed-f-replay-proposal-v1'", "'e140-fixed-f-replay-proposal-v1'", 1),
    ("'e139-explicit-whole-package-authorization-v1'", "'e140-explicit-whole-package-authorization-v1'", 1),
)
REPLACEMENTS = {
    CONTRACT: COMMON + (
        ("'E139'", "'E140'", 5),
        ("'e139-fixed-f-replay-policy-v1'", "'e140-fixed-f-replay-policy-v1'", 1),
        ("'e139-authority-consistency-only-v1'", "'e140-authority-consistency-only-v1'", 1),
        ("'e139-contract-consistency-only-v1'", "'e140-contract-consistency-only-v1'", 1),
        ("OLD_AUTH_SHA256='" + E138_AUTH + "'", "OLD_AUTH_SHA256='" + E139_AUTH + "'", 1),
        ("f['authorization_sha256']!=OLD_AUTH_SHA256",
         "f['authorization_sha256'] not in (OLD_AUTH_SHA256,'" + E138_AUTH + "','" + E137_AUTH + "')", 1),
        ('authorization_sha256!=OLD_AUTH_SHA256',
         "authorization_sha256 not in (OLD_AUTH_SHA256,'" + E138_AUTH + "','" + E137_AUTH + "')", 1),
    ),
    BOOTSTRAP: COMMON + (
        ("'E139'", "'E140'", 2),
        ("'e139-private-runtime-bootstrap-v1'", "'e140-private-runtime-bootstrap-v1'", 2),
        ("AUTH_SHA256 not in (OLD_E137_AUTH_SHA256,'" + E138_AUTH + "')",
         "AUTH_SHA256 not in (OLD_E137_AUTH_SHA256,'" + E138_AUTH + "','" + E139_AUTH + "')", 1),
    ),
    'physical_replay_capture_e138': (
        ("'physical-f-clean-replay-source-capture-e139-v1'", "'physical-f-clean-replay-source-capture-e140-v1'", 1),
        ("'physical_e138_contract':'6236ade200957cfc5476c726dc2fda45231806552291952d9cc1fd8778088730'",
         "'physical_e138_contract':'" + CONTRACT_EFFECTIVE_SHA256 + "'", 1),
    ),
    'physical_e138_runtime_primitives': (
        ("'physical-f-clean-replay-execution-e139-v1'", "'physical-f-clean-replay-execution-e140-v1'", 1),
        ("'physical-f-clean-replay-package-clock-e139-v1'", "'physical-f-clean-replay-package-clock-e140-v1'", 1),
        ("'e139-derived-services-binding-v1'", "'e140-derived-services-binding-v1'", 1),
    ),
    'physical_e138_root_receipt': (
        ("'e139-unqualified-root-receipt-diagnostic-v1'", "'e140-unqualified-root-receipt-diagnostic-v1'", 1),
        ("'e139-supervisor-final-cleanup-observation-v1'", "'e140-supervisor-final-cleanup-observation-v1'", 1),
        ("'e139-final-registered-root-receipt-v1'", "'e140-final-registered-root-receipt-v1'", 1),
    ),
    'physical_e138_role2_join': (
        ("'e139-final-registered-root-receipt-v1'", "'e140-final-registered-root-receipt-v1'", 1),
        ("'e139-authenticated-role2-owned-root-context-v1'", "'e140-authenticated-role2-owned-root-context-v1'", 1),
    ),
    'physical_e138_role3_export': (("'e139-authenticated-role2-owned-root-context-v1'", "'e140-authenticated-role2-owned-root-context-v1'", 1),),
    'physical_e138_batch_assembler': (
        ("'e139-private-runtime-bootstrap-v1'", "'e140-private-runtime-bootstrap-v1'", 1),
        ("'physical-f-clean-replay-execution-e139-v1'", "'physical-f-clean-replay-execution-e140-v1'", 1),
        ("'e139-supervisor-final-cleanup-observation-v1'", "'e140-supervisor-final-cleanup-observation-v1'", 1),
    ),
    'physical_e138_batch_candidate': (("'e139-batch-candidate-failure-v1'", "'e140-batch-candidate-failure-v1'", 1),),
    'physical_batch_diagnostics_e138': (("'e139-bounded-failure-diagnostic-v1'", "'e140-bounded-failure-diagnostic-v1'", 1),),
    'physical_e138_readback_runtime': (("'e139-readback-partial-failure-v1'", "'e140-readback-partial-failure-v1'", 1),),
    'physical_e138_dependency_binding': (("'e139-derived-dependency-binding-v1'", "'e140-derived-dependency-binding-v1'", 1),),
    'physical_engine_evidence_e138': (("'e139-finite-engine-evidence-v1'", "'e140-finite-engine-evidence-v1'", 1),),
    'physical_f_replay_recipe_e138': (("'physical-f-clean-replay-recipe-e139-candidate-v1'", "'physical-f-clean-replay-recipe-e140-candidate-v1'", 1),),
}
EFFECTIVE_OVERRIDES = {
    'physical_e138_contract': '2f780b36d6c7e652280163e2c485f285603555447ee7394f545a7c53b4aafc72',
    'physical_runtime_bootstrap_e138': 'af01857a8101304835af5adcb5e80849a043c553f2245cf134798593a8471cee',
    'physical_replay_capture_e138': 'ff19cd1af687a1b66e19ae7e1ca618a75b8ad8da25e331b61233ad16a940bbe0',
    'physical_e138_runtime_primitives': 'd71df34e6db71d47cfdfc20593279751f38e4bda4b6e08aa3b3557eba1bfd7bc',
    'physical_e138_root_receipt': 'b5e4512906bf251563081d64f6396a3e0bbb37480dc1d0daccd2337beb1c595f',
    'physical_e138_role2_join': 'f0e0dac613af84cd99eab6c0b14d35893f05ee05ef1c91b35bc1d96fdd51f6b5',
    'physical_e138_role3_export': '3486c804c0f36c7486d9d336fd3f845b2d63603dfc4a81775193e55e7cc90f32',
    'physical_e138_batch_assembler': 'd2be497c03d3ab20d45add7d35ca67ab511d082731fc88d6b135c30174e96c70',
    'physical_e138_batch_candidate': '6a68e23e1040f9fd5b857d0baaac0cf0e515bd181180ef71febd1117a2022ebb',
    'physical_batch_diagnostics_e138': 'b6c8fbf1640956d333f91176521512fabced355d95c6e9b56f52a8ab2aa5f447',
    'physical_e138_readback_runtime': 'ac61db41b3a39ccfe8383c998df82826a377378e382ab9821ca762153fe25ba0',
    'physical_e138_dependency_binding': '91c9e7064c4fbd4615686699b5a4f9da795c9ff77976b0c43fd102812d15e472',
    'physical_engine_evidence_e138': '3d84926f7d2a12181928cf5a4025e1777bd39fbc19102a3606047f65f3ccca2a',
    'physical_f_replay_recipe_e138': '483124d5cc547408ae5a71bda8a0f46a545acd1908ef616b4c032750b21e7970',
}


def specification():
    previous_rows = previous.specification()['origins']
    origins = {row['name']: row['effective_sha256'] for row in previous_rows}
    origins[BOOTSTRAP] = repair.EFFECTIVE_SHA256
    effective = dict(origins, **EFFECTIVE_OVERRIDES)
    return dict(schema='e139-source-derivation-v1',
        origins=[dict(name=n, sha256=origins[n], effective_sha256=effective[n]) for n in SOURCE_ORDER],
        rules=[dict(source=n, old_hex=old.encode('ascii').hex(), new_hex=new.encode('ascii').hex(), count=count)
               for n, rows in REPLACEMENTS.items() for old, new, count in rows])


def build(original_sources):
    """All original bytes must match the fixed 56-source historical roster."""
    prior = previous.build(original_sources)
    intermediate = prior.private_sources()
    repaired = repair.build(intermediate[BOOTSTRAP])
    intermediate[BOOTSTRAP] = repaired.private_sources()[BOOTSTRAP]
    result = derive(intermediate, specification())
    manifest = result.public_manifest()
    manifest['derivation_chain'] = dict(
        historical=prior.public_manifest(), bootstrap_repair=repaired.public_manifest())
    manifest['native_graph'] = dict(schema='e140-native-graph-candidate-v1', source_order=list(SOURCE_ORDER),
        root=ROOT, phase=PHASE, execution_ready=False, authority_supplied=False,
        dormant_legacy_execution_path='physical_e138_batch_candidate.execute NOT AN E140 ENTRY',
        pending=['independent review', 'controller/entry/transport/materials integration',
                 'new E140 explicit whole-package authorization'])
    return DerivationResult(result.private_sources(), manifest)
