"""Finite native graph bytes, NOT an entry, source-session release or grant.

build() performs no IO, import/compile of derived modules, or registry mutation.
It composes the six reviewed identity migrations with eight additional nodes
and 42 byte-identical legacy helpers. Compatibility module keys/errors remain.
The dormant batch_candidate still contains its E137 algorithm; it is included
for contract roster compatibility, NOT an E139 execution path. The actual path
is batch_assembler. Source-session freezing remains an independent caller duty.
"""
import base64

from scripts import e139_contract_bootstrap_candidate as pair
from scripts import e139_runtime_identity_candidate as runtime
from scripts.e139_source_derivation import derive, DerivationResult

SOURCE_ORDER = (
    'physical_e138_contract', 'direct_runtime_compatibility_e102', 'direct_diagnostic_policy_e102',
    'prospective_tessent_acceptance_v1', 'direct_low_memory_recipe_e104', 'direct_memory_sample_e101',
    'direct_memory_sample_e103', 'direct_observation_journal_e102', 'prospective_fault_translation_v2',
    'prospective_lsf_memory_preflight_v1', 'prospective_acceptance_materializer_v1', 'direct_scratch_monitor_e102',
    'prospective_acceptance_scratch_v1', 'direct_tessent_acceptance_e100', 'direct_tessent_acceptance_e104',
    'prospective_fault_translation_e129', 'prospective_report_dialect_e115', 'prospective_report_dialect_e126',
    'eq_group_coverage_e133_r2', 'prospective_input_binding_v1', 'prospective_acquisition_pilot_v1',
    'prospective_acquisition_request_v1', 'prospective_request_features_v1', 'prospective_stage_observation_v1',
    'prospective_tessent_stage_v1', 'prospective_acquisition_binding_v1', 'prospective_generation_recipe_e108',
    'prospective_generation_supervision_e109', 'prospective_generation_process_e113', 'prospective_generation_storage_e118',
    'physical_f_replay_execution_e135', 'physical_e138_runtime_primitives', 'physical_replay_source_reader_e135',
    'physical_replay_source_inventory_e135', 'physical_replay_capture_e138', 'physical_batch_diagnostics_e138',
    'physical_e138_root_receipt', 'prospective_runtime_profile_e112', 'prospective_runtime_adapter_e114',
    'physical_runtime_bootstrap_e138', 'physical_e138_batch_assembler', 'physical_f_replay_recipe_e135_r2',
    'physical_replay_capture_e137', 'physical_f_replay_execution_e137', 'physical_e137_root_receipt',
    'physical_engine_selector_e137', 'physical_engine_evidence_e137', 'physical_runtime_bootstrap_e137',
    'physical_stil_dependencies_e137', 'physical_e138_batch_candidate', 'physical_e138_dependency_binding',
    'physical_engine_evidence_e138', 'physical_f_replay_recipe_e138', 'physical_e138_role2_join',
    'physical_e138_role3_export', 'physical_e138_readback_runtime',
)

# Fixed local closure identities; these 42 sources receive zero edits.
UNCHANGED_PINS = {
    'direct_diagnostic_policy_e102': '67dbbd601cdcd667c06bc8b0c238016da2c6689a9549f0601b5f6a0fc7010ff0',
    'direct_low_memory_recipe_e104': '66843a6ae2a2660c85044835bda387221c779507b69fa4a5499de8149bd3ebbd',
    'direct_memory_sample_e101': '8a4e81fb3ef50cb3ad7fcd720d7f205ba7df6228b2af34dd87c0986968a22009',
    'direct_memory_sample_e103': '17e4522849a386a268f7135f870e8d49bb190c032b819cf69f037fd27ee13cbb',
    'direct_observation_journal_e102': 'e53e1d3b32f237519adf52b8d1005f7c592b428150e8b8e91bbe46878437c027',
    'direct_runtime_compatibility_e102': '2ec8387acec97e38604141ea5e108149dbc310823c23684da1d7fb194f8d71c1',
    'direct_scratch_monitor_e102': '8ef6652bcf18867f3a5db44aad103f3734ff7b886a3d04912274c5ed150b4174',
    'direct_tessent_acceptance_e100': '92f9915bc431483ba73cc38829356ca315a16ae39713b021b2025d0ce744fb58',
    'direct_tessent_acceptance_e104': '6b7961e8238b2676a9c90a69a1c554be7238daa789de2e41a1e820044e17b190',
    'eq_group_coverage_e133_r2': '879b0d244e4d649c4a6be5a673bb1b566000cce69194d555634ad3d8037fc37e',
    'physical_e137_root_receipt': 'f71bacfe5ab935dc2e02f6890a8c994ce625759b8dd7ff2c1a89e68b64bf815c',
    'physical_engine_evidence_e137': 'b1ed9394047575d4066459b091d2b7bcb542342711152530c1a22506db0f3df2',
    'physical_engine_selector_e137': 'efcf80e98b4a26051d057320e4dc75882929545fbd42be41be4336a2586d5d73',
    'physical_f_replay_execution_e135': '83fa927774b59d43ad838d09333f6ad787edfed27cd52043f9fcda4dc4b9f85f',
    'physical_f_replay_execution_e137': '7a02a84f6a3e4ac5dc9d3fb6ff6ba648aba96911e0ffdfbb2e87c3f8bdfcfafd',
    'physical_f_replay_recipe_e135_r2': '63ab7aba869d9d755488cb8aaa4e5629b595d9e1672b1db35458e565771a62d2',
    'physical_replay_capture_e137': '5d911a9df834b1e155f1bd200261ffb078be98bd0420b31b39d71140ef500e76',
    'physical_replay_source_inventory_e135': '9467ee407dec9fd9bccad3ffdc517a508789c38b404fe9ac7d9d499fbd1be48d',
    'physical_replay_source_reader_e135': '6d6f86341eca23d5b473f8e323a0440d50ea44d177032576f196b9b417690818',
    'physical_runtime_bootstrap_e137': 'd59531d92a2f3cd7080497d7a77eb51c61e543aecbeeb6304d21aae6ef07990d',
    'physical_stil_dependencies_e137': '0ea8dcc1454306084d12a9f4ac439c6d19c8eed9e036aac85b0eac510caacc3d',
    'prospective_acceptance_materializer_v1': 'a04127c07227814e331ede4268c6f8d5df4def4d7041c0c69ec048378216cab9',
    'prospective_acceptance_scratch_v1': 'ddf332e6d78a81cf2369bdcdee9e60c1ee3b9b1c22008bf7a77beaedee39cb86',
    'prospective_acquisition_binding_v1': '29804349ff853bd5ee2765f162e91037602affd3ef60ba0411cf4109254fe3bf',
    'prospective_acquisition_pilot_v1': 'be5c338ac9429920f08ccfd03cae7087e5114f90e05b51883408f7e0228e90f3',
    'prospective_acquisition_request_v1': '2cbd2fd1e0689d12e19c22ca8536a789cf7241ce11c5fc68f2d23a0ae85cebcf',
    'prospective_fault_translation_e129': 'f659ca52bc6c48645736162223d1f6a931c343d4dd6cafac690aaeff90a2c681',
    'prospective_fault_translation_v2': '2488abc20cf6e55aabb5d80317615645ed9bbaf80eb97d75f05920befd8b1961',
    'prospective_generation_process_e113': '6b1922de253550b3d4091f11186d9447867662c445e46fdc47801f3c340411f6',
    'prospective_generation_recipe_e108': 'c690a8de88b1b9c10b0f730d62391cc1b82aee31871e780af0044b441eaa7f31',
    'prospective_generation_storage_e118': '0045cb1c6ba4b81cf4f1d2d6c8723c44d69bb48d3b357c8c95e8a217c14597bb',
    'prospective_generation_supervision_e109': '6bc12ff0843316e4fdd96cb99016af1f271459547869537133f68e060e245f17',
    'prospective_input_binding_v1': '1acfed165d9cdfeedb6abd886ff028be221d840fe39c2894ca4070fd81ab5e32',
    'prospective_lsf_memory_preflight_v1': 'c63e8d9dea1aefef2061de2c3147c574f9dc2881e9b97dd89d585bfaf4fa46dd',
    'prospective_report_dialect_e115': '102ed449c9f12f46edebd5ab31bb99b8e14c3f465b0ac70b5121606ad3617b0d',
    'prospective_report_dialect_e126': '12fdb3e3cb7b52c32465f461fa63a6598f6bac555669d63540ac18e0bd3174a0',
    'prospective_request_features_v1': 'a592fb99a06c4f084ef10043ec6c215f0d72208c0dfe6ce608971653d56a6fd5',
    'prospective_runtime_adapter_e114': '57ad390828e2ce33e2bebd0830c787473e98a7ba1c31843e12b03759ef6a77f1',
    'prospective_runtime_profile_e112': 'b7f096782faefe9abcd9e3e748176ffcf3c2944c72cb1d39b32b0d196d1a2e3a',
    'prospective_stage_observation_v1': '4f87639fc8928b4f098f4d00510e7cc0e2d7d1115c33ca65c93c6494537f086b',
    'prospective_tessent_acceptance_v1': '6d4b45d303a4be34f03914b8f9cb4aad2d9fe73c41c666a6c12058c43ef5aac2',
    'prospective_tessent_stage_v1': 'f40abcd0162e4b698542a91288e26263b467789591bec125046f2c5f12c3b110',
}
EXTRA_ORIGIN_PINS = {
    'physical_replay_capture_e138': '3ab9950455e04336700b7de6c58b0bd07d2acc73e878d3c033a427bb4c2b3963',
    'physical_e138_batch_candidate': 'db107a779102a80dba68dccb132ff9941873842cbef99ea088fe23024ece05f1',
    'physical_batch_diagnostics_e138': 'c4ed6c0d1cdfdd7bdc7b0ad5feb08f2c76f4602a05b5bcce12db12bd300c9de2',
    'physical_e138_batch_assembler': '42f413b59abba7ac4a9f8b7a101c0d25d678bdebfa165f00cbe23a85f894e6d7',
    'physical_e138_readback_runtime': '853c70478844c8a659d0bb88e50824093e4e34cf15f6d9da002578ce451b67c4',
    'physical_e138_dependency_binding': '2cb17b773ecfbe3c88c27859a77118592a8439f2694052412741c5b9e9c96639',
    'physical_engine_evidence_e138': '965977782ed159a07ad6a464079c43408318c0281ea96ec69bf49b2e080bf246',
    'physical_f_replay_recipe_e138': 'd14f2dded701f4634a550e797cf568eebdbf262269f8ec8af2c93974e97883d9',
}
EXTRA_EFFECTIVE_PINS = {
    'physical_replay_capture_e138': '861d3e81e12d117db886b5eb4d50e8bd2b84d97359e90ef9f11a567e4cf74119',
    'physical_e138_batch_candidate': '7d848c3c2ccb58e0389a894e3e9111811356d2b7dc1e1886324d8894a51cbbbc',
    'physical_batch_diagnostics_e138': '7c9589d71b29da643ccdd5a7e6cc08aa9105b4a72b823c919d62def155d54404',
    'physical_e138_batch_assembler': 'ee109e0a8dfeaa9739e3c2a23699d343c2fde2f4e7211523b2ade49496bb7a7a',
    'physical_e138_readback_runtime': 'ef49028d45ee6478a5bf213b0d25df3a10a54d87526704d4c1ebd69773dfaf24',
    'physical_e138_dependency_binding': '88f1fb96ab7a36566a59c2addafcac60290c181429cddf696c6ceccfdd349710',
    'physical_engine_evidence_e138': '1f96dfb665f40ad3d190cb805ca971889950d525a3036d521e3f497a78b7d517',
    'physical_f_replay_recipe_e138': '06f3ff9cc587c1970b1a8589343e027fba6af7022eea746f765294fa654eb405',
}
# Complete quoted schema literals only; no global identifier/version rewrite.
EXTRA_REPLACEMENTS = {
    'physical_replay_capture_e138': (
        ("'physical-f-clean-replay-source-capture-e138-v1'", "'physical-f-clean-replay-source-capture-e139-v1'", 1),
        ("'physical_e138_contract':'19bdaaf461de3ff424df57cf8e263f80efd57fa2a67a9929d5f89c4188f917f6'",
         "'physical_e138_contract':'6236ade200957cfc5476c726dc2fda45231806552291952d9cc1fd8778088730'", 1)),
    'physical_e138_batch_candidate': (("'e138-batch-candidate-failure-v1'", "'e139-batch-candidate-failure-v1'", 1),),
    'physical_batch_diagnostics_e138': (("'e138-bounded-failure-diagnostic-v1'", "'e139-bounded-failure-diagnostic-v1'", 1),),
    'physical_e138_batch_assembler': (
        ("'e138-private-runtime-bootstrap-v1'", "'e139-private-runtime-bootstrap-v1'", 1),
        ("'physical-f-clean-replay-execution-e138-v1'", "'physical-f-clean-replay-execution-e139-v1'", 1),
        ("'e138-supervisor-final-cleanup-observation-v1'", "'e139-supervisor-final-cleanup-observation-v1'", 1)),
    'physical_e138_readback_runtime': (("'e138-readback-partial-failure-v1'", "'e139-readback-partial-failure-v1'", 1),),
    'physical_e138_dependency_binding': (("'e138-derived-dependency-binding-v1'", "'e139-derived-dependency-binding-v1'", 1),),
    'physical_engine_evidence_e138': (("'e138-finite-engine-evidence-v1'", "'e139-finite-engine-evidence-v1'", 1),),
    'physical_f_replay_recipe_e138': (("'physical-f-clean-replay-recipe-e138-candidate-v1'", "'physical-f-clean-replay-recipe-e139-candidate-v1'", 1),),
}


def specification():
    """Fresh finite graph specification, with literal reviewed identities."""
    origins = dict(UNCHANGED_PINS, **EXTRA_ORIGIN_PINS)
    effective = dict(UNCHANGED_PINS, **EXTRA_EFFECTIVE_PINS)
    rules = []
    for candidate in (pair, runtime):
        spec = candidate.specification()
        for row in spec['origins']:
            if row['name'] in origins:
                raise ValueError('E139_DUPLICATE_GRAPH_ORIGIN')
            origins[row['name']] = row['sha256']
            effective[row['name']] = row['effective_sha256']
        rules.extend(spec['rules'])
    if len(SOURCE_ORDER) != len(set(SOURCE_ORDER)) or set(SOURCE_ORDER) != set(origins):
        raise ValueError('E139_EXACT_NATIVE_GRAPH_ROSTER')
    rules.extend(dict(source=name, old_hex=old.encode('ascii').hex(),
                      new_hex=new.encode('ascii').hex(), count=count)
                 for name, rows in EXTRA_REPLACEMENTS.items() for old, new, count in rows)
    return dict(schema='e139-source-derivation-v1',
                origins=[dict(name=name, sha256=origins[name], effective_sha256=effective[name])
                         for name in SOURCE_ORDER], rules=rules)


def build(sources):
    result = derive(sources, specification())
    manifest = result.public_manifest()
    manifest['native_graph'] = dict(schema='e139-native-graph-candidate-v1',
        source_order=list(SOURCE_ORDER), execution_ready=False,
        execution_path='physical_e138_batch_assembler',
        dormant_legacy_execution_path='physical_e138_batch_candidate.execute NOT AN E139 ENTRY',
        pending=['script/controller/transport/phase integration', 'actual E139 authorization',
                 'independent exact-package review'])
    return DerivationResult(result.private_sources(), manifest)


def source_rows(sources):
    """Derive/verify first, then make loader-compatible rows, with no loading.

    A caller must freeze the unchanged scoped loader separately against the
    independently reviewed effective pins and SOURCE_ORDER. Rows are private
    source material and must not be logged or exported as public metadata.
    """
    result = build(sources)
    effective = result.private_sources()
    pins = {row['name']: row['effective_sha256'] for row in result.public_manifest()['sources']}
    return [dict(name=name, sha256=pins[name],
                 body_base64=base64.b64encode(effective[name]).decode('ascii')) for name in SOURCE_ORDER]
