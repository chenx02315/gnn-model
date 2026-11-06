"""Pure four-module wire-identity candidate, NOT a complete E139 graph.

No source import, compile, loader, IO, freeze filling or dispatch. Historical
module names, diagnostics and __e138_binding__ attributes remain compatibility
labels. All fixed legacy/helper source pins and default-None gates are retained.
Contract/bootstrap derivation is separate. Clock, worker-response and cleanup
producers outside this subset still require explicit migration and review.
"""
import copy

from scripts.e139_source_derivation import derive, DerivationResult


RUNTIME = 'physical_e138_runtime_primitives'
RECEIPT = 'physical_e138_root_receipt'
JOIN = 'physical_e138_role2_join'
EXPORT = 'physical_e138_role3_export'
MODULES = (RUNTIME, RECEIPT, JOIN, EXPORT)

# Deliberately enumerated full quoted wire literals, each exactly once.
REPLACEMENTS = {
    RUNTIME: (
        ("'physical-f-clean-replay-execution-e138-v1'", "'physical-f-clean-replay-execution-e139-v1'", 1),
        ("'physical-f-clean-replay-package-clock-e138-v1'", "'physical-f-clean-replay-package-clock-e139-v1'", 1),
        ("'e138-derived-services-binding-v1'", "'e139-derived-services-binding-v1'", 1),
    ),
    RECEIPT: (
        ("'e138-unqualified-root-receipt-diagnostic-v1'", "'e139-unqualified-root-receipt-diagnostic-v1'", 1),
        ("'e138-supervisor-final-cleanup-observation-v1'", "'e139-supervisor-final-cleanup-observation-v1'", 1),
        ("'e138-final-registered-root-receipt-v1'", "'e139-final-registered-root-receipt-v1'", 1),
    ),
    JOIN: (
        ("'e138-final-registered-root-receipt-v1'", "'e139-final-registered-root-receipt-v1'", 1),
        ("'e138-authenticated-role2-owned-root-context-v1'", "'e139-authenticated-role2-owned-root-context-v1'", 1),
    ),
    EXPORT: (
        ("'e138-authenticated-role2-owned-root-context-v1'", "'e139-authenticated-role2-owned-root-context-v1'", 1),
    ),
}
ORIGIN_PINS = {
    RUNTIME: 'ae0c139e9a7cb1a822b0fc95b4706fbb16f41cc1ee945963742a8f71cb97a213',
    RECEIPT: 'a689e5c3b4f51f9525c3ead79ad8114d3858951c717b1487a9a328a18d54a239',
    JOIN: 'd336762b31a57628c1dd29d2d0e6b0ea9968f2fd441c76cfad185c1bacc94597',
    EXPORT: 'ee5073af10faab34b8b6202b2deca62900d3f4d0d8b133cd61cf691a4015dea3',
}
EFFECTIVE_PINS = {
    RUNTIME: '422edd6f18270b74cd317d9248587320253aa7e7d507b5e9675a74e47a855b8e',
    RECEIPT: '2f7967e961e7b34b05eaa26cf695752134ae26f35103feef025c293d7a640476',
    JOIN: '9bd17395177574cba0c9f9524e87722e8e6edece9f9b62f67402ff0974bb792e',
    EXPORT: '8be706a439b7ba6ba961ea8568ee8efa9e427108b75c60fcc9f73596941f14dc',
}


def specification():
    """Independent snapshot of the finite source/rule/effective commitments."""
    return dict(schema='e139-source-derivation-v1',
        origins=[dict(name=name, sha256=ORIGIN_PINS[name],
                      effective_sha256=EFFECTIVE_PINS[name]) for name in MODULES],
        rules=[dict(source=name, old_hex=old.encode('ascii').hex(),
                    new_hex=new.encode('ascii').hex(), count=count)
               for name in MODULES for old, new, count in REPLACEMENTS[name]])


def schema_inventory():
    """Wire relationships, not evidence that producers/consumers executed.

    Names prefixed OUTSIDE_SUBSET describe missing integration obligations.
    Runtime constants consumed through module aliases are listed explicitly.
    """
    return copy.deepcopy([
        dict(schema='physical-f-clean-replay-execution-e139-v1',
             producers=['OUTSIDE_SUBSET:worker response/assembler'],
             consumers=[RUNTIME + '.SCHEMA', RECEIPT + '.worker.SCHEMA', JOIN + '.runtime.SCHEMA']),
        dict(schema='physical-f-clean-replay-package-clock-e139-v1',
             producers=['OUTSIDE_SUBSET:initial clock capture'],
             consumers=[RUNTIME + '.package_clock', RECEIPT + '.worker.package_clock',
                        JOIN + '.runtime.package_clock', EXPORT + '.runtime.package_clock']),
        dict(schema='e139-derived-services-binding-v1',
             producers=[RUNTIME + '.private_services'],
             consumers=['OUTSIDE_SUBSET:services binding audit']),
        dict(schema='e139-unqualified-root-receipt-diagnostic-v1',
             producers=[RECEIPT + '.tracked_services.Session.emit.partial'],
             consumers=['OUTSIDE_SUBSET:diagnostic persistence/audit']),
        dict(schema='e139-supervisor-final-cleanup-observation-v1',
             producers=['OUTSIDE_SUBSET:supervisor cleanup observer/assembler'],
             consumers=[RECEIPT + '.tracked_services.Session.emit']),
        dict(schema='e139-final-registered-root-receipt-v1',
             producers=[RECEIPT + '.tracked_services.Session.emit'], consumers=[JOIN + '.join']),
        dict(schema='e139-authenticated-role2-owned-root-context-v1',
             producers=[JOIN + '.join'], consumers=[EXPORT + '._authenticated_context']),
    ])


def build(sources):
    """Return pinned bytes and metadata only; leave every execution gate closed."""
    result = derive(sources, specification())
    manifest = result.public_manifest()
    manifest['candidate_scope'] = dict(
        schema='e139-four-module-wire-identity-candidate-v1',
        complete_private_graph=False, execution_ready=False,
        schema_links=schema_inventory(),
        pending=['contract/bootstrap composition', 'external producers and consumers',
                 'source graph and actual-byte freeze binding', 'independent review',
                 'actual E139 authorization', 'entry/transport integration'])
    return DerivationResult(result.private_sources(), manifest)
