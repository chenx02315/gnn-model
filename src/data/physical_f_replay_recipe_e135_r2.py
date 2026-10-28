"""Pure, disabled recipe candidate; no runtime entry or old module mutation.

The recovered 2021.2 reference requires external pattern reporting. This module
does not authorize use of E135's consumed budget or establish physical D95.
"""
from . import physical_f_replay_execution_e135 as legacy

SCHEMA = 'physical-f-replay-recipe-e135-r2-candidate-v1'
ROOT = '/temp/jiangchuanc/multimode_ate_physical_f_replay_e135_recipe_r2'
REFERENCE_SHA256 = '26dab6d35d24ce518e8d2d2256f92276a5337348d789c551b248d47c51fd9ab0'
INDEPENDENT_SEMANTIC_REVIEW = None
EXECUTION_AUTHORIZATION = None


def build_candidate(incremental, expectation_bytes):
    """Return Tcl bytes for review only; caller cannot inject commands or paths."""
    legacy.require(type(expectation_bytes) is bytes and
                   expectation_bytes == legacy.EXPECTED_INIT.encode('ascii'),
                   'EXACT_BASELINE_EXPECTATIONS_REQUIRED')
    old = legacy.build_recipe(incremental, expectation_bytes)
    text = old['body'].decode('ascii')
    load = 'read_patterns '+legacy.ROOT+'/inputs/tester.stil\n'
    simulate = 'simulate_patterns -source external\n'
    report = 'report_patterns > '+legacy.ROOT+'/snapshots/simulated.patterns.rpt\n'
    # Exact anchors fail closed if the frozen prototype changes underneath us.
    for anchor in (load, simulate, report):
        legacy.require(text.count(anchor) == 1, 'LEGACY_RECIPE_ANCHOR_DRIFT')
    text = text.replace(load, load+'report_patterns -external > '+legacy.ROOT+
                        '/snapshots/loaded.patterns.rpt\n')
    text = text.replace(simulate,
                        'simulate_patterns -source external -store_patterns none\n')
    text = text.replace(report, 'report_patterns -external > '+legacy.ROOT+
                        '/snapshots/simulated.patterns.rpt\n')
    text = text.replace(legacy.ROOT, ROOT)
    legacy.require(legacy.ROOT not in text and text.count('report_patterns -external > ') == 2,
                   'ISOLATED_EXTERNAL_REPORTS_REQUIRED')
    raw = text.encode('ascii')
    # The sourced helper is a second artifact, not part of the main Tcl body.
    # Bind the actual rebased bytes, never the parent helper's old-root digest.
    helper = expectation_bytes.decode('ascii')
    helper_anchor = '[open '+legacy.ROOT+'/inputs/F.basic r]'
    legacy.require(helper.count(helper_anchor) == 1, 'LEGACY_HELPER_ANCHOR_DRIFT')
    helper_bytes = helper.replace(legacy.ROOT, ROOT).encode('ascii')
    legacy.require(legacy.ROOT.encode('ascii') not in helper_bytes,
                   'ISOLATED_BASELINE_HELPER_REQUIRED')
    return dict(schema=SCHEMA, body=raw, sha256=legacy.sha(raw),
                parent_recipe_sha256=old['sha256'], reference_sha256=REFERENCE_SHA256,
                baseline_expectations_body=helper_bytes,
                baseline_expectations_sha256=legacy.sha(helper_bytes),
                parent_baseline_expectations_sha256=legacy.sha(expectation_bytes),
                independent_review_pass=False, execution_authorized=False,
                physical_d95_verified=False)
