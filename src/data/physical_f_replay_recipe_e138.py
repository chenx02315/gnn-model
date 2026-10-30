"""Pure E138 Tcl/helper derivation from the frozen reviewed parent recipe.

Only the execution-root bytes change. No filesystem, runtime admission or
Tessent entrypoint exists here. Parent modules and their gates stay untouched.
"""
from . import physical_f_replay_recipe_e135_r2 as parent
from . import physical_e138_contract as contract

ROOT=contract.ROOT
EXPECTED_PARENT_SOURCE_SHA256='63ab7aba869d9d755488cb8aaa4e5629b595d9e1672b1db35458e565771a62d2'


def build_candidate(incremental,parent_helper):
    require,sha=parent.legacy.require,parent.legacy.sha
    require(ROOT==contract.ROOT and ROOT!=parent.ROOT and ROOT!=parent.legacy.ROOT,
        'E138_RECIPE_FIXED_NEW_ROOT')
    old=parent.build_candidate(incremental,parent_helper)
    pairs=(('body','sha256'),('baseline_expectations_body','baseline_expectations_sha256'))
    derived={}
    for body_key,sha_key in pairs:
        raw=old[body_key]
        require(type(raw) is bytes and len(raw)<=131072 and sha(raw)==old[sha_key] and
            parent.ROOT.encode('ascii') in raw and parent.legacy.ROOT.encode('ascii') not in raw,
            'E138_RECIPE_PARENT_ARTIFACT_PIN')
        result=raw.replace(parent.ROOT.encode('ascii'),ROOT.encode('ascii'))
        require(parent.ROOT.encode('ascii') not in result and ROOT.encode('ascii') in result,
            'E138_RECIPE_ROOT_REBIND_INCOMPLETE')
        # Exact reverse equivalence rejects any edit beyond this root change.
        require(result.replace(ROOT.encode('ascii'),parent.ROOT.encode('ascii'))==raw,
            'E138_RECIPE_NON_ROOT_CHANGE')
        derived[body_key],derived[sha_key]=result,sha(result)
    return dict(derived,schema='physical-f-clean-replay-recipe-e138-candidate-v1',root=ROOT,
        parent_main_sha256=old['sha256'],parent_helper_sha256=old['baseline_expectations_sha256'],
        expected_parent_source_sha256=EXPECTED_PARENT_SOURCE_SHA256,
        parent_source_identity_observed=False,independent_review_pass=False,
        execution_authorized=False,execution_ready=False,physical_d95_verified=False)
