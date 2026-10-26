"""Pure internal Tcl identifier repair; not a new execution authorization.

Semantic E84 UIDs, RUN_ID, filenames, controls, lineage and report markers stay
unchanged. Only three exact tool-identifier suffixes per reviewed Tcl are edited.
No vendor length limit or successful Tessent execution is claimed.
"""
import copy
import re

from . import prospective_generation_recipe_e108 as recipe

SCHEMA = 'prospective-tool-identifier-repair-e123-v1'
ANCHOR = b'set run_id $::env(RUN_ID)\n'
HELPER = (b'set tool_id r\n'
          b'foreach tool_char [split $run_id ""] {append tool_id [format "%02x" [scan $tool_char "%c"]]}\n'
          b'puts "TOOL_DESIGN_ID_TOKEN=$tool_id"\n')
require, sha, canonical = recipe.require, recipe.sha, recipe.canonical


def encode(uid):
    """Injective byte-hex encoding for the validated ASCII semantic UID."""
    require(recipe.stage.safe_uid(uid), 'ASCII_SEMANTIC_UID_REQUIRED')
    return 'r' + uid.encode('ascii').hex()


def _patterns(name):
    kind = b'atpg' if name == 'common' else b'incremental'
    return (
        b'set_context patterns -scan -design_identifier ${circuit}_${mode}_mapped_' + kind + b'_${run_id}\n',
        b'  set_current_mode F_mapped_' + kind + b'_${run_id}\n',
        b'  set_current_mode ${mode}_mapped_' + kind + b'_${run_id}\n')


def validate_roster():
    """Check all 78 exact plan UIDs without assigning a vendor length limit."""
    plan = recipe.pilot.build_plan()
    uids, tokens, contexts, modes = [], [], [], []
    tessent_contexts, tessent_modes = [], []
    for phase in plan['phases']:
        for task in phase['tasks']:
            uid = task['task_uid']
            token = encode(uid)
            stage = task.get('stage', task.get('target_mode'))
            kind = 'atpg' if stage == 'H' else 'incremental'
            context = phase['circuit'] + '_' + stage + '_mapped_' + kind + '_' + token
            current = [prefix + '_mapped_' + kind + '_' + token for prefix in ('F', stage)]
            for value in [token, context] + current:
                require(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9_]*[A-Za-z0-9])?', value) is not None and
                        '__' not in value, 'TOOL_IDENTIFIER_CHARACTER_RULE')
            uids.append(uid)
            tokens.append(token)
            contexts.append(context)
            modes.extend(current)
            if task['kind'] == 'TESSENT':
                tessent_contexts.append(context)
                tessent_modes.extend(current)
    require(len(uids) == 78 and len(set(uids)) == len(set(tokens)) == len(set(contexts)) == 78,
            'FIXED_ROSTER_OR_ENCODING_COLLISION')
    return dict(semantic_task_uids=78, unique_tokens=78, unique_context_names=78,
                maximum_token_characters=max(map(len, tokens)),
                maximum_context_identifier_characters=max(map(len, contexts)),
                maximum_current_mode_characters=max(map(len, modes)),
                preview_scope='ALL_78_TASK_UIDS_INCLUDING_NON_TESSENT_TRANSLATION_UIDS',
                actual_tessent_task_count=len(tessent_contexts),
                maximum_tessent_context_identifier_characters=max(map(len, tessent_contexts)),
                maximum_tessent_current_mode_characters=max(map(len, tessent_modes)),
                tool_identifiers_alphanumeric_underscore_only=True,
                first_and_last_characters_alphanumeric=True, double_underscore_present=False,
                vendor_length_limit_verified=False)


def transform_sources(e108_sources):
    """Accept only exact E108 sources; return separately identified new bytes."""
    sources = copy.deepcopy(e108_sources)
    recipe._sources(sources)
    derived, rows = {}, {}
    for name in ('common', 'incremental'):
        original = sources[name]['tcl_bytes']
        require(original.count(ANCHOR) == 1 and b'tool_id' not in original and
                b'TOOL_DESIGN_ID_TOKEN' not in original, 'EXACT_UNREPAIRED_RUN_ID_ANCHOR')
        updated = original.replace(ANCHOR, ANCHOR + HELPER, 1)
        for pattern in _patterns(name):
            require(original.count(pattern) == 1, 'EXACT_THREE_TOOL_IDENTIFIER_LINES')
            replacement = pattern.replace(b'${run_id}', b'${tool_id}')
            require(pattern.count(b'${run_id}') == 1, 'EXACT_SUFFIX_REPLACEMENT')
            updated = updated.replace(pattern, replacement, 1)
        # Mechanical inverse proves there are no unrelated edits.
        inverse = updated.replace(ANCHOR + HELPER, ANCHOR, 1)
        for pattern in _patterns(name):
            inverse = inverse.replace(pattern.replace(b'${run_id}', b'${tool_id}'), pattern, 1)
        require(inverse == original and updated.count(b'${tool_id}') == 3 and
                updated.count(b'TOOL_DESIGN_ID_TOKEN=') == 1 and b'add_processors' not in updated,
                'IDENTIFIER_ONLY_TRANSFORMATION')
        derived[name] = updated
        rows[name] = dict(reviewed_base_source_sha256=sources[name]['base_sha256'],
            pre_repair_effective_sha256=sha(original), post_repair_effective_sha256=sha(updated),
            pre_repair_bytes=len(original), post_repair_bytes=len(updated),
            exact_diff_counts=dict(helper_block_insertions=1, helper_lines_inserted=3,
                design_identifier_suffix_replacements=1, current_mode_suffix_replacements=2,
                diagnostic_marker_insertions=1, unrelated_line_edits=0))
    manifest = dict(schema=SCHEMA, transformation='ASCII_UID_HEX_INTERNAL_TOOL_IDENTIFIERS_ONLY',
        encoding='r + semantic_uid.encode(ascii).hex()', sources=rows, roster=validate_roster(),
        semantic_uids_changed=False, runtime_run_id_changed=False, output_paths_changed=False,
        controls_changed=False, parent_sha_changed=False, legacy_markers_changed=False,
        random_or_compaction_policy_changed=False, source_ds_di_changed=False,
        helper_sha256=sha(HELPER), tessent_verified=False, vendor_length_limit_verified=False,
        execution_authorized=False, execution_ready=False, training_release=False,
        new_package_authorization_required=True)
    manifest['manifest_sha256'] = sha(canonical(manifest))
    return dict(derived_sources=derived, manifest=manifest)
