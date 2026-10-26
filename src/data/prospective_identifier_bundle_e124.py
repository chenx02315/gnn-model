"""Fixed offline whitelist compiler for the separately authorized E124 package.

Never modifies v1 files/modules, executes derived code, deploys or launches.
Only the named E108/E116/E118/E117/E120 edits below are supported. New context
and worker source bytes are deployment inputs and still require exact review.
"""
import ast
import base64
import copy
import difflib
import hashlib
import json
from pathlib import Path

from . import prospective_tool_identifiers_e123 as identifiers

ROOT = '/temp/jiangchuanc/multimode_ate_identifier_repair_e124_20261027_r1'
AUTH_SHA256 = 'b9fb213ad18081dd0970ab765cf869e9591621c0dabf5c9184f629e98e4317b0'
REVIEW_SHA256 = 'a1160a008bf698ab01e9654881b13365efa0fbebbc29b4ce04a29bf3f16909ce'
E123_SHA256 = '0d13a3c8592775df69e61636b30782cce4375cffd4fc9ecbfd9f07f04e09bf4d'
OLD_BOOT = '3ebeb9bb-410c-476c-a000-5c625f590473'
OLD_START = 2332488.679409259
SCHEMA = 'prospective-identifier-bundle-e124-v1'
CONTEXT_NAME = 'prospective_generation_context_e124'
WORKER_NAME = 'e124_worker'
require, canonical = identifiers.require, identifiers.canonical
ALLOWLIST = frozenset((
    'prospective_tessent_acceptance_v1', 'prospective_fault_translation_v2',
    'prospective_lsf_memory_preflight_v1', 'prospective_acceptance_materializer_v1',
    'prospective_acceptance_scratch_v1', 'direct_tessent_acceptance_e100',
    'direct_memory_sample_e101', 'direct_memory_sample_e103', 'direct_runtime_compatibility_e102',
    'direct_scratch_monitor_e102', 'direct_observation_journal_e102', 'direct_diagnostic_policy_e102',
    'direct_low_memory_recipe_e104', 'direct_tessent_acceptance_e104',
    'prospective_input_binding_v1', 'prospective_request_features_v1', 'prospective_acquisition_pilot_v1',
    'prospective_acquisition_request_v1', 'prospective_stage_observation_v1', 'prospective_tessent_stage_v1',
    'prospective_acquisition_binding_v1', 'prospective_generation_recipe_e108', 'prospective_runtime_profile_e112',
    'prospective_generation_supervision_e109', 'prospective_generation_materializer_e111',
    'prospective_generation_process_e113', 'prospective_runtime_adapter_e114', 'prospective_report_dialect_e115',
    'prospective_generation_controller_e116', 'prospective_generation_diagnostics_e120',
    'prospective_generation_artifacts_e117', 'prospective_generation_storage_e118'))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _read(repo, relative, pin=None):
    path = repo / relative
    require(not path.is_symlink() and path.stat().st_size <= 1048576, 'FIXED_REPO_SOURCE_BOUND')
    raw = path.read_bytes()
    require(len(raw) <= 1048576 and (pin is None or sha(raw) == pin), 'ORIGIN_SOURCE_PIN')
    return raw


def _literal(raw, name):
    tree = ast.parse(raw.decode('utf-8'))
    matches = [node.value for node in tree.body if isinstance(node, ast.Assign) and
               len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    require(len(matches) == 1, 'EXACT_FIXED_ROSTER_ASSIGNMENT')
    return ast.literal_eval(matches[0])


class _Edits(object):
    """Internal audit recorder, called only by the closed fixed derivations."""
    def __init__(self, name, raw):
        self.name, self.origin, self.raw, self.operations = name, raw, raw, []

    def exact(self, label, before, after, count=1):
        require(type(before) is bytes and before and self.raw.count(before) == count, 'EXACT_EDIT_' + label)
        offsets, cursor = [], 0
        for _ in range(count):
            offset = self.raw.index(before, cursor)
            offsets.append([offset, offset + len(before)])
            cursor = offset + len(before)
        old_sha = sha(self.raw)
        self.raw = self.raw.replace(before, after)
        self.operations.append(dict(edit=label, expected_count=count, actual_count=count,
            allowed_byte_ranges=offsets, before_fragment_sha256=sha(before), after_fragment_sha256=sha(after),
            before_source_sha256=old_sha, after_source_sha256=sha(self.raw)))

    def append(self, label, suffix):
        position, old_sha = len(self.raw), sha(self.raw)
        self.raw += suffix
        self.operations.append(dict(edit=label, expected_count=1, actual_count=1,
            allowed_byte_ranges=[[position, position]], before_fragment_sha256=sha(b''),
            after_fragment_sha256=sha(suffix), before_source_sha256=old_sha,
            after_source_sha256=sha(self.raw)))

    def audit(self):
        return dict(name=self.name, origin_sha256=sha(self.origin), sha256=sha(self.raw),
            changed=self.origin != self.raw, edits=self.operations,
            unified_diff=''.join(difflib.unified_diff(self.origin.decode('utf-8').splitlines(True),
                self.raw.decode('utf-8').splitlines(True), fromfile=self.name + ':v1', tofile=self.name + ':e124')))


def _recipe(raw, repaired):
    edit = _Edits('prospective_generation_recipe_e108', raw)
    edit.exact('NEW_EXCLUSIVE_ROOT', ("ROOT='" + identifiers.recipe.ROOT + "'").encode('ascii'),
               ("ROOT='" + ROOT + "'").encode('ascii'))
    edit.exact('EXPLICIT_REPAIR_TRANSFORMATION', b"transformation='EXACT_SINGLE_ADD_PROCESSORS_COMMAND_REMOVAL'",
        b"transformation='E108_PROCESSOR_REMOVAL_PLUS_E123_TOOL_IDENTIFIERS_AND_E124_NAMESPACE'")
    tcls = repaired['derived_sources']
    suffix = ('\n\n# E124 fixed derivation: original base verification remains unchanged.\n'
        '_E124_ORIGINAL_FREEZE_SOURCES = freeze_sources\n'
        '_E124_TCL_BYTES = ' + repr(tcls) + '\n'
        'EXECUTION_SOURCE_PINS = {name:(SOURCE_PINS[name][0],SOURCE_PINS[name][1],sha(raw))\n'
        '    for name,raw in _E124_TCL_BYTES.items()}\n'
        'def freeze_sources(common_bytes,incremental_bytes):\n'
        '    checked=_E124_ORIGINAL_FREEZE_SOURCES(common_bytes,incremental_bytes)\n'
        '    return {name:dict(base_sha256=checked[name]["base_sha256"],tcl_sha256=sha(raw),tcl_bytes=raw)\n'
        '        for name,raw in _E124_TCL_BYTES.items()}\n'
        'def _sources(value):\n'
        '    require(type(value) is dict and set(value)==set(_E124_TCL_BYTES),"E124_EXACT_SOURCE_ROSTER")\n'
        '    for name,raw in _E124_TCL_BYTES.items():\n'
        '        row=value[name]\n'
        '        require(type(row) is dict and set(row)=={"base_sha256","tcl_sha256","tcl_bytes"} and\n'
        '            row["base_sha256"]==SOURCE_PINS[name][1] and row["tcl_sha256"]==sha(raw) and\n'
        '            type(row["tcl_bytes"]) is bytes and row["tcl_bytes"]==raw,"E124_REPAIRED_SOURCE_CHANGED")\n')
    edit.append('FROZEN_BASE_VERIFIER_AND_REPAIRED_EXECUTION_SOURCES', suffix.encode('ascii'))
    return edit


def _controller(raw):
    edit = _Edits('prospective_generation_controller_e116', raw)
    edit.exact('NEW_CLOCK_PROVENANCE_DOC',
        b'The package clock is the original E112 boot-monotonic clock, never restarted.',
        b'The E124 package clock is the newly authorized boot-monotonic execution clock.')
    edit.exact('IMPORT_NEW_BOUND_CONTEXT', b'import time\n',
               b'import time\nfrom .prospective_generation_context_e124 import CONFIG\n')
    edit.exact('VERSION_SCHEMA', b"SCHEMA = 'prospective-generation-controller-e116-v1'",
               b"SCHEMA = 'prospective-identifier-controller-e124-v1'")
    for key, old in (('AUTH_SHA256', "'c11a7a29418680a3506f8bc9b7e6f5fcd564887a6c58b436f2e3ec83601b1ba9'"),
                     ('BOOT_ID', repr(OLD_BOOT)), ('PACKAGE_START', repr(OLD_START)),
                     ('PACKAGE_END', '2382888.679409259')):
        edit.exact('NEW_CONTEXT_' + key, (key + ' = ' + old + '\n').encode('ascii'),
                   (key + ' = CONFIG[' + repr(key) + ']\n').encode('ascii'))
    edit.exact('KEEP_E112_OLD_CAPTURE_CLOCK',
        b"prep.get('boot_id') == BOOT_ID and prep.get('remote_start_monotonic') == PACKAGE_START",
        ("prep.get('boot_id') == " + repr(OLD_BOOT) + " and prep.get('remote_start_monotonic') == " + repr(OLD_START)).encode('ascii'))
    return edit


def _storage(raw):
    edit = _Edits('prospective_generation_storage_e118', raw)
    edit.exact('IMPORT_NEW_BOUND_CONTEXT', b'import time\n',
               b'import time\nfrom .prospective_generation_context_e124 import CONFIG\n')
    edit.exact('NEW_CONTEXT_END', b'END = 2382888.679409259\n', b"END = CONFIG['PACKAGE_END']\n")
    return edit


def _artifacts(raw):
    edit = _Edits('prospective_generation_artifacts_e117', raw)
    edit.exact('EXACT_TOOL_TOKEN_VALUE', b'    found = {}\n',
        b'    expected["TOOL_DESIGN_ID_TOKEN"] = "r" + binding["task_uid"].encode("ascii").hex()\n    found = {}\n')
    edit.exact('RECOGNIZE_TOOL_TOKEN_MARKER', b"line.startswith(('MAPPED_', 'ATPG_'))",
               b"line.startswith(('MAPPED_', 'ATPG_', 'TOOL_DESIGN_ID_TOKEN'))", count=1)
    edit.exact('REJECT_INDENTED_TOOL_TOKEN_MARKER', b"line.lstrip().startswith(('MAPPED_', 'ATPG_'))",
               b"line.lstrip().startswith(('MAPPED_', 'ATPG_', 'TOOL_DESIGN_ID_TOKEN'))", count=1)
    return edit


def _diagnostics(raw):
    edit = _Edits('prospective_generation_diagnostics_e120', raw)
    edit.exact('REPAIRED_EXECUTION_ECHO_AND_POLICY_PINS', b'recipe.SOURCE_PINS',
               b'recipe.EXECUTION_SOURCE_PINS', count=2)
    return edit


def build_sources(context_source_bytes=None, worker_source_bytes=None):
    repo = Path(__file__).resolve().parents[2]
    review_raw = _read(repo, 'data/manifests/ranking_v6_e121_pre_review_20261026_r1.json', REVIEW_SHA256)
    reviewed = json.loads(review_raw.decode('ascii'))['reviewed']
    pins = reviewed['source_sha256']
    require(set(pins) == ALLOWLIST | {'e121_worker'}, 'EXACT_V1_REVIEW_ROSTER')
    old_runner = _read(repo, 'scripts/run_prospective_generation_e121.py', reviewed['controller_sha256'])
    pure = _literal(old_runner, 'PURE')
    legacy = _literal(_read(repo, 'scripts/run_direct_tessent_e104.py'), 'PINS')
    require(type(pure) is tuple and len(pure) == 18 and type(legacy) is tuple and len(legacy) == 14 and
            set(pure) | {name for name, _ in legacy} == ALLOWLIST and
            all(pins[name] == pin for name, pin in legacy), 'EXACT_PINS_PLUS_PURE_ALLOWLIST')
    origin = {name: _read(repo, 'src/data/' + name + '.py', pins[name]) for name in ALLOWLIST}
    _read(repo, 'scripts/worker_prospective_generation_e121.py', pins['e121_worker'])
    _read(repo, 'src/data/prospective_tool_identifiers_e123.py', E123_SHA256)
    # E123 operates only on original E108 bytes in this local process.
    base_common = _read(repo, 'src/data/templates/e108_common_base.tcl', reviewed['input_sha256']['common_tcl'])
    base_incremental = _read(repo, 'src/data/templates/e108_incremental_base.tcl', reviewed['input_sha256']['incremental_tcl'])
    repaired = identifiers.transform_sources(identifiers.recipe.freeze_sources(base_common, base_incremental))
    edits = {name: _Edits(name, raw) for name, raw in origin.items()}
    edits['prospective_generation_recipe_e108'] = _recipe(origin['prospective_generation_recipe_e108'], repaired)
    edits['prospective_generation_controller_e116'] = _controller(origin['prospective_generation_controller_e116'])
    edits['prospective_generation_storage_e118'] = _storage(origin['prospective_generation_storage_e118'])
    edits['prospective_generation_artifacts_e117'] = _artifacts(origin['prospective_generation_artifacts_e117'])
    edits['prospective_generation_diagnostics_e120'] = _diagnostics(origin['prospective_generation_diagnostics_e120'])
    context = (_read(repo, 'src/data/prospective_generation_context_e124.py')
               if context_source_bytes is None else context_source_bytes)
    worker = (_read(repo, 'scripts/worker_identifier_generation_e124.py')
              if worker_source_bytes is None else worker_source_bytes)
    require(all(type(raw) is bytes and 0 < len(raw) <= 1048576 for raw in (context, worker)), 'NEW_SOURCE_BYTES_BOUND')
    rows = []
    def add(name, raw, origin_pin):
        ast.parse(raw.decode('utf-8'), feature_version=(3, 6))
        rows.append(dict(name=name, origin_sha256=origin_pin, sha256=sha(raw), body=base64.b64encode(raw).decode('ascii')))
    for name, _ in legacy:
        add(name, edits[name].raw, pins[name])
    add(CONTEXT_NAME, context, None)
    for name in pure:
        add(name, edits[name].raw, pins[name])
        if name == 'prospective_generation_recipe_e108':
            add('prospective_tool_identifiers_e123', _read(repo, 'src/data/prospective_tool_identifiers_e123.py', E123_SHA256), E123_SHA256)
    add(WORKER_NAME, worker, None)
    policy_raw = _read(repo, 'contracts/prospective_generation_diagnostics_e120_v1.json', reviewed['input_sha256']['diagnostic_policy'])
    policy = json.loads(policy_raw.decode('ascii'))
    old_policy = copy.deepcopy(policy)
    for stage in ('H', 'M', 'F'):
        policy['effective_tcl_base64'][stage] = base64.b64encode(
            repaired['derived_sources']['common' if stage == 'H' else 'incremental']).decode('ascii')
    policy['execution_source_derivation'] = dict(schema=SCHEMA, origin_policy_sha256=sha(policy_raw),
        bundle_root=ROOT, tool_identifier_manifest_sha256=repaired['manifest']['manifest_sha256'],
        source_sha256={row['name']: row['sha256'] for row in rows if row['name'] in edits and edits[row['name']].operations})
    policy_bytes = canonical(policy) + b'\n'
    require(policy['startup'] == old_policy['startup'] and policy['generation'] == old_policy['generation'], 'DIAGNOSTIC_POLICY_UNCHANGED')
    manifest = dict(schema=SCHEMA, origin_review_sha256=REVIEW_SHA256, root=ROOT,
        authorization_sha256=AUTH_SHA256, source_order=[row['name'] for row in rows],
        origin_modules_verified=33, excluded_old_worker_origin_sha256=pins['e121_worker'],
        sources=[edits[name].audit() for name in sorted(edits)],
        new_sources=[{k: row[k] for k in ('name', 'origin_sha256', 'sha256')} for row in rows if row['name'] not in edits],
        policy=dict(origin_sha256=sha(policy_raw), sha256=sha(policy_bytes),
            allowed_json_pointers=['/effective_tcl_base64/H', '/effective_tcl_base64/M', '/effective_tcl_base64/F', '/execution_source_derivation'],
            startup_profiles_changed=False, generation_policy_changed=False),
        tool_identifier_manifest_sha256=repaired['manifest']['manifest_sha256'],
        execution_clock='NEW_E124_AUTHORIZED_CONFIG_NOT_OLD_E112_CAPTURE_CLOCK',
        e112_provenance_clock_preserved=dict(boot_id=OLD_BOOT, start_monotonic=OLD_START),
        original_files_modified=False, original_module_globals_modified=False,
        deployment_performed=False, tessent_launches=0, execution_ready=False, training_release=False)
    manifest['manifest_sha256'] = sha(canonical(manifest))
    return dict(sources=rows, manifest=manifest, policy_bytes=policy_bytes,
                tool_identifier_manifest=repaired['manifest'])
