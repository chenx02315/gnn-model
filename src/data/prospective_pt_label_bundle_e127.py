"""Closed offline E127 derivation of the exact independently reviewed E124 bundle.

Changes only the package namespace/context and the E117 statistics import.
No old files/globals, Tcl, semantic UIDs, controls or diagnostic rules change.
No remote/deployment/process/training capability is exposed by this compiler.
"""
import ast
import base64
import copy
import json
from pathlib import Path

from . import prospective_identifier_bundle_e124 as predecessor

ROOT = '/temp/jiangchuanc/multimode_ate_pt_label_repair_e127_20261027_r1'
AUTH_SHA256 = '106c9d5c874b79a2400ca11b17c08708c285cfcdd8147c226af10d81a9c73e52'
PROPOSAL_SHA256 = 'fa9ae57624c89835d152236ebccffb1ee6990604fbccf3ec63209e7c059ec715'
E124_COMPILER_SHA256 = 'fc7849c6d17d9907960f8efec25cbb314c6a03a1aa2d82afa1658d0fd38847be'
E124_REVIEW_SHA256 = '82072c094d6ed0b606ba710208609c29605d40209b60fbbe72284da86e7d88f9'
E126_SHA256 = '12fdb3e3cb7b52c32465f461fa63a6598f6bac555669d63540ac18e0bd3174a0'
CONTEXT_NAME = 'prospective_generation_context_e127'
WORKER_NAME = 'e127_worker'
PARSER_NAME = 'prospective_report_dialect_e126'
SCHEMA = 'prospective-pt-label-bundle-e127-v1'
ALLOWLIST = predecessor.ALLOWLIST | {PARSER_NAME}
require, sha, canonical = predecessor.require, predecessor.sha, predecessor.canonical


def _baseline(repo):
    predecessor._read(repo, 'src/data/prospective_identifier_bundle_e124.py', E124_COMPILER_SHA256)
    review = json.loads(predecessor._read(repo,
        'data/manifests/ranking_v6_e124_pre_review_20261027_r1.json', E124_REVIEW_SHA256).decode('ascii'))
    require(review.get('status') == 'PASS', 'E124_INDEPENDENT_REVIEW_REQUIRED')
    reviewed = review['reviewed']
    base = predecessor.build_sources()
    rows = base['sources']
    require(len(rows) == 35 and len({row['name'] for row in rows}) == 35 and
            {row['name']: row['sha256'] for row in rows} == reviewed['source_sha256'] and
            {row['name']: row['origin_sha256'] for row in rows} == reviewed['origin_source_sha256'],
            'EXACT_35_REVIEWED_E124_SOURCES')
    for row in rows:
        raw = base64.b64decode(row['body'], validate=True)
        require(sha(raw) == row['sha256'], 'E124_SOURCE_BODY_SHA')
    manifest = base['manifest']
    require(manifest['manifest_sha256'] == reviewed['bundle_manifest_sha256'] and
            sha(canonical({k: v for k, v in manifest.items() if k != 'manifest_sha256'})) == manifest['manifest_sha256'] and
            sha(base['policy_bytes']) == reviewed['input_sha256']['diagnostic_policy'], 'E124_MANIFEST_OR_POLICY_DRIFT')
    return base


def build_sources(context_source_bytes=None, worker_source_bytes=None):
    repo = Path(__file__).resolve().parents[2]
    base = _baseline(repo)
    edits = {row['name']: predecessor._Edits(row['name'], base64.b64decode(row['body'], validate=True))
             for row in base['sources']}
    recipe = edits['prospective_generation_recipe_e108']
    recipe.exact('E127_EXCLUSIVE_ROOT', ("ROOT='" + predecessor.ROOT + "'").encode('ascii'),
                 ("ROOT='" + ROOT + "'").encode('ascii'))
    controller = edits['prospective_generation_controller_e116']
    controller.exact('E127_BOUND_CONTEXT', b'from .prospective_generation_context_e124 import CONFIG',
                     b'from .prospective_generation_context_e127 import CONFIG')
    controller.exact('E127_CONTROLLER_SCHEMA', b"SCHEMA = 'prospective-identifier-controller-e124-v1'",
                     b"SCHEMA = 'prospective-pt-label-controller-e127-v1'")
    controller.exact('E127_CLOCK_DOC', b'The E124 package clock is the newly authorized boot-monotonic execution clock.',
                     b'The E127 package clock is the newly authorized boot-monotonic execution clock.')
    edits['prospective_generation_storage_e118'].exact('E127_BOUND_CONTEXT',
        b'from .prospective_generation_context_e124 import CONFIG', b'from .prospective_generation_context_e127 import CONFIG')
    edits['prospective_generation_artifacts_e117'].exact('E126_OBSERVED_PT_LABEL_PARSER',
        b'from . import prospective_report_dialect_e115 as reports',
        b'from . import prospective_report_dialect_e126 as reports')
    context = (predecessor._read(repo, 'src/data/prospective_generation_context_e127.py')
               if context_source_bytes is None else context_source_bytes)
    worker = (predecessor._read(repo, 'scripts/worker_pt_label_generation_e127.py')
              if worker_source_bytes is None else worker_source_bytes)
    parser = predecessor._read(repo, 'src/data/prospective_report_dialect_e126.py', E126_SHA256)
    require(all(type(raw) is bytes and 0 < len(raw) <= 1048576 for raw in (context, worker)), 'NEW_E127_SOURCE_BYTES_BOUND')
    rows, replacement_audits = [], []
    def add(name, raw, origin_sha):
        ast.parse(raw.decode('utf-8'), feature_version=(3, 6))
        rows.append(dict(name=name, origin_sha256=origin_sha, sha256=sha(raw),
                         body=base64.b64encode(raw).decode('ascii')))
    for old in base['sources']:
        name = old['name']
        if name == predecessor.CONTEXT_NAME or name == predecessor.WORKER_NAME:
            new_name = CONTEXT_NAME if name == predecessor.CONTEXT_NAME else WORKER_NAME
            raw = context if name == predecessor.CONTEXT_NAME else worker
            audit = predecessor._Edits(name, edits[name].origin)
            audit.exact('REPLACE_NEW_AUTHORIZED_' + new_name.upper(), audit.origin, raw)
            replacement_audits.append(dict(audit.audit(), new_name=new_name))
            add(new_name, raw, old['sha256'])
        else:
            add(name, edits[name].raw, old['sha256'])
            if name == 'prospective_report_dialect_e115':
                add(PARSER_NAME, parser, None)
    require(len(rows) == 36 and {row['name'] for row in rows} ==
            ALLOWLIST | {'prospective_tool_identifiers_e123', CONTEXT_NAME, WORKER_NAME}, 'EXACT_E127_SOURCE_ALLOWLIST')
    old_policy = json.loads(base['policy_bytes'].decode('ascii'))
    policy = copy.deepcopy(old_policy)
    policy['execution_source_derivation'] = dict(schema=SCHEMA, origin_policy_sha256=sha(base['policy_bytes']),
        origin_review_sha256=E124_REVIEW_SHA256, bundle_root=ROOT,
        tool_identifier_manifest_sha256=base['tool_identifier_manifest']['manifest_sha256'],
        source_sha256={row['name']: row['sha256'] for row in rows},
        statistics_parser_sha256=E126_SHA256, exact_observed_pt_label='posdet_testable',
        detected_definition='DS_PLUS_DI_ONLY_PT_EXCLUDED')
    require({k: v for k, v in policy.items() if k != 'execution_source_derivation'} ==
            {k: v for k, v in old_policy.items() if k != 'execution_source_derivation'}, 'E127_POLICY_RULE_DRIFT')
    policy_bytes = canonical(policy) + b'\n'
    audited = [edit.audit() for name, edit in sorted(edits.items())
               if name not in (predecessor.CONTEXT_NAME, predecessor.WORKER_NAME)] + replacement_audits
    manifest = dict(schema=SCHEMA, root=ROOT, authorization_sha256=AUTH_SHA256,
        proposal_sha256=PROPOSAL_SHA256, origin_compiler_sha256=E124_COMPILER_SHA256,
        origin_review_sha256=E124_REVIEW_SHA256, origin_bundle_manifest_sha256=base['manifest']['manifest_sha256'],
        source_order=[row['name'] for row in rows], sources=audited,
        added_sources=[dict(name=PARSER_NAME, origin_sha256=None, sha256=E126_SHA256,
                            derivation='EXACT_PINNED_E126_MODULE_NO_TEXT_REWRITE')],
        policy=dict(origin_sha256=sha(base['policy_bytes']), sha256=sha(policy_bytes),
                    allowed_json_pointers=['/execution_source_derivation'], effective_tcl_changed=False,
                    startup_profiles_changed=False, generation_policy_changed=False),
        tool_identifier_manifest_sha256=base['tool_identifier_manifest']['manifest_sha256'],
        execution_clock='NEW_E127_AUTHORIZED_CONFIG_OLD_E112_PROVENANCE_UNCHANGED',
        semantic_uids_changed=False, runtime_run_id_changed=False, run_uid_changed=False,
        output_path_change='ROOT_PREFIX_ONLY', original_files_modified=False,
        original_module_globals_modified=False, deployment_performed=False, tessent_launches=0,
        execution_ready=False, training_release=False)
    manifest['manifest_sha256'] = sha(canonical(manifest))
    return dict(sources=rows, manifest=manifest, policy_bytes=policy_bytes,
                tool_identifier_manifest=copy.deepcopy(base['tool_identifier_manifest']))
