#!/usr/bin/env python3
"""Release-gated, TRAIN-only source projection for ranking-v3 fold packages.

This is an export utility, never a training entrypoint.  Its defaults bind the
published source anchors; tests may inject toy anchors and counts explicitly.
"""
import argparse
import csv
import hashlib
import io
import json
import math
import re
from pathlib import Path

from src.data.ranking_v3_real_fold_package import export_real_fold
from src.models.runtime_ranking_v3 import FAMILIES, FEATURES, digest, plan_folds

FEATURE_FIELDS = ('role', 'family', 'circuit', 'action_uid', 'action_scheme',
                  'h_limit', 'm_limit', 'common_fault_count', 'graph_key')
OUTCOME_FIELDS = ('action_uid', 'execution_status', 'is_d95_feasible',
                  'total_cycles', 'policy_charged_runtime_s', 'epsilon_hit')
GRAPH_FIELDS = ('graph_key', 'circuit', 'graph_path', 'graph_sha256')
DEFAULT_EXPECTED = {
    'features.tsv': '8a46094f0bfb7112ffca9cb098fd69f545d8dda0d37be3c03e3eff43cb13e05d',
    'train_outcomes.tsv': 'df3c9f370305027e895199049e4d282d6b2e76de3284abadd63e273dead21318',
    'graph_manifest.tsv': '4422ce817f18c41bb2df55b066a5afed51ebfaab01261445883c5f2aaced89f3',
}
RELEASE_STATUS = 'PASS_TRAIN_ONLY_SOURCE_EXPORT_RELEASE'


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _valid_sha(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def _reject_symlink(path):
    path = Path(path)
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError('REAL_INPUT_SYMLINK')


def _validate_release(release, expected_release_sha256):
    """Pure gate: intentionally runs before inspecting any user-supplied path."""
    if not _valid_sha(expected_release_sha256) or not isinstance(release, dict):
        raise ValueError('REAL_INPUT_RELEASE')
    if (set(release) != {'status', 'code_review_sha256', 'user_authorization'} or
            release.get('status') != RELEASE_STATUS or
            not _valid_sha(release.get('code_review_sha256')) or
            release.get('user_authorization') is not True or
            digest(release) != expected_release_sha256):
        raise ValueError('REAL_INPUT_RELEASE')


def _read_tsv_once(path, expected_sha, fields, code):
    _reject_symlink(path)
    raw = Path(path).read_bytes()
    if _sha(raw) != expected_sha:
        raise ValueError(code + '_SHA')
    try:
        reader = csv.DictReader(io.StringIO(raw.decode('utf-8')), delimiter='\t')
        if tuple(reader.fieldnames or ()) != tuple(fields):
            raise ValueError(code + '_SCHEMA')
        return list(reader), raw
    except UnicodeDecodeError as exc:
        raise ValueError(code + '_UTF8') from exc


def _number(value, *, integer=False):
    if isinstance(value, bool):
        raise ValueError('REAL_INPUT_NUMBER')
    try:
        result = int(value) if integer else float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError('REAL_INPUT_NUMBER') from exc
    if not math.isfinite(float(result)) or (integer and str(result) != str(value)):
        raise ValueError('REAL_INPUT_NUMBER')
    return result


def _project_features(rows):
    train = [row for row in rows if row['role'] == 'TRAIN']
    if {row['circuit'] for row in train} != set(FAMILIES) or len({row['action_uid'] for row in train}) != len(train):
        raise ValueError('REAL_INPUT_TRAIN_ROSTER')
    if any(row['role'] not in ('TRAIN', 'VALIDATION') for row in rows):
        raise ValueError('REAL_INPUT_ROLE')
    if any(FAMILIES.get(row['circuit']) != row['family'] for row in train):
        raise ValueError('REAL_INPUT_FAMILY')
    maxima = {}
    for row in train:
        if row['action_scheme'] not in ('HF', 'HMF'):
            raise ValueError('REAL_INPUT_SCHEME')
        h, m = _number(row['h_limit'], integer=True), _number(row['m_limit'], integer=True)
        common = _number(row['common_fault_count'], integer=True)
        if h < 0 or m < 0 or common <= 0:
            raise ValueError('REAL_INPUT_FEATURE_VALUE')
        maxima[row['circuit']] = (max(maxima.get(row['circuit'], (0, 0))[0], h),
                                  max(maxima.get(row['circuit'], (0, 0))[1], m))
    result = []
    for row in train:
        h, m = int(row['h_limit']), int(row['m_limit'])
        hmax, mmax = maxima[row['circuit']]
        result.append({'action_uid': row['action_uid'], 'circuit': row['circuit'],
                       'family': row['family'], 'role': 'TRAIN', 'graph_key': row['graph_key'],
                       'action_scheme': row['action_scheme'], 'h_limit': h, 'm_limit': m,
                       'scheme_hf': 1.0 if row['action_scheme'] == 'HF' else 0.0,
                       'scheme_hmf': 1.0 if row['action_scheme'] == 'HMF' else 0.0,
                       'log1p_h_limit': math.log1p(h), 'log1p_m_limit': math.log1p(m),
                       'h_limit_fraction_of_circuit_max': h / float(max(hmax, 1)),
                       'm_limit_fraction_of_circuit_max': m / float(max(mmax, 1)),
                       'log1p_common_fault_count': math.log1p(int(row['common_fault_count']))})
    return sorted(result, key=lambda row: row['action_uid'])


def _project_outcomes(rows, train_uids, expected_count):
    if len(rows) != expected_count or len({row['action_uid'] for row in rows}) != len(rows):
        raise ValueError('REAL_INPUT_TRAIN_COUNT')
    if set(row['action_uid'] for row in rows) != set(train_uids):
        raise ValueError('REAL_INPUT_OUTCOME_JOIN')
    result = {}
    for row in rows:
        if row['execution_status'] != 'SUCCESS' or row['is_d95_feasible'] != '1':
            raise ValueError('REAL_INPUT_UNSAFE_OUTCOME')
        cycles = _number(row['total_cycles'], integer=True)
        runtime = _number(row['policy_charged_runtime_s'])
        if cycles <= 0 or runtime <= 0:
            raise ValueError('REAL_INPUT_UNSAFE_OUTCOME')
        # epsilon_hit is intentionally parsed only to reject malformed rows and
        # never projected into model features or the real-fold outcome shards.
        if row['epsilon_hit'] not in ('0', '1'):
            raise ValueError('REAL_INPUT_EPSILON')
        result[row['action_uid']] = {'execution_status': 'SUCCESS', 'is_d95_feasible': 1,
                                     'total_cycles': cycles,
                                     'policy_charged_runtime_s': runtime}
    return result


def _copy_train_graphs(graph_rows, train_rows, graph_root, output_root):
    _reject_symlink(graph_root)
    by_key = {row['graph_key']: row for row in graph_rows}
    key_circuits = {row['graph_key']: row['circuit'] for row in train_rows}
    if len({(row['graph_key'], row['circuit']) for row in train_rows}) != len(key_circuits):
        raise ValueError('REAL_INPUT_GRAPH_KEY_DRIFT')
    keys = set(key_circuits)
    if not keys <= set(by_key) or len(by_key) != len(graph_rows):
        raise ValueError('REAL_INPUT_GRAPH_JOIN')
    graphs = {}
    destination = output_root / 'graphs'; destination.mkdir()
    graph_root_resolved = Path(graph_root).resolve(strict=True)
    destination_resolved = destination.resolve(strict=True)
    for key in sorted(keys):
        row = by_key[key]
        if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', key) or
                row['circuit'] != key_circuits[key] or not _valid_sha(row['graph_sha256'])):
            raise ValueError('REAL_INPUT_GRAPH_SHA')
        relative = row['graph_path'].replace('\\', '/')
        if (not relative or relative.startswith('/') or re.match(r'^[A-Za-z]:', relative) or
                '..' in relative.split('/')):
            raise ValueError('REAL_INPUT_GRAPH_PATH')
        source = Path(graph_root, *relative.split('/'))
        _reject_symlink(source)
        if not source.resolve(strict=True).is_relative_to(graph_root_resolved):
            raise ValueError('REAL_INPUT_GRAPH_PATH')
        raw = source.read_bytes()
        if _sha(raw) != row['graph_sha256']:
            raise ValueError('REAL_INPUT_GRAPH_SHA')
        try:
            graph = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError('REAL_INPUT_GRAPH_SCHEMA') from exc
        if (not isinstance(graph, dict) or set(graph) != {'schema_version', 'circuit', 'nodes', 'edge_index'} or
                graph['schema_version'] != 'runtime-graph-v1' or graph['circuit'] != row['circuit'] or
                not isinstance(graph['nodes'], list) or not graph['nodes'] or not isinstance(graph['edge_index'], list) or
                any(not isinstance(node, dict) or set(node) != {'node_type', 'cell_type', 'sequential_flag'}
                    or not isinstance(node['node_type'], str) or not isinstance(node['cell_type'], str)
                    or not (type(node['sequential_flag']) is bool or
                            (type(node['sequential_flag']) is int and node['sequential_flag'] in (0, 1)))
                    for node in graph['nodes']) or
                any(not isinstance(edge, list) or len(edge) != 2 or any(type(point) is not int or point < 0 or point >= len(graph['nodes']) for point in edge)
                    for edge in graph['edge_index'])):
            raise ValueError('REAL_INPUT_GRAPH_SCHEMA')
        target = destination / (row['graph_key'] + '.json')
        if target.exists() or target.is_symlink() or not target.resolve(strict=False).is_relative_to(destination_resolved):
            raise ValueError('REAL_INPUT_GRAPH_TARGET')
        with target.open('xb') as stream:
            stream.write(raw)
        graphs[key] = _sha(raw)
    return graphs


def export_real_inputs(output_root, features_path, train_outcomes_path, graph_manifest_path, graph_root, *,
                       release, expected_release_sha256, expected=DEFAULT_EXPECTED, expected_train_count=1706):
    _validate_release(release, expected_release_sha256)
    if (Path(features_path).name != 'features.tsv' or
            Path(train_outcomes_path).name != 'train_outcomes.tsv' or
            Path(graph_manifest_path).name != 'graph_manifest.tsv'):
        raise ValueError('REAL_INPUT_SOURCE_NAMES')
    if set(expected) != set(DEFAULT_EXPECTED) or not all(_valid_sha(v) for v in expected.values()):
        raise ValueError('REAL_INPUT_EXPECTED_ANCHORS')
    feature_source, feature_raw = _read_tsv_once(features_path, expected['features.tsv'], FEATURE_FIELDS, 'REAL_INPUT_FEATURE')
    outcome_source, outcome_raw = _read_tsv_once(train_outcomes_path, expected['train_outcomes.tsv'], OUTCOME_FIELDS, 'REAL_INPUT_OUTCOME')
    graph_source, graph_raw = _read_tsv_once(graph_manifest_path, expected['graph_manifest.tsv'], GRAPH_FIELDS, 'REAL_INPUT_GRAPH_MANIFEST')
    rows = _project_features(feature_source)
    outcomes = _project_outcomes(outcome_source, [row['action_uid'] for row in rows], expected_train_count)
    output_root = Path(output_root); _reject_symlink(output_root); output_root.mkdir(exist_ok=False)
    graphs = _copy_train_graphs(graph_source, rows, graph_root, output_root)
    source_input_sha256 = {'features.tsv': _sha(feature_raw),
                           'train_outcomes.tsv': _sha(outcome_raw),
                           'graph_manifest.tsv': _sha(graph_raw)}
    source_sha256 = digest({'source_input_sha256': source_input_sha256,
                           'graph_sha256': graphs})
    fold_release = {'status': 'PASS_TRAIN_ONLY_DATA_RELEASE', 'source_sha256': source_sha256,
                    'independent_review_pass': True, 'roles': ['TRAIN']}
    folds = {}
    for fold in plan_folds(rows):
        folds[fold.family] = export_real_fold(output_root / ('fold_' + fold.family), rows, outcomes, fold,
                                              release=fold_release, source_sha256=source_sha256)
    metadata = {'schema_version': 'ranking-v3-real-train-family-metadata-v1', 'scope': 'REAL_TRAIN_ONLY_RELEASED_SIX_FOLD',
                'families': FAMILIES, 'graph_sha256': graphs}
    metadata_path = output_root / 'family_metadata.json'
    with metadata_path.open('xb') as stream:
        stream.write((json.dumps(metadata, sort_keys=True, separators=(',', ':')) + '\n').encode())
    family_metadata_sha256 = _sha(metadata_path.read_bytes())
    receipt = {'schema_version': 'ranking-v3-real-input-export-receipt-v1', 'scope': 'REAL_TRAIN_ONLY_RELEASED_SIX_FOLD',
               'release_sha256': expected_release_sha256, 'source_sha256': source_sha256,
               'source_input_sha256': source_input_sha256, 'graph_sha256': graphs,
               'family_metadata_sha256': family_metadata_sha256,
               'train_action_count': len(rows), 'train_outcome_count': len(outcomes),
               'graph_count': len(graphs), 'fold_manifest_sha256': folds}
    with (output_root / 'receipt.json').open('xb') as stream:
        stream.write((json.dumps(receipt, sort_keys=True, separators=(',', ':')) + '\n').encode())
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-root', required=True); parser.add_argument('--features', required=True)
    parser.add_argument('--train-outcomes', required=True); parser.add_argument('--graph-manifest', required=True)
    parser.add_argument('--graph-root', required=True); parser.add_argument('--release-json', required=True)
    parser.add_argument('--expected-release-sha256', required=True)
    args = parser.parse_args(argv)
    release = json.loads(Path(args.release_json).read_text(encoding='utf-8'))
    print(json.dumps(export_real_inputs(args.output_root, args.features, args.train_outcomes,
          args.graph_manifest, args.graph_root, release=release,
          expected_release_sha256=args.expected_release_sha256), sort_keys=True))


if __name__ == '__main__':
    main()
