"""Pure declared-string comparison; never resolve a path or certify a call."""
import hashlib
from scripts import project_ranking_v6_e40_result_paths as producer


def summarize(payload):
    if not producer.validate_response(payload):
        raise ValueError('E40_METADATA_RESPONSE_REJECTED')
    groups = {}
    for item in payload['files']:
        version = item['coverage_root'].rsplit('/', 1)[-1]
        for row in item['rows']:
            uid = '{}:hf_refine:H64-F4:{}'.format(item['circuit'], row['candidate'])
            groups.setdefault(uid, {})[version] = row
    targets = []
    for uid, versions in sorted(groups.items()):
        if set(versions) != {'10_coverage95_v1', '10_coverage95_v2_merge_reclassify'}:
            raise ValueError('E40_SCOPE_PAIR_REQUIRED')
        comparison = {}
        for field in ('h_result', 'f_result'):
            values = [versions[v][field] for v in ('10_coverage95_v1', '10_coverage95_v2_merge_reclassify')]
            comparison[field] = {
                'classification': ('missing_declaration' if not all(values) else
                                   'same_declared_string' if values[0] == values[1] else
                                   'different_declared_strings'),
                'v1_sha256_of_trimmed_declaration': hashlib.sha256(values[0].encode('ascii')).hexdigest(),
                'v2_sha256_of_trimmed_declaration': hashlib.sha256(values[1].encode('ascii')).hexdigest(),
                'v1_missing': not bool(values[0]), 'v2_missing': not bool(values[1])}
        targets.append(dict(source_candidate_uid=uid, declared_path_comparison=comparison))
    if len(targets) != 4:
        raise ValueError('E40_FOUR_TARGETS_REQUIRED')
    return dict(status='PARTIAL_DECLARED_PATHS_NOT_INVOCATION_CERTIFICATION', targets=targets,
                file_count=4, source_bytes=32919, all_scanned_data_rows=73, target_rows=8,
                result_files_opened=False, quality_evaluated=False, source_origin_assigned=False,
                costs_computed=False, invocation_identity_certified=False, training_release=False,
                strings_resolved_or_rebased=False,
                interpretation='Exact trimmed declaration strings only; equality is not file identity, independent invocation or cost ownership.')
