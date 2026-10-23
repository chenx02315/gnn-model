"""Pure fixed E94 Tessent translated-status acceptance recipe compiler.

This module performs no filesystem, process, network, Tessent, or ATPG work.
It accepts only the pinned E85/E93 observation shapes and produces four fixed
future-scratch recipes plus literal Tcl bytes.  A recipe is not launch authority.
"""
import hashlib
import json
import re

SCHEMA = 'prospective-tessent-acceptance-recipe-v1'
ROOT = '/temp/jiangchuanc/multimode_ate_acceptance_e94_20261023_r1'
PHASE4 = '/temp/jiangchuanc/multimode_ate_phase4_20260825_A/10_circuits'
E85_SHA256 = '702968b299d36f7d85bdfa3f2b6c9a23fb99cd8f5094ed0ed37fa6e002794e74'
E93_SHA256 = 'b461f3ede76e88e1b73c25ba616d3047b4d5c56c1bab317dd0c824fd0f000c22'
LAUNCHER = '/cad/mentor/tessent2021_2/bin/tessent'
LAUNCHER_SHA256 = 'd92e81eaacf0727fd18d4cafa67d7c9a066069c6d8f7fc05caaf1252c3e44905'
LIBRARY = ('/home/jiangchuanc/Desktop/work/SCC28NHK_HSC31_LVT_V0p1/'
           'liberty/0.8v/scc28nhk_hsc31_lvt_scan.tcelllib')
LIBRARY_SHA256 = '34a3ca7df9262548eaf05ff544e2da080a541ab60467ef23193f6543ac5e5217'
TOPS = {'aes_core': 'aes_cipher_top', 'spi': 'spi_top'}
COUNTS = {'aes_core': 71216, 'spi': 10418}
ROSTER = (('aes_core', 'H_TO_M', 'M'), ('aes_core', 'H_TO_F', 'F'),
          ('spi', 'H_TO_M', 'M'), ('spi', 'H_TO_F', 'F'))
TREE_IDENTITIES = {
    ('aes_core', 'H'): ('d2790b690818a06e2f2766da78634368a73c88a07ff156421b0fa25e71c12287', 40, 11),
    ('aes_core', 'M'): ('cf3ad90c295b4ad6e775bc288e738fd74c97a1f9725af6616ed25f642dfb8353', 40, 11),
    ('aes_core', 'F'): ('ac602e864f6e5746622e0faf26e68a4a317f90e15eb0f2bc5350013216402259', 19, 9),
    ('spi', 'H'): ('f0bba6966e59707014ac52f7fc34c55cd1acb4cb10488b56bcddd689a91d3d35', 42, 11),
    ('spi', 'M'): ('112ab605cbf56af8f7d7ab544174b61b5b9550cb7e4ecf08d7284e95cdfa4d8e', 42, 11),
    ('spi', 'F'): ('2347df778235d5882f82043b2e6848b0ad82452bfd13f98c1a5f6110c95db765', 19, 9),
}
SHA_RE = re.compile(r'[0-9a-f]{64}\Z')


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def exact(value, keys, reason):
    require(type(value) is dict and set(value) == set(keys), reason)


def _pairs(items):
    value = {}
    for key, item in items:
        require(key not in value, 'DUPLICATE_JSON_KEY')
        value[key] = item
    return value


def observation(value, supplied_sha, expected_sha, reason):
    require(type(supplied_sha) is str and supplied_sha == expected_sha, reason + '_PIN')
    require(type(value) is bytes, reason + '_RAW_BYTES_REQUIRED')
    require(sha(value) == expected_sha, reason + '_RAW_SHA')
    try:
        return json.loads(value.decode('ascii'), object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(
                              ValueError('NONFINITE_JSON')))
    except (UnicodeError, ValueError) as exc:
        raise ValueError(reason + '_JSON') from exc


def validate_e85(value):
    exact(value, ('actual_atpg_calls', 'actual_atpg_memory_limit_bytes',
        'actual_atpg_timeout_s', 'binary', 'body_bytes_hashed',
        'executable_version_verified', 'execution_ready',
        'external_programs_launched', 'fault_mapping_semantics_verified',
        'filesystem_available', 'graph_authenticated', 'helper_self_limits_applied',
        'host_resource_metadata', 'hostname', 'library', 'platform',
        'python_version', 'remote_writes', 'schema', 'status', 'training_release',
        'tree_directories_observed', 'tree_entries_observed',
        'tree_global_bound_reached', 'tsdb_trees'), 'E85_KEYS')
    require(value['schema'] == 'e85-acquisition-tree-input-probe-v1' and
            value['status'] == 'PASS_BOUNDED_INPUT_HASHES_ONLY_NOT_EXECUTION_READY' and
            value['hostname'] == 'bupt-vncs2' and value['platform'] == 'linux',
            'E85_STATUS_HOST')
    binary = value['binary']
    exact(binary, ('body_sha256', 'bytes', 'candidates_tested',
        'components_inspected', 'invalid_components', 'last_candidate_reason',
        'program_launched', 'resolved_binary', 'status', 'symlink_hops',
        'version_verified'), 'E85_BINARY_KEYS')
    require(binary['resolved_binary'] == LAUNCHER and
            binary['body_sha256'] == LAUNCHER_SHA256 and
            binary['status'] == 'CURRENT_BINARY_BODY_HASHED_NO_VERSION' and
            binary['version_verified'] is False and
            binary['program_launched'] is False, 'E85_BINARY_IDENTITY')
    library = value['library']
    exact(library, ('body_sha256', 'bytes', 'mode', 'path', 'resolved_path',
                    'status', 'symlink_hops'), 'E85_LIBRARY_KEYS')
    require(library['resolved_path'] == LIBRARY and
            library['body_sha256'] == LIBRARY_SHA256 and
            library['status'] == 'CURRENT_BODY_HASHED', 'E85_LIBRARY_IDENTITY')
    trees = value['tsdb_trees']
    require(type(trees) is list and len(trees) == 6, 'E85_TREE_COUNT')
    found = {}
    for row in trees:
        exact(row, ('anomalies', 'anomaly_count', 'body_bytes', 'directories',
                    'entries', 'regular_files_hashed', 'root', 'status',
                    'tree_complete', 'tree_sha256'), 'E85_TREE_KEYS')
        match = re.fullmatch(re.escape(PHASE4) +
            r'/(aes_core|spi)/99_tmp/([HMF])_mapped_tsdb', row['root'])
        require(match is not None, 'E85_TREE_ROOT')
        key = match.groups()
        require(key not in found and key in TREE_IDENTITIES, 'E85_TREE_SET')
        expected_sha, files, directories = TREE_IDENTITIES[key]
        require(row['tree_sha256'] == expected_sha and
                row['regular_files_hashed'] == files and
                row['directories'] == directories and
                row['tree_complete'] is True and row['status'] == 'CURRENT_TREE_HASHED' and
                row['anomaly_count'] == 0 and row['anomalies'] == [],
                'E85_TREE_IDENTITY')
        found[key] = row
    require(set(found) == set(TREE_IDENTITIES), 'E85_TREE_SET')
    return found


def validate_e93(value):
    exact(value, ('actual_atpg_calls', 'body_bytes', 'execution_ready',
        'files_read', 'input_files', 'observation_sha256', 'programs_launched',
        'remote_writes', 'results', 'schema', 'training_release', 'training_runs',
        'validation_role'), 'E93_KEYS')
    require(value['schema'] == 'e93-real-input-translation-compatibility-v1' and
            value['validation_role'] ==
            'READ_ONLY_COMPUTED_COMPATIBILITY_NOT_TESSENT_ACCEPTANCE_ATPG_OR_PILOT_COST' and
            value['files_read'] == 10 and value['actual_atpg_calls'] == 0 and
            value['programs_launched'] == 0 and value['remote_writes'] == 0 and
            value['execution_ready'] is False, 'E93_STATUS')
    files = value['input_files']
    require(type(files) is list and len(files) == 10, 'E93_INPUT_FILE_COUNT')
    basics = {}
    seen_files = set()
    expected_files = {(circuit, role) for circuit in TOPS for role in
                      ('manifest', 'mapping', 'M_basic', 'F_basic', 'source_mtfi')}
    for row in files:
        exact(row, ('bytes', 'circuit', 'role', 'sha256'), 'E93_INPUT_FILE_KEYS')
        require(row['circuit'] in TOPS and type(row['role']) is str and
                SHA_RE.fullmatch(row['sha256']) is not None and
                type(row['bytes']) is int and row['bytes'] > 0, 'E93_INPUT_FILE')
        file_key = (row['circuit'], row['role'])
        require(file_key in expected_files and file_key not in seen_files,
                'E93_INPUT_FILE_SET')
        seen_files.add(file_key)
        if row['role'] in ('M_basic', 'F_basic'):
            key = (row['circuit'], row['role'][0])
            require(key not in basics, 'E93_BASIC_DUPLICATE')
            basics[key] = row
    require(set(basics) == {(circuit, mode) for circuit in TOPS
                            for mode in ('M', 'F')}, 'E93_BASIC_SET')
    require(seen_files == expected_files, 'E93_INPUT_FILE_SET')
    results = value['results']
    require(type(results) is list and len(results) == 4, 'E93_RESULT_COUNT')
    found = {}
    keys = ('byte_counts', 'circuit', 'input_sha256', 'manifest_sha256',
            'output_mtfi_sha256', 'status', 'transition')
    for row in results:
        exact(row, keys, 'E93_RESULT_KEYS')
        key = (row['circuit'], row['transition'])
        require(key in {(c, t) for c, t, _ in ROSTER} and key not in found and
                row['status'] == 'PASS_COMPUTED_COMPATIBILITY_ONLY' and
                SHA_RE.fullmatch(row['manifest_sha256']) is not None and
                SHA_RE.fullmatch(row['output_mtfi_sha256']) is not None,
                'E93_RESULT_IDENTITY')
        exact(row['byte_counts'], ('manifest', 'mapping', 'output_mtfi',
            'source_mtfi', 'target_basic'), 'E93_RESULT_BYTE_KEYS')
        exact(row['input_sha256'], ('mapping', 'source_mtfi', 'target_basic'),
              'E93_RESULT_INPUT_KEYS')
        found[key] = row
    require(set(found) == {(c, t) for c, t, _ in ROSTER}, 'E93_RESULT_SET')
    return basics, found


def _tcl(circuit, transition, mode, scratch, tsdb_copy, common_faults,
         status_file):
    top = TOPS[circuit]
    lines = [
        '# Fixed E94 translated-status acceptance only; no ATPG.\n',
        'set_context patterns -scan -design_identifier %s_%s_mapped_acceptance_e94\n' %
            (circuit, mode),
        'set_tsdb_output_directory {%s}\n' % tsdb_copy,
        'read_cell_library {%s}\n' % LIBRARY,
        'read_design %s -design_identifier %s_%s_mapped_insert -verbose\n' %
            (top, circuit, mode),
        'set_current_design %s\n' % top,
    ]
    if mode == 'F':
        lines.extend(('set_current_mode F_mapped_acceptance_e94\n',
                      'import_scan_mode F_fullscan_4ch\n'))
    else:
        lines.extend(('set_current_mode M_mapped_acceptance_e94\n',
                      'import_scan_mode edt_mode\n',
                      'set_static_dft_signal_values async_set_reset_static_disable 1\n'))
    lines.extend((
        'set_clock_off_simulation ON\n',
        'set_split_capture_cycle ON\n',
        'set_system_mode analysis\n',
        'add_processors localhost:1\n',
        'set_random_atpg OFF\n',
    ))
    if mode == 'F':
        lines.append('set_atpg_fill X\n')
    lines.extend((
        'set_fault_type Stuck\n',
        'read_faults {%s} -show_warnings\n' % common_faults,
        'read_faults {%s} -merge -show_warnings\n' % status_file,
        'reset_au_faults -reclassify\n',
        'report_statistics -detailed_analysis > /dev/null\n',
        'puts "E94_TRANSLATED_STATUS_ACCEPTANCE=PASS %s %s"\n' %
            (circuit, transition),
        'exit\n'))
    raw = ''.join(lines).encode('ascii')
    lowered = raw.lower()
    for forbidden in (b'create_patterns', b'write_faults', b'write_patterns',
                      b'\nsource ', b'\neval ', b'\nexec '):
        require(forbidden not in lowered, 'TCL_FORBIDDEN_COMMAND')
    require(scratch.encode('ascii') in raw, 'TCL_SCRATCH_BINDING')
    return raw


def compile_acceptance(e85, e93, e85_sha256, e93_sha256):
    e85_value = observation(e85, e85_sha256, E85_SHA256, 'E85')
    e93_value = observation(e93, e93_sha256, E93_SHA256, 'E93')
    trees = validate_e85(e85_value)
    basics, results = validate_e93(e93_value)
    items = []
    serial = []
    for circuit, transition, mode in ROSTER:
        scratch = ROOT + '/scratch/' + circuit + '_' + mode
        tsdb_copy = scratch + '/isolated_tsdb'
        status_file = scratch + '/inputs/translated_status.mtfi'
        translation_manifest = scratch + '/inputs/translation_manifest.json'
        tcl_path = scratch + '/accept_translated_status.tcl'
        common_faults = (PHASE4 + '/' + circuit + '/03_fault_universe/common_' +
            circuit + '_m16_phase4_v2/' + mode + '_common_initial_faults.basic')
        tree = trees[(circuit, mode)]
        result = results[(circuit, transition)]
        basic = basics[(circuit, mode)]
        require(result['input_sha256']['target_basic'] == basic['sha256'],
                'E93_TARGET_BASIC_BINDING')
        tcl = _tcl(circuit, transition, mode, scratch, tsdb_copy,
                   common_faults, status_file)
        row = dict(circuit=circuit, transition=transition, target_mode=mode,
            top_module=TOPS[circuit], expected_common_count=COUNTS[circuit],
            future_scratch=scratch, future_scratch_must_not_preexist=True,
            tcl_path=tcl_path, tcl_sha256=sha(tcl),
            argv=[LAUNCHER, '-shell', '-license_wait', '5', '-dofile', tcl_path],
            cwd=scratch, launcher_sha256=LAUNCHER_SHA256,
            library_resolved_path=LIBRARY, library_sha256=LIBRARY_SHA256,
            common_basic_path=common_faults, common_basic_sha256=basic['sha256'],
            translated_status_path=status_file,
            translated_status_sha256=result['output_mtfi_sha256'],
            translation_manifest_path=translation_manifest,
            translation_manifest_sha256=result['manifest_sha256'],
            tsdb_source_root=tree['root'], tsdb_source_tree_sha256=tree['tree_sha256'],
            tsdb_source_regular_files=tree['regular_files_hashed'],
            tsdb_source_directories=tree['directories'],
            isolated_tsdb_copy=tsdb_copy, tcl_bytes=tcl)
        items.append(row)
        serial.append({key: value for key, value in row.items() if key != 'tcl_bytes'})
    body = dict(schema=SCHEMA, root=ROOT,
        observations={'e85': E85_SHA256, 'e93': E93_SHA256},
        exact_roster=[list(row) for row in ROSTER], items=serial,
        all_four_dependencies_fail_closed=True,
        future_execution_policy=
            'ONE_REVIEWED_FOUR_ITEM_PACKAGE_SEQUENTIAL_STOP_ON_FIRST_FAILURE_ZERO_RETRIES',
        tessent_may_write_implicit_scratch=True,
        real_run_requires_isolated_tsdb_copy_and_output=True,
        source_trees_are_read_only_inputs=True,
        library_body_identity_verified_by_e85=True,
        tsdb_tree_identities_verified_by_e85=True,
        requires_fresh_prelaunch_identity_recheck=True,
        future_executor_log_policy={
            'exit_code_must_equal': 0,
            'pass_marker_must_appear_exactly_once': True,
            'reject_case_insensitive_tokens': ['ERROR', 'FATAL',
                                               'invalid pin_pathname'],
            'warning_policy':
                'FAIL_ON_ANY_WARNING_UNLESS_SEPARATELY_REVIEWED_EXACT_ALLOWLIST_IS_PINNED',
            'reviewed_warning_allowlist': [],
            'pass_marker_alone_is_semantic_acceptance': False,
        },
        engine_version_verified=False, resource_limits_verified=False,
        scratch_created=False, scratch_publication_verified=False,
        tsdb_isolated_copy_verified=False, os_guard_verified=False,
        tessent_acceptance_verified=False, semantic_acceptance_verified=False,
        actual_tessent_calls=0,
        actual_atpg_calls=0, create_patterns_calls=0, d95_verified=False,
        counts_exported=False, execution_ready=False, training_release=False)
    return dict(body, items=items, recipe_sha256=sha(canonical(body)))
