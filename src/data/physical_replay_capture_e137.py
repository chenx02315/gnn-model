"""Disabled-by-default E137 metadata capture core, not a remote controller."""
import math
import re
import stat

from . import physical_replay_source_reader_e135 as source
from . import physical_replay_source_inventory_e135 as inventory

require,sha,canonical,decode = source.require,source.sha,source.canonical,source.decode
AUTH_SHA = None  # Future actual authority and independent source freeze required.
PROPOSAL_SHA = 'f9b7da390b21c5c3280a7d4688494a3c3315b45091c7657db197b633cfcc4cd9'
SCHEMA = 'physical-f-clean-replay-source-capture-e137-v1'
DEPENDENCY_SHA256 = {
    'physical_replay_source_reader_e135':'6d6f86341eca23d5b473f8e323a0440d50ea44d177032576f196b9b417690818',
    'physical_replay_source_inventory_e135':'9467ee407dec9fd9bccad3ffdc517a508789c38b404fe9ac7d9d499fbd1be48d',
}
BOUNDS = dict(seconds=60,pattern_bytes=67108864,tree_bytes=2147483648,tree_entries=4000,
    tree_depth=32,response_bytes=6291456,inherited_tree_metadata_bytes=1048576)
PATTERN = dict(role='pattern',path=inventory.BASE+'/runs/e116-aes_core/attempts/F_aes_core:HF:h1:F/tester.stil',
    bytes=443378,sha256='333d9f9bd359cf9066501a41e748b2182f5c787ffd46e112c7b5c5c2c6c5eae2')
INPUT_PINS = tuple(dict(pin) for pin in inventory.INPUTS)
TREE_PIN = dict(path=inventory.TREE,sha256=inventory.ORIGINAL_TREE_SHA,bytes=3759776,files=19,directories=9)


def check_authority(authority,proposal):
    require(type(AUTH_SHA) is str and re.fullmatch('[0-9a-f]{64}',AUTH_SHA) is not None,'NO_FROZEN_E137_AUTHORITY')
    require(type(authority) is bytes and type(proposal) is bytes and sha(authority) == AUTH_SHA and
        sha(proposal) == PROPOSAL_SHA,'EXACT_NEW_E137_AUTHORITY_AND_PROPOSAL')
    auth,plan = decode(authority),decode(proposal)
    require(auth.get('schema') == 'physical-f-clean-replay-authorization-e137-v1' and
        plan.get('schema') == 'physical-f-clean-replay-proposal-e137-v1' and
        auth.get('approval_source') == 'explicit_user_reply' and auth.get('user_authorization_received') is True and
        auth.get('user_reply') == '\u90a3\u5c31\u6279\u51c6' and auth.get('approved_package') == 'E137' and
        auth.get('proposal_sha256') == PROPOSAL_SHA and
        type(auth.get('approved_scope')) is dict and
        canonical(auth['approved_scope']) == canonical(plan.get('scope_if_granted')),'EXACT_E137_WHOLE_PACKAGE_SCOPE')
    scope,fixed = auth['approved_scope'],plan['fixed_source_scope']
    require(scope['read_connection_seconds_max'] == BOUNDS['seconds'] and scope['source_pattern_bytes_max'] == BOUNDS['pattern_bytes'] and
        scope['source_TSDB_copy_bytes_max'] == BOUNDS['tree_bytes'] and scope['source_tree_entries_max'] == BOUNDS['tree_entries'] and
        scope['source_tree_depth_max'] == BOUNDS['tree_depth'] and scope['initial_response_bytes_max'] == BOUNDS['response_bytes'] and
        scope['automatic_retries'] == 0 and all(scope[k] is False for k in ('history_or_source_writes','B_access','BLIND_access','training')),
        'EXACT_E137_CAPTURE_BOUNDS')
    require(fixed['scope_root']+'/'+fixed['pattern_relative'] == PATTERN['path'] and
        fixed['pattern_observed_bytes'] == PATTERN['bytes'] and fixed['pattern_observed_sha256'] == PATTERN['sha256'] and
        fixed['scope_root']+'/'+fixed['tree_relative'] == TREE_PIN['path'] and
        all(fixed['tree_expected_'+key] == TREE_PIN[key] for key in ('sha256','bytes','files','directories')) and
        fixed['source_pattern_export_to_desktop'] is False and
        fixed['dependency_allowlist_is_only_the_three_pinned_files_and_exact_hashed_TSDB_tree_members'] is True and
        fixed['unlisted_dependency_is_terminal_no_scope_root_scan_or_on_the_fly_manifest_expansion'] is True and
        fixed['pattern_reference_is_current_r1_hash_receipt_not_historical_vector_identity_proof'] is True,
        'EXACT_E137_SOURCE_PINS')
    for prefix,pin in zip(('library','basic'),INPUT_PINS):
        require(fixed['scope_root']+'/'+fixed[prefix+'_relative'] == pin['path'] and
            fixed[prefix+'_bytes'] == pin['bytes'] and fixed[prefix+'_sha256'] == pin['sha256'],'EXACT_E137_INPUT_PINS')


def _identity(info,size,directory=False):
    require(type(info) is dict and set(info) == set(source.FIELDS) and all(type(n) is int and n >= 0 for n in info.values()) and
        info['st_uid'] == 1047 and (stat.S_ISDIR(info['st_mode']) and info['st_nlink'] >= 1 if directory else
        stat.S_ISREG(info['st_mode']) and info['st_nlink'] == 1 and info['st_size'] == size),'E137_EXACT_IDENTITY')


def validate_receipt(raw):
    """Validate hash/metadata consistency only; cannot locally rehash absent bodies."""
    require(type(raw) is bytes and 0 < len(raw) <= BOUNDS['response_bytes'],'E137_METADATA_CAP')
    value = decode(raw)
    require(type(value) is dict and set(value) == {'schema','authorization_sha256','proposal_sha256','dependency_sha256',
        'bounds','pattern','inputs','tree','complete','historical_vector_identity_proven','execution_ready','training_release',
        'resource_enforcement_claimed','stil_dependency_completeness_verified'} and value['schema'] == SCHEMA and value['authorization_sha256'] == AUTH_SHA and
        value['proposal_sha256'] == PROPOSAL_SHA and value['dependency_sha256'] == DEPENDENCY_SHA256 and
        value['bounds'] == BOUNDS and value['complete'] is True and all(value[k] is False for k in
        ('historical_vector_identity_proven','execution_ready','training_release','resource_enforcement_claimed','stil_dependency_completeness_verified')),'E137_CAPTURE_SCHEMA')
    require(type(value['inputs']) is list and len(value['inputs']) == 2,'E137_EXACT_TWO_INPUTS')
    for row,pin in zip([value['pattern']]+value['inputs'],[PATTERN]+list(INPUT_PINS)):
        require(type(row) is dict and set(row) == {'role','path','bytes','sha256','identity','whole_file_hashed'} and
            all(row[k] == pin[k] for k in pin) and type(row['bytes']) is int and row['whole_file_hashed'] is True,
            'E137_EXACT_HASH_ONLY_FILE')
        _identity(row['identity'],row['bytes'])
    tree = value['tree']
    require(type(tree) is dict and set(tree) == {'path','entries','bytes','rows','sha256','sha256_scope','complete',
        'original_tree_sha256','original_tree_matches'} and tree['path'] == TREE_PIN['path'] and tree['complete'] is True and
        tree['sha256_scope'] == 'E85_SORTED_CHILD_DEPTH_FIRST_TREE' and tree['sha256'] == tree['original_tree_sha256'] == TREE_PIN['sha256'] and
        tree['original_tree_matches'] is True and type(tree['rows']) is list and 1 <= len(tree['rows']) <= BOUNDS['tree_entries']+1 and
        type(tree['entries']) is int and tree['entries'] == len(tree['rows'])-1,'E137_EXACT_ORIGINAL_TREE')
    rows,children,total,files,directories = {},{},0,0,0
    for row in tree['rows']:
        require(type(row) is dict,'E137_TREE_ROW')
        directory = row.get('kind') == 'directory'
        require(set(row) == ({'relative','kind','bytes','sha256','identity'} if directory else
            {'relative','kind','bytes','sha256','identity','whole_file_hashed'}),'E137_TREE_ROW_SHAPE')
        rel = row['relative']
        require(type(rel) is str and rel not in rows and (rel == '' or
            len(rel.split('/')) <= BOUNDS['tree_depth'] and all(inventory.safe_name(name) for name in rel.split('/'))),
            'E137_TREE_ROW_PATH')
        require(type(row['bytes']) is int and 0 <= row['bytes'] <= BOUNDS['tree_bytes'],'E137_TREE_ROW_SIZE')
        _identity(row['identity'],row['bytes'],directory)
        if directory:
            require(row['bytes'] == 0 and row['sha256'] is None,'E137_TREE_DIRECTORY_ROW')
            directories += 1
        else:
            require(row['kind'] == 'file' and row['whole_file_hashed'] is True and type(row['sha256']) is str and
                re.fullmatch('[0-9a-f]{64}',row['sha256']) is not None,'E137_TREE_FILE_ROW')
            total += row['bytes']
            files += 1
        if rel:
            parent = rel.rsplit('/',1)[0] if '/' in rel else ''
            require(parent in rows and rows[parent]['kind'] == 'directory','E137_TREE_PARENT')
            children.setdefault(parent,[]).append(rel)
        else:
            require(not rows and directory,'E137_TREE_ROOT')
        rows[rel] = row
    order = []
    def visit(rel):
        order.append(rel)
        for child in sorted(children.get(rel,[])):
            if rows[child]['kind'] == 'directory':
                visit(child)
            else:
                order.append(child)
    visit('')
    require(order == [row['relative'] for row in tree['rows']] and type(tree['bytes']) is int and
        tree['bytes'] == total == TREE_PIN['bytes'] and files == TREE_PIN['files'] and directories == TREE_PIN['directories'],
        'E137_TREE_EXACT_BYTES_COUNTS_ORDER')
    digest = sha(canonical([[r['relative'],r['kind'],r['bytes'],r['sha256']] for r in tree['rows']]))
    require(digest == TREE_PIN['sha256'],'E137_COMPLETE_TREE_SHA')
    return value


def capture(authority,proposal,deadline,tick,monotonic):
    """Fixed sources only. Caller supplies the unchanged deadline/resource guard."""
    check_authority(authority,proposal)  # No IO or caller callback before this gate.
    require(callable(tick) and callable(monotonic) and type(deadline) in (int,float) and
        math.isfinite(deadline),'E137_SUPPLIED_GUARDS')
    began = monotonic()
    require(type(began) in (int,float) and math.isfinite(began) and 0 <= began < deadline <= began+BOUNDS['seconds'],
        'E137_FIXED_READ_DEADLINE')
    last = [began]
    def guard():
        now = monotonic()
        require(type(now) in (int,float) and math.isfinite(now) and last[0] <= now < deadline,'E137_READ_DEADLINE')
        last[0] = now
        tick()
        now = monotonic()
        require(type(now) in (int,float) and math.isfinite(now) and last[0] <= now < deadline,'E137_READ_DEADLINE')
        last[0] = now
    guard()
    require(source.FILES[0] == dict(role='pattern',path=PATTERN['path'],uid=1047,cap=BOUNDS['pattern_bytes'],export=False) and
        tuple(inventory.INPUTS) == INPUT_PINS and inventory.TREE == TREE_PIN['path'] and
        inventory.MAX_ENTRIES == BOUNDS['tree_entries'] and inventory.MAX_DEPTH == BOUNDS['tree_depth'] and
        inventory.MAX_BYTES == BOUNDS['tree_bytes'],'E137_FIXED_HELPER_SCOPE')
    pattern = source.read_file(source.FILES[0],guard)  # Never select FILES[1]/PDF.
    require(all(pattern[k] == PATTERN[k] for k in PATTERN),'E137_PATTERN_DRIFT')
    inputs = [inventory.read_input(pin,guard) for pin in INPUT_PINS]
    tree = inventory.inventory(guard)
    value = dict(schema=SCHEMA,authorization_sha256=AUTH_SHA,proposal_sha256=PROPOSAL_SHA,
        dependency_sha256=dict(DEPENDENCY_SHA256),bounds=dict(BOUNDS),pattern=pattern,inputs=inputs,tree=tree,
        complete=True,historical_vector_identity_proven=False,execution_ready=False,training_release=False,
        resource_enforcement_claimed=False,stil_dependency_completeness_verified=False)
    guard()
    validate_receipt(canonical(value))
    guard()
    return value
