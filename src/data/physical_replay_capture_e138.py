"""Native, default-disabled E138 source capture; no transport or tool entry.

Only the pinned E127 pattern/two inputs/one tree are hashed, never exported.
The injected tick must enforce the 512MiB sampled worker/descendant budget
and original package/boot limits; this module does not prove enforcement.
Source attributes and an authority record are consistency bindings, not
independent consent, OS authentication or physical source provenance.
"""
import math
import re
import stat

from . import physical_replay_source_reader_e135 as source
from . import physical_replay_source_inventory_e135 as inventory
from . import prospective_acceptance_materializer_v1 as anchored
from . import physical_e138_contract as contract

require,sha,canonical,decode = contract.require,contract.sha,contract.canonical,contract.decode
AUTH_SHA = PROPOSAL_SHA = None  # No entrypoint may infer these from supplied bytes.
SCHEMA = 'physical-f-clean-replay-source-capture-e138-v1'
DEPENDENCY_SHA256 = {
    'physical_e138_contract':'19bdaaf461de3ff424df57cf8e263f80efd57fa2a67a9929d5f89c4188f917f6',
    'prospective_acceptance_materializer_v1':'a04127c07227814e331ede4268c6f8d5df4def4d7041c0c69ec048378216cab9',
    'physical_replay_source_reader_e135':'6d6f86341eca23d5b473f8e323a0440d50ea44d177032576f196b9b417690818',
    'physical_replay_source_inventory_e135':'9467ee407dec9fd9bccad3ffdc517a508789c38b404fe9ac7d9d499fbd1be48d',
}
BOUNDS = dict(seconds=60,sampled_memory_bytes=536870912,pattern_bytes=67108864,tree_bytes=2147483648,tree_entries=4000,
    tree_depth=32,response_bytes=6291456,inherited_tree_metadata_bytes=1048576)
PATTERN = dict(role='pattern',path=inventory.BASE+'/runs/e116-aes_core/attempts/F_aes_core:HF:h1:F/tester.stil',
    bytes=443378,sha256='333d9f9bd359cf9066501a41e748b2182f5c787ffd46e112c7b5c5c2c6c5eae2')
INPUT_PINS = tuple(dict(pin) for pin in inventory.INPUTS)
TREE_PIN = dict(path=inventory.TREE,sha256=inventory.ORIGINAL_TREE_SHA,bytes=3759776,files=19,directories=9)


def _source_bindings():
    """Source-tag consistency only; the reviewed bootstrap establishes origin."""
    modules = dict(physical_replay_source_reader_e135=source,
        physical_replay_source_inventory_e135=inventory,
        prospective_acceptance_materializer_v1=anchored,physical_e138_contract=contract)
    require(type(DEPENDENCY_SHA256) is dict and set(DEPENDENCY_SHA256) == set(modules) and
        all(type(pin) is str and re.fullmatch('[0-9a-f]{64}',pin) is not None
            for pin in DEPENDENCY_SHA256.values()) and
        all(getattr(module,'__source_sha256__',None) == DEPENDENCY_SHA256[name]
            for name,module in modules.items()),'E138_FROZEN_DEPENDENCY_SOURCE_BINDINGS')


def check_authority(authority,proposal):
    """Pins are supplied by a future reviewed entrypoint, never learned here."""
    # This pure check rejects default/old grants before IO, time or callbacks.
    result = contract.check_authority(authority,proposal,AUTH_SHA,PROPOSAL_SHA)
    _source_bindings()
    return result


def _identity(info,size,directory=False):
    require(type(info) is dict and set(info) == set(source.FIELDS) and all(type(n) is int and n >= 0 for n in info.values()) and
        info['st_uid'] == 1047 and (stat.S_ISDIR(info['st_mode']) and info['st_nlink'] >= 1 if directory else
        stat.S_ISREG(info['st_mode']) and info['st_nlink'] == 1 and info['st_size'] == size),'E138_EXACT_IDENTITY')


def validate_receipt(raw):
    """Validate hash/metadata consistency only; cannot locally rehash absent bodies."""
    require(type(AUTH_SHA) is str and re.fullmatch('[0-9a-f]{64}',AUTH_SHA) is not None and
        AUTH_SHA != contract.OLD_AUTH_SHA256 and type(PROPOSAL_SHA) is str and
        re.fullmatch('[0-9a-f]{64}',PROPOSAL_SHA) is not None,'E138_RECEIPT_PINS_NOT_CONFIGURED')
    _source_bindings()
    require(type(raw) is bytes and 0 < len(raw) <= BOUNDS['response_bytes'],'E138_METADATA_CAP')
    value = decode(raw)
    require(type(value) is dict and set(value) == {'schema','authorization_sha256','proposal_sha256','dependency_sha256',
        'bounds','pattern','inputs','tree','complete','historical_vector_identity_proven','execution_ready','training_release',
        'resource_enforcement_claimed','stil_dependency_completeness_verified','remote_authorization_proven',
        'source_provenance_authenticated'} and value['schema'] == SCHEMA and value['authorization_sha256'] == AUTH_SHA and
        value['proposal_sha256'] == PROPOSAL_SHA and value['dependency_sha256'] == DEPENDENCY_SHA256 and
        canonical(value['bounds']) == canonical(BOUNDS) and value['complete'] is True and all(value[k] is False for k in
        ('historical_vector_identity_proven','execution_ready','training_release','resource_enforcement_claimed','stil_dependency_completeness_verified','remote_authorization_proven',
            'source_provenance_authenticated')),'E138_CAPTURE_SCHEMA')
    require(type(value['inputs']) is list and len(value['inputs']) == 2,'E138_EXACT_TWO_INPUTS')
    for row,pin in zip([value['pattern']]+value['inputs'],[PATTERN]+list(INPUT_PINS)):
        require(type(row) is dict and set(row) == {'role','path','bytes','sha256','identity','whole_file_hashed'} and
            all(row[k] == pin[k] for k in pin) and type(row['bytes']) is int and row['whole_file_hashed'] is True,
            'E138_EXACT_HASH_ONLY_FILE')
        _identity(row['identity'],row['bytes'])
    tree = value['tree']
    require(type(tree) is dict and set(tree) == {'path','entries','bytes','rows','sha256','sha256_scope','complete',
        'original_tree_sha256','original_tree_matches'} and tree['path'] == TREE_PIN['path'] and tree['complete'] is True and
        tree['sha256_scope'] == 'E85_SORTED_CHILD_DEPTH_FIRST_TREE' and tree['sha256'] == tree['original_tree_sha256'] == TREE_PIN['sha256'] and
        tree['original_tree_matches'] is True and type(tree['rows']) is list and 1 <= len(tree['rows']) <= BOUNDS['tree_entries']+1 and
        type(tree['entries']) is int and tree['entries'] == len(tree['rows'])-1,'E138_EXACT_ORIGINAL_TREE')
    rows,children,total,files,directories = {},{},0,0,0
    for row in tree['rows']:
        require(type(row) is dict,'E138_TREE_ROW')
        directory = row.get('kind') == 'directory'
        require(set(row) == ({'relative','kind','bytes','sha256','identity'} if directory else
            {'relative','kind','bytes','sha256','identity','whole_file_hashed'}),'E138_TREE_ROW_SHAPE')
        rel = row['relative']
        require(type(rel) is str and rel not in rows and (rel == '' or
            len(rel.split('/')) <= BOUNDS['tree_depth'] and all(inventory.safe_name(name) for name in rel.split('/'))),
            'E138_TREE_ROW_PATH')
        require(type(row['bytes']) is int and 0 <= row['bytes'] <= BOUNDS['tree_bytes'],'E138_TREE_ROW_SIZE')
        _identity(row['identity'],row['bytes'],directory)
        if directory:
            require(row['bytes'] == 0 and row['sha256'] is None,'E138_TREE_DIRECTORY_ROW')
            directories += 1
        else:
            require(row['kind'] == 'file' and row['whole_file_hashed'] is True and type(row['sha256']) is str and
                re.fullmatch('[0-9a-f]{64}',row['sha256']) is not None,'E138_TREE_FILE_ROW')
            total += row['bytes']
            files += 1
        if rel:
            parent = rel.rsplit('/',1)[0] if '/' in rel else ''
            require(parent in rows and rows[parent]['kind'] == 'directory','E138_TREE_PARENT')
            children.setdefault(parent,[]).append(rel)
        else:
            require(not rows and directory,'E138_TREE_ROOT')
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
        'E138_TREE_EXACT_BYTES_COUNTS_ORDER')
    digest = sha(canonical([[r['relative'],r['kind'],r['bytes'],r['sha256']] for r in tree['rows']]))
    require(digest == TREE_PIN['sha256'],'E138_COMPLETE_TREE_SHA')
    return value


def capture(authority,proposal,deadline,tick,monotonic):
    """Fixed sources only. Caller supplies the unchanged deadline/resource guard."""
    check_authority(authority,proposal)  # No IO, time or caller callback before this gate.
    require(BOUNDS['sampled_memory_bytes'] == contract.POLICY['sampled_worker_and_descendant_rss_swap_bytes_max'] and
        BOUNDS['seconds'] == contract.POLICY['read_seconds_max'],'E138_POLICY_CAPTURE_BOUNDS')
    require(callable(tick) and callable(monotonic) and type(deadline) in (int,float) and
        math.isfinite(deadline),'E138_SUPPLIED_GUARDS')
    began = monotonic()
    require(type(began) in (int,float) and math.isfinite(began) and 0 <= began < deadline <= began+BOUNDS['seconds'],
        'E138_FIXED_READ_DEADLINE')
    last = [began]
    def guard():
        now = monotonic()
        require(type(now) in (int,float) and math.isfinite(now) and last[0] <= now < deadline,'E138_READ_DEADLINE')
        last[0] = now
        tick()
        now = monotonic()
        require(type(now) in (int,float) and math.isfinite(now) and last[0] <= now < deadline,'E138_READ_DEADLINE')
        last[0] = now
    guard()
    require(source.FILES[0] == dict(role='pattern',path=PATTERN['path'],uid=1047,cap=BOUNDS['pattern_bytes'],export=False) and
        tuple(inventory.INPUTS) == INPUT_PINS and inventory.TREE == TREE_PIN['path'] and
        inventory.MAX_ENTRIES == BOUNDS['tree_entries'] and inventory.MAX_DEPTH == BOUNDS['tree_depth'] and
        inventory.MAX_BYTES == BOUNDS['tree_bytes'],'E138_FIXED_HELPER_SCOPE')
    pattern = source.read_file(source.FILES[0],guard)  # Never select FILES[1]/PDF.
    require(all(pattern[k] == PATTERN[k] for k in PATTERN),'E138_PATTERN_DRIFT')
    inputs = [inventory.read_input(pin,guard) for pin in INPUT_PINS]
    tree = inventory.inventory(guard)
    value = dict(schema=SCHEMA,authorization_sha256=AUTH_SHA,proposal_sha256=PROPOSAL_SHA,
        dependency_sha256=dict(DEPENDENCY_SHA256),bounds=dict(BOUNDS),pattern=pattern,inputs=inputs,tree=tree,
        complete=True,historical_vector_identity_proven=False,execution_ready=False,training_release=False,
        resource_enforcement_claimed=False,stil_dependency_completeness_verified=False,
        remote_authorization_proven=False,source_provenance_authenticated=False)
    guard()
    validate_receipt(canonical(value))
    guard()
    return value

