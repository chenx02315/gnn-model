"""One approved source identity/PDF capture; no simulation or tool launch."""
import ast
import base64
import datetime
import math
import os
from pathlib import Path
import platform
import re
import stat
import sys
import time

from src.data import physical_replay_source_reader_e135 as core
from src.data import physical_replay_source_inventory_e135 as inv

require,sha,canonical,decode = core.require,core.sha,core.canonical,core.decode
AUTH = 'contracts/physical_f_pattern_replay_authorization_e135.json'
AUTH_SHA = '03f0da9fec34c21433737fe51ee79e69aea7d2e8c7df94e333a78ca9be3d69b3'
CORE_SHA = '6d6f86341eca23d5b473f8e323a0440d50ea44d177032576f196b9b417690818'
PROPOSAL = 'contracts/physical_f_pattern_replay_proposal_e135_v1.json'
PROPOSAL_SHA = core.PROPOSAL_SHA
E128_SHA = 'd70818980f52ad17e9a1d7eb917d9618d1bf203d4ec29b7e780430529528189e'
SCHEMA = 'physical-replay-initial-source-capture-e135-v1'
PHASE_NAME = 'v6_e135_f_replay_r1'
MAX_RESPONSE,MAX_METADATA = 48*1048576,1048576
REVIEW_KEYS = ('payload_sha256','controller_sha256','source_sha256','input_sha256',
    'authorization_sha256','proposal_sha256','plan_sha256')


def check_authority(authority,proposal):
    require(sha(authority) == AUTH_SHA and sha(proposal) == PROPOSAL_SHA,'ACTUAL_NEW_E135_GRANT')
    auth,plan = decode(authority),decode(proposal)
    require(auth.get('schema') == 'physical-f-pattern-replay-authorization-e135-v1' and
        plan.get('schema') == 'physical-f-pattern-replay-proposal-e135-v1' and
        auth.get('user_reply') == '\u6279\u51c6 E135 \u6574\u5305' and
        auth.get('approval_source') == 'explicit_user_reply' and auth.get('user_authorization_received') is True and
        auth.get('proposal_sha256') == PROPOSAL_SHA and type(auth.get('approved_scope')) is dict and
        auth['approved_scope'] == plan.get('scope_if_granted'),'EXACT_WHOLE_PACKAGE_SCOPE')
    scope = auth['approved_scope']
    for key,value in dict(A_connections_max=3,readback_seconds_each_max=60,whole_package_wall_seconds_max=3600,
            remote_reader_versions_max=1,automatic_retries=0,source_pattern_bytes_max=67108864,
            reference_pdf_bytes_max=33554432,initial_readback_response_bytes_max=MAX_RESPONSE,
            fixed_source_tree_entries_max=4000,fixed_source_tree_depth_max=32,source_TSDB_copy_bytes_max=2147483648,
            sampled_worker_and_descendants_rss_swap_bytes_max=536870912).items():
        require(type(scope.get(key)) is int and scope[key] == value,'EXACT_CAPTURE_BUDGET')
    require(scope['candidate_pattern_path'] == core.FILES[0]['path'] and
        scope['reference_pdf_candidate'] == core.FILES[1]['path'] and scope['single_TSDB_source_candidate'] == inv.TREE and
        all(scope[k] is False for k in ('source_pattern_export_to_desktop','reference_pdf_export_to_Git',
        'history_or_source_tree_writes','B_access','BLIND_access','training')),'EXACT_READ_ONLY_PATH_SCOPE')


def metadata(value):
    source = value.get('source_receipt')
    if source is not None:
        source = dict(source,files=[{k:v for k,v in r.items() if k != 'body_base64'} for r in source['files']])
    return dict(value,source_receipt=source)


def collect(spec,started):
    from src.data import direct_tessent_acceptance_e104 as direct
    value = dict(schema=SCHEMA,capture_complete=False,error=None,stage='AUTHORITY',hostname=platform.node(),
        uid=os.getuid() if hasattr(os,'getuid') else None,python_version=list(sys.version_info[:3]),boot_id=None,
        remote_start_monotonic=started,remote_end_monotonic=None,sampled_peak_rss_swap_bytes=0,
        remote_utc_sample=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds'),
        remote_clock_sample_monotonic=time.monotonic(),remote_package_deadline_monotonic=started+3600,
        source_receipt=None,inputs=[],tree=None,filesystem_writes=0,child_launches=0,environment_reads=0,
        tessent_launches=0,training_release=False,semantics_verified=False,execution_ready=False)
    domain,next_sample = None,[0]
    def tick():
        now = time.monotonic()
        require(started <= now < started+60,'INITIAL_READ_DEADLINE')
        if now >= next_sample[0]:
            require(not domain.sample() and domain.peak <= 536870912,'MEMORY_OR_CHILD_STOP')
            next_sample[0] = now+.25
        require(time.monotonic() < started+60,'INITIAL_READ_DEADLINE')
    try:
        check_authority(base64.b64decode(spec['authority'],validate=True),base64.b64decode(spec['proposal'],validate=True))
        require(type(started) in (int,float) and math.isfinite(started) and started >= 0,'BOOTSTRAP_CLOCK')
        require(sys.platform.startswith('linux') and value['hostname'] == 'bupt-vncs2' and value['uid'] == 1047,'FIXED_A_HOST_UID')
        value['stage'] = 'BOOT_AND_MONITOR'
        value['boot_id'] = direct.base._small('/proc/sys/kernel/random/boot_id',128).decode('ascii').strip()
        require(re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value['boot_id']) is not None,'BOOT_ID')
        domain = direct.Descendants()
        rows = []
        value['source_receipt'] = dict(schema=core.SCHEMA,files=rows,source_provenance_authenticated=False,
            semantics_verified=False,execution_ready=False)
        for record in core.FILES:
            value['stage'] = 'READ_'+record['role'].upper()
            rows.append(core.read_file(record,tick))
        for pin in inv.INPUTS:
            value['stage'] = 'HASH_'+pin['role'].upper()
            value['inputs'].append(inv.read_input(pin,tick))
        value['stage'] = 'TSDB_INVENTORY'
        value['tree'] = inv.inventory(tick)
        tick()
        value['capture_complete'],value['stage'] = True,'COMPLETE'
    except BaseException as exc:
        value['error'] = dict(type=type(exc).__name__,code=str(exc) if type(exc) is ValueError else 'INITIAL_READ_FAILED',stage=value['stage'])
    finally:
        value['remote_end_monotonic'] = time.monotonic()
        if domain is not None:
            value['sampled_peak_rss_swap_bytes'] = domain.peak
    require(len(canonical(metadata(value))) <= MAX_METADATA,'INITIAL_METADATA_CAP')
    require(len(canonical(value)) <= MAX_RESPONSE,'INITIAL_RESPONSE_CAP')
    return value


def dependency_proof(repo,control):
    """Only exact already-local E128 snapshot and its E127 execution proof."""
    from scripts import read_pt_label_failure_e128 as prior
    from scripts import audit_common_universe_e130 as audit
    from src.data import prospective_pt_label_bundle_e127 as bundle
    proof = prior._execution_proof(repo,control)
    raw = (control.STAGING/'v6_e128_failure_readback_20261027_r1/stdout.json').read_bytes()
    require(sha(raw) == E128_SHA,'EXACT_LOCAL_E128_SNAPSHOT')
    rows = decode(raw)['files']
    def body(name):
        row = next(r for r in rows if r['path'] == prior.ROOT+'/journal/'+name)
        data = base64.b64decode(row['body_base64'],validate=True)
        require(len(data) == row['bytes'] and sha(data) == row['sha256'],'E128_BODY_PIN')
        return data
    preparation = decode(body('task_002_preparation.json'))
    binding = decode(body('task_002_intent.json'))['binding']
    e88 = (repo/'data/manifests/ranking_v6_e88_input_observation_20261023_r1.json').read_bytes()
    common = next(r for r in decode(e88)['roots'] if r['circuit'] == 'aes_core')
    env = audit._F_envelope(bundle.build_sources(),binding,repo,common['files']['manifest.json']['sha256'])
    require(env['envelope_sha256'] == preparation['effective_envelope_sha256'] and
        env['output_paths']['stil'] == core.FILES[0]['path'] and env['env']['CELL_LIBRARY'] == inv.INPUTS[0]['path'] and
        env['env']['TSDB_INPUT_DIR'] == inv.TREE and env['required_tasks'][0]['target_native_common_faults'] == inv.INPUTS[1]['path'],
        'DERIVED_EXACT_F_DEPENDENCIES')
    require(common['files']['F_common_initial_faults.basic'] == {k:inv.INPUTS[1][k] for k in ('bytes','sha256')},'E88_F_BASIC_PIN')
    e85 = (repo/'data/manifests/ranking_v6_e85_input_observation_20261023_r1.json').read_bytes()
    execution_review = decode((repo/prior.EXECUTION_REVIEW).read_bytes())['reviewed']
    require(sha(e85) == execution_review['input_sha256']['e85'],'EXACT_EXECUTED_E85_INPUT')
    library = decode(e85)['library']
    require(library['bytes'] == inv.INPUTS[0]['bytes'] and library['body_sha256'] == inv.INPUTS[0]['sha256'] and
        preparation['input_receipt']['tsdb']['path'] == inv.TREE and
        preparation['input_receipt']['tsdb']['sha256'] == inv.ORIGINAL_TREE_SHA,'E85_AND_E128_DEPENDENCY_PINS')
    return dict(e128=sha(raw),e85=sha(e85),e88=sha(e88),preparation=sha(body('task_002_preparation.json')),
        execution_proof=sha(canonical(proof)),envelope=env['envelope_sha256'],
        local_e128_deriver=sha(Path(prior.__file__).read_bytes()),local_e130_deriver=sha(Path(audit.__file__).read_bytes()))


def prepare():
    from scripts import acceptance_transport_e98 as control
    from scripts.run_direct_tessent_e104 import PINS
    repo = Path(__file__).resolve().parents[1]
    authority,proposal = (repo/AUTH).read_bytes(),(repo/PROPOSAL).read_bytes()
    check_authority(authority,proposal)
    inputs = dependency_proof(repo,control)
    sources = []
    for name,pin in list(PINS)+[('physical_replay_source_reader_e135',CORE_SHA),
            ('physical_replay_source_inventory_e135',None),('e135_source_capture',None)]:
        path = Path(__file__) if name == 'e135_source_capture' else repo/'src/data'/(name+'.py')
        raw = path.read_bytes()
        require(pin is None or sha(raw) == pin,'FROZEN_SOURCE_CHANGED')
        ast.parse(raw.decode('utf-8'),feature_version=(3,6))
        sources.append(dict(name=name,sha256=sha(raw),body=base64.b64encode(raw).decode('ascii')))
    spec = dict(authority=base64.b64encode(authority).decode('ascii'),proposal=base64.b64encode(proposal).decode('ascii'))
    wire = canonical(dict(sources=sources,spec=spec)).decode('ascii')
    payload = ('import time\nbootstrap_started=time.monotonic()\n'
        'import base64,hashlib,json,types,sys\np=json.loads('+repr(wire)+')\n'
        'for name in ("src","src.data"):\n'
        ' m=types.ModuleType(name);m.__path__=[];sys.modules[name]=m\n'
        ' if name=="src.data":sys.modules["src"].data=m\n'
        'for row in p["sources"]:\n'
        ' raw=base64.b64decode(row["body"],validate=True)\n'
        ' if hashlib.sha256(raw).hexdigest()!=row["sha256"]:raise ValueError("SOURCE_SHA")\n'
        ' name="src.data."+row["name"];m=types.ModuleType(name);m.__package__="src.data"\n'
        ' sys.modules[name]=m;setattr(sys.modules["src.data"],row["name"],m)\n'
        ' exec(compile(raw,"<read-only-"+row["name"]+">","exec"),m.__dict__)\n'
        'result=sys.modules["src.data.e135_source_capture"].collect(p["spec"],bootstrap_started)\n'
        'print(json.dumps(result,sort_keys=True,allow_nan=False),flush=True)\n').encode('ascii')
    ast.parse(payload.decode('ascii'),feature_version=(3,6))
    return dict(payload=payload,payload_sha256=sha(payload),controller_sha256=sha(Path(__file__).read_bytes()),
        source_sha256={r['name']:r['sha256'] for r in sources},input_sha256=inputs,
        authorization_sha256=AUTH_SHA,proposal_sha256=PROPOSAL_SHA,
        plan_sha256=sha(canonical(dict(sources=list(core.FILES),inputs=list(inv.INPUTS),tree=inv.TREE))))


def valid_identity(info,size,directory=False):
    require(type(info) is dict and set(info) == set(core.FIELDS) and all(type(n) is int and n >= 0 for n in info.values()) and
        info['st_uid'] == 1047 and (stat.S_ISDIR(info['st_mode']) and info['st_nlink'] >= 1 if directory else
        stat.S_ISREG(info['st_mode']) and info['st_nlink'] == 1 and info['st_size'] == size),'INVENTORY_IDENTITY_METADATA')


def validate_response(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_RESPONSE,'INITIAL_RESPONSE_CAP')
    v = decode(raw)
    require(v.get('schema') == SCHEMA and v.get('capture_complete') is True and v.get('error') is None and
        v.get('stage') == 'COMPLETE' and v.get('hostname') == 'bupt-vncs2' and type(v.get('uid')) is int and v['uid'] == 1047,
        'COMPLETE_A_CAPTURE_REQUIRED')
    require(type(v.get('python_version')) is list and len(v['python_version']) == 3 and
        all(type(n) is int and n >= 0 for n in v['python_version']) and type(v.get('boot_id')) is str and
        re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',v['boot_id']) is not None,'RUNTIME_METADATA')
    start,end = v.get('remote_start_monotonic'),v.get('remote_end_monotonic')
    require(all(type(n) in (int,float) and math.isfinite(n) and n >= 0 for n in (start,end)) and start <= end < start+60,'READ_INTERVAL')
    sample = v.get('remote_clock_sample_monotonic')
    require(type(sample) in (int,float) and math.isfinite(sample) and start <= sample <= end and
        v.get('remote_package_deadline_monotonic') == start+3600,'ORIGINAL_REMOTE_PACKAGE_CLOCK')
    datetime.datetime.strptime(v['remote_utc_sample'],'%Y-%m-%dT%H:%M:%S.%f%z')
    require(type(v.get('sampled_peak_rss_swap_bytes')) is int and 0 <= v['sampled_peak_rss_swap_bytes'] <= 536870912,'MEMORY_BOUND')
    require(all(type(v.get(k)) is int and v[k] == 0 for k in ('filesystem_writes','child_launches','environment_reads','tessent_launches')) and
        all(v.get(k) is False for k in ('training_release','semantics_verified','execution_ready')),'READ_ONLY_NOT_REPLAY')
    require(len(canonical(metadata(v))) <= MAX_METADATA,'INITIAL_METADATA_CAP')
    source = core.validate_receipt(canonical(v['source_receipt']))
    require(type(v['inputs']) is list and len(v['inputs']) == 2,'EXACT_TWO_INPUTS')
    for pin,row in zip(inv.INPUTS,v['inputs']):
        require(type(row) is dict and set(row) == {'role','path','bytes','sha256','identity','whole_file_hashed'} and
            all(row[k] == pin[k] for k in pin) and type(row['bytes']) is int and row['whole_file_hashed'] is True,'PINNED_INPUT_RECEIPT')
        valid_identity(row['identity'],row['bytes'])
    tree = v['tree']
    require(type(tree) is dict and set(tree) == {'path','entries','bytes','rows','sha256','sha256_scope','complete','original_tree_sha256','original_tree_matches'} and
        tree['path'] == inv.TREE and tree['complete'] is True and tree['sha256_scope'] == 'E85_SORTED_CHILD_DEPTH_FIRST_TREE' and
        tree['original_tree_sha256'] == inv.ORIGINAL_TREE_SHA and type(tree['rows']) is list and
        1 <= len(tree['rows']) <= inv.MAX_ENTRIES+1 and type(tree['entries']) is int and tree['entries'] == len(tree['rows'])-1,
        'COMPLETE_EXACT_TREE')
    paths,total,order = {},0,[]
    for row in tree['rows']:
        directory = row.get('kind') == 'directory'
        require(set(row) == ({'relative','kind','bytes','sha256','identity'} if directory else
            {'relative','kind','bytes','sha256','identity','whole_file_hashed'}),'TREE_ROW_SHAPE')
        rel = row['relative']
        require(type(rel) is str and rel not in paths and (rel == '' or
            len(rel.split('/')) <= inv.MAX_DEPTH and all(inv.safe_name(n) for n in rel.split('/'))),'TREE_ROW_PATH')
        require(type(row['bytes']) is int and 0 <= row['bytes'] <= inv.MAX_BYTES,'TREE_ROW_SIZE')
        valid_identity(row['identity'],row['bytes'],directory)
        if directory:
            require(row['bytes'] == 0 and row['sha256'] is None,'TREE_DIRECTORY_ROW')
        else:
            require(row['kind'] == 'file' and row['whole_file_hashed'] is True and type(row['sha256']) is str and
                re.fullmatch('[0-9a-f]{64}',row['sha256']) is not None,'TREE_FILE_ROW')
            total += row['bytes']
        if rel:
            parent = rel.rsplit('/',1)[0] if '/' in rel else ''
            require(parent in paths and paths[parent]['kind'] == 'directory','TREE_PARENT_ROSTER')
        else:
            require(not paths and directory,'TREE_ROOT_ROW')
        paths[rel] = row
    def visit(rel):
        order.append(rel)
        children = sorted(p for p in paths if p and (p.rsplit('/',1)[0] if '/' in p else '') == rel)
        for child in children:
            if paths[child]['kind'] == 'directory':
                visit(child)
            else:
                order.append(child)
    visit('')
    require(order == [r['relative'] for r in tree['rows']] and type(tree['bytes']) is int and tree['bytes'] == total <= inv.MAX_BYTES,
        'COMPLETE_TREE_ORDER_AND_BYTES')
    digest = sha(canonical([[r['relative'],r['kind'],r['bytes'],r['sha256']] for r in tree['rows']]))
    require(tree['sha256'] == digest and type(tree['original_tree_matches']) is bool and
        tree['original_tree_matches'] == (digest == inv.ORIGINAL_TREE_SHA),'TREE_FULL_INVENTORY_SHA')
    return v,base64.b64decode(source['files'][1]['body_base64'],validate=True)


def remaining(first):
    """Reuse the immutable first-call clock across later local Python processes."""
    require(first.get('authorization_sha256') == AUTH_SHA and first.get('local_clock_domain') ==
        dict(host=platform.node(),clock=time.get_clock_info('monotonic').implementation),'SAME_PACKAGE_LOCAL_CLOCK_DOMAIN')
    start,end,now = first['local_monotonic_start'],first['local_monotonic_deadline'],time.monotonic()
    require(all(type(n) in (int,float) and math.isfinite(n) for n in (start,end,now)) and end == start+3600 and start <= now < end,'PACKAGE_MONOTONIC_EXPIRED')
    utc = datetime.datetime.strptime(first['local_utc_deadline'],'%Y-%m-%dT%H:%M:%S.%f%z')
    utc_start = datetime.datetime.strptime(first['local_utc_start'],'%Y-%m-%dT%H:%M:%S.%f%z')
    utc_now = datetime.datetime.now(datetime.timezone.utc)
    require((utc-utc_start).total_seconds() == 3600 and
        abs((utc_now-utc_start).total_seconds()-(now-start)) <= 5,'PACKAGE_CLOCK_DIVERGENCE')
    seconds = min(end-now,(utc-utc_now).total_seconds())
    require(seconds > 1,'PACKAGE_UTC_EXPIRED')
    return seconds


_remaining = remaining


def execute(review_path,reviewed_payload_sha):
    from scripts import acceptance_transport_e98 as control
    plan = prepare()
    review = decode(Path(review_path).read_bytes())
    expected = {k:plan[k] for k in REVIEW_KEYS}
    require(review.get('status') == 'PASS' and review.get('reviewed') == expected and reviewed_payload_sha == plan['payload_sha256'],
        'INDEPENDENT_EXACT_NEW_REVIEW_REQUIRED')
    helper = control.load_transport()
    fingerprint = helper.verify_cached_host('A')
    phase = control.STAGING/PHASE_NAME
    phase.mkdir(exist_ok=False)
    now,started = datetime.datetime.now(datetime.timezone.utc),time.monotonic()
    first = dict(expected,host_fingerprint=fingerprint,calls_max=3,automatic_retries=0,
        local_utc_start=now.isoformat(timespec='microseconds'),
        local_utc_deadline=(now+datetime.timedelta(seconds=3600)).isoformat(timespec='microseconds'),
        local_monotonic_start=started,local_monotonic_deadline=started+3600,
        local_clock_domain=dict(host=platform.node(),clock=time.get_clock_info('monotonic').implementation))
    control.write_new(phase/'start.json',control.encode(first))
    read = phase/'read1'
    read.mkdir(exist_ok=False)
    control.write_new(read/'intent.json',control.encode(dict(call_index=1,calls_max=3,attempt_consumed=True,
        automatic_retries=0,payload_sha256=plan['payload_sha256'],authorization_sha256=AUTH_SHA)))
    try:
        helper.TIMEOUT = min(60,max(1,int(_remaining(first))))
        observed = helper.transport(helper.command('A'),plan['payload'],MAX_RESPONSE)
    except BaseException as exc:
        control.write_new(read/'transport.json',control.encode(dict(error_type=type(exc).__name__,status='ATTEMPT_CONSUMED_NO_RETRY')))
        raise
    control.write_new(read/'stdout.json',observed['stdout'])
    control.write_new(read/'stderr.log',observed['stderr'])
    receipt = {k:v for k,v in observed.items() if k not in ('stdout','stderr')}
    for key in ('stdout','stderr'):
        receipt[key+'_bytes'],receipt[key+'_sha256'] = len(observed[key]),sha(observed[key])
    control.write_new(read/'transport.json',control.encode(receipt))
    require(observed['exit_code'] == 0 and not any(observed[k] for k in ('timeout','overflow','write_failed','threads_incomplete')),'TRANSPORT_FAILED_NO_RETRY')
    _remaining(first)
    value,pdf = validate_response(observed['stdout'])
    _remaining(first)
    control.write_new(phase/'package_clock.json',control.encode(dict(schema='physical-f-replay-package-clock-e135-v1',
        authorization_sha256=AUTH_SHA,proposal_sha256=PROPOSAL_SHA,reader_payload_sha256=plan['payload_sha256'],
        initial_response_sha256=sha(observed['stdout']),
        boot_id=value['boot_id'],remote_start_monotonic=value['remote_start_monotonic'],
        remote_deadline_monotonic=value['remote_package_deadline_monotonic'],
        remote_utc_sample=value['remote_utc_sample'],remote_clock_sample_monotonic=value['remote_clock_sample_monotonic'],
        local_utc_start=first['local_utc_start'],local_utc_deadline=first['local_utc_deadline'],
        local_monotonic_start=first['local_monotonic_start'],local_monotonic_deadline=first['local_monotonic_deadline'],
        local_clock_domain=first['local_clock_domain'],start_file_sha256=sha((phase/'start.json').read_bytes()))))
    output = read/'files'
    output.mkdir(exist_ok=False)
    pdfrow = value['source_receipt']['files'][1]
    control.write_new(output/pdfrow['sha256'],pdf)
    _remaining(first)
    control.write_new(read/'validated.json',control.encode(dict(pdf_sha256=sha(pdf),metadata=metadata(value),
        source_provenance_authenticated=False,execution_ready=False,training_release=False)))
    return dict(phase=str(phase),pdf_file=str(output/pdfrow['sha256']),package_clock=first,
        calls_consumed=1,calls_max=3,execution_ready=False,training_release=False)
