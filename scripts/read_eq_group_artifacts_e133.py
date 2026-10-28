"""One exact seven-file read/export; no body parser, coverage decision or retry."""
import ast
import base64
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import stat
import sys
import time

AUTH = 'contracts/eq_group_coverage_certificate_authorization_e133_20261027.json'
AUTH_SHA = 'cdfd9f7eca7f7c0eee875c486db091a1b93832c73092aa2e92810c94afddced2'
PROPOSAL = 'contracts/eq_group_coverage_certificate_proposal_e133_v1.json'
PROPOSAL_SHA = '91c75adfdfb933be12cacf0ebb17346a97ba7bf549ace9e75e4082573de333c7'
SCHEMA = 'eq-group-owned-artifact-readback-e133-v1'
PHASE_NAME = 'v6_e133_eq_group_readback_20261027_r1'
MAX_FILE,MAX_TOTAL,MAX_RESPONSE,MAX_METADATA = 8*1048576,16*1048576,24*1048576,65536
FILES = (
    dict(path="/temp/jiangchuanc/multimode_ate_pt_label_repair_e127_20261027_r1/aes_core/03_fault_universe/common_frozen/manifest.json",bytes=1554,sha256="c1239fb3ff04b6db8ef49265bf5902cfbaf058b229ad84214c4c8d21748a1f2f"),
    dict(path="/temp/jiangchuanc/multimode_ate_pt_label_repair_e127_20261027_r1/aes_core/03_fault_universe/common_frozen/canonical_fault_mapping.tsv",bytes=3385680,sha256="b81d0cd552645ef9ceae251a066e1483d098870c22a0e111ea0abbf4ed7867f8"),
    dict(path="/temp/jiangchuanc/multimode_ate_pt_label_repair_e127_20261027_r1/aes_core/03_fault_universe/common_frozen/F_common_initial_faults.basic",bytes=2245666,sha256="70b549870374c4b31f342d5a6fbd10db5d5d8f5eb3844c3eb8d28d45767fb566"),
    dict(path="/temp/jiangchuanc/multimode_ate_pt_label_repair_e127_20261027_r1/aes_core/runs/e116-aes_core/attempts/F_aes_core:HF:h1:F/faults.mtfi",bytes=2520140,sha256="55f6850eee753e3aff90b7b2199a366cb635a7b6a00adae84b1f20fc049ded5f"),
    dict(path="/temp/jiangchuanc/multimode_ate_pt_label_repair_e127_20261027_r1/aes_core/runs/e116-aes_core/attempts/F_aes_core:HF:h1:F/statistics.rpt",bytes=1576,sha256="629b433cd87ad7e471834decf9cce0f47735268da7028215b0eed68f8c60fff4"),
    dict(path="/temp/jiangchuanc/multimode_ate_pt_label_repair_e127_20261027_r1/aes_core/runs/e116-aes_core/attempts/F_aes_core:HF:h1:F/pre_atpg_statistics.rpt",bytes=1531,sha256="35de9953800c5be1c792c2026040a2c53b0e88984b40cc9e32a6f4a2e9014911"),
    dict(path="/temp/jiangchuanc/multimode_ate_pt_label_repair_e127_20261027_r1/aes_core/runs/e116-aes_core/attempts/F_aes_core:HF:h1:F/faults.rpt",bytes=2247877,sha256="7f02656b2f78d818c2da4d2f58448fb48d202d167f8cd60a84155ee15a1e02d3"),
)
REVIEW_KEYS = ('payload_sha256','controller_sha256','source_sha256','authorization_sha256','proposal_sha256','plan_sha256')


def require(ok,code):
    if not ok:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def decode(raw):
    def pairs(items):
        value = {}
        for key,item in items:
            require(key not in value,'DUPLICATE_JSON_KEY')
            value[key] = item
        return value
    return json.loads(raw.decode('ascii'),object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE_JSON')))


def check_authority(authority,proposal):
    require(sha(authority) == AUTH_SHA and sha(proposal) == PROPOSAL_SHA,'ACTUAL_NEW_AUTHORITY_AND_PROPOSAL')
    auth,plan = decode(authority),decode(proposal)
    require(auth.get('user_reply') == '\u6279\u51c6 E133 \u6574\u5305' and auth.get('user_authorization_received') is True and
        auth.get('proposal_sha256') == PROPOSAL_SHA and auth.get('approved_scope') == plan.get('scope_if_granted'),
        'EXACT_AUTHORIZED_READ_SCOPE')
    scope = auth['approved_scope']
    require(scope['fixed_files'] == list(FILES) and scope['fixed_file_count'] == 7 and
        scope['single_file_bytes_max'] == MAX_FILE and scope['total_body_bytes_max'] == MAX_TOTAL and
        scope['response_bytes_max'] == MAX_RESPONSE and scope['seconds_per_call_max'] == 60 and
        scope['capture_wall_seconds_max'] == 300 and scope['sampled_memory_bytes_max'] == 536870912 and
        all(type(scope[k]) is int and scope[k] == 1 for k in ('A_read_only_calls_max','A_read_attempts_max','remote_reader_versions_max')) and
        scope['automatic_retries'] == 0 and all(scope[k] == 0 for k in ('Tessent_launches','ATPG_launches','LSF_jobs')) and
        all(scope[k] is False for k in ('B_access','BLIND_access','training','candidate_join_or_training_release','old_D95_contract_or_history_modification')),
        'FIXED_READ_BUDGET_AND_NO_EXPERIMENT')


def read_file(pin,tick,total):
    from src.data import prospective_acceptance_materializer_v1 as anchored
    require(pin in FILES and type(pin['bytes']) is int and 0 < pin['bytes'] <= MAX_FILE,'EXACT_APPROVED_FILE_PIN')
    tick()
    parent,name = pin['path'].rsplit('/',1)
    parent_fd,fd = anchored._directory(parent),None
    try:
        parent_identity = anchored._identity(os.fstat(parent_fd))
        named = os.stat(name,dir_fd=parent_fd,follow_symlinks=False)
        cap = MAX_METADATA if name.endswith(('.json','.rpt')) and name != 'faults.rpt' else MAX_FILE
        require(stat.S_ISREG(named.st_mode) and named.st_nlink == 1 and named.st_uid == 1047,'PREOPEN_SINGLE_LINK_OWNED_REGULAR')
        require(named.st_size == pin['bytes'] and 0 < named.st_size <= cap and total[0]+named.st_size <= MAX_TOTAL,'PINNED_SIZE_OR_TOTAL_BOUND')
        fd = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent_fd)
        opened = os.fstat(fd)
        require(anchored._identity(named) == anchored._identity(opened) and opened.st_uid == 1047,'PINNED_FILE_IDENTITY')
        remaining,digest,parts,tail = named.st_size,hashlib.sha256(),[],b''
        while remaining:
            tick()
            raw = os.read(fd,min(65536,remaining))
            require(bool(raw),'PINNED_FILE_SHORT_READ')
            remaining -= len(raw)
            total[0] += len(raw)
            digest.update(raw)
            combined = tail+raw
            stop = len(combined)//3*3
            if stop:
                parts.append(base64.b64encode(combined[:stop]).decode('ascii'))
            tail = combined[stop:]
        if tail:
            parts.append(base64.b64encode(tail).decode('ascii'))
        require(not os.read(fd,1),'PINNED_FILE_GREW')
        tick()
        current = os.fstat(fd)
        final = os.stat(name,dir_fd=parent_fd,follow_symlinks=False)
        require(anchored._identity(named) == anchored._identity(current) == anchored._identity(final) and
            current.st_uid == final.st_uid == 1047,'PINNED_FILE_CHANGED')
        fresh = anchored._directory(parent)
        try:
            require(anchored._identity(os.fstat(fresh)) == parent_identity,'PINNED_PARENT_CHANGED')
        finally:
            os.close(fresh)
        require(digest.hexdigest() == pin['sha256'],'FULL_APPROVED_SHA_MISMATCH')
        return dict(path=pin['path'],bytes=named.st_size,sha256=digest.hexdigest(),whole_file_hashed=True,
                    identity=identity(current),body_base64=''.join(parts))
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent_fd)


def identity(info):
    return {key:getattr(info,key) for key in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_size','st_mtime_ns','st_ctime_ns')}


def metadata_only(value):
    return dict(value,files=[{key:item for key,item in row.items() if key != 'body_base64'} for row in value['files']])


def collect(spec,started):
    from src.data import direct_tessent_acceptance_e104 as direct
    result = dict(schema=SCHEMA,capture_complete=False,error=None,stage='AUTHORITY_CHECK',
        hostname=platform.node(),uid=os.getuid() if hasattr(os,'getuid') else None,boot_id=None,
        python_version=list(sys.version_info[:3]),remote_start_monotonic=started,remote_end_monotonic=None,
        capture_deadline_monotonic=started+300,files=[],body_bytes_hashed=0,sampled_peak_rss_swap_bytes=0,
        filesystem_writes=0,child_launches=0,environment_reads=0,tessent_launches=0,atpg_launches=0,
        training_runs=0,old_experiment_clock_changed=False,parse_or_analysis_performed=False,
        coverage_semantics_proven=False,frozen_contract_d95_pass=False,training_release=False)
    total,domain,next_sample = [0],None,[0]
    def tick():
        require(time.monotonic() < started+60,'NEW_READ_CALL_DEADLINE')
        if time.monotonic() >= next_sample[0]:
            require(not domain.sample() and domain.peak <= 536870912,'MEMORY_OR_CHILD_STOP')
            next_sample[0] = time.monotonic()+.25
        require(time.monotonic() < started+60,'NEW_READ_CALL_DEADLINE')
    try:
        check_authority(base64.b64decode(spec['authority'],validate=True),base64.b64decode(spec['proposal'],validate=True))
        require(type(started) in (int,float) and math.isfinite(started) and started >= 0,'NEW_CAPTURE_CLOCK')
        require(sys.platform.startswith('linux') and result['hostname'] == 'bupt-vncs2' and result['uid'] == 1047,'FIXED_A_UID_PLATFORM')
        result['stage'] = 'BOOT_ID_CHECK'
        result['boot_id'] = direct.base._small('/proc/sys/kernel/random/boot_id',128).decode('ascii').strip()
        require(re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',result['boot_id']) is not None,'ACTUAL_BOOT_ID')
        result['stage'] = 'MEMORY_MONITOR_SETUP'
        domain = direct.Descendants()
        for index,pin in enumerate(FILES):
            result['stage'] = 'READ_APPROVED_FILE_%d'%index
            result['files'].append(read_file(pin,tick,total))
        tick()
        result['capture_complete'],result['stage'] = True,'COMPLETE'
    except BaseException as exc:
        result['error'] = dict(type=type(exc).__name__,stage=result['stage'],
            code=str(exc) if type(exc) is ValueError else 'FIXED_READ_FAILED_AT_'+result['stage'])
    finally:
        result['remote_end_monotonic'] = time.monotonic()
        result['body_bytes_hashed'] = total[0]
        if domain is not None:
            result['sampled_peak_rss_swap_bytes'] = domain.peak
    require(len(canonical(metadata_only(result))) <= MAX_METADATA,'CAPTURE_METADATA_BOUND')
    require(len(canonical(result)) <= MAX_RESPONSE,'EXPORT_RESPONSE_BOUND')
    return result


def prepare():
    from scripts.run_direct_tessent_e104 import PINS
    repo = Path(__file__).resolve().parents[1]
    authority,proposal = (repo/AUTH).read_bytes(),(repo/PROPOSAL).read_bytes()
    check_authority(authority,proposal)
    sources = []
    for name,pin in list(PINS)+[('e133_artifact_reader',None)]:
        raw = (Path(__file__) if pin is None else repo/'src/data'/(name+'.py')).read_bytes()
        require(pin is None or sha(raw) == pin,'FROZEN_MONITOR_SOURCE_CHANGED')
        ast.parse(raw.decode('utf-8'),feature_version=(3,6))
        sources.append(dict(name=name,sha256=sha(raw),body=base64.b64encode(raw).decode('ascii')))
    spec = dict(authority=base64.b64encode(authority).decode('ascii'),proposal=base64.b64encode(proposal).decode('ascii'))
    package = json.dumps(dict(sources=sources,spec=spec),separators=(',',':'))
    payload = ('import time\nbootstrap_started=time.monotonic()\n'
        'import base64,hashlib,json,types,sys\n'
        'p=json.loads('+repr(package)+')\n'
        'for name in ("src","src.data"):\n'
        ' m=types.ModuleType(name);m.__path__=[];sys.modules[name]=m\n'
        ' if name=="src.data":sys.modules["src"].data=m\n'
        'for row in p["sources"]:\n'
        ' raw=base64.b64decode(row["body"],validate=True)\n'
        ' if hashlib.sha256(raw).hexdigest()!=row["sha256"]:raise ValueError("SOURCE_SHA")\n'
        ' name="src.data."+row["name"];m=types.ModuleType(name);m.__package__="src.data"\n'
        ' sys.modules[name]=m;setattr(sys.modules["src.data"],row["name"],m)\n'
        ' exec(compile(raw,"<read-only-"+row["name"]+">","exec"),m.__dict__)\n'
        'result=sys.modules["src.data.e133_artifact_reader"].collect(p["spec"],bootstrap_started)\n'
        'print(json.dumps(result,sort_keys=True,allow_nan=False),flush=True)\n').encode('ascii')
    require(len(payload) <= 1048576,'FIXED_READER_PAYLOAD_BOUND')
    ast.parse(payload.decode('ascii'),feature_version=(3,6))
    return dict(payload=payload,payload_sha256=sha(payload),controller_sha256=sha(Path(__file__).read_bytes()),
        source_sha256={row['name']:row['sha256'] for row in sources},authorization_sha256=AUTH_SHA,
        proposal_sha256=PROPOSAL_SHA,plan_sha256=sha(canonical(list(FILES))))


def validate_response(raw):
    """Verify all complete hashes before returning ANY decoded body for storage."""
    require(type(raw) is bytes and 0 < len(raw) <= MAX_RESPONSE,'EXPORT_RESPONSE_BOUND')
    value = decode(raw)
    require(type(value) is dict and value.get('schema') == SCHEMA and value.get('hostname') == 'bupt-vncs2' and
        type(value.get('uid')) is int and value['uid'] == 1047 and value.get('capture_complete') is True and
        value.get('stage') == 'COMPLETE' and value.get('error') is None,'COMPLETE_FIXED_READ_REQUIRED')
    require(type(value.get('boot_id')) is str and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value['boot_id']) is not None,'ACTUAL_READ_BOOT_ID')
    require(type(value.get('python_version')) is list and len(value['python_version']) == 3 and
        all(type(n) is int and n >= 0 for n in value['python_version']),'EXACT_PYTHON_VERSION_METADATA')
    start,end = value.get('remote_start_monotonic'),value.get('remote_end_monotonic')
    require(all(type(n) in (int,float) and math.isfinite(n) and n >= 0 for n in (start,end)) and
        start <= end < start+60 and value.get('capture_deadline_monotonic') == start+300,'NEW_CAPTURE_INTERVAL')
    for key in ('filesystem_writes','child_launches','environment_reads','tessent_launches','atpg_launches','training_runs'):
        require(type(value.get(key)) is int and value[key] == 0,'READ_ONLY_NO_EXPERIMENT')
    for key in ('old_experiment_clock_changed','parse_or_analysis_performed','coverage_semantics_proven','frozen_contract_d95_pass','training_release'):
        require(value.get(key) is False,'NO_ANALYSIS_OR_OLD_CONTRACT_CHANGE')
    require(type(value.get('sampled_peak_rss_swap_bytes')) is int and 0 <= value['sampled_peak_rss_swap_bytes'] <= 536870912,'SAMPLED_MEMORY_BOUND')
    rows = value.get('files')
    require(type(rows) is list and len(rows) == 7 and len(canonical(metadata_only(value))) <= MAX_METADATA,'EXACT_SEVEN_FILE_METADATA')
    bodies,total = [],0
    for pin,row in zip(FILES,rows):
        require(type(row) is dict and set(row) == {'path','bytes','sha256','whole_file_hashed','identity','body_base64'} and
            all(row[k] == pin[k] for k in ('path','bytes','sha256')) and type(row['bytes']) is int and
            row['whole_file_hashed'] is True and 0 < row['bytes'] <= MAX_FILE,'EXACT_APPROVED_FILE_RECEIPT')
        info = row['identity']
        fields = {'st_dev','st_ino','st_mode','st_nlink','st_uid','st_size','st_mtime_ns','st_ctime_ns'}
        require(type(info) is dict and set(info) == fields and all(type(n) is int and n >= 0 for n in info.values()) and
            stat.S_ISREG(info['st_mode']) and info['st_nlink'] == 1 and info['st_uid'] == 1047 and info['st_size'] == row['bytes'],
            'REGULAR_OWNED_STABLE_RECEIPT_METADATA')
        body = base64.b64decode(row['body_base64'],validate=True)
        total += len(body)
        require(len(body) == pin['bytes'] and sha(body) == pin['sha256'] and total <= MAX_TOTAL,'COMPLETE_ALL_SEVEN_BODY_SHA')
        bodies.append(body)
    require(type(value.get('body_bytes_hashed')) is int and value['body_bytes_hashed'] == total,'TOTAL_HASHED_BODY_BYTES')
    return value,bodies


def _remaining(first):
    domain = dict(pid=os.getpid(),host=platform.node(),clock=time.get_clock_info('monotonic').implementation)
    require(first.get('local_clock_domain') == domain,'SAME_LOCAL_PROCESS_CLOCK_REQUIRED')
    start,last = first.get('local_monotonic_start'),first.get('local_monotonic_deadline')
    now = time.monotonic()
    require(all(type(n) in (int,float) and math.isfinite(n) for n in (start,last,now)) and
        last == start+300 and start <= now < last,'LOCAL_MONOTONIC_CAPTURE_EXPIRED')
    utc_end = datetime.datetime.strptime(first['local_utc_deadline'],'%Y-%m-%dT%H:%M:%S.%f%z')
    remaining = min(last-now,(utc_end-datetime.datetime.now(datetime.timezone.utc)).total_seconds())
    require(remaining > 1,'LOCAL_WALL_CAPTURE_EXPIRED')
    return remaining


def execute(review_path,reviewed_payload_sha):
    from scripts import acceptance_transport_e98 as control
    plan = prepare()
    review = decode(Path(review_path).read_bytes())
    expected = {key:plan[key] for key in REVIEW_KEYS}
    require(review.get('status') == 'PASS' and review.get('reviewed') == expected and reviewed_payload_sha == plan['payload_sha256'],
            'INDEPENDENT_EXACT_NEW_REVIEW_REQUIRED')
    helper = control.load_transport()
    fingerprint = helper.verify_cached_host('A')
    phase = control.STAGING/PHASE_NAME
    phase.mkdir(exist_ok=False)
    now,started = datetime.datetime.now(datetime.timezone.utc),time.monotonic()
    first = dict(expected,host_fingerprint=fingerprint,call_index=1,calls_max=1,attempt_consumed=True,automatic_retries=0,
        local_utc_start=now.isoformat(timespec='microseconds'),
        local_utc_deadline=(now+datetime.timedelta(seconds=300)).isoformat(timespec='microseconds'),
        local_monotonic_start=started,local_monotonic_deadline=started+300,
        local_clock_domain=dict(pid=os.getpid(),host=platform.node(),clock=time.get_clock_info('monotonic').implementation),
        old_experiment_clock_changed=False)
    control.write_new(phase/'start.json',control.encode(first))
    try:
        helper.TIMEOUT = min(60,max(1,int(_remaining(first))))
        observed = helper.transport(helper.command('A'),plan['payload'],MAX_RESPONSE)
    except BaseException as exc:
        control.write_new(phase/'transport.json',control.encode(dict(error_type=type(exc).__name__,status='ATTEMPT_CONSUMED_NO_RETRY')))
        raise
    control.write_new(phase/'stdout.json',observed['stdout'])
    control.write_new(phase/'stderr.log',observed['stderr'])
    receipt = {k:v for k,v in observed.items() if k not in ('stdout','stderr')}
    for key in ('stdout','stderr'):
        receipt[key+'_bytes'],receipt[key+'_sha256'] = len(observed[key]),sha(observed[key])
    control.write_new(phase/'transport.json',control.encode(receipt))
    require(observed['exit_code'] == 0 and not any(observed[k] for k in ('timeout','overflow','write_failed','threads_incomplete')),'TRANSPORT_FAILED_NO_RETRY')
    _remaining(first)
    value,bodies = validate_response(observed['stdout'])
    _remaining(first)
    output = phase/'files'
    output.mkdir(exist_ok=False)
    files = []
    for row,body in zip(value['files'],bodies):
        _remaining(first)
        control.write_new(output/row['sha256'],body)
        files.append(dict(path=row['path'],file=row['sha256'],bytes=len(body),sha256=sha(body)))
    _remaining(first)
    control.write_new(phase/'validated.json',control.encode(dict(files=files,all_seven_complete_hashes_verified=True,
        parser_or_analysis_performed=False,coverage_semantics_proven=False,frozen_contract_d95_pass=False,training_release=False)))
    return dict(phase=str(phase),files=files,coverage_semantics_proven=False,training_release=False)
