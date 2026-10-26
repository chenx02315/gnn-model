"""Fresh E124 offline review package and create-once A-only transport controller."""
import ast
import base64
import datetime
import json
import math
from pathlib import Path
import re
import sys

from scripts import acceptance_transport_e98 as transport
from src.data import prospective_identifier_bundle_e124 as bundle

ROOT = Path(__file__).resolve().parents[1]
PHASE = transport.STAGING/'v6_e124_identifier_generation_20261027_r1'
AUTH = 'contracts/prospective_identifier_repair_authorization_e124_20261027.json'
AUTH_SHA256 = 'b9fb213ad18081dd0970ab765cf869e9591621c0dabf5c9184f629e98e4317b0'
E112 = transport.STAGING/'v6_e112_preparation_20261026_r1/stdout.json'
E112_SHA256 = 'fd09999da5355c8b66fb0bbae0e6f495544bbf578df8894b01ac5fc8685864ae'
WALL_SECONDS = 50400
CAP = 1048576
REVIEW_KEYS = ('payload_sha256', 'package_sha256', 'controller_sha256', 'source_sha256',
               'origin_source_sha256', 'input_sha256', 'authorization_sha256', 'bundle_manifest_sha256')


def _json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('DUPLICATE_JSON_KEY')
            value[key] = item
        return value
    return json.loads(raw.decode('ascii'), object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE_JSON')))


def prepare():
    authority = (ROOT/AUTH).read_bytes()
    if transport.sha(authority) != AUTH_SHA256:
        raise ValueError('EXACT_NEW_AUTHORITY_REQUIRED')
    compiled = bundle.build_sources(worker_source_bytes=(ROOT/'scripts/worker_identifier_generation_e124.py').read_bytes())
    rows, manifest = compiled['sources'], compiled['manifest']
    names = [row['name'] for row in rows]
    if (names != manifest['source_order'] or len(names) != len(set(names)) or
            names[-1] != bundle.WORKER_NAME or 'prospective_acquisition_protocol_e105' in names or
            set(names) != bundle.ALLOWLIST | {bundle.CONTEXT_NAME, bundle.WORKER_NAME, 'prospective_tool_identifiers_e123'} or
            manifest['root'] != bundle.ROOT or manifest['authorization_sha256'] != AUTH_SHA256):
        raise ValueError('FIXED_DERIVED_SOURCE_ROSTER')
    for row in rows:
        source = base64.b64decode(row['body'], validate=True)
        if transport.sha(source) != row['sha256']:
            raise ValueError('AFTER_SOURCE_SHA')
        ast.parse(source.decode('utf-8'), feature_version=(3, 6))
    origin_review = _json((ROOT/'data/manifests/ranking_v6_e121_pre_review_20261026_r1.json').read_bytes())['reviewed']
    files = dict(authority=authority, e112=E112.read_bytes(), diagnostic_policy=compiled['policy_bytes'],
        e85=(ROOT/'data/manifests/ranking_v6_e85_input_observation_20261023_r1.json').read_bytes(),
        e88=(ROOT/'data/manifests/ranking_v6_e88_input_observation_20261023_r1.json').read_bytes(),
        e93=(ROOT/'data/manifests/ranking_v6_e93_input_observation_20261023_r1.json').read_bytes(),
        common_tcl=(ROOT/'src/data/templates/e108_common_base.tcl').read_bytes(),
        incremental_tcl=(ROOT/'src/data/templates/e108_incremental_base.tcl').read_bytes())
    for name in ('e85','e88','e93','common_tcl','incremental_tcl'):
        if transport.sha(files[name]) != origin_review['input_sha256'][name]:
            raise ValueError('FROZEN_COHORT_INPUT_CHANGED')
    if transport.sha(files['e112']) != E112_SHA256:
        raise ValueError('COHORT_SNAPSHOT_CHANGED_NOT_NEW_CLOCK')
    source_sha = {row['name']:row['sha256'] for row in rows}
    profile_row = next(row for row in rows if row['name'] == 'prospective_runtime_profile_e112')
    package = dict(inputs={k:base64.b64encode(v).decode('ascii') for k,v in files.items()},
        source_sha256=source_sha, runtime_profile_source=profile_row['body'],
        runtime_profile_source_sha256=profile_row['sha256'], bundle_manifest=manifest,
        review_gates=dict(implementation_review_passed_claim=True, independent_review_passed_claim=True))
    wire = json.dumps(dict(sources=rows, package=package), separators=(',', ':'))
    payload = (
        'import time\nbootstrap_started=time.monotonic()\n'
        'clock={"authorization_sha256":'+repr(AUTH_SHA256)+',"start_monotonic":bootstrap_started,'
        '"deadline_monotonic":bootstrap_started+50400,"boot_id":None,"root":'+repr(bundle.ROOT)+','
        '"new_authorized_package_clock":True,"cohort_snapshot_is_clock":False}\n'
        'try:\n'
        ' import base64,hashlib,json,types,sys,os,platform\n'
        ' with open("/proc/sys/kernel/random/boot_id","rb") as boot_stream: boot=boot_stream.read(129).decode("ascii").strip()\n'
        ' clock["boot_id"]=boot\n'
        ' if not (sys.platform.startswith("linux") and platform.node()=="bupt-vncs2" and os.getuid()==1047): raise ValueError("FIXED_A_HOST")\n'
        ' p=json.loads('+repr(wire)+')\n'
        ' for name in ("src","src.data"):\n'
        '  m=types.ModuleType(name);m.__path__=[];sys.modules[name]=m\n'
        '  if name=="src.data":sys.modules["src"].data=m\n'
        ' for row in p["sources"]:\n'
        '  raw=base64.b64decode(row["body"],validate=True)\n'
        '  if hashlib.sha256(raw).hexdigest()!=row["sha256"]: raise ValueError("AFTER_SOURCE_SHA")\n'
        '  name="src.data."+row["name"];m=types.ModuleType(name);m.__package__="src.data"\n'
        '  sys.modules[name]=m;setattr(sys.modules["src.data"],row["name"],m)\n'
        '  if row["name"]=="prospective_generation_context_e124":\n'
        '   m.__dict__["__runtime_context__"]={"authority_bytes":base64.b64decode(p["package"]["inputs"]["authority"],validate=True),"boot_id":boot,"start_monotonic":bootstrap_started,"current_monotonic":time.monotonic()}\n'
        '  exec(compile(raw,"<e124-"+row["name"]+">","exec"),m.__dict__)\n'
        '  m.__source_sha256__=row["sha256"]\n'
        ' result=sys.modules["src.data.e124_worker"].execute(p["package"])\n'
        'except BaseException as exc:\n'
        ' result={"schema":"prospective-identifier-worker-e124-v1","status":"STOPPED_FIRST_FAILURE","error_type":type(exc).__name__,"error_code":"BOOTSTRAP_OR_SOURCE_LOAD_FAILED","bootstrap":None,"clock":clock,"execution_ready":False,"training_release":False,"runtime_values_disclosed":False}\n'
        'import json\nprint(json.dumps(result,sort_keys=True,allow_nan=False),flush=True)\n').encode('ascii')
    if len(payload) > 4*1048576:
        raise ValueError('PAYLOAD_BOUND')
    ast.parse(payload.decode('ascii'), feature_version=(3, 6))
    return dict(payload=payload, payload_sha256=transport.sha(payload), payload_bytes=len(payload),
        package_sha256=transport.sha(transport.encode(package)), controller_sha256=transport.sha(Path(__file__).read_bytes()),
        source_sha256=source_sha, origin_source_sha256={row['name']:row['origin_sha256'] for row in rows},
        input_sha256={k:transport.sha(v) for k,v in files.items()}, authorization_sha256=AUTH_SHA256,
        bundle_manifest_sha256=manifest['manifest_sha256'])


def validate_response(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= CAP:
        raise ValueError('RESPONSE_BOUND')
    value = _json(raw)
    common = {'schema','status','bootstrap','clock','execution_ready','training_release','runtime_values_disclosed'}
    if (type(value) is not dict or value.get('schema') != 'prospective-identifier-worker-e124-v1' or
            set(value) not in (common | {'summary'}, common | {'error_type','error_code'}) or
            any(value.get(k) is not False for k in ('execution_ready','training_release','runtime_values_disclosed'))):
        raise ValueError('EXACT_METADATA_ONLY_WORKER_RESPONSE')
    clock = value['clock']
    if (type(clock) is not dict or set(clock) != {'authorization_sha256','boot_id','start_monotonic',
            'deadline_monotonic','root','new_authorized_package_clock','cohort_snapshot_is_clock'} or
            clock['authorization_sha256'] != AUTH_SHA256 or clock['root'] != bundle.ROOT or
            clock['new_authorized_package_clock'] is not True or clock['cohort_snapshot_is_clock'] is not False or
            any(type(clock[k]) not in (int,float) or not math.isfinite(clock[k]) or clock[k] < 0
                for k in ('start_monotonic','deadline_monotonic')) or
            clock['deadline_monotonic'] != clock['start_monotonic']+WALL_SECONDS or
            (clock['boot_id'] is not None and (type(clock['boot_id']) is not str or
                re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',clock['boot_id']) is None))):
        raise ValueError('FRESH_NEW_PACKAGE_CLOCK_REQUIRED')
    bootstrap = value['bootstrap']
    fields = {'bytes','sha256','cleaned','returncode','launch_attempted','values_disclosed'}
    if bootstrap is not None and (type(bootstrap) is not dict or set(bootstrap) not in (set(),fields) or
            (bootstrap and (bootstrap['values_disclosed'] is not False or type(bootstrap['bytes']) is not int or
                not 0 <= bootstrap['bytes'] <= 65536 or type(bootstrap['sha256']) is not str or
                re.fullmatch('[0-9a-f]{64}',bootstrap['sha256']) is None))):
        raise ValueError('BOOTSTRAP_METADATA_ONLY')
    if value['status'] not in ('STOPPED_FIRST_FAILURE','FIXED_78_TASKS_COLLECTED'):
        raise ValueError('WORKER_STATUS')
    if value['status'] == 'FIXED_78_TASKS_COLLECTED':
        summary = value.get('summary',{})
        if (clock['boot_id'] is None or summary.get('root') != bundle.ROOT or
                summary.get('original_package_start') != clock['start_monotonic'] or
                summary.get('original_package_deadline') != clock['deadline_monotonic'] or
                summary.get('counts') != dict(tessent_debited=48,translation_debited=30,
                    selftest_cases_reserved=3,selftest_cases_accepted=3,committed_tasks=78)):
            raise ValueError('EXACT_FRESH_COMPLETION_REQUIRED')
    return value


def execute(review_path, reviewed_sha):
    plan = prepare()
    expected = {key:plan[key] for key in REVIEW_KEYS}
    review = _json(Path(review_path).read_bytes())
    if review.get('status') != 'PASS' or review.get('reviewed') != expected or reviewed_sha != plan['payload_sha256']:
        raise ValueError('FRESH_INDEPENDENT_EXACT_REVIEW_REQUIRED')
    helper = transport.load_transport()
    fingerprint = helper.verify_cached_host('A')
    PHASE.mkdir(exist_ok=False)
    local_start = datetime.datetime.now(datetime.timezone.utc)
    local_deadline = local_start+datetime.timedelta(seconds=WALL_SECONDS)
    helper.TIMEOUT = WALL_SECONDS  # One call, measured locally no later than remote clock starts.
    transport.write_new(PHASE/'start.json', transport.encode(dict(expected, host_fingerprint=fingerprint,
        local_utc_start=local_start.isoformat(), local_utc_deadline=local_deadline.isoformat(),
        first_new_package_call_consumed=True, clock_must_not_be_reset=True, sessions_max=1, automatic_retries=0,
        wall_seconds_max=WALL_SECONDS, cohort_snapshot_is_clock=False, remote_clock_unknown_until_response=True)))
    try:
        remaining = (local_deadline-datetime.datetime.now(datetime.timezone.utc)).total_seconds()
        if remaining <= 10:
            raise ValueError('LOCAL_FIRST_CALL_DEADLINE_NO_RENEWAL')
        helper.TIMEOUT = int(remaining)
        observed = helper.transport(helper.command('A'), plan['payload'], CAP)
    except BaseException as exc:
        transport.write_new(PHASE/'transport.json',transport.encode(dict(error_type=type(exc).__name__,
            status='TRANSPORT_RAISED_ATTEMPT_CONSUMED_NO_RETRY')))
        raise
    transport.write_new(PHASE/'stdout.json',observed['stdout'])
    transport.write_new(PHASE/'stderr.log',observed['stderr'])
    receipt = {k:v for k,v in observed.items() if k not in ('stdout','stderr')}
    for name in ('stdout','stderr'):
        receipt[name+'_bytes'],receipt[name+'_sha256'] = len(observed[name]),transport.sha(observed[name])
    transport.write_new(PHASE/'transport.json',transport.encode(receipt))
    if observed['exit_code'] != 0 or any(observed[k] for k in ('timeout','overflow','write_failed','threads_incomplete')):
        raise ValueError('TRANSPORT_FAILED_OR_UNKNOWN_NO_RETRY')
    result = validate_response(observed['stdout'])
    transport.write_new(PHASE/'package_clock.json',transport.encode(result['clock']))
    if result['status'] != 'FIXED_78_TASKS_COLLECTED':
        raise ValueError('WORKER_STOPPED_FIRST_FAILURE_NO_RETRY')
    return dict(phase=str(PHASE),status=result['status'],execution_ready=False,training_release=False)


def main():
    args = sys.argv[1:]
    if args == ['prepare']:
        print(json.dumps({k:v for k,v in prepare().items() if k != 'payload'},sort_keys=True))
    elif len(args) == 3 and args[0] == 'execute':
        print(json.dumps(execute(args[1],args[2]),sort_keys=True))
    else:
        raise ValueError('USE_PREPARE_OR_EXECUTE_REVIEW_PATH_PAYLOAD_SHA')


if __name__ == '__main__':
    main()
