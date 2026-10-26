"""Offline exact deployment package and one independently reviewed A session."""
import ast
import base64
import datetime
import importlib
import json
from pathlib import Path
import sys

from scripts import acceptance_transport_e98 as transport
from scripts.run_direct_tessent_e104 import PINS
from scripts import run_generation_warnings_e119 as proof

ROOT = Path(__file__).resolve().parents[1]
PHASE = transport.STAGING/'v6_e121_generation_20261026_r1'
LOCAL_END = datetime.datetime(2026, 10, 26, 19, 29, 37, 523027, tzinfo=datetime.timezone.utc)
CAP = 1048576
POLICY = 'contracts/prospective_generation_diagnostics_e120_v1.json'
PURE = (
    'prospective_input_binding_v1', 'prospective_request_features_v1', 'prospective_acquisition_pilot_v1',
    'prospective_acquisition_request_v1', 'prospective_stage_observation_v1', 'prospective_tessent_stage_v1',
    'prospective_acquisition_binding_v1', 'prospective_generation_recipe_e108', 'prospective_runtime_profile_e112',
    'prospective_generation_supervision_e109', 'prospective_generation_materializer_e111',
    'prospective_generation_process_e113', 'prospective_runtime_adapter_e114', 'prospective_report_dialect_e115',
    'prospective_generation_controller_e116', 'prospective_generation_diagnostics_e120',
    'prospective_generation_artifacts_e117', 'prospective_generation_storage_e118')
REVIEW_KEYS = ('payload_sha256', 'package_sha256', 'controller_sha256', 'source_sha256', 'input_sha256',
               'authorization_sha256', 'original_clock_sha256')


def remaining_seconds():
    remaining = (LOCAL_END-datetime.datetime.now(datetime.timezone.utc)).total_seconds()
    if remaining <= 10:
        raise ValueError('ORIGINAL_LOCAL_DEADLINE_EXPIRED_OR_CLEANUP_RESERVE')
    return remaining


def prepare():
    authority = (ROOT/proof.AUTH).read_bytes()
    if transport.sha(authority) != proof.AUTH_SHA:
        raise ValueError('ACTUAL_AUTHORIZATION_CHANGED')
    clock_sha = proof._prior_proof()
    if not (ROOT/'src/data/prospective_generation_diagnostics_e120.py').is_file() or not (ROOT/POLICY).is_file():
        raise ValueError('REVIEWED_E120_POLICY_AND_MODULE_REQUIRED')
    policy = (ROOT/POLICY).read_bytes()
    # Validation is pure and fail-closed; no policy is inferred from source hashes.
    diagnostics = importlib.import_module('src.data.prospective_generation_diagnostics_e120')
    diagnostics.build_gate(policy)
    from src.data import prospective_tessent_acceptance_v1 as pins
    from src.data import prospective_generation_recipe_e108 as recipe
    rows = []
    roster = list(PINS)+[(name, None) for name in PURE]+[('e121_worker', None)]
    for name, pin in roster:
        path = ROOT/('scripts/worker_prospective_generation_e121.py' if name == 'e121_worker' else 'src/data/'+name+'.py')
        raw = path.read_bytes()
        digest = transport.sha(raw)
        if pin is not None and digest != pin:
            raise ValueError('PINNED_LEGACY_SOURCE_CHANGED')
        ast.parse(raw.decode('utf-8'), feature_version=(3, 6))
        rows.append(dict(name=name, sha256=digest, body=base64.b64encode(raw).decode('ascii')))
    files = dict(authority=authority, e112=(proof.PRIOR/'stdout.json').read_bytes(),
        e85=(ROOT/'data/manifests/ranking_v6_e85_input_observation_20261023_r1.json').read_bytes(),
        e88=(ROOT/'data/manifests/ranking_v6_e88_input_observation_20261023_r1.json').read_bytes(),
        e93=(ROOT/'data/manifests/ranking_v6_e93_input_observation_20261023_r1.json').read_bytes(),
        common_tcl=(ROOT/'src/data/templates/e108_common_base.tcl').read_bytes(),
        incremental_tcl=(ROOT/'src/data/templates/e108_incremental_base.tcl').read_bytes(), diagnostic_policy=policy)
    for name, pin in (('e85', pins.E85_SHA256),
                      ('e88', 'f46ed9fea9f5fecaea146ae75807db06fbd75887fc21a995a8da44ebe65b09c8')):
        if transport.sha(files[name]) != pin:
            raise ValueError('FROZEN_INPUT_CHANGED')
    if transport.sha(files['e93']) != pins.E93_SHA256 or transport.sha(files['e112']) != proof.PRIOR_SHA:
        raise ValueError('FROZEN_INPUT_CHANGED')
    recipe.freeze_sources(files['common_tcl'], files['incremental_tcl'])
    source_sha = {r['name']:r['sha256'] for r in rows}
    profile_row = next(r for r in rows if r['name'] == 'prospective_runtime_profile_e112')
    package = dict(inputs={k:base64.b64encode(v).decode('ascii') for k, v in files.items()},
        source_sha256=source_sha, runtime_profile_source=profile_row['body'],
        runtime_profile_source_sha256=profile_row['sha256'],
        review_gates=dict(implementation_review_passed_claim=True, independent_review_passed_claim=True))
    package_raw = transport.encode(package)
    wire = json.dumps(dict(sources=rows, package=package), separators=(',', ':'))
    payload = ('import base64,hashlib,json,types,sys\n'
        'p=json.loads('+repr(wire)+')\n'
        'for name in ("src","src.data"):\n'
        ' m=types.ModuleType(name);m.__path__=[];sys.modules[name]=m\n'
        ' if name=="src.data":sys.modules["src"].data=m\n'
        'for row in p["sources"]:\n'
        ' raw=base64.b64decode(row["body"],validate=True)\n'
        ' assert hashlib.sha256(raw).hexdigest()==row["sha256"]\n'
        ' name="src.data."+row["name"];m=types.ModuleType(name);m.__package__="src.data"\n'
        ' sys.modules[name]=m;setattr(sys.modules["src.data"],row["name"],m)\n'
        ' exec(compile(raw,"<frozen-"+row["name"]+">","exec"),m.__dict__)\n'
        ' m.__source_sha256__=row["sha256"]\n'
        'result=sys.modules["src.data.e121_worker"].execute(p["package"])\n'
        'print(json.dumps(result,sort_keys=True,allow_nan=False),flush=True)\n').encode('ascii')
    if len(payload) > 4*1048576:
        raise ValueError('PAYLOAD_BOUND')
    ast.parse(payload.decode('ascii'), feature_version=(3, 6))
    return dict(payload=payload, payload_sha256=transport.sha(payload), payload_bytes=len(payload),
        package_sha256=transport.sha(package_raw), controller_sha256=transport.sha(Path(__file__).read_bytes()),
        source_sha256=source_sha, input_sha256={k:transport.sha(v) for k, v in files.items()},
        authorization_sha256=proof.AUTH_SHA, original_clock_sha256=clock_sha)


def validate_response(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= CAP:
        raise ValueError('WORKER_RESPONSE_BOUND')
    value = proof._json(raw)
    if (type(value) is not dict or value.get('schema') != 'prospective-generation-worker-e121-v1' or
            value.get('execution_ready') is not False or value.get('training_release') is not False or
            value.get('runtime_values_disclosed') is not False):
        raise ValueError('WORKER_RESPONSE_SCHEMA_OR_RELEASE')
    common_keys = {'schema', 'status', 'bootstrap', 'execution_ready', 'training_release', 'runtime_values_disclosed'}
    if set(value) not in (common_keys | {'summary'}, common_keys | {'error_type', 'error_code'}):
        raise ValueError('WORKER_RESPONSE_EXACT_FIELDS')
    bootstrap = value['bootstrap']
    if bootstrap is not None and (type(bootstrap) is not dict or
            set(bootstrap) not in (set(), {'bytes', 'sha256', 'cleaned', 'returncode', 'launch_attempted', 'values_disclosed'}) or
            (bootstrap and (bootstrap.get('values_disclosed') is not False or
                type(bootstrap.get('bytes')) is not int or not 0 <= bootstrap['bytes'] <= 65536))):
        raise ValueError('BOOTSTRAP_METADATA_ONLY')
    if value.get('status') not in ('STOPPED_FIRST_FAILURE', 'FIXED_78_TASKS_COLLECTED'):
        raise ValueError('WORKER_STATUS')
    if value['status'] == 'FIXED_78_TASKS_COLLECTED':
        summary = value.get('summary', {})
        if summary.get('counts') != dict(tessent_debited=48, translation_debited=30, selftest_cases_reserved=3,
                                        selftest_cases_accepted=3, committed_tasks=78):
            raise ValueError('EXACT_COMPLETION_REQUIRED')
    return value


def execute(review_path, reviewed_sha):
    remaining_seconds()
    plan = prepare()
    review = proof._json(Path(review_path).read_bytes())
    expected = {k:plan[k] for k in REVIEW_KEYS}
    if review.get('status') != 'PASS' or review.get('reviewed') != expected or reviewed_sha != plan['payload_sha256']:
        raise ValueError('INDEPENDENT_EXACT_REVIEW_REQUIRED')
    remaining_seconds()
    helper = transport.load_transport()
    fingerprint = helper.verify_cached_host('A')
    PHASE.mkdir(exist_ok=False)
    remaining = remaining_seconds()
    helper.TIMEOUT = max(1, int(remaining))  # No new 14-hour window; cleanup is inside original deadline.
    transport.write_new(PHASE/'start.json', transport.encode(dict(expected, host_fingerprint=fingerprint,
        local_utc_start=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        original_local_deadline=LOCAL_END.isoformat(), timeout_seconds=helper.TIMEOUT,
        sessions_max=1, automatic_retries=0, generation_attempt_consumed=True)))
    try:
        observed = helper.transport(helper.command('A'), plan['payload'], CAP)
    except BaseException as exc:
        transport.write_new(PHASE/'transport.json', transport.encode(dict(error_type=type(exc).__name__,
            status='TRANSPORT_RAISED_ATTEMPT_CONSUMED_NO_RETRY')))
        raise
    transport.write_new(PHASE/'stdout.json', observed['stdout'])
    transport.write_new(PHASE/'stderr.log', observed['stderr'])
    receipt = {k:v for k, v in observed.items() if k not in ('stdout', 'stderr')}
    for k in ('stdout', 'stderr'):
        receipt[k+'_sha256'], receipt[k+'_bytes'] = transport.sha(observed[k]), len(observed[k])
    transport.write_new(PHASE/'transport.json', transport.encode(receipt))
    if observed['exit_code'] != 0 or any(observed[k] for k in ('timeout', 'overflow', 'write_failed', 'threads_incomplete')):
        raise ValueError('TRANSPORT_FAILED_OR_UNKNOWN_NO_RETRY')
    result = validate_response(observed['stdout'])
    if result['status'] != 'FIXED_78_TASKS_COLLECTED':
        raise ValueError('WORKER_STOPPED_FIRST_FAILURE_NO_RETRY')
    return dict(phase=str(PHASE), status=result['status'], execution_ready=False, training_release=False)


def main():
    args = sys.argv[1:]
    if args == ['prepare']:
        print(json.dumps({k:v for k, v in prepare().items() if k != 'payload'}, sort_keys=True))
    elif len(args) == 3 and args[0] == 'execute':
        print(json.dumps(execute(args[1], args[2]), sort_keys=True))
    else:
        raise ValueError('USE_PREPARE_OR_EXECUTE_REVIEW_PATH_PAYLOAD_SHA')


if __name__ == '__main__':
    main()
