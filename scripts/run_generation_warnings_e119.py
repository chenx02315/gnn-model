"""Offline exact review then one A-only read session, on the original E112 clock."""
import ast
import base64
import datetime
import json
import math
from pathlib import Path
import sys

from scripts import acceptance_transport_e98 as control
from scripts.run_direct_tessent_e104 import PINS
from scripts import probe_generation_warnings_e119 as probe

ROOT = Path(__file__).resolve().parents[1]
AUTH = 'contracts/prospective_acquisition_authorization_e111_20261026.json'
AUTH_SHA = 'c11a7a29418680a3506f8bc9b7e6f5fcd564887a6c58b436f2e3ec83601b1ba9'
PRIOR = control.STAGING / 'v6_e112_preparation_20261026_r1'
PRIOR_SHA = 'fd09999da5355c8b66fb0bbae0e6f495544bbf578df8894b01ac5fc8685864ae'
PHASE = control.STAGING / 'v6_e119_warning_metadata_20261026_r1'
CAP = probe.MAX_RESPONSE
REVIEW_KEYS = ('payload_sha256', 'controller_sha256', 'authorization_sha256',
               'source_sha256', 'prior_response_sha256', 'original_clock_sha256')


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('DUPLICATE_JSON_KEY')
        value[key] = item
    return value


def _json(raw):
    return json.loads(raw.decode('ascii'), object_pairs_hook=_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE_JSON')))


def _prior_proof():
    raw = (PRIOR / 'stdout.json').read_bytes()
    if control.sha(raw) != PRIOR_SHA:
        raise ValueError('ORIGINAL_PREPARATION_RESPONSE_CHANGED')
    prior = _json(raw)
    base = '/temp/jiangchuanc/multimode_ate_phase4_20260825_A/10_circuits/'
    expected = {base+c+'/04_single_mode/H_'+c+'_H_full_phase4_v2/'+name
                for c in ('aes_core', 'spi') for name in ('statistics.rpt', 'patterns.rpt', 'tester.stil')}
    if (prior.get('capture_complete') is not True or len(prior.get('reports', [])) != 6 or
            {r['path'] for r in prior['reports']} != expected):
        raise ValueError('EXACT_SIX_PRIOR_REPORTS_REQUIRED')
    clock_raw = (PRIOR / 'package_clock.json').read_bytes()
    clock = _json(clock_raw)
    if clock != dict(boot_id=probe.BOOT, clock_must_not_be_reset=True, preparation_response_sha256=PRIOR_SHA,
                     remote_deadline_monotonic=probe.END, remote_start_monotonic=2332488.679409259):
        raise ValueError('ORIGINAL_CLOCK_CHANGED')
    return control.sha(clock_raw)


def prepare():
    if control.sha((ROOT / AUTH).read_bytes()) != AUTH_SHA:
        raise ValueError('ACTUAL_AUTHORIZATION_CHANGED')
    clock_sha = _prior_proof()
    sources = []
    for name, pin in list(PINS) + [('e119_probe', None)]:
        path = ROOT / ('scripts/probe_generation_warnings_e119.py' if pin is None else 'src/data/'+name+'.py')
        raw = path.read_bytes()
        digest = control.sha(raw)
        if pin is not None and digest != pin:
            raise ValueError('LEGACY_SOURCE_CHANGED')
        sources.append(dict(name=name, sha256=digest, body=base64.b64encode(raw).decode('ascii')))
    package = json.dumps(dict(sources=sources), separators=(',', ':'))
    payload = (
        'import time\nbootstrap_started=time.monotonic()\n'
        'import base64,hashlib,json,types,sys\n'
        'p=json.loads('+repr(package)+')\n'
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
        'result=sys.modules["src.data.e119_probe"].collect(bootstrap_started)\n'
        'print(json.dumps(result,sort_keys=True,allow_nan=False),flush=True)\n').encode('ascii')
    if len(payload) > 1048576:
        raise ValueError('PAYLOAD_BOUND')
    ast.parse(payload.decode('ascii'), feature_version=(3, 6))
    return dict(payload=payload, payload_sha256=control.sha(payload), payload_bytes=len(payload),
                controller_sha256=control.sha(Path(__file__).read_bytes()), authorization_sha256=AUTH_SHA,
                source_sha256={r['name']: r['sha256'] for r in sources}, prior_response_sha256=PRIOR_SHA,
                original_clock_sha256=clock_sha)


def validate_response(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= CAP:
        raise ValueError('RESPONSE_BOUND')
    value = _json(raw)
    if type(value) is not dict or value.get('schema') != probe.SCHEMA:
        raise ValueError('RESPONSE_SCHEMA')
    if (value.get('hostname') != 'bupt-vncs2' or type(value.get('uid')) is not int or value['uid'] != 1047 or
            value.get('boot_id') != probe.BOOT or value.get('original_deadline_monotonic') != probe.END or
            value.get('clock_must_not_be_reset') is not True):
        raise ValueError('ORIGINAL_HOST_BOOT_CLOCK_REQUIRED')
    for key in ('execution_ready', 'training_release', 'warnings_qualified', 'sampling_is_hard_memory_guarantee'):
        if value.get(key) is not False:
            raise ValueError('NO_RELEASE_OR_WARNING_QUALIFICATION')
    for key in ('explicit_filesystem_writes', 'child_launches', 'environment_reads', 'atpg_launches', 'training_runs'):
        if type(value.get(key)) is not int or value[key] != 0:
            raise ValueError('NO_WRITE_LAUNCH_OR_ENVIRONMENT_READ')
    start, end = value.get('remote_start_monotonic'), value.get('remote_end_monotonic')
    if (any(type(t) not in (int, float) or not math.isfinite(t) for t in (start, end)) or
            not 2332488.679409259 <= start <= end or end >= probe.END or end-start >= 30):
        raise ValueError('ORIGINAL_OR_COLLECTOR_DEADLINE')
    if type(value.get('capture_complete')) is not bool:
        raise ValueError('CAPTURE_STATUS')
    rows = value.get('reports')
    if type(rows) is not list or len(rows) > 2:
        raise ValueError('REPORT_COUNT')
    paths, total = [], 0
    for row in rows:
        if type(row) is not dict or set(row) != {'path', 'bytes', 'sha256', 'body_base64', 'whole_file_hashed'}:
            raise ValueError('REPORT_FIELDS')
        if row['path'] not in probe.PATHS or row['path'] in paths:
            raise ValueError('FIXED_REPORT_SCOPE')
        paths.append(row['path'])
        if type(row['bytes']) is not int or not 0 < row['bytes'] <= probe.MAX_FILE or row['whole_file_hashed'] is not True:
            raise ValueError('FULL_REPORT_BOUND')
        body = base64.b64decode(row['body_base64'], validate=True)
        if len(body) != row['bytes'] or control.sha(body) != row['sha256']:
            raise ValueError('FULL_REPORT_BYTES_SHA')
        total += len(body)
    if paths != list(probe.PATHS)[:len(paths)]:
        raise ValueError('ORDERED_FIRST_FAILURE_PREFIX')
    hashed, peak = value.get('body_bytes_hashed'), value.get('sampled_peak_rss_swap_bytes')
    if (type(hashed) is not int or not total <= hashed <= 2*probe.MAX_FILE or
            type(peak) is not int or not 0 <= peak <= 536870912):
        raise ValueError('RESOURCE_RECEIPTS')
    if value['capture_complete'] and (paths != list(probe.PATHS) or value.get('error') is not None or hashed != total):
        raise ValueError('INCOMPLETE_CAPTURE')
    if not value['capture_complete'] and type(value.get('error')) is not dict:
        raise ValueError('FIRST_FAILURE_REQUIRED')
    return value


def execute(review_path, reviewed_sha):
    plan = prepare()
    review = _json(Path(review_path).read_bytes())
    expected = {key: plan[key] for key in REVIEW_KEYS}
    if reviewed_sha != plan['payload_sha256'] or review.get('status') != 'PASS' or review.get('reviewed') != expected:
        raise ValueError('INDEPENDENT_EXACT_REVIEW_REQUIRED')
    helper = control.load_transport()
    fingerprint = helper.verify_cached_host('A')
    PHASE.mkdir(exist_ok=False)
    control.write_new(PHASE/'start.json', control.encode(dict(expected, host_fingerprint=fingerprint,
        local_utc_start=datetime.datetime.now(datetime.timezone.utc).isoformat(), sessions_max=1,
        automatic_retries=0, additional_historical_reports_max=2, prior_historical_reports=6,
        original_deadline_monotonic=probe.END, original_boot_id=probe.BOOT,
        clock_must_not_be_reset=True, response_cap=CAP, attempt_consumed_before_transport=True)))
    try:
        transport = helper.transport(helper.command('A'), plan['payload'], CAP)
    except Exception as exc:
        control.write_new(PHASE/'transport.json', control.encode(dict(
            failure='TRANSPORT_RAISED_NO_RETRY', type=type(exc).__name__, attempt_consumed=True)))
        raise
    control.write_new(PHASE/'stdout.json', transport['stdout'])
    control.write_new(PHASE/'stderr.log', transport['stderr'])
    receipt = {k: v for k, v in transport.items() if k not in ('stdout', 'stderr')}
    for key in ('stdout', 'stderr'):
        receipt[key+'_sha256'] = control.sha(transport[key])
        receipt[key+'_bytes'] = len(transport[key])
    control.write_new(PHASE/'transport.json', control.encode(receipt))
    if transport['exit_code'] != 0 or any(transport[k] for k in ('timeout', 'overflow', 'write_failed', 'threads_incomplete')):
        raise ValueError('TRANSPORT_FAILED_OR_UNKNOWN_NO_RETRY')
    result = validate_response(transport['stdout'])
    control.write_new(PHASE/'validated.json', control.encode(dict(capture_complete=result['capture_complete'],
        report_count=len(result['reports']), warnings_qualified=False, execution_ready=False, training_release=False)))
    if not result['capture_complete']:
        raise ValueError('READONLY_CAPTURE_FIRST_FAILURE_NO_RETRY')
    return dict(phase=str(PHASE), report_count=2, warnings_qualified=False, execution_ready=False, training_release=False)


def main():
    args = sys.argv[1:]
    if args == ['prepare']:
        print(json.dumps({k: v for k, v in prepare().items() if k != 'payload'}, sort_keys=True))
    elif len(args) == 3 and args[0] == 'execute':
        print(json.dumps(execute(args[1], args[2]), sort_keys=True))
    else:
        raise ValueError('USE_PREPARE_OR_EXECUTE_REVIEW_PATH_PAYLOAD_SHA')


if __name__ == '__main__':
    main()
