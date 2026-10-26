"""One create-once, reviewed, A-only preparation call. No ATPG entry point."""
import base64
import datetime
import json
import math
from pathlib import Path
import re
import sys

from scripts import acceptance_transport_e98 as control
from scripts.run_direct_tessent_e104 import PINS

ROOT = Path(__file__).resolve().parents[1]
AUTH = 'contracts/prospective_acquisition_authorization_e111_20261026.json'
AUTH_SHA = 'c11a7a29418680a3506f8bc9b7e6f5fcd564887a6c58b436f2e3ec83601b1ba9'
INPUTS = (
    ('e85', 'data/manifests/ranking_v6_e85_input_observation_20261023_r1.json',
     '702968b299d36f7d85bdfa3f2b6c9a23fb99cd8f5094ed0ed37fa6e002794e74'),
    ('e88', 'data/manifests/ranking_v6_e88_input_observation_20261023_r1.json',
     'f46ed9fea9f5fecaea146ae75807db06fbd75887fc21a995a8da44ebe65b09c8'),
)
PHASE = control.STAGING / 'v6_e112_preparation_20261026_r1'
CAP = 1048576


def prepare():
    if control.sha((ROOT / AUTH).read_bytes()) != AUTH_SHA:
        raise ValueError('ACTUAL_AUTHORIZATION_CHANGED')
    package = dict(sources=[], inputs={})
    sources = [(name, ROOT / 'src/data' / (name + '.py'), pin) for name, pin in PINS]
    sources += [
        ('prospective_runtime_profile_e112', ROOT / 'src/data/prospective_runtime_profile_e112.py', None),
        ('e112_probe', ROOT / 'scripts/probe_preparation_e112.py', None),
    ]
    for name, path, pin in sources:
        raw = path.read_bytes()
        digest = control.sha(raw)
        if pin is not None and digest != pin:
            raise ValueError('LEGACY_SOURCE_CHANGED')
        package['sources'].append(dict(name=name, sha256=digest,
                                      body=base64.b64encode(raw).decode('ascii')))
    for name, path, pin in INPUTS:
        raw = (ROOT / path).read_bytes()
        if control.sha(raw) != pin:
            raise ValueError('FROZEN_INPUT_CHANGED')
        package['inputs'][name] = base64.b64encode(raw).decode('ascii')
    payload = (
        'import time\n'
        'bootstrap_started=time.monotonic()\n'
        'import base64,hashlib,json,types,sys\n'
        'p=json.loads(' + repr(json.dumps(package, separators=(',', ':'))) + ')\n'
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
        'profile=next(row for row in p["sources"] if row["name"]=="prospective_runtime_profile_e112")\n'
        'result=sys.modules["src.data.e112_probe"].collect('
        'base64.b64decode(p["inputs"]["e85"]),base64.b64decode(p["inputs"]["e88"]),'
        'base64.b64decode(profile["body"]))\n'
        'result["collector_start_monotonic"]=result["remote_start_monotonic"]\n'
        'result["remote_start_monotonic"]=bootstrap_started\n'
        'print(json.dumps(result,sort_keys=True,allow_nan=False),flush=True)\n'
    ).encode('ascii')
    if len(payload) > CAP:
        raise ValueError('PAYLOAD_BOUND')
    compile(payload, '<E112-offline>', 'exec')
    return dict(payload=payload, payload_sha256=control.sha(payload), payload_bytes=len(payload),
                authorization_sha256=AUTH_SHA, controller_sha256=control.sha(Path(__file__).read_bytes()),
                source_sha256={row['name']: row['sha256'] for row in package['sources']})


def validate_response(raw):
    if len(raw) > CAP:
        raise ValueError('RESPONSE_BOUND')
    result = json.loads(raw.decode('ascii'), parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE')))
    if not isinstance(result, dict) or result.get('schema') != 'e112-readonly-preparation-v1':
        raise ValueError('RESPONSE_SCHEMA')
    if result.get('hostname') != 'bupt-vncs2' or type(result.get('uid')) is not int or result['uid'] != 1047:
        raise ValueError('HOST_IDENTITY')
    for key in ('execution_ready', 'training_release'):
        if result.get(key) is not False:
            raise ValueError('NO_RELEASE')
    for key in ('explicit_filesystem_writes', 'atpg_launches', 'training_runs'):
        if type(result.get(key)) is not int or result[key] != 0:
            raise ValueError('NO_WRITE_OR_EXPERIMENT')
    start, end = result.get('remote_start_monotonic'), result.get('remote_end_monotonic')
    if any(type(value) not in (int, float) or not math.isfinite(value) or value < 0 for value in (start, end)) or end < start:
        raise ValueError('REMOTE_CLOCK')
    if not isinstance(result.get('boot_id'), str) or re.fullmatch('[0-9a-f-]{36}', result['boot_id']) is None:
        raise ValueError('BOOT_ID')
    if type(result.get('capture_complete')) is not bool:
        raise ValueError('CAPTURE_STATUS')
    base = '/temp/jiangchuanc/multimode_ate_phase4_20260825_A/10_circuits/'
    allowed = {base + circ + '/04_single_mode/H_' + circ + '_H_full_phase4_v2/' + name
               for circ in ('aes_core', 'spi') for name in ('statistics.rpt', 'patterns.rpt', 'tester.stil')}
    reports = result.get('reports')
    if not isinstance(reports, list) or len(reports) > 6:
        raise ValueError('REPORT_COUNT')
    paths = [row.get('path') for row in reports if isinstance(row, dict)]
    if len(paths) != len(reports) or len(set(paths)) != len(paths) or not set(paths) <= allowed:
        raise ValueError('REPORT_SCOPE')
    if result['capture_complete'] and set(paths) != allowed:
        raise ValueError('INCOMPLETE_REPORTS')
    from scripts import probe_preparation_e112 as probe
    profile = result.get('runtime_profile')
    if profile is not None:
        if profile.get('schema') == 'e112-runtime-profile-v1':
            probe._validate_profile_metadata(profile)
        elif profile != dict(schema='e112-runtime-profile-unqualified-v1', qualified=False,
                             reason='UNKNOWN_METADATA_FORMAT', values_disclosed=False):
            raise ValueError('PROFILE_METADATA_ONLY')
    elif result['capture_complete']:
        raise ValueError('MISSING_PROFILE')
    e85 = json.loads((ROOT / INPUTS[0][1]).read_bytes())
    e88 = json.loads((ROOT / INPUTS[1][1]).read_bytes())
    expected = {row['root']: (row['body_bytes'], row['tree_sha256']) for row in e85['tsdb_trees']}
    expected[probe.pins.LIBRARY] = (e85['library']['bytes'], probe.pins.LIBRARY_SHA256)
    for row in e88['roots']:
        common = base + row['circuit'] + '/03_fault_universe/common_' + row['circuit'] + '_m16_phase4_v2/'
        for name, pin in row['files'].items():
            expected[common + name] = (pin['bytes'], pin['sha256'])
    frozen = result.get('frozen_inputs')
    if not isinstance(frozen, list):
        raise ValueError('FROZEN_RECEIPTS')
    seen = set()
    for row in frozen:
        path = row.get('path') if isinstance(row, dict) else None
        if path not in expected or path in seen or (row.get('bytes'), row.get('sha256')) != expected[path]:
            raise ValueError('FROZEN_RECEIPT_SCOPE_OR_PIN')
        seen.add(path)
    launcher = result.get('launcher')
    if launcher is not None and (launcher.get('path') != probe.pins.LAUNCHER or
            launcher.get('bytes') != e85['binary']['bytes'] or launcher.get('sha256') != probe.pins.LAUNCHER_SHA256):
        raise ValueError('LAUNCHER_RECEIPT')
    if result['capture_complete'] and (seen != set(expected) or launcher is None or result.get('error') is not None):
        raise ValueError('INCOMPLETE_FROZEN_RECEIPTS')
    return result


def execute(review_path, reviewed_sha):
    plan = prepare()
    review = json.loads(Path(review_path).read_text(encoding='utf-8'))
    expected = {key: plan[key] for key in ('payload_sha256', 'controller_sha256', 'authorization_sha256', 'source_sha256')}
    if reviewed_sha != plan['payload_sha256'] or review.get('status') != 'PASS' or review.get('reviewed') != expected:
        raise ValueError('INDEPENDENT_EXACT_REVIEW_REQUIRED')
    helper = control.load_transport()
    fingerprint = helper.verify_cached_host('A')
    PHASE.mkdir(exist_ok=False)
    local_start = datetime.datetime.now(datetime.timezone.utc)
    control.write_new(PHASE / 'start.json', control.encode(dict(
        expected, local_utc_start=local_start.isoformat(),
        host_fingerprint=fingerprint, remote_preparation_attempt_consumed=True,
        sessions_max=1, automatic_retries=0, response_cap=CAP,
        package_clock_starts_this_call=True, package_wall_seconds_max=50400)))
    control.write_new(PHASE / 'package_clock_intent.json', control.encode(dict(
        first_preparation_attempt_consumed=True, clock_must_not_be_reset=True,
        local_utc_start=local_start.isoformat(),
        local_utc_deadline=(local_start + datetime.timedelta(seconds=50400)).isoformat(),
        remote_clock_unknown_until_validated_response=True,
        missing_remote_clock_blocks_further_remote_execution=True,
        transport_or_validation_failure_does_not_restore_budget=True)))
    transport = helper.transport(helper.command('A'), plan['payload'], CAP)
    control.write_new(PHASE / 'stdout.json', transport['stdout'])
    control.write_new(PHASE / 'stderr.log', transport['stderr'])
    receipt = {key: value for key, value in transport.items() if key not in ('stdout', 'stderr')}
    for name in ('stdout', 'stderr'):
        receipt[name + '_sha256'] = control.sha(transport[name])
        receipt[name + '_bytes'] = len(transport[name])
    control.write_new(PHASE / 'transport.json', control.encode(receipt))
    if transport['exit_code'] != 0 or any(transport[key] for key in ('timeout', 'overflow', 'write_failed', 'threads_incomplete')):
        raise ValueError('TRANSPORT_FAILED_OR_UNKNOWN_NO_RETRY')
    response = validate_response(transport['stdout'])
    clock = dict(boot_id=response['boot_id'], remote_start_monotonic=response['remote_start_monotonic'],
                 remote_deadline_monotonic=response['remote_start_monotonic'] + 50400,
                 clock_must_not_be_reset=True, preparation_response_sha256=receipt['stdout_sha256'])
    control.write_new(PHASE / 'package_clock.json', control.encode(clock))
    print(json.dumps(dict(capture_complete=response['capture_complete'], error=response.get('error'),
                          report_count=len(response['reports']), phase=str(PHASE),
                          execution_ready=False, **receipt), sort_keys=True))
    if not response['capture_complete']:
        raise ValueError('READONLY_PREPARATION_FIRST_FAILURE_NO_RETRY')


def main():
    args = sys.argv[1:]
    if args == ['prepare']:
        print(json.dumps({key: value for key, value in prepare().items() if key != 'payload'}, sort_keys=True))
    elif len(args) == 3 and args[0] == 'execute':
        execute(args[1], args[2])
    else:
        raise ValueError('USE_PREPARE_OR_EXECUTE_REVIEW_PATH_PAYLOAD_SHA')


if __name__ == '__main__':
    main()
