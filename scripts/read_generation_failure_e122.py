"""Fixed owned-output readback only; offline review precedes one A read call.

No tool launch, retry, source mutation, environment capture or historical-report
access. Local transport imports are delayed; the frozen remote reader uses only
stdlib and the already pinned anchored-IO/E104 sampling bundle.
"""
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

ROOT = '/temp/jiangchuanc/multimode_ate_prospective_e108_20261025_r1'
SIDECAR = ROOT + '.initial_intent.json'
BOOT = '3ebeb9bb-410c-476c-a000-5c625f590473'
START = 2332488.679409259
END = 2382888.679409259
AUTH_SHA = 'c11a7a29418680a3506f8bc9b7e6f5fcd564887a6c58b436f2e3ec83601b1ba9'
E112_SHA = 'fd09999da5355c8b66fb0bbae0e6f495544bbf578df8894b01ac5fc8685864ae'
PRIOR_SHA = '05ec97c35b0c7558267f45cccaca2b0e68664c5fe5b974f1ba284c61d25122cd'
SCHEMA = 'generation-owned-failure-readback-e122-v1'
MAX_METADATA = 65536
MAX_LOG = 2 * 1048576
MAX_TOTAL = 5 * 1048576
MAX_RESPONSE = 8 * 1048576
TOOL_LOG = ROOT + '/aes_core/runs/e116-aes_core/logs/H_aes_core:HF:h1:H.log'
JOURNAL = ROOT + '/journal/'
PATHS = (SIDECAR, ROOT + '/code/common.tcl', ROOT + '/code/incremental.tcl') + tuple(
    JOURNAL + name for name in ('package_summary.json', 'task_000_observation.json',
        'task_000_stdout.log', 'task_000_stdout_ack.json', 'task_000_spawn_identity.json',
        'task_000_preparation.json', 'task_000_intent.json', 'initialization.json',
        'selftest_intent.json', 'selftest_observation.json')) + tuple(
    JOURNAL + 'selftest_callback_' + case + '_' + name
    for case in ('success', 'timeout', 'setsid_child')
    for name in ('observation.json', 'receipt.json', 'output.log')) + (TOOL_LOG,)
LOGS = frozenset((JOURNAL + 'task_000_stdout.log', TOOL_LOG))
REVIEW_KEYS = ('payload_sha256', 'controller_sha256', 'source_sha256',
               'authorization_sha256', 'prior_response_sha256', 'original_clock_sha256')
LOCAL_END = datetime.datetime(2026, 10, 26, 19, 29, 37, 523027, tzinfo=datetime.timezone.utc)


def require(ok, code):
    if not ok:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def _json(raw):
    return json.loads(raw.decode('ascii'), object_pairs_hook=_pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE_JSON')))


def collect(remote_start=None):
    from src.data import prospective_acceptance_materializer_v1 as io
    from src.data import direct_tessent_acceptance_e104 as direct
    started = time.monotonic() if remote_start is None else remote_start
    result = dict(schema=SCHEMA, capture_complete=False, error=None, hostname=platform.node(),
        uid=os.getuid() if hasattr(os, 'getuid') else None, boot_id=None,
        remote_start_monotonic=started, remote_end_monotonic=None,
        original_start_monotonic=START, original_deadline_monotonic=END,
        clock_must_not_be_reset=True, files=[], body_bytes_hashed=0,
        sampled_peak_rss_swap_bytes=0, explicit_filesystem_writes=0, child_launches=0,
        environment_reads=0, atpg_launches=0, training_runs=0, additional_historical_reports=0,
        execution_ready=False, training_release=False, sampling_is_hard_memory_guarantee=False)
    domain, deadline, total, next_sample = None, None, [0], [0]
    def tick():
        now = time.monotonic()
        require(now < deadline, 'READBACK_DEADLINE')
        if now >= next_sample[0]:
            require(not domain.sample(), 'UNEXPECTED_CHILDREN')
            next_sample[0] = time.monotonic() + .25
        require(time.monotonic() < deadline, 'READBACK_DEADLINE')
    def read(path):
        tick()
        parent, name = path.rsplit('/', 1)
        directory = io._directory(parent)
        fd = None
        try:
            parent_identity = (os.fstat(directory).st_dev, os.fstat(directory).st_ino)
            try:
                named = os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                require(path == TOOL_LOG, 'REQUIRED_OWNED_FILE_MISSING')
                return dict(path=path, status='MISSING')
            cap = MAX_LOG if path in LOGS else MAX_METADATA
            require(stat.S_ISREG(named.st_mode) and named.st_nlink == 1 and named.st_uid == 1047,
                    'SINGLE_LINK_OWNED_REGULAR_REQUIRED')
            require(0 <= named.st_size <= cap and total[0] + named.st_size <= MAX_TOTAL, 'READBACK_BODY_BOUND')
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            before = os.fstat(fd)
            require(io._identity(named) == io._identity(before) and before.st_uid == 1047, 'OWNED_FILE_CHANGED')
            remaining, blocks, digest = named.st_size, [], hashlib.sha256()
            while remaining:
                tick()
                raw = os.read(fd, min(65536, remaining))
                require(bool(raw), 'OWNED_FILE_SHORT_READ')
                remaining -= len(raw)
                total[0] += len(raw)
                digest.update(raw)
                blocks.append(raw)
            tick()
            after = os.stat(name, dir_fd=directory, follow_symlinks=False)
            require(io._identity(before) == io._identity(os.fstat(fd)) == io._identity(after) and
                    after.st_uid == 1047, 'OWNED_FILE_CHANGED')
            fresh = io._directory(parent)
            try:
                info = os.fstat(fresh)
                require((info.st_dev, info.st_ino) == parent_identity, 'OWNED_PARENT_REPLACED')
            finally:
                os.close(fresh)
            return dict(path=path, status='READ', bytes=before.st_size, sha256=digest.hexdigest(),
                        body_base64=base64.b64encode(b''.join(blocks)).decode('ascii'), whole_file_hashed=True)
        finally:
            if fd is not None:
                os.close(fd)
            os.close(directory)
    try:
        require(sys.platform.startswith('linux') and result['hostname'] == 'bupt-vncs2' and result['uid'] == 1047,
                'FIXED_HOST_UID_PLATFORM')
        require(type(started) in (int, float) and math.isfinite(started) and START <= started < END,
                'ORIGINAL_CLOCK_REQUIRED')
        deadline = min(END, started + 30)
        boot = direct.base._small('/proc/sys/kernel/random/boot_id', 128).decode('ascii').strip()
        result['boot_id'] = boot
        require(boot == BOOT, 'ORIGINAL_BOOT_REQUIRED')
        domain = direct.Descendants()
        tick()
        for path in PATHS:
            result['files'].append(read(path))
        tick()
        result['capture_complete'] = True
    except BaseException as exc:
        result['error'] = dict(type=type(exc).__name__, code=str(exc) if type(exc) is ValueError else 'OWNED_READBACK_FAILED')
    finally:
        result['remote_end_monotonic'] = time.monotonic()
        result['body_bytes_hashed'] = total[0]
        if domain is not None:
            result['sampled_peak_rss_swap_bytes'] = domain.peak
    require(len(canonical(result)) <= MAX_RESPONSE, 'READBACK_RESPONSE_BOUND')
    return result


def _local_remaining():
    value = (LOCAL_END - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
    require(value > 1, 'ORIGINAL_LOCAL_DEADLINE_EXPIRED')
    return value


def prepare():
    from scripts import acceptance_transport_e98 as control
    from scripts.run_direct_tessent_e104 import PINS
    repo = Path(__file__).resolve().parents[1]
    require(sha((repo / 'contracts/prospective_acquisition_authorization_e111_20261026.json').read_bytes()) == AUTH_SHA,
            'ACTUAL_AUTHORIZATION_CHANGED')
    prior = control.STAGING / 'v6_e121_generation_20261026_r1/stdout.json'
    raw = prior.read_bytes()
    require(sha(raw) == PRIOR_SHA, 'ACTUAL_FAILED_WORKER_RESPONSE_CHANGED')
    worker = _json(raw)
    summary = worker.get('summary', {})
    require(worker.get('status') == 'STOPPED_FIRST_FAILURE' and
            summary.get('counts') == dict(tessent_debited=1, translation_debited=0, committed_tasks=0,
                selftest_cases_reserved=3, selftest_cases_accepted=3) and
            summary.get('failed_task_uid') == 'aes_core:HF:h1:H' and
            summary.get('error', {}).get('code') == 'TESSENT_OBSERVATION_REJECTED', 'FIXED_FAILURE_PROOF')
    clock_raw = (control.STAGING / 'v6_e112_preparation_20261026_r1/package_clock.json').read_bytes()
    require(_json(clock_raw) == dict(boot_id=BOOT, clock_must_not_be_reset=True,
        preparation_response_sha256=E112_SHA, remote_deadline_monotonic=END,
        remote_start_monotonic=START), 'ORIGINAL_CLOCK_CHANGED')
    sources = []
    for name, pin in list(PINS) + [('e122_failure_readback', None)]:
        path = Path(__file__) if pin is None else repo / ('src/data/' + name + '.py')
        source = path.read_bytes()
        digest = sha(source)
        require(pin is None or digest == pin, 'PINNED_LEGACY_SOURCE_CHANGED')
        ast.parse(source.decode('utf-8'), feature_version=(3, 6))
        sources.append(dict(name=name, sha256=digest, body=base64.b64encode(source).decode('ascii')))
    package = json.dumps(dict(sources=sources), separators=(',', ':'))
    payload = ('import time\nbootstrap_started=time.monotonic()\n'
        'import base64,hashlib,json,types,sys\n'
        'p=json.loads(' + repr(package) + ')\n'
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
        'result=sys.modules["src.data.e122_failure_readback"].collect(bootstrap_started)\n'
        'print(json.dumps(result,sort_keys=True,allow_nan=False),flush=True)\n').encode('ascii')
    require(len(payload) <= 1048576, 'READBACK_PAYLOAD_BOUND')
    ast.parse(payload.decode('ascii'), feature_version=(3, 6))
    return dict(payload=payload, payload_sha256=sha(payload), controller_sha256=sha(Path(__file__).read_bytes()),
        source_sha256={row['name']: row['sha256'] for row in sources}, authorization_sha256=AUTH_SHA,
        prior_response_sha256=PRIOR_SHA, original_clock_sha256=sha(clock_raw))


def validate_response(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_RESPONSE, 'READBACK_RESPONSE_BOUND')
    value = _json(raw)
    require(type(value) is dict and value.get('schema') == SCHEMA and value.get('hostname') == 'bupt-vncs2' and
            type(value.get('uid')) is int and value['uid'] == 1047 and value.get('boot_id') == BOOT and
            value.get('original_start_monotonic') == START and value.get('original_deadline_monotonic') == END and
            value.get('clock_must_not_be_reset') is True, 'READBACK_IDENTITY_CLOCK')
    for key in ('execution_ready', 'training_release', 'sampling_is_hard_memory_guarantee'):
        require(value.get(key) is False, 'NO_RELEASE_OR_HARD_MEMORY_CLAIM')
    for key in ('explicit_filesystem_writes', 'child_launches', 'environment_reads', 'atpg_launches',
                'training_runs', 'additional_historical_reports'):
        require(type(value.get(key)) is int and value[key] == 0, 'READONLY_OWNED_OUTPUTS_ONLY')
    start, end = value.get('remote_start_monotonic'), value.get('remote_end_monotonic')
    require(all(type(t) in (int, float) and math.isfinite(t) for t in (start, end)) and
            START <= start <= end < END and end - start < 30, 'READBACK_CLOCK_INTERVAL')
    rows = value.get('files')
    require(type(rows) is list and len(rows) <= len(PATHS), 'READBACK_FILE_COUNT')
    total = 0
    for index, row in enumerate(rows):
        require(type(row) is dict and row.get('path') == PATHS[index], 'ORDERED_FIXED_FIRST_FAILURE_PREFIX')
        if row.get('status') == 'MISSING':
            require(set(row) == {'path', 'status'} and row['path'] == TOOL_LOG, 'ONLY_OPTIONAL_TOOL_LOG_MAY_BE_MISSING')
            continue
        require(set(row) == {'path', 'status', 'bytes', 'sha256', 'body_base64', 'whole_file_hashed'} and
                row['status'] == 'READ' and row['whole_file_hashed'] is True and type(row['bytes']) is int and
                0 <= row['bytes'] <= (MAX_LOG if row['path'] in LOGS else MAX_METADATA), 'READBACK_FILE_BOUND')
        body = base64.b64decode(row['body_base64'], validate=True)
        require(len(body) == row['bytes'] and sha(body) == row['sha256'], 'READBACK_FILE_BYTES_SHA')
        total += len(body)
    require(type(value.get('body_bytes_hashed')) is int and total <= value['body_bytes_hashed'] <= MAX_TOTAL and
            type(value.get('sampled_peak_rss_swap_bytes')) is int and
            0 <= value['sampled_peak_rss_swap_bytes'] <= 536870912, 'READBACK_RESOURCE_RECEIPTS')
    require(type(value.get('capture_complete')) is bool, 'READBACK_CAPTURE_STATUS')
    if value['capture_complete']:
        require(len(rows) == len(PATHS) and value.get('error') is None and total == value['body_bytes_hashed'],
                'READBACK_COMPLETE_SCOPE')
    else:
        require(type(value.get('error')) is dict, 'READBACK_FIRST_FAILURE_REQUIRED')
    return value


def execute(review_path, reviewed_payload_sha):
    from scripts import acceptance_transport_e98 as control
    _local_remaining()
    plan = prepare()
    review = _json(Path(review_path).read_bytes())
    expected = {key: plan[key] for key in REVIEW_KEYS}
    require(review.get('status') == 'PASS' and review.get('reviewed') == expected and
            reviewed_payload_sha == plan['payload_sha256'], 'INDEPENDENT_EXACT_REVIEW_REQUIRED')
    _local_remaining()
    helper = control.load_transport()
    fingerprint = helper.verify_cached_host('A')
    phase = control.STAGING / 'v6_e122_failure_readback_20261026_r1'
    phase.mkdir(exist_ok=False)
    helper.TIMEOUT = min(40, max(1, int(_local_remaining())))
    control.write_new(phase / 'start.json', control.encode(dict(expected, host_fingerprint=fingerprint,
        sessions_max=1, automatic_retries=0, owned_outputs_only=True, new_historical_reports=0,
        original_deadline_monotonic=END, original_boot_id=BOOT, response_cap=MAX_RESPONSE)))
    try:
        observed = helper.transport(helper.command('A'), plan['payload'], MAX_RESPONSE)
    except BaseException as exc:
        control.write_new(phase / 'transport.json', control.encode(dict(error_type=type(exc).__name__,
            status='TRANSPORT_RAISED_NO_RETRY')))
        raise
    control.write_new(phase / 'stdout.json', observed['stdout'])
    control.write_new(phase / 'stderr.log', observed['stderr'])
    receipt = {k: v for k, v in observed.items() if k not in ('stdout', 'stderr')}
    for key in ('stdout', 'stderr'):
        receipt[key + '_bytes'], receipt[key + '_sha256'] = len(observed[key]), sha(observed[key])
    control.write_new(phase / 'transport.json', control.encode(receipt))
    require(observed['exit_code'] == 0 and not any(observed[k] for k in
        ('timeout', 'overflow', 'write_failed', 'threads_incomplete')), 'TRANSPORT_FAILED_OR_UNKNOWN_NO_RETRY')
    result = validate_response(observed['stdout'])
    control.write_new(phase / 'validated.json', control.encode(dict(capture_complete=result['capture_complete'],
        files=len(result['files']), execution_ready=False, training_release=False)))
    require(result['capture_complete'], 'OWNED_READBACK_FIRST_FAILURE_NO_RETRY')
    return dict(phase=str(phase), files=len(result['files']), capture_complete=True,
                execution_ready=False, training_release=False)


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
