"""Fixed approved E73 SSH phase; at most one probe and one execution dispatch."""
import base64
import hashlib
import json
from pathlib import Path
import sys

from scripts import run_prospective_metadata_v1 as transport_api

ROOT = Path(__file__).resolve().parents[1]
STAGING = ROOT.parent / 'runtime_training_staging_20260928'
PHASE_NAME = 'v6_e73_linux_validation_20261021_r1'
AUTH = 'contracts/prospective_linux_lifecycle_authorization_e73_20261021.json'
AUTH_SHA = 'd758c91cd61a0aaa3745387892acf5b82de327c3a27c83dc0db0d623029a1bda'
SCOPE = 'contracts/prospective_linux_lifecycle_scope_e72_v1.json'
SCOPE_SHA = '82fa3c895afbde96935d2c849ca07e5fc7159a0715400fbd2b9f5bde56639dad'
GATE = 'scripts/verify_prospective_linux_lifecycle_v1.py'
GATE_SHA = '68b9104149b3adbc9c2d7cad21bbe8c080364428027503fb5cb38fd27ea31bf9'
SOURCES = dict(probe='scripts/probe_linux_lifecycle_environment_e73.py',
               execute='scripts/execute_linux_lifecycle_e73.py')
MANIFEST = 'data/manifests/ranking_v6_e73_execution_freeze_20261021_r1.json'


def require(ok, code):
    if not ok:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_fixed(relative, maximum):
    path = ROOT / relative
    require(not path.is_symlink() and path.is_file() and path.stat().st_size <= maximum,
            'FIXED_SMALL_FILE')
    raw = path.read_bytes()
    require(len(raw) <= maximum, 'FIXED_SMALL_FILE')
    return raw


def payload(mode, source):
    if mode == 'probe':
        return source
    gate = read_fixed(GATE, 16384)
    require(sha(gate) == GATE_SHA, 'GATE_SOURCE_PIN')
    manifest_raw = read_fixed(MANIFEST, 4096)
    manifest = transport_api.decode(manifest_raw)
    require(set(manifest) == {'image_id', 'source_sha256', 'scope_sha256', 'auth_sha256'},
            'FREEZE_SCHEMA')
    require(manifest['source_sha256'] == GATE_SHA and manifest['scope_sha256'] == SCOPE_SHA
            and manifest['auth_sha256'] == AUTH_SHA, 'FREEZE_PINS')
    request = dict(image_id=manifest['image_id'], source_b64=base64.b64encode(gate).decode('ascii'),
                   manifest=manifest)
    return (b"__name__ = '_reviewed_e73_payload'\n" + source +
            ('\nraise SystemExit(main(%r))\n' % request).encode('ascii'))


def run(mode):
    require(type(mode) is str and mode in SOURCES, 'FIXED_MODE')
    require(sha(read_fixed('scripts/run_prospective_metadata_v1.py', 16384)) ==
            'e0b1e62352781f96dc7d0e5a2a1a27e7f278b63c8aaaa07dbd946c1795c0f434', 'TRANSPORT_SOURCE_PIN')
    auth_raw = read_fixed(AUTH, 4096)
    require(sha(auth_raw) == AUTH_SHA and sha(read_fixed(SCOPE, 8192)) == SCOPE_SHA,
            'AUTH_SCOPE_PIN')
    require(json.loads(auth_raw.decode('utf-8'))['user_authorization_received'] is True, 'USER_APPROVAL')
    source = read_fixed(SOURCES[mode], 12288)
    review_name = 'data/manifests/ranking_v6_e73_%s_prerun_review_20261021_r1.json' % mode
    review = transport_api.decode(read_fixed(review_name, 4096))
    require(review['verdict'] == 'PASS_INDEPENDENT_PREEXECUTION_REVIEW'
            and review['mode'] == mode and review['source_sha256'] == sha(source)
            and review['controller_sha256'] == sha(read_fixed('scripts/run_linux_lifecycle_phase_e73.py', 12288))
            and review['authorization_sha256'] == AUTH_SHA, 'INDEPENDENT_REVIEW_PIN')
    raw = payload(mode, source)
    phase = STAGING / PHASE_NAME
    anchor = dict(authorization_sha256=AUTH_SHA, scope_sha256=SCOPE_SHA, phase=PHASE_NAME)
    if phase.exists():
        require(transport_api.decode((phase/'anchor.json').read_bytes()) == anchor, 'PHASE_ANCHOR')
        require((phase/'sessions.jsonl').is_file(), 'PHASE_JOURNAL')
    else:
        phase.mkdir(exist_ok=False)
        transport_api.write_new(phase/'anchor.json', anchor)
        with (phase/'sessions.jsonl').open('xb') as stream:
            stream.flush()
    lease = phase/'active.lock'
    with lease.open('xb') as stream:
        stream.write(b'ACTIVE\n')
    try:
        journal = phase/'sessions.jsonl'
        require(journal.stat().st_size <= 16384, 'JOURNAL_BOUND')
        events = [transport_api.decode(line) for line in journal.read_bytes().splitlines()]
        starts = [e for e in events if e['event'] == 'START']
        ends = {e['mode']: e for e in events if e['event'] == 'END'}
        require(all(e['mode'] in ends for e in starts), 'UNRESOLVED_SESSION_STOP')
        require(mode not in {e['mode'] for e in starts}, 'NO_REPEAT_DISPATCH')
        if mode == 'execute':
            require('probe' in ends and ends['probe']['accepted'], 'PROBE_GATE_REQUIRED')
        used_input = sum(e['stdin_bytes'] for e in starts)
        used_output = sum(e['return_bytes'] for e in ends.values())
        require(len(starts) < 4 and used_input + len(raw) <= 32768, 'SESSION_OR_UPLOAD_BOUND')
        cap = min(8192, 16384-used_output)
        require(cap > 0, 'RETURN_BOUND')
        pin = transport_api.verify_cached_host('B')
        output = phase/('%02d_%s' % (len(starts)+1, mode))
        output.mkdir(exist_ok=False)
        transport_api.write_new(output/'request.json', dict(mode=mode, stdin_bytes=len(raw),
            payload_sha256=sha(raw), source_sha256=sha(source), host_pin=pin,
            review_sha256=sha(read_fixed(review_name, 4096)), automatic_retries=0))
        transport_api.append_event(journal, dict(event='START', mode=mode,
            stdin_bytes=len(raw), source_sha256=sha(source), output_cap=cap))
        result = transport_api.transport(transport_api.command('B'), raw, cap)
        for key in ('stdout', 'stderr'):
            with (output/(key+'.log')).open('xb') as stream:
                stream.write(result[key])
        accepted = False
        try:
            response = transport_api.decode(result['stdout'])
            if mode == 'probe':
                flags = response.get('docker_create_capabilities')
                require(response.get('schema') == 'e73-environment-probe-v1'
                    and response.get('platform') == 'linux' and 'reason' not in response
                    and type(flags) is dict and set(flags) == {'--cgroup-conf', '--cgroupns',
                        '--memory', '--memory-swap', '--pids-limit', '--pull', '--read-only',
                        '--tmpfs', '--cap-drop'} and all(type(v) is bool for v in flags.values())
                    and response.get('lifecycle_gate_pass') is False, 'PROBE_RESPONSE_SCHEMA')
            accepted = (result['exit_code'] == 0 and not result['stderr'] and
                not any(result[k] for k in ('timeout','overflow','write_failed','threads_incomplete')) and
                response['host'] == 'bupt-gpus1' and response['status'] == (
                    'metadata_collected' if mode == 'probe' else 'PASS_LINUX_SYNTHETIC_GATE'))
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            pass
        receipt = {k: v for k, v in result.items() if k not in ('stdout', 'stderr')}
        receipt.update(accepted=bool(accepted), stdout_sha256=sha(result['stdout']),
                       stderr_sha256=sha(result['stderr']))
        transport_api.write_new(output/'transport.json', receipt)
        transport_api.append_event(journal, dict(event='END', mode=mode, accepted=bool(accepted),
            return_bytes=len(result['stdout'])+len(result['stderr'])))
        print(json.dumps(dict(mode=mode, accepted=bool(accepted), execution_ready=False, training_release=False)))
        return 0 if accepted else 2
    finally:
        lease.unlink()


if __name__ == '__main__':
    require(len(sys.argv) == 2, 'ONE_FIXED_PHASE_MODE')
    raise SystemExit(run(sys.argv[1]))
