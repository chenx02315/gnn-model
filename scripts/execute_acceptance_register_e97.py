"""Exactly one reviewed held-registration attempt; never resumes the job."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'scripts/register_acceptance_job_e97.py'
TRANSPORT = ROOT / 'scripts/run_prospective_metadata_v1.py'
TRANSPORT_SHA = 'e0b1e62352781f96dc7d0e5a2a1a27e7f278b63c8aaaa07dbd946c1795c0f434'
AUTH = ROOT / 'contracts/prospective_acceptance_authorization_e97_20261024.json'
AUTH_SHA = 'db9aa1bd63c7a3f7c9935ff4e99c2931041e59fb225b39e4338b06efd1619935'
PHASE = ROOT.parent / 'runtime_training_staging_20260928/v6_e97_registration_20261024_r1'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')


def write_new(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def prepare(reviewed_sha):
    if type(reviewed_sha) is not str or re.fullmatch('[0-9a-f]{64}', reviewed_sha) is None:
        raise ValueError('REVIEWED_HELPER_SHA_REQUIRED')
    raw = SOURCE.read_bytes()
    if len(raw) > 32768 or sha(raw) != reviewed_sha:
        raise ValueError('HELPER_CHANGED')
    if sha(AUTH.read_bytes()) != AUTH_SHA or sha(TRANSPORT.read_bytes()) != TRANSPORT_SHA:
        raise ValueError('AUTHORIZATION_OR_TRANSPORT_CHANGED')
    call = ('\nimport resource\n'
            'for kind,cap in ((resource.RLIMIT_AS,268435456),(resource.RLIMIT_CPU,20)):\n'
            ' soft,hard=resource.getrlimit(kind)\n'
            ' chosen=min([cap]+[v for v in (soft,hard) if v!=resource.RLIM_INFINITY])\n'
            ' resource.setrlimit(kind,(chosen,chosen))\n'
            'try:\n'
            ' result=register()\n'
            ' sys.stdout.write(json.dumps(result,sort_keys=True)+"\\n")\n'
            'except Exception:\n'
            ' sys.stdout.write("{\\"status\\":\\"REGISTRATION_FAILED_OR_UNKNOWN_NO_RETRY\\",\\"jobs_submitted\\":null}\\n")\n'
            ' sys.exit(1)\n')
    payload = raw + call.encode('ascii')
    compile(payload, '<e97-registration>', 'exec')
    return payload


def load_transport():
    spec = importlib.util.spec_from_file_location('e97_registration_transport', TRANSPORT)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.TIMEOUT = 90  # Two clients <=30s each plus verification/fsync overhead.
    return helper


def main():
    if len(sys.argv) != 2:
        raise ValueError('ONE_REVIEWED_HELPER_SHA_REQUIRED')
    payload = prepare(sys.argv[1])
    helper = load_transport()
    fingerprint = helper.verify_cached_host('A')
    PHASE.mkdir(exist_ok=False)
    write_new(PHASE / 'start.json', encode(dict(schema='e97-registration-start-v1',
        authorization_sha256=AUTH_SHA, helper_sha256=sys.argv[1],
        payload_sha256=sha(payload), host_fingerprint=fingerprint,
        sessions_max=1, automatic_retries=0, submission_attempts_max=1,
        transport_seconds=90, helper_memory_bytes=268435456, helper_cpu_seconds=20,
        registration_review_passed=False, pre_resume_review_passed=False,
        automatic_resume=False)))
    result = helper.transport(helper.command('A'), payload, 16384)
    write_new(PHASE / 'stdout.json', result['stdout'])
    write_new(PHASE / 'stderr.log', result['stderr'])
    receipt = {k: v for k, v in result.items() if k not in ('stdout', 'stderr')}
    receipt.update(stdout_bytes=len(result['stdout']), stderr_bytes=len(result['stderr']),
                   stdout_sha256=sha(result['stdout']), stderr_sha256=sha(result['stderr']))
    write_new(PHASE / 'transport.json', encode(receipt))
    if result['exit_code'] != 0 or any(result[k] for k in
            ('timeout', 'overflow', 'write_failed', 'threads_incomplete')):
        raise ValueError('REGISTRATION_FAILED_OR_UNKNOWN_NO_RETRY')
    observation = helper.decode(result['stdout'])
    if (observation.get('schema') != 'e97-held-registration-result-v1' or
            type(observation.get('job_id')) is not int or observation['job_id'] <= 0 or
            observation.get('status') != 'REGISTERED_HELD_REVIEW_PENDING' or
            observation.get('automatic_resume') is not False):
        raise ValueError('REGISTRATION_UNCONFIRMED_ATTEMPT_CONSUMED_NO_RETRY')
    print(json.dumps(observation, sort_keys=True))


if __name__ == '__main__':
    main()
