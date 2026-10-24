"""Bounded E98 control transport; not an automatic executor or job scheduler."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
AUTH = ROOT / 'contracts/prospective_acceptance_authorization_e98_20261024.json'
AUTH_SHA = 'da27486a2ed20d55c8b8de7071882364c9648ab49054d2a319d07cb2a73076f5'
TRANSPORT = ROOT / 'scripts/run_prospective_metadata_v1.py'
TRANSPORT_SHA = 'e0b1e62352781f96dc7d0e5a2a1a27e7f278b63c8aaaa07dbd946c1795c0f434'
STAGING = ROOT.parent / 'runtime_training_staging_20260928'
OPERATIONS = frozenset(('retire_observe','retire_execute','retire_confirm',
    'deployment','registration','registration_review','pre_resume_observation','resume',
    'host_queue_observation') +
    tuple('job_observation_' + str(n) for n in range(1, 17)))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, indent=2)+'\n').encode('ascii')


def write_new(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def load_transport():
    if sha(TRANSPORT.read_bytes()) != TRANSPORT_SHA:
        raise ValueError('TRANSPORT_CHANGED')
    spec=importlib.util.spec_from_file_location('e98_pinned_transport',str(TRANSPORT))
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.TIMEOUT=120
    return module


def execute_phase(operation, payload, reviewed_payload_sha, cap=16384):
    if operation not in OPERATIONS or type(payload) is not bytes or len(payload)>1048576:
        raise ValueError('FIXED_OPERATION_OR_PAYLOAD_BOUND')
    if type(reviewed_payload_sha) is not str or re.fullmatch('[0-9a-f]{64}',reviewed_payload_sha) is None or sha(payload)!=reviewed_payload_sha:
        raise ValueError('REVIEWED_PAYLOAD_CHANGED')
    if type(cap) is not int or not 1024<=cap<=262144:
        raise ValueError('RESPONSE_CAP')
    if sha(AUTH.read_bytes())!=AUTH_SHA:
        raise ValueError('AUTHORIZATION_CHANGED')
    helper=load_transport()
    fingerprint=helper.verify_cached_host('A')
    phase=STAGING/('v6_e98_'+operation+'_20261024_r1')
    phase.mkdir(exist_ok=False)
    write_new(phase/'start.json',encode(dict(operation=operation,authorization_sha256=AUTH_SHA,
        payload_sha256=reviewed_payload_sha,host_fingerprint=fingerprint,
        sessions_max=1,automatic_retries=0,response_cap=cap)))
    result=helper.transport(helper.command('A'),payload,cap)
    write_new(phase/'stdout.json',result['stdout'])
    write_new(phase/'stderr.log',result['stderr'])
    receipt={k:v for k,v in result.items() if k not in ('stdout','stderr')}
    receipt.update(stdout_sha256=sha(result['stdout']),stdout_bytes=len(result['stdout']),
        stderr_sha256=sha(result['stderr']),stderr_bytes=len(result['stderr']))
    write_new(phase/'transport.json',encode(receipt))
    if result['exit_code']!=0 or any(result[k] for k in ('timeout','overflow','write_failed','threads_incomplete')):
        raise ValueError('CONTROL_FAILED_OR_UNKNOWN_NO_RETRY')
    return dict(phase=str(phase),response=helper.decode(result['stdout']),transport=receipt)
