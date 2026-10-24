"""One approved new-directory deployment. Never registers or resumes a job."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'scripts/deploy_acceptance_bundle_e98.py'
TRANSPORT = ROOT / 'scripts/run_prospective_metadata_v1.py'
TRANSPORT_SHA = 'e0b1e62352781f96dc7d0e5a2a1a27e7f278b63c8aaaa07dbd946c1795c0f434'
AUTH = ROOT / 'contracts/prospective_acceptance_authorization_e98_20261024.json'
AUTH_SHA = 'da27486a2ed20d55c8b8de7071882364c9648ab49054d2a319d07cb2a73076f5'
STAGE = ROOT.parent / 'runtime_training_staging_20260928/v6_e98_execution_bundle_20261024_r1'
PHASE = ROOT.parent / 'runtime_training_staging_20260928/v6_e98_deployment_20261024_r1'
ARCHIVE_SHA = '172be8939e3b3934313b52d85b1db9a43735a6c80c0d659ed22e70395bad6b62'
MANIFEST_SHA = 'c6780832d3d0e62d030c4cc74814f2f9550be710ade154f40bf6ec0512bd29ef'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_new(path, value):
    with path.open('xb') as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare(reviewed_sha):
    if type(reviewed_sha) is not str or re.fullmatch('[0-9a-f]{64}', reviewed_sha) is None:
        raise ValueError('REVIEWED_HELPER_SHA_REQUIRED')
    source = SOURCE.read_bytes()
    if len(source) > 32768 or sha(source) != reviewed_sha:
        raise ValueError('HELPER_CHANGED')
    if sha(TRANSPORT.read_bytes()) != TRANSPORT_SHA or sha(AUTH.read_bytes()) != AUTH_SHA:
        raise ValueError('AUTHORIZATION_OR_TRANSPORT_CHANGED')
    archive = (STAGE / 'e98_execution_bundle.tar.gz').read_bytes()
    manifest = (STAGE / 'e98_code_manifest.json').read_bytes()
    if len(archive) > 524288 or sha(archive) != ARCHIVE_SHA or sha(manifest) != MANIFEST_SHA:
        raise ValueError('BUNDLE_CHANGED')
    config = dict(archive_b64=base64.b64encode(archive).decode('ascii'),
                  archive_sha256=ARCHIVE_SHA, manifest_sha256=MANIFEST_SHA,
                  manifest_files=json.loads(manifest.decode('ascii'))['files'], tar_bytes=266240)
    helper = load_module(SOURCE, 'e98_reviewed_deployer')
    helper._unpack(config)  # Pure validation only; never call deploy locally.
    call = ('\nimport resource\n'
            'for kind,cap in ((resource.RLIMIT_AS,268435456),(resource.RLIMIT_CPU,20)):\n'
            ' soft,hard=resource.getrlimit(kind)\n'
            ' chosen=min([cap]+[v for v in (soft,hard) if v!=resource.RLIM_INFINITY])\n'
            ' resource.setrlimit(kind,(chosen,chosen))\n'
            'try:\n'
            ' result=deploy(json.loads(%r))\n'
            ' sys.stdout.write(json.dumps(result,sort_keys=True)+"\\n")\n'
            'except Exception:\n'
            ' sys.stdout.write("{\\"status\\":\\"DEPLOYMENT_FAILED_PARTIAL_PRESERVED\\",\\"jobs_submitted\\":0}\\n")\n'
            ' sys.exit(1)\n') % json.dumps(config, sort_keys=True)
    payload = source + call.encode('ascii')
    if len(payload) > 1048576:
        raise ValueError('PAYLOAD_BOUND')
    compile(payload, '<e98-deployment>', 'exec')
    return payload


def main():
    if len(sys.argv) != 2:
        raise ValueError('ONE_REVIEWED_HELPER_SHA_REQUIRED')
    payload = prepare(sys.argv[1])
    transport = load_module(TRANSPORT, 'e98_deploy_transport')
    fingerprint = transport.verify_cached_host('A')
    PHASE.mkdir(exist_ok=False)
    write_new(PHASE / 'start.json', encode(dict(schema='e98-deployment-start-v1',
        helper_sha256=sys.argv[1], payload_sha256=sha(payload),
        authorization_sha256=AUTH_SHA, archive_sha256=ARCHIVE_SHA,
        manifest_sha256=MANIFEST_SHA, host_fingerprint=fingerprint,
        sessions_max=1, automatic_retries=0, jobs_submitted=0)))
    result = transport.transport(transport.command('A'), payload, 16384)
    write_new(PHASE / 'stdout.json', result['stdout'])
    write_new(PHASE / 'stderr.log', result['stderr'])
    receipt = {k: v for k, v in result.items() if k not in ('stdout', 'stderr')}
    receipt.update(stdout_sha256=sha(result['stdout']), stderr_sha256=sha(result['stderr']),
                   stdout_bytes=len(result['stdout']), stderr_bytes=len(result['stderr']))
    write_new(PHASE / 'transport.json', encode(receipt))
    if result['exit_code'] != 0 or any(result[k] for k in
            ('timeout', 'overflow', 'write_failed', 'threads_incomplete')):
        raise ValueError('DEPLOYMENT_FAILED_NO_RETRY_PARTIAL_PRESERVED')
    observation = transport.decode(result['stdout'])
    if (observation.get('schema') != 'e98-bundle-deployment-v1' or
            observation.get('status') != 'DEPLOYED_ONLY' or
            observation.get('manifest_sha256') != MANIFEST_SHA or
            observation.get('jobs_submitted') != 0 or observation.get('files') != 24):
        raise ValueError('DEPLOYMENT_RECEIPT_FAILED')
    print(json.dumps(observation, sort_keys=True))


if __name__ == '__main__':
    main()


