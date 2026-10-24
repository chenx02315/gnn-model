"""Read only seven fixed registration records for the one known E97 job."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'scripts/register_acceptance_job_e97.py'
SOURCE_SHA = 'd9a30b7e94cfa3ed4fcff4306f09f147ada4c615210ecb5a2954362ad8e09a3a'
TRANSPORT = ROOT / 'scripts/run_prospective_metadata_v1.py'
TRANSPORT_SHA = 'e0b1e62352781f96dc7d0e5a2a1a27e7f278b63c8aaaa07dbd946c1795c0f434'
PHASE = ROOT.parent / 'runtime_training_staging_20260928/v6_e97_registration_review_inputs_20261024_r1'
JOB_ID = 394230


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def prepare():
    source = SOURCE.read_bytes()
    if sha(source) != SOURCE_SHA or sha(TRANSPORT.read_bytes()) != TRANSPORT_SHA:
        raise ValueError('REVIEWED_SOURCE_CHANGED')
    suffix = '''
import base64,resource
for kind,cap in ((resource.RLIMIT_AS,268435456),(resource.RLIMIT_CPU,20)):
 soft,hard=resource.getrlimit(kind)
 chosen=min([cap]+[v for v in (soft,hard) if v!=resource.RLIM_INFINITY])
 resource.setrlimit(kind,(chosen,chosen))
require(sys.platform.startswith('linux') and platform.node()=='bupt-vncs2','HOST_REQUIRED')
files={}
total=0
for name in ('intent.json','submission_result.json','result.json','bsub_stdout.bin','bsub_stderr.bin','bjobs_stdout.bin','bjobs_stderr.bin'):
 raw,info=_read(ROOT+'/registration/'+name,min(16384,32768-total))
 total+=len(raw)
 require(total<=32768,'REGISTRATION_EVIDENCE_BOUND')
 files[name]=dict(bytes=len(raw),sha256=sha(raw),base64=base64.b64encode(raw).decode('ascii'))
value=json.loads(base64.b64decode(files['result.json']['base64']).decode('ascii'))
require(type(value.get('job_id')) is int and value['job_id']==394230,'EXACT_KNOWN_JOB')
response=json.dumps(dict(schema='e97-registration-evidence-v1',job_id=394230,files=files,programs_launched=0,jobs_submitted=0),sort_keys=True)
require(len(response.encode('ascii'))+1<=65536,'RESPONSE_BOUND')
sys.stdout.write(response+'\\n')
'''
    payload = source + suffix.encode('ascii')
    compile(payload, '<e97-registration-inspection>', 'exec')
    return payload


def write_new(path, raw):
    with path.open('xb') as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def main():
    payload = prepare()
    spec = importlib.util.spec_from_file_location('e97_inspection_transport', TRANSPORT)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    key = helper.verify_cached_host('A')
    PHASE.mkdir(exist_ok=False)
    write_new(PHASE/'start.json',json.dumps(dict(job_id=JOB_ID,source_sha256=SOURCE_SHA,
        payload_sha256=sha(payload),host_fingerprint=key,sessions_max=1,automatic_retries=0,
        fixed_files=7,body_bytes_max=32768,programs_launched=0,jobs_submitted=0),sort_keys=True).encode('ascii'))
    result = helper.transport(helper.command('A'), payload,65536)
    write_new(PHASE/'stdout.json',result['stdout'])
    write_new(PHASE/'stderr.log',result['stderr'])
    receipt={k:v for k,v in result.items() if k not in ('stdout','stderr')}
    receipt.update(stdout_sha256=sha(result['stdout']),stdout_bytes=len(result['stdout']),
                   stderr_sha256=sha(result['stderr']),stderr_bytes=len(result['stderr']))
    write_new(PHASE/'transport.json',json.dumps(receipt,sort_keys=True).encode('ascii'))
    if result['exit_code']!=0 or any(result[k] for k in ('timeout','overflow','write_failed','threads_incomplete')):
        raise ValueError('INSPECTION_FAILED_NO_RETRY')
    value=helper.decode(result['stdout'])
    if value.get('schema')!='e97-registration-evidence-v1' or value.get('job_id')!=JOB_ID:
        raise ValueError('EVIDENCE_IDENTITY')
    print(json.dumps(dict(job_id=JOB_ID,files=len(value['files']),programs_launched=0)))


if __name__ == '__main__':
    main()
