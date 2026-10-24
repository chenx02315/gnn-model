"""One fresh read-only bjobs query for Job 394230; no resume or submission."""
import base64
import json
from pathlib import Path
from scripts import execute_acceptance_register_e97 as transport_base

ROOT = Path(__file__).resolve().parents[1]
PHASE = ROOT.parent / 'runtime_training_staging_20260928/v6_e97_fresh_job_state_20261024_r1'
JOB_ID = 394230


def prepare():
    raw = transport_base.SOURCE.read_bytes()
    if transport_base.sha(raw) != 'd9a30b7e94cfa3ed4fcff4306f09f147ada4c615210ecb5a2954362ad8e09a3a':
        raise ValueError('QUERY_HELPER_CHANGED')
    if transport_base.sha(transport_base.TRANSPORT.read_bytes()) != transport_base.TRANSPORT_SHA:
        raise ValueError('TRANSPORT_CHANGED')
    suffix = '''
import resource,base64
for kind,cap in ((resource.RLIMIT_AS,268435456),(resource.RLIMIT_CPU,20)):
 soft,hard=resource.getrlimit(kind)
 chosen=min([cap]+[v for v in (soft,hard) if v!=resource.RLIM_INFINITY])
 resource.setrlimit(kind,(chosen,chosen))
require(sys.platform.startswith('linux') and platform.node()=='bupt-vncs2','HOST_REQUIRED')
result=_client([BINDIR+'bjobs','-l','394230'])
response=dict(schema='e97-fresh-job-state-v1',job_id=394230,status=result['status'],returncode=result['returncode'],stdout_base64=base64.b64encode(result['stdout']).decode('ascii'),stderr_base64=base64.b64encode(result['stderr']).decode('ascii'),programs_launched=1,jobs_submitted=0,resume_calls=0)
out=json.dumps(response,sort_keys=True)
require(len(out.encode('ascii'))+1<=16384,'QUERY_OUTPUT_BOUND')
sys.stdout.write(out+'\\n')
'''
    payload = raw + suffix.encode('ascii')
    compile(payload,'<e97-read-only-job-query>','exec')
    return payload


def main():
    payload = prepare()
    helper = transport_base.load_transport()
    key = helper.verify_cached_host('A')
    PHASE.mkdir(exist_ok=False)
    transport_base.write_new(PHASE/'start.json',transport_base.encode(dict(job_id=JOB_ID,
        payload_sha256=transport_base.sha(payload),host_fingerprint=key,
        sessions_max=1,automatic_retries=0,programs_launched=1,jobs_submitted=0,resume_calls=0)))
    result = helper.transport(helper.command('A'),payload,16384)
    transport_base.write_new(PHASE/'stdout.json',result['stdout'])
    transport_base.write_new(PHASE/'stderr.log',result['stderr'])
    receipt={k:v for k,v in result.items() if k not in ('stdout','stderr')}
    receipt.update(stdout_sha256=transport_base.sha(result['stdout']),stdout_bytes=len(result['stdout']),
                   stderr_sha256=transport_base.sha(result['stderr']),stderr_bytes=len(result['stderr']))
    transport_base.write_new(PHASE/'transport.json',transport_base.encode(receipt))
    if result['exit_code']!=0 or any(result[k] for k in ('timeout','overflow','write_failed','threads_incomplete')):
        raise ValueError('QUERY_FAILED_NO_RETRY')
    value=helper.decode(result['stdout'])
    if value.get('job_id')!=JOB_ID or value.get('schema')!='e97-fresh-job-state-v1':
        raise ValueError('QUERY_IDENTITY')
    print(base64.b64decode(value['stdout_base64']).decode('ascii'))


if __name__ == '__main__':
    main()
