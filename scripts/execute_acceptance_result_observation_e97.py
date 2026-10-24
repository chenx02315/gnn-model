"""Explicit bounded observation of one known job; no automatic polling loop."""
import json
import sys
from scripts import execute_acceptance_register_e97 as common
from scripts import inspect_acceptance_job_result_e97 as inspector


def main():
    if len(sys.argv) != 3 or sys.argv[2] not in ('1','2','3','4'):
        raise ValueError('REVIEWED_HELPER_AND_FIXED_PHASE_INDEX_REQUIRED')
    prepared = inspector.prepare_payload(sys.argv[1], int(sys.argv[2]))
    if common.sha(common.TRANSPORT.read_bytes()) != common.TRANSPORT_SHA:
        raise ValueError('TRANSPORT_CHANGED')
    helper = common.load_transport()
    key = helper.verify_cached_host('A')
    phase = common.ROOT.parent / 'runtime_training_staging_20260928' / prepared['phase_name']
    phase.mkdir(exist_ok=False)
    common.write_new(phase/'start.json',common.encode(dict(
        payload_sha256=prepared['payload_sha256'],helper_sha256=sys.argv[1],
        host_fingerprint=key,job_id=394230,sessions_max=1,automatic_retries=0)))
    result = helper.transport(helper.command('A'),prepared['payload'],prepared['response_cap'])
    common.write_new(phase/'stdout.json',result['stdout'])
    common.write_new(phase/'stderr.log',result['stderr'])
    receipt={k:v for k,v in result.items() if k not in ('stdout','stderr')}
    receipt.update(stdout_sha256=common.sha(result['stdout']),stdout_bytes=len(result['stdout']),
        stderr_sha256=common.sha(result['stderr']),stderr_bytes=len(result['stderr']))
    common.write_new(phase/'transport.json',common.encode(receipt))
    if result['exit_code']!=0 or any(result[k] for k in ('timeout','overflow','write_failed','threads_incomplete')):
        raise ValueError('OBSERVATION_FAILED_NOT_A_JOB_RESTART_SIGNAL')
    value=helper.decode(result['stdout'])
    if value.get('schema')!='e97-job-result-observation-v1' or value.get('job_id')!=394230:
        raise ValueError('RESPONSE_IDENTITY')
    print(json.dumps(dict(job_id=394230,phase=str(phase),scheduler_client_status=value['scheduler_client_status'],
        scheduler_returncode=value['scheduler_returncode'],files=[dict(path=x['path'],status=x['status']) for x in value['files']]),sort_keys=True))


if __name__=='__main__':
    main()
