"""Explicit read-only observations of the single E98 job, never a retry loop."""
import json
import sys
from scripts import acceptance_transport_e98 as control
from scripts import inspect_acceptance_job_result_e98 as inspector


def main():
    if len(sys.argv)!=4 or sys.argv[3] not in tuple(str(n) for n in range(1,control.MAX_JOB_OBSERVATIONS+1)):
        raise ValueError('REVIEWED_HELPER_PAYLOAD_SHA_FIXED_OBSERVATION_INDEX_REQUIRED')
    helper_sha,payload_sha,index=sys.argv[1:]
    prepared=inspector.prepare_payload(helper_sha)
    result=control.execute_phase('job_observation_'+index,prepared['payload'],payload_sha,prepared['response_cap'])
    value=result['response']
    if value.get('schema')!='e98-job-result-observation-v1' or value.get('job_id')!=394238:
        raise ValueError('E98_RESULT_IDENTITY')
    print(json.dumps(dict(job_id=394238,phase=result['phase'],scheduler_client_status=value['scheduler_client_status'],
        scheduler_returncode=value['scheduler_returncode'],files=[dict(path=x['path'],status=x['status']) for x in value['files']]),sort_keys=True))


if __name__=='__main__':main()
