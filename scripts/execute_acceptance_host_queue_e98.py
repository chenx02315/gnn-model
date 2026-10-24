"""One explicit read-only observation of the host assigned to Job 394238."""
import json
import sys

from scripts import acceptance_transport_e98 as control
from scripts import inspect_acceptance_host_queue_e98 as inspector


def main():
    if len(sys.argv) != 3:
        raise ValueError('REVIEWED_HELPER_AND_PAYLOAD_SHA_REQUIRED')
    helper_sha, payload_sha = sys.argv[1:]
    prepared = inspector.prepare_payload(helper_sha)
    result = control.execute_phase('host_queue_observation', prepared['payload'],
                                   payload_sha, prepared['response_cap'])
    value = result['response']
    if (value.get('schema') != 'e98-host-queue-observation-v1'
            or value.get('host') != 'bupt-vncs2'
            or value.get('job_scope') != 394238
            or value.get('observation_only') is not True
            or type(value.get('jobs_submitted')) is not int
            or value['jobs_submitted'] != 0
            or type(value.get('resume_calls')) is not int
            or value['resume_calls'] != 0
            or type(value.get('cancellation_calls')) is not int
            or value['cancellation_calls'] != 0):
        raise ValueError('FIXED_HOST_OBSERVATION_IDENTITY')
    if (value.get('client_status') != 'CLIENT_COMPLETE'
            or type(value.get('client_returncode')) is not int
            or value['client_returncode'] != 0):
        raise ValueError('HOST_QUERY_NOT_COMPLETE_EVIDENCE_SAVED_NO_RETRY')
    print(json.dumps(dict(phase=result['phase'], observation=value), sort_keys=True))


if __name__ == '__main__':
    main()
