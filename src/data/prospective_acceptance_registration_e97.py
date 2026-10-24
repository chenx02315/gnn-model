"""Pure E97 registration planner; no filesystem, scheduler, or launch operations."""
import hashlib
import json
import re

ROOT = '/temp/jiangchuanc/gnn_model_acceptance_e97_20261024_r1_bundle'
OBSERVATION_SHA256 = '2bd0d91f6d900bd9e317467549e4655e3b9b997e24b17dc870b3e52ceac42da9'
AUTHORIZATION_SHA256 = 'db9aa1bd63c7a3f7c9935ff4e99c2931041e59fb225b39e4338b06efd1619935'
CONFIG_SHA256 = '3f1babe5cb5ce50a5fe08a86b9befa3f28f6ba73e96c5cd180e5add540bdf76b'
BINDIR = '/cad/lsf/9.1/linux2.6-glibc2.3-x86_64/bin/'
JOB_NAME = 'gnn_e97_acceptance_r1'
EXECUTABLES = ('bsub', 'bjobs', 'bresume', 'blaunch', 'lsid', 'bqueues')


class RegistrationError(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise RegistrationError(code)


def _pairs(rows):
    result = {}
    for key, value in rows:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def _pinned(raw, expected):
    require(type(raw) is bytes and len(raw) <= 65536, 'RAW_BYTES_BOUND')
    require(hashlib.sha256(raw).hexdigest() == expected, 'SOURCE_PIN')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs)


def _observation(value):
    require(type(value) is dict and value.get('schema') == 'acceptance_lsf_setup_e97_v1'
            and value.get('status') == 'PASS_BOUNDED_SETUP_METADATA_ONLY'
            and value.get('hostname') == 'bupt-vncs2' and value.get('errors') == [],
            'OBSERVATION_SCOPE')
    config = value.get('config', {})
    require(config.get('status') == 'read' and config.get('sha256') == CONFIG_SHA256,
            'CONFIG_PIN')
    unit = config.get('selected_parameters', {}).get('LSF_UNIT_FOR_LIMITS', {})
    require(unit.get('status') == 'present' and type(unit.get('count')) is int and
            unit['count'] == 1 and unit.get('raw_token') == 'MB', 'EXPLICIT_MB_REQUIRED')
    programs = value.get('executables', {})
    require(set(programs) == set(EXECUTABLES), 'EXECUTABLE_SET')
    for name in EXECUTABLES:
        row = programs[name]
        require(row.get('status') == 'present' and row.get('path') == BINDIR + name,
                'EXECUTABLE_PATH')
        meta = row.get('metadata', {})
        require(set(meta) == {'dev', 'gid', 'ino', 'mode', 'mtime_ns', 'size', 'uid'}
                and all(type(item) is int and item >= 0 for item in meta.values())
                and meta['size'] > 0 and meta['ino'] > 0 and meta['mode'] & 0o111,
                'EXECUTABLE_METADATA')


def build_registration(observation_bytes, authorization_bytes, bundle_manifest_sha):
    observation = _pinned(observation_bytes, OBSERVATION_SHA256)
    authorization = _pinned(authorization_bytes, AUTHORIZATION_SHA256)
    _observation(observation)
    require(authorization.get('schema') == 'prospective-acceptance-authorization-e97-v1'
            and authorization.get('user_authorization_received') is True and
            authorization.get('actual_job_registered') is False and
            authorization.get('job_id') is None and
            authorization.get('allowed', {}).get('single_held_job_registration') is True,
            'AUTHORIZATION_SCOPE')
    require(type(bundle_manifest_sha) is str and
            re.fullmatch('[0-9a-f]{64}', bundle_manifest_sha), 'MANIFEST_PIN')
    stdout = ROOT + '/registration/stdout.log'
    stderr = ROOT + '/registration/stderr.log'
    argv = [BINDIR + 'bsub', '-H', '-rn', '-n', '1', '-q', 'normal', '-m', 'bupt-vncs2', '-J', JOB_NAME,
        '-M', '512', '-R', 'rusage[mem=512] span[hosts=1]', '-W', '45',
        '-cwd', ROOT, '-oo', stdout, '-eo', stderr, BINDIR + 'blaunch',
        '/usr/bin/python3', '-I', '-S', '-B', ROOT + '/scripts/run_acceptance_job_e97.py']
    return dict(schema='e97-held-registration-plan-v1', argv=argv, bundle_root=ROOT,
        stdout_path=stdout, stderr_path=stderr, code_manifest_sha256=bundle_manifest_sha,
        authorization_sha256=AUTHORIZATION_SHA256, observation_sha256=OBSERVATION_SHA256,
        required_fresh_config_sha256=CONFIG_SHA256,
        fresh_config_reread_required_before_submission=True,
        expected_executables=observation['executables'],
        constraints=dict(job_count_max=1, array=False, rerunnable=False, workers=1,
            held_at_registration=True, automatic_retries=0, job_wall_seconds=2700,
            ram_cap_bytes=536870912, ram_plus_swap_cap_bytes=536870912),
        unknown_submission_consumes_only_attempt=True, automatic_resume=False,
        independent_registration_review_required=True, fresh_pre_resume_review_required=True,
        actual_job_memory_proof=False, memory_units_evidence_only=True,
        jobs_submitted=0, execution_ready=False, training_release=False)


def parse_submission(stdout):
    """Only a literal unique success receipt identifies a candidate job ID."""
    require(type(stdout) is bytes and len(stdout) <= 4096, 'SUBMISSION_OUTPUT_BOUND')
    match = re.fullmatch(rb'Job <([1-9][0-9]{0,18})> is submitted to queue <normal>\.\n?', stdout)
    require(match is not None, 'UNKNOWN_SUBMISSION_CONSUMED_NO_RETRY')
    job_id = int(match.group(1))
    require(job_id < 2**63, 'JOB_ID_BOUND')
    return job_id


def build_registration_query(job_id):
    require(type(job_id) is int and 0 < job_id < 2**63, 'EXACT_JOB_ID')
    return [BINDIR + 'bjobs', '-l', str(job_id)]


def validate_registration(state, expected_job_id):
    """Validate reviewed structured evidence, never invent absent bjobs fields."""
    build_registration_query(expected_job_id)
    require(type(state) is dict and set(state) == {'job_id', 'state', 'queue',
        'job_name', 'number_processes', 'rerunnable', 'array', 'requested_host'}, 'REVIEWED_FIELDS_REQUIRED')
    require(type(state['job_id']) is int and state['job_id'] == expected_job_id,
            'JOB_ID_MISMATCH')
    require(state['state'] == 'PSUSP' and state['queue'] == 'normal' and
            state['job_name'] == JOB_NAME, 'HELD_STATE_QUEUE_NAME')
    require(state['requested_host'] == 'bupt-vncs2', 'EXACT_REQUESTED_HOST_REQUIRED')
    require(type(state['number_processes']) is int and state['number_processes'] == 1
            and state['rerunnable'] is False and state['array'] is False,
            'SINGLE_NONARRAY_NONRERUNNABLE')
    return dict(job_id=expected_job_id, registration_fields_verified=True,
                automatic_resume=False, actual_job_memory_proof=False)
