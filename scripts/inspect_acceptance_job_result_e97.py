"""Read-only fixed Job 394230 observation. No automatic or remote execution."""
import base64
import hashlib
import json
import platform
import sys
import types
from pathlib import Path

JOB_ID = 394230
ROOT = '/temp/jiangchuanc/gnn_model_acceptance_e97_20261024_r1_bundle'
BASE_SHA256 = 'd9a30b7e94cfa3ed4fcff4306f09f147ada4c615210ecb5a2954362ad8e09a3a'
RESPONSE_CAP = 262144
FIXED_FILES = ((ROOT + '/registration/stdout.log', 16384),
               (ROOT + '/registration/stderr.log', 16384),
               (ROOT + '/runtime/gate.json', 131072))


class InspectionError(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise InspectionError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      allow_nan=False, separators=(',', ':')).encode('ascii')


def _body(raw):
    return dict(base64=base64.b64encode(raw).decode('ascii'), sha256=sha(raw), bytes=len(raw))


def _base(source):
    require(type(source) is bytes and len(source) <= 65536 and sha(source) == BASE_SHA256,
            'FROZEN_BASE_PIN')
    module = types.ModuleType('e97_frozen_registration_definitions')
    # The pinned source contains definitions only and no automatic entry point.
    exec(compile(source, '<e97-frozen-registration-definitions>', 'exec'), module.__dict__)
    require(module.ROOT == ROOT and module.CLIENT_CAP == 8192, 'FROZEN_BASE_SCOPE')
    return module


def observe(base_source):
    """One query plus three exact reads. Missing files are not success evidence."""
    require(sys.platform.startswith('linux') and platform.node() == 'bupt-vncs2', 'LINUX_HOST_REQUIRED')
    frozen = _base(base_source)
    query = frozen._client([frozen.BINDIR + 'bjobs', '-l', str(JOB_ID)])
    require(type(query['stdout']) is bytes and type(query['stderr']) is bytes and
            len(query['stdout']) + len(query['stderr']) <= frozen.CLIENT_CAP, 'CLIENT_OUTPUT_BOUND')
    files = []
    for path, cap in FIXED_FILES:
        try:
            raw, info = frozen._read(path, cap)
            require(type(raw) is bytes and len(raw) <= cap, 'FIXED_FILE_BOUND')
            files.append(dict(path=path, status='READ', body=_body(raw),
                identity=dict(dev=info.st_dev, ino=info.st_ino, size=info.st_size,
                    mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns)))
        except FileNotFoundError:
            files.append(dict(path=path, status='MISSING'))
    result = dict(schema='e97-job-result-observation-v1', job_id=JOB_ID,
        observation_only=True, scheduler_client_status=query['status'],
        scheduler_returncode=query['returncode'], scheduler_stdout=_body(query['stdout']),
        scheduler_stderr=_body(query['stderr']), files=files,
        programs_launched=1, jobs_submitted=0, resume_calls=0,
        kernel_gate_pass_claimed=False, execution_success_claimed=False,
        training_release=False)
    require(len(encode(result)) <= RESPONSE_CAP, 'RESPONSE_BOUND')
    return result


def prepare_payload(reviewed_sha256, phase_index=1):
    """Local preparation only. Controller owns exclusive phase storage/transport.

    The caller must supply an independently reviewed SHA for this exact helper.
    Indices 2..4 allow explicit read-only follow-ups, not an automatic retry loop.
    """
    require(type(phase_index) is int and 1 <= phase_index <= 4, 'FIXED_PHASE_INDEX')
    own_source = Path(__file__).read_bytes()
    require(type(reviewed_sha256) is str and sha(own_source) == reviewed_sha256,
            'HELPER_REVIEW_PIN')
    base_source = Path(__file__).with_name('register_acceptance_job_e97.py').read_bytes()
    require(sha(base_source) == BASE_SHA256, 'FROZEN_BASE_PIN')
    suffix = ('\nimport resource\n'
        'for _kind,_cap in ((resource.RLIMIT_AS,268435456),(resource.RLIMIT_CPU,20)):\n'
        ' _soft,_hard=resource.getrlimit(_kind)\n'
        ' _chosen=min([_cap]+[v for v in (_soft,_hard) if v!=resource.RLIM_INFINITY])\n'
        ' resource.setrlimit(_kind,(_chosen,_chosen))\n'
        '_source=base64.b64decode(' + repr(base64.b64encode(base_source).decode('ascii')) + ',validate=True)\n'
        '_result=observe(_source)\n'
        'sys.stdout.buffer.write(encode(_result)+b"\\n")\n')
    payload = own_source + suffix.encode('ascii')
    compile(payload, '<e97-read-only-result-inspection>', 'exec')
    return dict(payload=payload, payload_sha256=sha(payload), response_cap=RESPONSE_CAP,
        phase_name='v6_e97_job_result_observation_20261024_r' + str(phase_index),
        exclusive_phase_required=True, automatic_retries=0, programs_launched_max=1,
        jobs_submitted=0, resume_calls=0)
