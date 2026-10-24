"""One fixed read-only LSF host query. Importing/preparing never executes it."""
import base64
import hashlib
import json
import os
import platform
import stat
import sys
import types
from pathlib import Path

BASE_SHA256 = 'a1dfbfae37df48b9c2284a01e58f7e2ac1ca220519e7ed16403827bb143adfba'
CONFIG_SHA256 = '3f1babe5cb5ce50a5fe08a86b9befa3f28f6ba73e96c5cd180e5add540bdf76b'
BINDIR = '/cad/lsf/9.1/linux2.6-glibc2.3-x86_64/bin/'
HOST = 'bupt-vncs2'
RESPONSE_CAP = 32768


class HostInspectionError(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise HostInspectionError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii')


def _base(source):
    require(type(source) is bytes and len(source) <= 65536 and sha(source) == BASE_SHA256,
            'FROZEN_BASE_PIN')
    module = types.ModuleType('frozen_e98_host_query_definitions')
    exec(compile(source, '<frozen-e98-host-query-definitions>', 'exec'), module.__dict__)
    require(module.BINDIR == BINDIR and module.CLIENT_CAP == 8192, 'FROZEN_BASE_SCOPE')
    return module


def _metadata(info):
    return dict(dev=info.st_dev, ino=info.st_ino, size=info.st_size,
        mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns,
        mode=stat.S_IMODE(info.st_mode), nlink=info.st_nlink, uid=info.st_uid, gid=info.st_gid)


def _executable_metadata(directory):
    info = os.stat('bhosts', dir_fd=directory, follow_symlinks=False)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink >= 1
            and info.st_size > 0 and stat.S_IMODE(info.st_mode) & 0o111
            and not stat.S_IMODE(info.st_mode) & 0o022, 'BHOSTS_IDENTITY_UNSAFE')
    return _metadata(info)


def observe(base_source):
    """Query only bhosts -l bupt-vncs2; executable body is never read."""
    require(sys.platform.startswith('linux') and platform.node() == HOST, 'LINUX_HOST_REQUIRED')
    frozen = _base(base_source)
    config, config_info = frozen._read('/cad/lsf/conf/lsf.conf', 262144)
    require(sha(config) == CONFIG_SHA256, 'LSF_CONFIG_PIN')
    directory = frozen._directory(BINDIR.rstrip('/'))  # Every component O_NOFOLLOW.
    try:
        before = _executable_metadata(directory)
        argv = [BINDIR + 'bhosts', '-l', HOST]
        client = frozen._client(argv)
        after = _executable_metadata(directory)
        require(before == after, 'BHOSTS_METADATA_DRIFT')
    finally:
        os.close(directory)
    require(type(client['stdout']) is bytes and type(client['stderr']) is bytes and
            len(client['stdout']) + len(client['stderr']) <= 8192, 'CLIENT_OUTPUT_BOUND')
    bodies = {}
    for name in ('stdout', 'stderr'):
        raw = client[name]
        bodies[name] = dict(base64=base64.b64encode(raw).decode('ascii'), bytes=len(raw), sha256=sha(raw))
    result = dict(schema='e98-host-queue-observation-v1', host=HOST, job_scope=394238,
        observation_only=True,
        argv=argv, program_launch_attempts=1, client_status=client['status'],
        client_returncode=client['returncode'], output=bodies,
        config_sha256=CONFIG_SHA256, config_metadata=_metadata(config_info),
        executable_metadata_before=before, executable_metadata_after=after,
        identity_evidence='FIRST_OBSERVATION_NOT_PREVIOUSLY_PINNED',
        executable_body_read=False, causal_queue_reason_claimed=False,
        jobs_submitted=0, resume_calls=0, cancellation_calls=0, automatic_retries=0)
    require(len(encode(result)) <= RESPONSE_CAP, 'RESPONSE_BOUND')
    return result


def prepare_payload(reviewed_sha256):
    """Local preparation only. Independent review and transport remain external."""
    own = Path(__file__).read_bytes()
    require(type(reviewed_sha256) is str and sha(own) == reviewed_sha256, 'HELPER_REVIEW_PIN')
    frozen = Path(__file__).with_name('register_acceptance_job_e98.py').read_bytes()
    require(sha(frozen) == BASE_SHA256, 'FROZEN_BASE_PIN')
    suffix = ('\nimport resource\n'
        'for _kind,_cap in ((resource.RLIMIT_AS,268435456),(resource.RLIMIT_CPU,20)):\n'
        ' _soft,_hard=resource.getrlimit(_kind)\n'
        ' _chosen=min([_cap]+[v for v in (_soft,_hard) if v!=resource.RLIM_INFINITY])\n'
        ' resource.setrlimit(_kind,(_chosen,_chosen))\n'
        '_source=base64.b64decode(' + repr(base64.b64encode(frozen).decode('ascii')) + ',validate=True)\n'
        'sys.stdout.buffer.write(encode(observe(_source))+b"\\n")\n')
    payload = own + suffix.encode('ascii')
    compile(payload, '<e98-one-host-query>', 'exec')
    return dict(payload=payload, payload_sha256=sha(payload), response_cap=RESPONSE_CAP,
        exclusive_phase_required=True, automatic_retries=0, programs_launched_max=1,
        jobs_submitted=0, resume_calls=0, cancellation_calls=0)
