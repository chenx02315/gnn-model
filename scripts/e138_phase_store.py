"""Create-once local E138 evidence store; no transport or execution authority.

Caller owns trusted staging, packet review, authority and clock validation.
This single-process store never resumes an existing phase, never authenticates
remote data, and is not a hostile-filesystem/concurrent-writer sandbox.
Validator callbacks run only after raw transport records have been fsynced.
"""
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import stat
import time

PHASE='v6_e138_clean_F_replay_r1'
ROLES=('capture','execution','readback')
CAPS={'capture':6291456,'execution':6291456,'readback':25165824}
RESULT_KEYS=frozenset(('stdout','stderr','exit_code','timeout','overflow','write_failed','threads_incomplete'))


class StoreFailure(ValueError):
    pass


def require(ok,code):
    if not ok:raise StoreFailure(code)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def _hex(value):return type(value) is str and len(value)==64 and all(c in '0123456789abcdef' for c in value)


def write_new(path,raw):
    with path.open('xb') as stream:
        require(stream.write(raw)==len(raw),'E138_LOCAL_SHORT_WRITE')
        stream.flush();os.fsync(stream.fileno())


class PhaseStore(object):
    """No network/callback on construction; create() is the first local write.

    Hashes bind bytes, not reviewer identity or consent. Success here does not
    qualify owned-clean root, release readback, or prove scientific success.
    """
    def __init__(self,staging,authorization_sha256,proposal_sha256):
        require(_hex(authorization_sha256) and _hex(proposal_sha256),'E138_LOCAL_GRANT_PINS')
        self.parent=Path(staging);self.phase=self.parent/PHASE
        self.auth=authorization_sha256;self.proposal=proposal_sha256
        self._created=False;self._closed=False;self._active=None;self._accepted=[]

    def create(self):
        require(not self._created and not self._closed,'E138_LOCAL_CREATE_ONCE')
        info=self.parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and not self.parent.is_symlink() and
            not getattr(info,'st_file_attributes',0)&1024,'E138_LOCAL_TRUSTED_STAGING_REQUIRED')
        # Exclusive phase directory is also the restart tombstone. Never delete
        # it when a later write fails; a new instance cannot reset this budget.
        self.phase.mkdir(exist_ok=False);self._created=True
        failed=False;record=None
        try:
            self._start=time.monotonic();self._utc=datetime.datetime.now(datetime.timezone.utc)
            self._domain=(platform.node(),time.get_clock_info('monotonic').implementation)
            self._identity=(self.phase.stat().st_dev,self.phase.stat().st_ino)
            record=dict(schema='e138-local-original-clock-v1',authorization_sha256=self.auth,
                proposal_sha256=self.proposal,start=self._start,end=self._start+3600,
                utc_start=self._utc.strftime('%Y-%m-%dT%H:%M:%S.%f%z'),
                utc_end=(self._utc+datetime.timedelta(seconds=3600)).strftime('%Y-%m-%dT%H:%M:%S.%f%z'),
                domain=dict(host=self._domain[0],clock=self._domain[1]))
            write_new(self.phase/'start.json',canonical(record))
        except BaseException:
            self._closed=True;failed=True
        if failed:raise StoreFailure('E138_LOCAL_START_SAVE_FAILED')
        return record

    def remaining(self):
        require(self._created and not self._closed,'E138_LOCAL_CLOSED_OR_NOT_CREATED')
        info=self.phase.lstat()
        require(stat.S_ISDIR(info.st_mode) and not self.phase.is_symlink() and
            not getattr(info,'st_file_attributes',0)&1024 and
            (info.st_dev,info.st_ino)==self._identity,'E138_LOCAL_PHASE_CHANGED')
        now=time.monotonic();utc=datetime.datetime.now(datetime.timezone.utc)
        elapsed=(utc-self._utc).total_seconds()
        require(type(now) in (int,float) and math.isfinite(now) and self._start<=now<self._start+3600 and
            (platform.node(),time.get_clock_info('monotonic').implementation)==self._domain and
            abs(elapsed-(now-self._start))<=5,'E138_LOCAL_ORIGINAL_CLOCK')
        result=min(self._start+3600-now,3600-elapsed)
        require(result>10,'E138_LOCAL_CLEANUP_RESERVE')
        return result

    def reserve(self,role,payload_sha256):
        require(role in ROLES and _hex(payload_sha256),'E138_LOCAL_ROLE_AND_PAYLOAD')
        self.remaining()
        require(self._active is None and len(self._accepted)<3 and role==ROLES[len(self._accepted)],
            'E138_LOCAL_ROLE_ORDER_OR_USED')
        directory=self.phase/role
        intent=dict(role=role,attempt_consumed=True,role_index=ROLES.index(role)+1,
            connections_max=3,automatic_retries=0,payload_sha256=payload_sha256)
        failed=False
        try:
            directory.mkdir(exist_ok=False);self._active=(role,directory)
            write_new(directory/'intent.json',canonical(intent))
        except BaseException:
            self._closed=True;failed=True
        if failed:raise StoreFailure('E138_LOCAL_INTENT_SAVE_FAILED')
        return intent

    def close(self,reason):
        require(reason in ('TRANSPORT_FAILED','VALIDATION_FAILED','LOCAL_PERSISTENCE_FAILED','CONTROLLER_STOP'),
            'E138_LOCAL_CLOSE_REASON')
        require(self._created and not self._closed,'E138_LOCAL_ALREADY_CLOSED')
        self._closed=True
        failed=False
        try:
            write_new(self.phase/'closed.json',canonical(dict(schema='e138-local-terminal-v1',reason=reason,
                role=self._active[0] if self._active else None,automatic_retries=0,execution_ready=False)))
        except BaseException:failed=True
        if failed:raise StoreFailure('E138_LOCAL_CLOSE_SAVE_FAILED')

    def record(self,result,validator):
        require(self._active is not None and not self._closed,'E138_LOCAL_ACTIVE_ROLE_REQUIRED')
        if not callable(validator):
            self.close('VALIDATION_FAILED')
            raise StoreFailure('E138_LOCAL_VALIDATOR_REQUIRED')
        role,directory=self._active
        # Only shape/bounds are inspected before saving. Raw JSON is not parsed.
        bounded=(type(result) is dict and set(result)==RESULT_KEYS and
            type(result['stdout']) is bytes and len(result['stdout'])<=CAPS[role] and
            type(result['stderr']) is bytes and len(result['stderr'])<=65536 and
            (result['exit_code'] is None or type(result['exit_code']) is int) and
            all(type(result[key]) is bool for key in ('timeout','overflow','write_failed','threads_incomplete')))
        if not bounded:
            self.close('TRANSPORT_FAILED')
            raise StoreFailure('E138_LOCAL_BOUNDED_TRANSPORT_RECORD')
        stdout,stderr=result['stdout'],result['stderr']
        transport={key:value for key,value in result.items() if key not in ('stdout','stderr')}
        transport.update(stdout_bytes=len(stdout),stdout_sha256=sha(stdout),stderr_bytes=len(stderr),stderr_sha256=sha(stderr))
        transport_raw=canonical(transport)
        failed=False
        try:
            write_new(directory/'stdout.raw',stdout)
            write_new(directory/'stderr.raw',stderr)
            write_new(directory/'transport.json',transport_raw)
        except BaseException:
            failed=True
        if failed:
            self.close('LOCAL_PERSISTENCE_FAILED')
            raise StoreFailure('E138_LOCAL_RAW_SAVE_FAILED')
        if result['exit_code']!=0 or stderr or any(result[key] for key in ('timeout','overflow','write_failed','threads_incomplete')):
            self.close('TRANSPORT_FAILED')
            raise StoreFailure('E138_LOCAL_TRANSPORT_FAILED_NO_RETRY')
        failed=False;value=None
        try:
            self.remaining()
            value=validator(stdout,stderr,transport_raw)
            require(type(value) is bytes and len(value)<=65536,'E138_LOCAL_VALIDATION_RECEIPT_BOUND')
            self.remaining()
        except BaseException:
            failed=True
        if failed:
            self.close('VALIDATION_FAILED')
            raise StoreFailure('E138_LOCAL_VALIDATION_FAILED_NO_RETRY')
        failed=False
        try:
            write_new(directory/'validation.raw',value)
            write_new(directory/'accepted.json',canonical(dict(schema='e138-local-persisted-validation-v1',
                role=role,authorization_sha256=self.auth,proposal_sha256=self.proposal,
                intent_sha256=sha((directory/'intent.json').read_bytes()),
                stdout_sha256=sha(stdout),stderr_sha256=sha(stderr),transport_sha256=sha(transport_raw),
                validation_sha256=sha(value),remote_authentication_proven=False,execution_ready=False)))
        except BaseException:
            failed=True
        if failed:
            self.close('LOCAL_PERSISTENCE_FAILED')
            raise StoreFailure('E138_LOCAL_RECEIPT_SAVE_FAILED')
        self._accepted.append(role);self._active=None
        return value
