"""E98 exact old-job retirement. Import is inert; mutation needs external review.

No submission/resume, no executable-body reads, no old-file writes or retries.
The controller must pin this source, frozen base and authorization before use.
"""
import base64
import hashlib
import json
import os
import platform
import re
import stat
import sys
import time

from scripts import register_acceptance_job_e97 as base

JOB_ID = 394230
OLD_ROOT = '/temp/jiangchuanc/gnn_model_acceptance_e97_20261024_r1_bundle'
CONTROL_PARENT = '/temp/jiangchuanc'
CONTROL_NAME = 'gnn_model_acceptance_e98_20261024_r1_control'
AUTH_SHA256 = 'da27486a2ed20d55c8b8de7071882364c9648ab49054d2a319d07cb2a73076f5'
MAX_AGE = 300
OUTPUT_CAP = 32768
TERMINAL = ('DONE', 'EXIT')
ACTIVE = ('PEND', 'RUN', 'PSUSP', 'USUSP', 'SSUSP', 'WAIT', 'PROV', 'UNKWN', 'ZOMBI')


class RetireError(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise RetireError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _host():
    require(sys.platform.startswith('linux') and platform.node() == 'bupt-vncs2',
            'E98_LINUX_HOST_REQUIRED')


def _metadata():
    fd = base._directory(base.BINDIR.rstrip('/'))
    try:
        row = os.stat('bkill', dir_fd=fd, follow_symlinks=False)
        require(stat.S_ISREG(row.st_mode) and row.st_mode & 0o111 and
                row.st_nlink >= 1 and row.st_size > 0, 'E98_BKILL_TYPE')
        return dict(path=base.BINDIR + 'bkill', dev=row.st_dev, ino=row.st_ino,
                    uid=row.st_uid, gid=row.st_gid, mode=stat.S_IMODE(row.st_mode),
                    nlink=row.st_nlink, size=row.st_size, mtime_ns=row.st_mtime_ns,
                    ctime_ns=row.st_ctime_ns)
    finally:
        os.close(fd)


def _client_record(result):
    require(type(result) is dict and type(result.get('stdout')) is bytes and
            type(result.get('stderr')) is bytes and
            len(result['stdout']) + len(result['stderr']) <= 8192, 'E98_CLIENT_BOUND')
    return dict(status=result['status'], returncode=result['returncode'],
                stdout_base64=base64.b64encode(result['stdout']).decode('ascii'),
                stderr_base64=base64.b64encode(result['stderr']).decode('ascii'))


def _state(result):
    _client_record(result)
    require(result['status'] == 'CLIENT_COMPLETE' and
            type(result['returncode']) is int and result['returncode'] == 0 and
            result['stderr'] == b'', 'E98_QUERY_UNCONFIRMED')
    text = re.sub(r'\n {20,}', '', result['stdout'].decode('ascii'))
    command = (base.BINDIR + 'blaunch /usr/bin/python3 -I -S -B ' +
               OLD_ROOT + '/scripts/run_acceptance_job_e97.py')
    for pattern, expected in ((r'(?:^|\n)Job <([^>]+)>', str(JOB_ID)),
                              (r'Job Name <([^>]+)>', 'gnn_e97_acceptance_r1'),
                              (r'Command <([^>]+)>', command),
                              (r'Specified CWD <([^>]+)>', OLD_ROOT)):
        require(re.findall(pattern, text) == [expected], 'E98_EXACT_OLD_JOB_REQUIRED')
    states = re.findall(r'Status <([^>]+)>', text)
    require(len(states) == 1 and states[0] in TERMINAL + ACTIVE, 'E98_STATE_UNKNOWN')
    return states[0]


def _query():
    return base._client([base.BINDIR + 'bjobs', '-l', str(JOB_ID)])


def observe():
    """One read-only exact-ID query plus fixed bkill metadata discovery."""
    _host()
    result = _query()
    state = _state(result)
    value = dict(schema='e98-retirement-observation-v1', job_id=JOB_ID,
                 observed_at_epoch=int(time.time()), authorization_sha256=AUTH_SHA256,
                 state=state, query=_client_record(result), bkill_metadata=_metadata(),
                 jobs_submitted=0, cancellation_calls=0, remote_writes=0)
    require(len(canonical(value)) <= OUTPUT_CAP, 'E98_OUTPUT_BOUND')
    return value


def _review(observation, review_bytes, trusted_review_sha):
    require(type(observation) is dict and
            observation.get('schema') == 'e98-retirement-observation-v1' and
            type(observation.get('job_id')) is int and observation['job_id'] == JOB_ID and
            observation.get('authorization_sha256') == AUTH_SHA256,
            'E98_OBSERVATION_IDENTITY')
    require(type(observation.get('observed_at_epoch')) is int and
            0 <= time.time() - observation['observed_at_epoch'] <= MAX_AGE,
            'E98_OBSERVATION_STALE')
    require(type(review_bytes) is bytes and len(review_bytes) <= 8192 and
            type(trusted_review_sha) is str and
            re.fullmatch('[0-9a-f]{64}', trusted_review_sha) and
            sha(review_bytes) == trusted_review_sha, 'E98_EXTERNAL_REVIEW_PIN')
    review = json.loads(review_bytes.decode('ascii'), object_pairs_hook=base._pairs)
    require(type(review) is dict and set(review) == {'schema', 'job_id', 'passed',
            'independent', 'observation_sha256', 'issued_at_epoch'}, 'E98_REVIEW_KEYS')
    require(review['schema'] == 'e98-independent-retirement-review-v1' and
            type(review['job_id']) is int and review['job_id'] == JOB_ID and
            review['passed'] is True and review['independent'] is True and
            review['observation_sha256'] == sha(canonical(observation)),
            'E98_INDEPENDENT_REVIEW_REQUIRED')
    require(type(review['issued_at_epoch']) is int and
            observation['observed_at_epoch'] <= review['issued_at_epoch'] <= time.time() and
            0 <= time.time() - review['issued_at_epoch'] <= MAX_AGE, 'E98_REVIEW_STALE')


def _result(status, state, calls, **extra):
    value = dict(schema='e98-retirement-result-v1', job_id=JOB_ID, status=status,
                 observed_state=state, terminal_confirmed=state in TERMINAL,
                 cancellation_calls=calls, automatic_retries=0, jobs_submitted=0,
                 training_release=False, actual_atpg_calls=0)
    value.update(extra)
    require(len(canonical(value)) <= OUTPUT_CAP, 'E98_OUTPUT_BOUND')
    return value


def _terminal_proof(directory, state, query, attempted):
    require(state in TERMINAL and type(attempted) is bool, 'E98_TERMINAL_PROOF_REQUIRED')
    proof = dict(schema='e98-old-job-retirement-result-v1', job_id=JOB_ID,
                 terminal_confirmed=True, terminal_state=state,
                 latest_bjobs_stdout_sha256=sha(query['stdout']),
                 latest_bjobs_stdout_bytes=len(query['stdout']),
                 cancellation_attempted=attempted, authorization_sha256=AUTH_SHA256)
    base._persist(directory, 'retirement_result.json', canonical(proof))
    return proof


def retire_once(observation, review_bytes, trusted_review_sha):
    """Review-bound exact-ID cancellation; any existing control forbids repeat.

    An ambiguous bkill outcome still consumes the only attempt. A later
    read-only observation may establish terminal state; never call this again.
    """
    _host()
    _review(observation, review_bytes, trusted_review_sha)
    require(_metadata() == observation['bkill_metadata'], 'E98_BKILL_METADATA_CHANGED')
    before = _query()
    state = _state(before)
    parent = base._directory(CONTROL_PARENT)
    directory = None
    try:
        os.mkdir(CONTROL_NAME, 0o700, dir_fd=parent)
        os.fsync(parent)
        directory = os.open(CONTROL_NAME, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent)
        row = os.fstat(directory)
        require(stat.S_ISDIR(row.st_mode) and row.st_uid == os.getuid() and
                stat.S_IMODE(row.st_mode) == 0o700, 'E98_CONTROL_DIRECTORY')
        base._persist(directory, 'before_stdout.bin', before['stdout'])
        base._persist(directory, 'before_stderr.bin', before['stderr'])
        if state in TERMINAL:
            proof = _terminal_proof(directory, state, before, False)
            return _result('ALREADY_TERMINAL', state, 0,
                           query=_client_record(before), terminal_proof=proof)
        _review(observation, review_bytes, trusted_review_sha)
        require(_metadata() == observation['bkill_metadata'], 'E98_BKILL_METADATA_CHANGED')
        base._persist(directory, 'cancellation_intent.json', canonical(dict(
            schema='e98-cancellation-intent-v1', job_id=JOB_ID,
            argv=[base.BINDIR + 'bkill', str(JOB_ID)], attempt_consumed=True,
            automatic_retries=0, authorization_sha256=AUTH_SHA256,
            observation_sha256=sha(canonical(observation)), review_sha256=trusted_review_sha)))
        killed = base._client([base.BINDIR + 'bkill', str(JOB_ID)])
        _client_record(killed)
        base._persist(directory, 'bkill_stdout.bin', killed['stdout'])
        base._persist(directory, 'bkill_stderr.bin', killed['stderr'])
        # Preserve outcome even if the final query cannot start or confirm.
        base._persist(directory, 'bkill_outcome.json', canonical(_client_record(killed)))
        try:
            after = _query()
        except Exception:
            after = dict(status='CLIENT_FAILURE_UNKNOWN', returncode=None,
                         stdout=b'', stderr=b'')
        _client_record(after)
        base._persist(directory, 'after_stdout.bin', after['stdout'])
        base._persist(directory, 'after_stderr.bin', after['stderr'])
        try:
            state = _state(after)
        except (ValueError, UnicodeError):
            state = 'UNKNOWN'
        status = ('TERMINAL_CONFIRMED' if state in TERMINAL else
                  'CANCELLATION_PENDING_CONFIRMATION')
        value = _result(status, state, 1, cancellation=_client_record(killed),
                        query=_client_record(after))
        summary = dict((k, v) for k, v in value.items() if k not in ('cancellation', 'query'))
        summary.update(bkill_stdout_sha256=sha(killed['stdout']),
                       bkill_stderr_sha256=sha(killed['stderr']),
                       after_stdout_sha256=sha(after['stdout']),
                       after_stderr_sha256=sha(after['stderr']))
        base._persist(directory, 'cancel_result.json', canonical(summary))
        if state in TERMINAL:
            value['terminal_proof'] = _terminal_proof(directory, state, after, True)
        require(len(canonical(value)) <= OUTPUT_CAP, 'E98_OUTPUT_BOUND')
        return value
    finally:
        if directory is not None:
            os.close(directory)
        os.close(parent)


def finalize_terminal():
    """One read-only same-ID query; exclusively write terminal proof if ready.

    Only follows this helper's retained cancellation result, never bkill again.
    Pending evidence is not a terminal proof and is never overwritten.
    """
    _host()
    directory = base._directory(CONTROL_PARENT + '/' + CONTROL_NAME)
    try:
        row = os.fstat(directory)
        require(stat.S_ISDIR(row.st_mode) and row.st_uid == os.getuid() and
                stat.S_IMODE(row.st_mode) == 0o700, 'E98_CONTROL_DIRECTORY')
        raw, _ = base._read(CONTROL_PARENT + '/' + CONTROL_NAME + '/cancel_result.json', 16384)
        prior = json.loads(raw.decode('ascii'), object_pairs_hook=base._pairs)
        require(prior.get('schema') == 'e98-retirement-result-v1' and
                type(prior.get('job_id')) is int and prior['job_id'] == JOB_ID and
                type(prior.get('cancellation_calls')) is int and prior['cancellation_calls'] == 1,
                'E98_RETAINED_CANCELLATION_REQUIRED')
        latest = _query()
        state = _state(latest)
        if state not in TERMINAL:
            return _result('CANCELLATION_PENDING_CONFIRMATION', state, 0,
                           query=_client_record(latest))
        base._persist(directory, 'terminal_stdout.bin', latest['stdout'])
        base._persist(directory, 'terminal_stderr.bin', latest['stderr'])
        proof = _terminal_proof(directory, state, latest, True)
        return _result('TERMINAL_CONFIRMED', state, 0,
                       query=_client_record(latest), terminal_proof=proof)
    finally:
        os.close(directory)
