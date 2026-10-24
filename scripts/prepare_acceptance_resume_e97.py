"""Phased E97 resume core. Nothing executes on import; reviews are external inputs.

Review digest trust anchors must come from independent review, not this module.
Requested -n1/nonarray evidence is not actual worker or kernel-memory proof.
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
ROOT = base.ROOT
MAX_AGE = 300


class ResumeError(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise ResumeError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':')).encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _host():
    require(sys.platform.startswith('linux') and platform.node() == 'bupt-vncs2', 'LINUX_HOST_REQUIRED')


def analyze_bjobs(raw):
    """Parse only explicit literal evidence; never infer omitted worker counts."""
    require(type(raw) is bytes and len(raw) <= base.CLIENT_CAP, 'QUERY_BYTES_BOUND')
    text = re.sub(r'\n {20,}', '', raw.decode('ascii'))
    gaps = []
    def exact(pattern, expected, gap):
        found = re.findall(pattern, text)
        if found != [expected]:
            gaps.append(gap)
    exact(r'(?:^|\n)Job <([^>]+)>', str(JOB_ID), 'EXACT_JOB_ID_NOT_PROVEN')
    exact(r'Job Name <([^>]+)>', 'gnn_e97_acceptance_r1', 'JOB_NAME_NOT_PROVEN')
    exact(r'Status <([^>]+)>', 'PSUSP', 'LATEST_PSUSP_NOT_PROVEN')
    exact(r'Queue <([^>]+)>', 'normal', 'NORMAL_QUEUE_NOT_PROVEN')
    exact(r'Specified Hosts <([^>]+)>', 'bupt-vncs2', 'REQUESTED_HOST_NOT_PROVEN')
    command = base.BINDIR + 'blaunch /usr/bin/python3 -I -S -B ' + ROOT + '/scripts/run_acceptance_job_e97.py'
    exact(r'Command <([^>]+)>', command, 'ENTRY_COMMAND_NOT_PROVEN')
    exact(r'Specified CWD <([^>]+)>', ROOT, 'BUNDLE_CWD_NOT_PROVEN')
    exact(r'RUNLIMIT\s*\n\s*([0-9.]+ min of [^\s]+)', '45.0 min of bupt-vncs2', 'RUNLIMIT_45MIN_NOT_PROVEN')
    exact(r'MEMLIMIT\s*\n\s*([0-9]+ M)\s', '512 M', 'REQUESTED_MEMORY_NOT_PROVEN')
    if text.count('Not Re-runnable') != 1:
        gaps.append('NONRERUNNABLE_NOT_PROVEN')
    if text.count('with hold') != 1:
        gaps.append('HELD_SUBMISSION_NOT_PROVEN')
    return dict(gaps=gaps, requested_worker_count_directly_observed=False,
        nonarray_directly_observed=False, actual_worker_count_verified=False,
        actual_job_memory_proof=False)


def _query():
    result = base._client([base.BINDIR + 'bjobs', '-l', str(JOB_ID)])
    require(result['status'] == 'CLIENT_COMPLETE' and type(result['returncode']) is int
            and result['returncode'] == 0 and result['stderr'] == b'', 'LATEST_QUERY_FAILED')
    return result['stdout']


def _registration_evidence():
    raw_intent, _ = base._read(ROOT + '/registration/intent.json', 16384)
    intent = json.loads(raw_intent.decode('ascii'), object_pairs_hook=base._pairs)
    require(intent.get('schema') == 'e97-registration-intent-v1' and
            intent.get('argv') == base._argv() and
            intent.get('manifest_sha256') == base.MANIFEST_SHA256 and
            intent.get('fresh_config_sha256') == base.CONFIG_SHA256 and
            intent.get('only_attempt_consumed_before_spawn') is True and
            type(intent.get('automatic_retries')) is int and intent['automatic_retries'] == 0,
            'DURABLE_REGISTRATION_INTENT')
    output, _ = base._read(ROOT + '/registration/bsub_stdout.bin', base.CLIENT_CAP)
    require(base._submission_id(dict(status='CLIENT_COMPLETE', returncode=0, stdout=output)) == JOB_ID,
            'STRICT_REGISTRATION_JOB_ID')
    return dict(intent_sha256=sha(raw_intent), submission_stdout_sha256=sha(output),
        requested_workers=1, requested_nonarray=True,
        evidence_basis='EXACT_DURABLE_ARGV_AND_STRICT_SUBMISSION_ID_NOT_ACTUAL_WORKER_STATE',
        worker_LSB_JOBINDEX_check_pending=True)


def observe():
    """Read-only phase: one exact job query; does not issue a permit or resume."""
    _host()
    base._verify()
    registration = _registration_evidence()
    raw = _query()
    observation = dict(schema='e97-pre-resume-observation-v1', job_id=JOB_ID,
        observed_at_epoch=int(time.time()), bjobs_stdout_sha256=sha(raw),
        bjobs_stdout_base64=base64.b64encode(raw).decode('ascii'),
        analysis=analyze_bjobs(raw), registration=registration,
        manifest_sha256=base.MANIFEST_SHA256, authorization_sha256=base.AUTH_SHA256,
        config_sha256=base.CONFIG_SHA256, resume_calls=0, reviews_granted=False)
    require(len(canonical(observation)) <= 16384, 'OBSERVATION_OUTPUT_BOUND')
    return observation


def validate_reviews(observation, review_bytes, trusted_review_pins):
    """Verify externally pinned independent receipts, never manufacture PASS.

    Both mappings have exactly registration and pre_resume keys. The caller's
    literal pins must be independently reviewed before this function is used.
    """
    keys = {'registration', 'pre_resume'}
    require(type(review_bytes) is dict and set(review_bytes) == keys and
            type(trusted_review_pins) is dict and set(trusted_review_pins) == keys,
            'EXTERNAL_REVIEW_INPUTS_REQUIRED')
    require(observation.get('schema') == 'e97-pre-resume-observation-v1' and
            type(observation.get('job_id')) is int and observation['job_id'] == JOB_ID,
            'OBSERVATION_IDENTITY')
    require(type(observation.get('observed_at_epoch')) is int and
            0 <= time.time() - observation['observed_at_epoch'] <= MAX_AGE, 'OBSERVATION_STALE')
    require(observation.get('manifest_sha256') == base.MANIFEST_SHA256 and
            observation.get('authorization_sha256') == base.AUTH_SHA256 and
            observation.get('config_sha256') == base.CONFIG_SHA256, 'OBSERVATION_SOURCE_PINS')
    require(observation.get('analysis', {}).get('gaps') == [], 'EXPLICIT_SCHEDULER_EVIDENCE_GAPS')
    observation_sha = sha(canonical(observation))
    for stage in sorted(keys):
        raw = review_bytes[stage]
        pin = trusted_review_pins[stage]
        require(type(raw) is bytes and len(raw) <= 8192 and type(pin) is str and
                re.fullmatch('[0-9a-f]{64}', pin) and sha(raw) == pin, 'INDEPENDENT_REVIEW_PIN')
        receipt = json.loads(raw.decode('ascii'), object_pairs_hook=base._pairs)
        require(type(receipt) is dict and set(receipt) == {'schema', 'stage', 'job_id',
            'passed', 'independent', 'reviewer', 'issued_at_epoch', 'observation_sha256',
            'composite_requested_worker_nonarray_accepted'}, 'REVIEW_KEYS')
        require(receipt['schema'] == 'e97-independent-resume-review-v1' and
                receipt['stage'] == stage and type(receipt['job_id']) is int and
                receipt['job_id'] == JOB_ID and receipt['passed'] is True and
                receipt['independent'] is True and type(receipt['reviewer']) is str and
                re.fullmatch('[A-Za-z0-9_.-]{1,64}', receipt['reviewer']) and
                receipt['observation_sha256'] == observation_sha and
                receipt['composite_requested_worker_nonarray_accepted'] is True,
                'INDEPENDENT_REVIEW_REQUIRED')
        require(type(receipt['issued_at_epoch']) is int and
                observation['observed_at_epoch'] <= receipt['issued_at_epoch'] <= time.time()
                and 0 <= time.time() - receipt['issued_at_epoch'] <= MAX_AGE, 'REVIEW_STALE')
    return observation_sha


def _verify_resume_binary():
    directory = base._directory(base.BINDIR.rstrip('/'))
    try:
        info = os.stat('bresume', dir_fd=directory, follow_symlinks=False)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 4 and
            (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_uid,
             info.st_gid, stat.S_IMODE(info.st_mode)) ==
            (43, 1049102, 3021440, 1404504463000000000, 0, 10007, 0o755), 'RESUME_BINARY_PIN')
    finally:
        os.close(directory)


def resume_once(observation, review_bytes, trusted_review_pins):
    """Explicit mutation phase, never called by observe or on import.

    Requires a separately reviewed invocation. Any partial intent/permit is
    retained and prevents repeating this one-shot workflow.
    """
    _host()
    observation_sha = validate_reviews(observation, review_bytes, trusted_review_pins)
    base._verify()
    _verify_resume_binary()
    require(_registration_evidence() == observation['registration'], 'REGISTRATION_EVIDENCE_CHANGED')
    latest = _query()
    require(sha(latest) == observation['bjobs_stdout_sha256'] and
            analyze_bjobs(latest)['gaps'] == [], 'LATEST_JOB_CHANGED_REVIEW_AGAIN')
    validate_reviews(observation, review_bytes, trusted_review_pins)
    root = base._directory(ROOT)
    directory = None
    try:
        os.mkdir('resume', 0o700, dir_fd=root)
        os.fsync(root)
        directory = os.open('resume', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
        info = os.fstat(directory)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
                stat.S_IMODE(info.st_mode) == 0o700, 'RESUME_DIRECTORY')
        base._persist(directory, 'intent.json', canonical(dict(schema='e97-resume-intent-v1',
            job_id=JOB_ID, observation_sha256=observation_sha,
            review_pins=trusted_review_pins, attempt_consumed=True, automatic_retries=0)))
        permit = dict(schema='e97-resume-permit-v1', job_id=JOB_ID,
            registration_review_passed=True, pre_resume_review_passed=True,
            authorization_sha256=base.AUTH_SHA256, code_manifest_sha256=base.MANIFEST_SHA256,
            issued_at_epoch=int(time.time()))
        base._persist(root, 'e97_resume_permit.json', canonical(permit))
        # No change after a stale review: partial evidence and permit stay retained.
        validate_reviews(observation, review_bytes, trusted_review_pins)
        outcome = base._client([base.BINDIR + 'bresume', str(JOB_ID)])
        base._persist(directory, 'stdout.bin', outcome['stdout'])
        base._persist(directory, 'stderr.bin', outcome['stderr'])
        accepted = (outcome['status'] == 'CLIENT_COMPLETE' and type(outcome['returncode']) is int
            and outcome['returncode'] == 0 and outcome['stderr'] == b'' and
            outcome['stdout'] == b'Job <394230> is being resumed\n')
        result = dict(schema='e97-resume-result-v1', job_id=JOB_ID, resume_attempted=True,
            resume_acknowledged=accepted, status='RESUME_ACK_ONLY' if accepted else
            'UNKNOWN_RESUME_CONSUMED_NO_RETRY', automatic_retries=0,
            client_status=outcome['status'], returncode=outcome['returncode'],
            execution_success_verified=False, training_release=False)
        base._persist(directory, 'result.json', canonical(result))
        return result
    finally:
        if directory is not None:
            os.close(directory)
        os.close(root)
