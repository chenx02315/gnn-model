"""Fixed four-case acceptance coordinator; no CLI or default authorization.

The caller must separately authenticate user approval, registration and fresh
resume reviews. A matching authorization dictionary is not proof of consent.
Nothing executes merely by importing this module.
"""
import hashlib
import json
import os
import re
import stat
import threading
import time

from . import prospective_tessent_acceptance_v1 as recipes

SCHEMA = 'prospective-acceptance-coordinator-v1'
AUTH_SCHEMA = 'e96-acceptance-authorization-v1'
SCOPE = 'E94_FOUR_NO_PATTERN_ACCEPTANCE_ONLY'
MAX_MEMORY = 536870912
JOB_SECONDS = 2700
JOURNAL_NAME = 'coordinator_events.jsonl'
MAX_RECORD = 65536
MAX_JOURNAL = 1048576
_WORKER = threading.Lock()


class CoordinatorError(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise CoordinatorError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      allow_nan=False).encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def validate_authorization(value, recipe_sha256):
    require(type(value) is dict and set(value) == {'schema', 'approved', 'job_id',
        'memory_cap_bytes', 'recipe_sha256', 'scope'}, 'AUTHORIZATION_KEYS')
    require(value['schema'] == AUTH_SCHEMA and value['approved'] is True and
            value['scope'] == SCOPE and value['recipe_sha256'] == recipe_sha256,
            'AUTHORIZATION_SCOPE_OR_RECIPE')
    require(type(value['job_id']) is int and 0 < value['job_id'] < 2**63,
            'AUTHORIZATION_JOB_ID')
    require(type(value['memory_cap_bytes']) is int and
            0 < value['memory_cap_bytes'] <= MAX_MEMORY,
            'AUTHORIZATION_MEMORY_CAP')
    return sha(canonical(value))


class _DurableJournal:
    """Exclusive fixed-name journal; an ACK follows fsync and exact readback."""
    def __init__(self, directory_fd):
        self.parent = directory_fd
        self.fd = None
        self.head = '0' * 64
        self.count = 0
        self.bytes = 0
        self.prefix_sha256 = sha(b'')
        try:
            self.fd = os.open(JOURNAL_NAME, os.O_RDWR | os.O_CREAT | os.O_EXCL |
                os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0), 0o600,
                dir_fd=self.parent)
            self.identity = self._check()
            os.fsync(self.parent)
        except BaseException:
            self.close()
            raise

    def _check(self):
        info = os.fstat(self.fd)
        named = os.stat(JOURNAL_NAME, dir_fd=self.parent, follow_symlinks=False)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                (info.st_dev, info.st_ino) == (named.st_dev, named.st_ino),
                'JOURNAL_IDENTITY')
        return info.st_dev, info.st_ino

    def append(self, kind, payload):
        require(kind in ('HEADER', 'MATERIALIZED', 'INTENT', 'PREFLIGHT', 'LAUNCHED',
                         'TERMINAL', 'STOP', 'CLOSE') and self.count < 32,
                'JOURNAL_EVENT_BOUND')
        require(self._check() == self.identity and
                os.fstat(self.fd).st_size == self.bytes, 'JOURNAL_CHANGED')
        previous = os.pread(self.fd, self.bytes, 0)
        require(len(previous) == self.bytes and sha(previous) == self.prefix_sha256,
                'JOURNAL_PREFIX_CHANGED')
        body = dict(schema=SCHEMA, seq=self.count + 1, kind=kind,
                    prev=self.head, payload=payload)
        digest = sha(canonical(body))
        raw = canonical(dict(body, sha256=digest)) + b'\n'
        require(len(raw) <= MAX_RECORD and self.bytes + len(raw) <= MAX_JOURNAL,
                'JOURNAL_BYTE_BOUND')
        os.lseek(self.fd, self.bytes, os.SEEK_SET)
        left = raw
        while left:
            written = os.write(self.fd, left)
            require(type(written) is int and 0 < written <= len(left), 'SHORT_WRITE')
            left = left[written:]
        os.fsync(self.fd)
        require(os.pread(self.fd, len(raw), self.bytes) == raw and
                self._check() == self.identity and
                os.fstat(self.fd).st_size == self.bytes + len(raw),
                'JOURNAL_ACK_READBACK')
        self.head = digest
        self.count += 1
        self.bytes += len(raw)
        self.prefix_sha256 = sha(previous + raw)
        return dict(seq=self.count, sha256=digest)

    def close(self):
        fd, parent = self.fd, self.parent
        self.fd = self.parent = None
        try:
            if fd is not None:
                os.close(fd)
        finally:
            if parent is not None:
                os.close(parent)


def _components():
    from .prospective_acceptance_materializer_v1 import Materializer
    from .prospective_acceptance_process_v1 import AcceptanceProcess
    return Materializer, AcceptanceProcess


def _error_code(exc):
    text = str(exc)
    return text if re.fullmatch(r'[A-Z][A-Z0-9_]{0,95}', text) else type(exc).__name__


def run_package(raw_e85, raw_e93, authorization, license_environment=None):
    """Execute only after external authorization/reviews; caller owns that gate.

    Library tests replace the two physical components. This is not a scheduler
    registration entry point, not an ATPG pilot, and not a training release.
    """
    plan = recipes.compile_acceptance(raw_e85, raw_e93, recipes.E85_SHA256,
                                      recipes.E93_SHA256)
    authority_sha = validate_authorization(authorization, plan['recipe_sha256'])
    require(_WORKER.acquire(False), 'SINGLE_WORKER_REQUIRED')
    materializer = None
    journal = None
    receipts = []
    started = time.monotonic()
    ordinal = 0
    launch_seen = False
    preflight_seen = False
    try:
        Materializer, Process = _components()
        materializer = Materializer(raw_e85, raw_e93, authorization)
        materializer.initialize_bundle()
        journal = _DurableJournal(materializer.journal_directory_fd())
        journal.append('HEADER', dict(authorization_assertion_sha256=authority_sha,
            job_id=authorization['job_id'], memory_cap_bytes=authorization['memory_cap_bytes'],
            recipe_sha256=plan['recipe_sha256'],
            caller_must_authenticate_user_and_registration_reviews=True))

        def event_sink(kind, payload):
            nonlocal launch_seen, preflight_seen
            require(1 <= ordinal <= 4, 'LAUNCH_ACK_ORDER')
            if kind == 'PREFLIGHT':
                require(not preflight_seen and not launch_seen, 'PREFLIGHT_ACK_ORDER')
                ack = journal.append('PREFLIGHT', dict(ordinal=ordinal, evidence=payload))
                require(time.monotonic() < started + JOB_SECONDS,
                        'JOB_WALL_BUDGET')
                preflight_seen = True
            else:
                require(kind == 'LAUNCHED' and preflight_seen and not launch_seen,
                        'LAUNCH_ACK_ORDER')
                ack = journal.append('LAUNCHED', dict(ordinal=ordinal, evidence=payload))
                launch_seen = True
            return ack

        process = Process(raw_e85, raw_e93, authorization,
                          license_environment=license_environment, event_sink=event_sink,
                          package_deadline=started + JOB_SECONDS)
        for ordinal, (circuit, transition, mode) in enumerate(recipes.ROSTER, 1):
            require(time.monotonic() - started < JOB_SECONDS, 'JOB_WALL_BUDGET')
            item = materializer.materialize_item(circuit, transition)
            require(item['circuit'] == circuit and item['transition'] == transition,
                    'MATERIALIZED_ROSTER_BINDING')
            journal.append('MATERIALIZED', dict(ordinal=ordinal, circuit=circuit,
                transition=transition, tcl_sha256=item['tcl_sha256'],
                translated_status_sha256=item['translated_status_sha256'],
                translation_manifest_sha256=item['translation_manifest_sha256']))
            require(JOB_SECONDS - (time.monotonic() - started) >= 600,
                    'INSUFFICIENT_ITEM_WALL_BUDGET')
            launch_seen = False
            preflight_seen = False
            journal.append('INTENT', dict(ordinal=ordinal, circuit=circuit,
                transition=transition, maximum_attempts=1, automatic_retries=0))
            require(JOB_SECONDS - (time.monotonic() - started) >= 600,
                    'INSUFFICIENT_ITEM_WALL_BUDGET')
            receipt = process.run_item(circuit, transition)
            require(type(receipt) is dict and receipt.get('circuit') == circuit and
                    receipt.get('transition') == transition and
                    receipt.get('actual_atpg_calls') == 0 and
                    receipt.get('execution_ready') is False and
                    receipt.get('training_release') is False, 'RECEIPT_BOUNDARY')
            journal.append('TERMINAL', dict(ordinal=ordinal, receipt=receipt))
            receipts.append(receipt)
            require(preflight_seen and launch_seen and receipt.get('accepted') is True and
                    receipt.get('cleanup_verified') is True and
                    type(receipt.get('returncode')) is int and receipt['returncode'] == 0,
                    'ACCEPTANCE_OR_CLEANUP_FAILED')
        require(time.monotonic() - started <= JOB_SECONDS, 'JOB_WALL_BUDGET')
        ack = journal.append('CLOSE', dict(status='FOUR_ACCEPTANCE_CASES_COMPLETE_ONLY',
            cases=len(receipts), actual_atpg_calls=0, training_release=False))
        return dict(schema=SCHEMA, status='FOUR_ACCEPTANCE_CASES_COMPLETE_ONLY',
            receipts=receipts, journal_head=ack['sha256'], actual_atpg_calls=0,
            execution_ready=False, training_release=False)
    except BaseException as exc:
        if journal is not None:
            try:
                journal.append('STOP', dict(ordinal=ordinal, error_code=_error_code(exc),
                    completed_receipts=len(receipts), automatic_retries=0,
                    no_further_launches=True))
            except BaseException:
                pass  # Partial durable evidence is retained, never repaired/restarted.
        raise
    finally:
        try:
            if journal is not None:
                journal.close()
        finally:
            try:
                if materializer is not None:
                    materializer.close()
            finally:
                _WORKER.release()
