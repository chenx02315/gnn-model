"""Default-disabled A-only adapter. No CLI, grant discovery, or live invocation.

Verified source bytes and cached host keys are separate trust boundaries; an
attribute or matching hash is not user consent. Controller integration remains
pending: send returns the COMPLETE native eight-key result, not PhaseStore's
seven-key projection. Local SSH cleanup does not prove remote termination.
"""
import math
from pathlib import Path
import threading
import time
import types

from scripts import e138_reviewed_envelope as envelope
from src.data import physical_e138_contract as contract

FROZEN = None
AUTHORIZATION_SHA256 = None
PROPOSAL_SHA256 = None
HELPER_SHA256 = 'e0b1e62352781f96dc7d0e5a2a1a27e7f278b63c8aaaa07dbd946c1795c0f434'
HOST = 'bupt-vncs2'
ENDPOINT = 'vnc.buptic.top'
HOST_KEY = 'SHA256:9+c0w59UN6NMPA6MnG45jtRW63JT9gKLTBxtnnSpJqM'
ROLES = ('capture', 'execution', 'readback')
LIMITS = dict(capture=60, execution=2400, readback=60)
CAPS = dict(capture=6291456, execution=6291456, readback=25165824)
RESULT_KEYS = frozenset(('stdout','stderr','exit_code','timeout','overflow',
                         'write_failed','threads_incomplete','remote_termination_verified'))
require = contract.require


class PinnedTransport:
    scope = 'PINNED_A_SSH_TRANSPORT_NOT_CONTROLLER_RELEASE'
    remote_termination_proven = False

    def __init__(self, authority, proposal):
        f = FROZEN
        require(type(f) is dict and set(f) == {'authorization_sha256','proposal_sha256'} and
                contract._hex(AUTHORIZATION_SHA256) and contract._hex(PROPOSAL_SHA256) and
                f['authorization_sha256'] == AUTHORIZATION_SHA256 and
                f['proposal_sha256'] == PROPOSAL_SHA256, 'E138_TRANSPORT_EXTERNAL_RELEASE_REQUIRED')
        contract.check_authority(authority, proposal, AUTHORIZATION_SHA256, PROPOSAL_SHA256)
        path = Path(__file__).resolve().with_name('run_prospective_metadata_v1.py')
        raw = path.read_bytes()
        require(0 < len(raw) <= 65536 and envelope.sha(raw) == HELPER_SHA256,
                'E138_TRANSPORT_HELPER_SOURCE_CHANGED')
        namespace = dict(__name__='_e138_verified_transport_private', __file__=str(path))
        exec(compile(raw, '<e138-verified-transport>', 'exec'), namespace)
        require(namespace['HOSTS']['A'] == (ENDPOINT, ENDPOINT, HOST_KEY),
                'E138_TRANSPORT_FIXED_A_IDENTITY')
        self._namespace = namespace
        self._index = 0
        self._terminal = False
        self._lock = threading.Lock()

    def send(self, *, host, role, payload, remote_command, timeout):
        require(self._lock.acquire(blocking=False), 'E138_TRANSPORT_CONCURRENT_CALL')
        try:
            return self._send(host, role, payload, remote_command, timeout)
        finally:
            self._lock.release()

    def _send(self, host, role, payload, remote_command, timeout):
        started = time.monotonic()
        require(not self._terminal and self._index < 3, 'E138_TRANSPORT_TERMINAL')
        # Invalid candidates terminally stop this instance before subprocesses.
        failed = False
        try:
            require(type(host) is str and host == HOST and role == ROLES[self._index] and
                    type(payload) is bytes and 0 < len(payload) <= envelope.MAX_PAYLOAD and
                    type(remote_command) is str and
                    remote_command == envelope.remote_command(role, envelope.sha(payload)) and
                    type(timeout) in (int,float) and math.isfinite(timeout) and
                    0 < timeout <= LIMITS[role], 'E138_TRANSPORT_EXACT_CALL')
            # Consume BEFORE cached-key subprocess or SSH. No automatic retries.
            self._index += 1
            require(started + timeout - time.monotonic() > 20,
                    'E138_TRANSPORT_KEY_AND_CLEANUP_RESERVE')
            namespace = dict(self._namespace, TIMEOUT=timeout,
                             HOSTS={'A': (ENDPOINT, ENDPOINT, HOST_KEY)})
            def private(name):
                fn = namespace[name]
                return types.FunctionType(fn.__code__, namespace)
            require(private('verify_cached_host')('A') == HOST_KEY,
                    'E138_TRANSPORT_CACHED_KEY')
            command = ['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
                '-o','UpdateHostKeys=no','-o','ConnectTimeout=8','-o','HostKeyAlgorithms=ssh-ed25519',
                ENDPOINT,remote_command]
            # Command prefix is the pinned helper's A-only argv, never B/wire argv.
            require(private('command')('A')[:-1] == command[:-1], 'E138_TRANSPORT_FIXED_ARGV')
            # The historical helper does not catch reader thread exceptions or
            # detect short stdin writes. Private wrappers close those gaps while
            # preserving the pinned helper and all native result fields.
            pipe_failed = threading.Event()
            launch_overrun = threading.Event()
            startup_result = [None]
            class StartupStopped(Exception):
                pass
            original_subprocess = namespace['subprocess']
            class Pipe:
                def __init__(self, stream): self.stream = stream
                def read(self, size):
                    try:
                        value = self.stream.read(size)
                        if type(value) is not bytes: raise OSError('PIPE_READ_TYPE')
                        return value
                    except BaseException:
                        pipe_failed.set()
                        return b''
                def write(self, raw):
                    try:
                        count = self.stream.write(raw)
                        if type(count) is not int or count != len(raw): raise OSError('PIPE_SHORT_WRITE')
                        return count
                    except BaseException:
                        pipe_failed.set()
                        raise OSError('E138_PIPE_WRITE_FAILED') from None
                def close(self):
                    try: self.stream.close()
                    except BaseException:
                        pipe_failed.set()
                        raise OSError('E138_PIPE_CLOSE_FAILED') from None
            def popen(*args, **kwargs):
                remaining = started + timeout - time.monotonic() - 10
                require(remaining > 0, 'E138_TRANSPORT_PRESPAWN_WINDOW_EXPIRED')
                process = original_subprocess.Popen(*args, **kwargs)
                # Popen itself has no timeout. Its delay must never open another
                # active budget once the pinned helper starts its own timer.
                remaining = started + timeout - time.monotonic() - 10
                namespace['TIMEOUT'] = max(.01, remaining)
                if remaining <= 0:
                    launch_overrun.set()
                    try:
                        process.kill()
                    except BaseException:
                        pipe_failed.set()
                    try:
                        process.wait(timeout=5)
                    except BaseException:
                        pipe_failed.set()
                    for name in ('stdin','stdout','stderr'):
                        try: getattr(process,name).close()
                        except BaseException: pipe_failed.set()
                    code = getattr(process, 'returncode', None)
                    # No reader/writer threads are started after startup expiry.
                    # Unread pipe bytes are unknown, not claimed preserved.
                    startup_result[0] = dict(stdout=b'',stderr=b'',
                        exit_code=code if type(code) is int else None,timeout=True,
                        overflow=False,write_failed=False,threads_incomplete=True,
                        remote_termination_verified=False)
                    raise StartupStopped()
                for name in ('stdin','stdout','stderr'):
                    setattr(process, name, Pipe(getattr(process, name)))
                return process
            namespace['subprocess'] = types.SimpleNamespace(Popen=popen,PIPE=original_subprocess.PIPE,
                TimeoutExpired=original_subprocess.TimeoutExpired)
            active = started + timeout - time.monotonic() - 10
            require(active > 0, 'E138_TRANSPORT_EXHAUSTED_TOTAL_WINDOW')
            namespace['TIMEOUT'] = active
            try:
                result = private('transport')(command, payload, CAPS[role])
            except StartupStopped:
                result = startup_result[0]
            if pipe_failed.is_set(): result['threads_incomplete'] = True
            if launch_overrun.is_set() or time.monotonic() >= started + timeout:
                result['timeout'] = True
            require(type(result) is dict and set(result) == RESULT_KEYS and
                    type(result['stdout']) is bytes and type(result['stderr']) is bytes and
                    len(result['stdout']) + len(result['stderr']) <= CAPS[role] and
                    result['remote_termination_verified'] is False and
                    (result['exit_code'] is None or type(result['exit_code']) is int) and
                    all(type(result[k]) is bool for k in
                        ('timeout','overflow','write_failed','threads_incomplete')),
                    'E138_TRANSPORT_NATIVE_RESULT')
            if self._index == 3 or result['exit_code'] != 0 or result['stderr'] or any(result[k]
                    for k in ('timeout','overflow','write_failed','threads_incomplete')):
                self._terminal = True
            return result
        except BaseException:
            failed = True
        if failed:
            self._terminal = True
            raise ValueError('E138_TRANSPORT_STOPPED_FIRST_FAILURE') from None
