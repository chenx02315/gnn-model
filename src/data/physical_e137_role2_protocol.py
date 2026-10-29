"""Bounded role2 protocol coordinator; missing release capabilities deny by default.

Authenticated first-call/role1 loading, source-bundle loading, private runtime
bootstrap and physical instance assembly must be supplied by reviewed code.
This module cannot authenticate a reviewer, a transport or an engine by itself.
"""
import math
import struct
from . import physical_engine_ack_e137 as ack
from . import physical_engine_selector_e137 as selector

require,sha,canonical,decode = ack.require,ack.sha,ack.canonical,ack.decode
CAP = 65536
AUTH_SHA256 = None
INSTANCE_ASSEMBLER_SHA256 = None
INSTANCE_ASSEMBLER = None
FIRST_CALL_VERIFIER_SHA256 = None
FIRST_CALL_VERIFIER = None
SELECTOR_SHA256 = 'efcf80e98b4a26051d057320e4dc75882929545fbd42be41be4336a2586d5d73'
ACK_SHA256 = '5132a0f5a611d21507d3cc7df0173bb7fbb46ef3e9d4a69d6c77bc2e29ecabb6'


def _hash(value):
    return type(value) is str and ack._hex(value)


def write_frame(stream,raw,tick):
    require(type(raw) is bytes and 0 < len(raw) <= CAP,'ROLE2_FRAME_BOUND')
    view = memoryview(struct.pack('!I',len(raw))+raw)
    while view:
        tick()
        count = stream.write(view[:65536])
        require(type(count) is int and 0 < count <= min(len(view),65536),'ROLE2_FRAME_WRITE')
        view = view[count:]
    stream.flush()


def read_frame(stream,tick,save_raw):
    """save_raw receives complete wire bytes BEFORE JSON or semantic parsing."""
    def take(count):
        chunks = []
        while count:
            tick()
            raw = stream.read(min(count,65536))
            require(type(raw) is bytes and 0 < len(raw) <= min(count,65536),'ROLE2_SHORT_FRAME')
            chunks.append(raw);count -= len(raw)
        return b''.join(chunks)
    prefix = take(4)
    size = struct.unpack('!I',prefix)[0]
    if not 0 < size <= CAP:
        save_raw(prefix)
        raise ValueError('ROLE2_FRAME_BOUND')
    raw = take(size)
    save_raw(prefix+raw)
    return raw


def _capability(function,pin,code):
    require(_hash(pin) and callable(function) and getattr(function,'__source_sha256__',None) == pin,code)


def decode_frame_bytes(wire):
    """Standalone bounded frame including exact EOF; not a live pipe EOF probe."""
    require(type(wire) is bytes and 4 < len(wire) <= CAP+4,'ROLE2_FRAME_BOUND')
    count = struct.unpack('!I',wire[:4])[0]
    require(0 < count <= CAP and len(wire) == count+4,'ROLE2_FRAME_LENGTH_OR_TRAILING_BYTES')
    return wire[4:]


class Session(object):
    """One in-process attempt. Cross-process debit and authenticated callbacks external."""
    def __init__(self):
        self.used = False

    def run(self,package,now,utc_now,bootstrap,snapshot,emit,receive_review,persist,worker):
        # Never invoke a callback, clock, FS or process before default release gates.
        require(_hash(AUTH_SHA256),'ROLE2_ACTUAL_AUTHORITY_NOT_FROZEN')
        _capability(FIRST_CALL_VERIFIER,FIRST_CALL_VERIFIER_SHA256,'ROLE2_FIRST_CALL_VERIFIER_MISSING')
        _capability(INSTANCE_ASSEMBLER,INSTANCE_ASSEMBLER_SHA256,'ROLE2_INSTANCE_ASSEMBLER_MISSING')
        require(not self.used,'ROLE2_ONE_ATTEMPT_NO_RETRY')
        self.used = True
        clock = FIRST_CALL_VERIFIER(package)
        require(type(clock) is dict and set(clock) == {'authorization_sha256','clock_sha256','role2_payload_sha256',
            'remote_start','remote_end','utc_end','nonce'} and clock['authorization_sha256'] == AUTH_SHA256 and
            all(_hash(clock[k]) for k in ('clock_sha256','role2_payload_sha256','nonce')) and
            all(type(clock[k]) in (int,float) and math.isfinite(clock[k]) for k in ('remote_start','remote_end','utc_end')) and
            clock['remote_end'] == clock['remote_start']+3600,'ROLE2_ORIGINAL_CLOCK')
        start = now()
        connection_end = min(clock['remote_end'],start+2400)
        def tick():
            current,utc = now(),utc_now()
            require(type(current) in (int,float) and math.isfinite(current) and
                clock['remote_start'] <= current < connection_end-10 and
                type(utc) in (int,float) and math.isfinite(utc) and utc < clock['utc_end'],'ROLE2_ORIGINAL_DEADLINE')
        tick()
        persist('role2_intent.json',canonical(dict(clock,connection_end=connection_end,bootstrap_max=1,selfchecks_max=3,
            tool_launches_max=1,automatic_retries=0)))
        # bootstrap must supervise exactly one <=30s/64KiB fixed module child;
        # raw environment values remain ONLY in this RAM mapping.
        environment,bootstrap_metadata = bootstrap(tick)
        require(type(environment) is dict and type(bootstrap_metadata) is dict,'ROLE2_BOOTSTRAP_RESULT')
        require(set(bootstrap_metadata) == {'output_bytes','output_sha256','values_disclosed','bootstrap_children'} and
            type(bootstrap_metadata['output_bytes']) is int and 0 <= bootstrap_metadata['output_bytes'] <= 65536 and
            _hash(bootstrap_metadata['output_sha256']) and bootstrap_metadata['values_disclosed'] is False and
            type(bootstrap_metadata['bootstrap_children']) is int and bootstrap_metadata['bootstrap_children'] == 1,
            'ROLE2_PRIVATE_BOOTSTRAP_METADATA')
        persist('bootstrap_metadata.json',canonical(bootstrap_metadata))
        tick()
        observed = snapshot(tuple(selector.CANDIDATES),tick)
        # Actual IO, UID/type/anchor/hash enforcement belongs to the frozen sampler.
        require(type(observed) is dict and set(observed) <= set(selector.CANDIDATES),'ROLE2_FINITE_SNAPSHOT')
        private_spec,redacted = INSTANCE_ASSEMBLER(package,clock,environment,observed,tick)
        require(type(private_spec) is dict and type(redacted) is bytes and len(redacted) <= CAP,'ROLE2_INSTANCE_BOUND')
        bindings = dict(authorization_sha256=AUTH_SHA256,original_clock_sha256=clock['clock_sha256'],
            role2_payload_sha256=clock['role2_payload_sha256'],instance_sha256=sha(canonical(private_spec)),
            metadata_sha256=sha(redacted),nonce=clock['nonce'],role='execution')
        evidence = ack.make_evidence(bindings)
        persist('redacted_metadata.json',redacted)
        persist('evidence.json',evidence)
        emit(evidence,redacted,tick)
        tick()
        # trusted SHA must originate in authenticated parent review handling,
        # NEVER be calculated here from a self-declared PASS receipt.
        ack_raw,review_raw,trusted_sha = receive_review(tick)
        persist('ack.raw',ack_raw);persist('review.raw',review_raw)
        result = ack.validate_ack(ack_raw,evidence,review_raw,trusted_sha)
        tick()
        persist('ack_binding.json',canonical(result))
        # Controller's persist MUST create these exclusively and durably before release.
        persist('instance_consumed.json',canonical(dict(instance_sha256=bindings['instance_sha256'],
            evidence_sha256=sha(evidence),nonce=clock['nonce'],automatic_retries=0)))
        tick()
        # worker adapter must inert-load frozen source privately, recheck actual
        # instance/source hashes, then use existing 3-selfcheck/one-tool worker.
        return worker(private_spec,clock,connection_end,tick)
