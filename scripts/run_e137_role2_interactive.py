"""Bounded same-channel evidence/ACK adapters. Not an SSH executor/release gate."""
import struct
from . import acceptance_transport_e98 as control
from src.data import physical_e137_role2_protocol as protocol
from src.data import physical_engine_ack_e137 as ack

RELEASE_PACKET_SHA256 = None


def review_exchange(reader,writer,private_stage,trusted_review_provider,tick):
    """Private stage and provider trust are established externally, not by PASS text.

    No subprocess/network calls. Caller owns actual SSH handle cleanup/deadlines,
    reviewed packet/role ledger, and authenticates the independent review channel.
    """
    require = protocol.require
    require(RELEASE_PACKET_SHA256 is not None,'ROLE2_INTERACTIVE_PACKET_UNRELEASED')
    stage = private_stage
    stage.mkdir(exist_ok=False)
    def save(name):
        return lambda raw:control.write_new(stage/name,raw)
    evidence_raw = protocol.read_frame(reader,tick,save('evidence.frame'))
    metadata_raw = protocol.read_frame(reader,tick,save('metadata.frame'))
    evidence = ack.evidence_context(evidence_raw)
    require(ack.sha(metadata_raw) == evidence['metadata_sha256'],'ROLE2_METADATA_EVIDENCE_JOIN')
    # No commands/paths/code accepted in the ACK; provider returns trusted digest
    # from outside these wire frames, not a value echoed by the A worker.
    review_raw,expected_review_sha = trusted_review_provider(evidence_raw,metadata_raw)
    control.write_new(stage/'review.raw',review_raw)
    ack_raw = ack.make_ack(evidence_raw)
    checked = ack.validate_ack(ack_raw,evidence_raw,review_raw,expected_review_sha)
    control.write_new(stage/'ack.raw',ack_raw)
    tick()
    control.write_new(stage/'ack_consumed.json',control.encode(checked))
    protocol.write_frame(writer,ack_raw,tick)
    protocol.write_frame(writer,review_raw,tick)
    return dict(ack_sent=True,instance_sha256=evidence['instance_sha256'],execution_ready=False,
        reviewer_authentication_proven=False,cross_process_single_use_proven=False)


def readiness():
    return dict(execution_ready=False,missing=[
        'AUTHENTICATED_ROLE1_CLOCK_LOADER','PHYSICAL_SUPERVISED_BOOTSTRAP_AND_FINITE_SAMPLER',
        'EXACT_INSTANCE_ASSEMBLER_AND_PRIVATE_WORKER_LOADER','REVIEWED_SSH_TRANSPORT_AND_ROLE_LEDGER_WIRING'])
