"""Single-reference binary stream. No size ceiling, source writes or launches."""
import hashlib
import os
import platform
import re
import stat
import struct
import sys
import time

from .physical_replay_source_reader_e135 import require,sha,canonical,decode,identity,FIELDS

AUTH_SHA = 'e349356f0c58ec99935097c3a0daf65bfd837f6bc601c7e4ad7eadc803b07494'
SOURCE = '/cad/mentor/tessent2021_2/doc/pdfdocs/tshell_ref.pdf'
SCHEMA = 'reference-binary-stream-e135-r2-v1'
CHUNK,META,RESERVE,INT64 = 65536,65536,2147483648,9223372036854775807
SCOPE = dict(source_path=SOURCE,source_owner_uid=0,source_file_size_bytes_max=None,
    old_32MiB_file_gate_bypassed_only_for_this_single_read=True,
    nonempty_regular_single_link_stable_file_required=True,A_read_only_connections_max=1,
    attempts_max=1,automatic_retries=0,seconds_max=60,chunk_bytes_max=CHUNK,
    remote_sampled_rss_swap_bytes_max=536870912,metadata_bytes_max=META,
    local_free_disk_reserve_bytes=RESERVE,stream_binary_directly_to_exclusive_file=True,
    whole_PDF_in_RAM_or_base64_JSON=False,new_local_phase='v6_e135_reference_stream_r2',
    E135_original_phase_or_clock_or_evidence_modification=False,reopen_E135_whole_package=False,
    approve_E136_help_or_simulation_package=False,Tessent_launches=0,LSF_jobs=0,
    B_access=False,BLIND_access=False,training=False)


def check_authority(raw):
    require(type(raw) is bytes and sha(raw) == AUTH_SHA,'EXACT_NARROW_SIZE_EXCEPTION')
    auth = decode(raw)
    require(auth.get('schema') == 'reference-size-gate-exception-e135-r2-v1' and
        auth.get('approval_source') == 'explicit_user_reply' and auth.get('user_authorization_received') is True and
        auth.get('user_reply') == '\u90a3\u5c31\u628a\u95e8\u7981\u5148\u6682\u65f6\u5173\u95ed' and
        canonical(auth.get('scope')) == canonical(SCOPE) and
        auth.get('temporary_exception_auto_ends_on_success_or_first_failure') is True,'EXACT_ONE_READ_SCOPE')


def send(write,raw,tick):
    view = memoryview(raw)
    while view:
        tick()
        count = write(view[:CHUNK])
        require(type(count) is int and 0 < count <= min(len(view),CHUNK),'STREAM_WRITE_FAILED')
        view = view[count:]


def frame(write,value,tick):
    raw = canonical(value)
    require(0 < len(raw) <= META,'STREAM_METADATA_CAP')
    send(write,struct.pack('!I',len(raw))+raw,tick)


def stream_file(write,tick,runtime,state):
    """Only SOURCE; hashes all bytes with bounded reads and sends no base64."""
    from . import prospective_acceptance_materializer_v1 as anchored
    tick()
    parent,name = SOURCE.rsplit('/',1)
    parent_fd,fd = anchored._directory(parent),None
    try:
        parent_identity = identity(os.fstat(parent_fd))
        named = os.stat(name,dir_fd=parent_fd,follow_symlinks=False)
        state['observed_identity'] = identity(named)
        require(stat.S_ISREG(named.st_mode) and named.st_nlink == 1 and named.st_uid == 0,'REFERENCE_PREOPEN_REGULAR_SINGLE_LINK_UID0')
        require(type(named.st_size) is int and 0 < named.st_size <= INT64,'REFERENCE_NONEMPTY_INT64_SIZE')
        fd = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent_fd)
        require(identity(os.fstat(fd)) == identity(named),'REFERENCE_OPEN_CHANGED')
        header = dict(schema=SCHEMA,kind='HEADER',status='READY',source_path=SOURCE,
            body_bytes=named.st_size,identity=identity(named),runtime=runtime,authorization_sha256=AUTH_SHA)
        state['header_started'] = True
        frame(write,header,tick)
        remaining,digest = named.st_size,hashlib.sha256()
        while remaining:
            tick()
            count = min(CHUNK,remaining)
            raw = os.read(fd,count)
            require(type(raw) is bytes and 0 < len(raw) <= count,'REFERENCE_SHORT_READ')
            digest.update(raw)
            send(write,raw,tick)
            remaining -= len(raw)
        tick()
        require(not os.read(fd,1),'REFERENCE_GREW')
        current = identity(os.fstat(fd))
        require(current == identity(named) == identity(os.stat(name,dir_fd=parent_fd,follow_symlinks=False)),
            'REFERENCE_CHANGED')
        require(identity(os.fstat(parent_fd)) == parent_identity,'REFERENCE_HELD_PARENT_CHANGED')
        fresh = anchored._directory(parent)
        try:
            require(identity(os.fstat(fresh)) == parent_identity,'REFERENCE_PARENT_ANCHOR_CHANGED')
        finally:
            os.close(fresh)
        tick()
        footer = dict(schema=SCHEMA,kind='FOOTER',status='COMPLETE',body_bytes=named.st_size,
            sha256=digest.hexdigest(),identity=current,parent_identity=parent_identity,
            whole_file_hashed=True,file_identity_stable=True,parent_anchor_stable=True,
            remote_end_monotonic=time.monotonic(),sampled_peak_rss_swap_bytes=runtime['sampled_peak_rss_swap_bytes'])
        frame(write,footer,tick)
        return footer
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent_fd)


def run(authority,output,error,started):
    """High-level authorized remote emitter; errors never inject JSON into body."""
    from . import direct_tessent_acceptance_e104 as direct
    state,runtime,domain = {},{},None
    stage,next_sample = 'AUTHORITY',[0]
    def tick():
        now = time.monotonic()
        require(started <= now < started+60,'REFERENCE_STREAM_DEADLINE')
        if now >= next_sample[0]:
            require(not domain.sample() and domain.peak <= 536870912,'REFERENCE_MEMORY_OR_CHILD')
            next_sample[0] = now+.25
        runtime['sampled_peak_rss_swap_bytes'] = domain.peak
        require(time.monotonic() < started+60,'REFERENCE_STREAM_DEADLINE')
    try:
        check_authority(authority)
        stage = 'RUNTIME'
        require(type(started) in (int,float) and started >= 0,'REFERENCE_BOOTSTRAP_CLOCK')
        require(sys.platform.startswith('linux') and platform.node() == 'bupt-vncs2' and os.getuid() == 1047,'REFERENCE_HOST_UID')
        boot = direct.base._small('/proc/sys/kernel/random/boot_id',128).decode('ascii').strip()
        require(re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot) is not None,'REFERENCE_BOOT_ID')
        runtime.update(hostname='bupt-vncs2',uid=1047,boot_id=boot,python_version=list(sys.version_info[:3]),
            remote_start_monotonic=started,sampled_peak_rss_swap_bytes=0,child_launches=0,source_writes=0,
            environment_reads=0,tessent_launches=0,training_release=False)
        domain = direct.Descendants()
        tick()
        stage = 'REFERENCE_STREAM'
        def write(raw):
            count = output.write(raw)
            output.flush()
            return count
        stream_file(write,tick,runtime,state)
        output.flush()
        return True
    except BaseException as exc:
        diagnostic = dict(schema=SCHEMA,status='FAILED',stage=stage,error_type=type(exc).__name__,
            code=str(exc) if type(exc) is ValueError else 'REFERENCE_STREAM_FAILED',
            observed_identity=state.get('observed_identity'),header_started=state.get('header_started',False))
        raw = canonical(diagnostic)
        if len(raw) <= META:
            try:
                error.write(raw+b'\n')
                error.flush()
            except BaseException:
                pass
        if not state.get('header_started'):
            try:
                frame(output.write,dict(schema=SCHEMA,kind='HEADER',status='FAILED',body_bytes=0,
                    diagnostic=diagnostic),lambda:None)
                output.flush()
            except BaseException:
                pass
        return False
