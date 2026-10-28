"""Narrow single-read streaming controller; never buffers a whole PDF."""
import ast
import base64
import hashlib
import math
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import struct
import subprocess
import threading
import time

from src.data import reference_stream_e135_r2 as core

require,sha,canonical,decode = core.require,core.sha,core.canonical,core.decode
AUTH = 'contracts/reference_size_gate_exception_e135_r2.json'
AUTH_SHA = core.AUTH_SHA
PHASE = 'v6_e135_reference_stream_r2'
OLD_CORE_SHA = '6d6f86341eca23d5b473f8e323a0440d50ea44d177032576f196b9b417690818'
REVIEW_KEYS = ('payload_sha256','controller_sha256','source_sha256','authorization_sha256','protocol_sha256')
PROTOCOL = dict(schema=core.SCHEMA,source=core.SOURCE,frames='U32_BE_JSON_HEADER__N_RAW_BODY_BYTES__U32_BE_JSON_FOOTER__EOF',
    metadata_max=core.META,chunk_max=core.CHUNK,seconds_max=60,local_active_seconds_max=50,cleanup_reserve_seconds=10,file_size_max=None,
    disk_reserve=core.RESERVE,publication='EXCLUSIVE_HARDLINK_THEN_UNLINK_OWNED_PARTIAL')


def prepare():
    from scripts.run_direct_tessent_e104 import PINS
    repo = Path(__file__).resolve().parents[1]
    authority = (repo/AUTH).read_bytes()
    core.check_authority(authority)
    sources = []
    for name,pin in list(PINS)+[('physical_replay_source_reader_e135',OLD_CORE_SHA),('reference_stream_e135_r2',None)]:
        raw = (repo/'src/data'/(name+'.py')).read_bytes()
        require(pin is None or sha(raw) == pin,'PINNED_STREAM_SOURCE_CHANGED')
        ast.parse(raw.decode('utf-8'),feature_version=(3,6))
        sources.append(dict(name=name,sha256=sha(raw),body=base64.b64encode(raw).decode('ascii')))
    wire = canonical(dict(sources=sources,authority=base64.b64encode(authority).decode('ascii'))).decode('ascii')
    payload = ('import time\nstarted=time.monotonic()\n'
        'import base64,hashlib,json,types,sys\np=json.loads('+repr(wire)+')\n'
        'for name in ("src","src.data"):\n'
        ' m=types.ModuleType(name);m.__path__=[];sys.modules[name]=m\n'
        ' if name=="src.data":sys.modules["src"].data=m\n'
        'for row in p["sources"]:\n'
        ' raw=base64.b64decode(row["body"],validate=True)\n'
        ' if hashlib.sha256(raw).hexdigest()!=row["sha256"]:raise ValueError("SOURCE_SHA")\n'
        ' name="src.data."+row["name"];m=types.ModuleType(name);m.__package__="src.data"\n'
        ' sys.modules[name]=m;setattr(sys.modules["src.data"],row["name"],m)\n'
        ' exec(compile(raw,"<reference-stream-"+row["name"]+">","exec"),m.__dict__)\n'
        'ok=sys.modules["src.data.reference_stream_e135_r2"].run(base64.b64decode(p["authority"],validate=True),sys.stdout.buffer,sys.stderr.buffer,started)\n'
        'raise SystemExit(0 if ok else 1)\n').encode('ascii')
    ast.parse(payload.decode('ascii'),feature_version=(3,6))
    return dict(payload=payload,payload_sha256=sha(payload),controller_sha256=sha(Path(__file__).read_bytes()),
        source_sha256={r['name']:r['sha256'] for r in sources},authorization_sha256=AUTH_SHA,
        protocol_sha256=sha(canonical(PROTOCOL)))


def checked_identity(value,size):
    require(type(value) is dict and set(value) == set(core.FIELDS) and
        all(type(n) is int and 0 <= n <= core.INT64 for n in value.values()) and
        stat.S_ISREG(value['st_mode']) and value['st_nlink'] == 1 and value['st_uid'] == 0 and
        value['st_size'] == size,'REFERENCE_REGULAR_UID0_METADATA')


def local_identity(info):
    value = core.identity(info)
    if os.name == 'nt':
        # Python3.13 Windows path-stat ctime is creation time, fstat ctime differs.
        # Source Linux identity retains all eight fields; disk bytes are rehashed.
        del value['st_ctime_ns']
    return value


def read_frame(stream,path,tick):
    """Preserve bounded raw frame before interpreting JSON."""
    with path.open('xb') as saved:
        def take(count):
            parts = []
            while count:
                tick()
                raw = stream.read(min(count,core.CHUNK))
                require(type(raw) is bytes and 0 < len(raw) <= min(count,core.CHUNK),'SHORT_STREAM_FRAME')
                saved.write(raw)
                saved.flush()
                parts.append(raw)
                count -= len(raw)
            return b''.join(parts)
        prefix = take(4)
        count = struct.unpack('!I',prefix)[0]
        require(0 < count <= core.META,'FRAME_METADATA_CAP')
        raw = take(count)
        os.fsync(saved.fileno())
    return decode(raw)


def receive(stream,phase,tick,disk_free=None):
    """Stream body to disk; return only bounded validation metadata, never PDF."""
    header = read_frame(stream,phase/'header.frame',tick)
    require(type(header) is dict and set(header) == {'schema','kind','status','source_path','body_bytes','identity','runtime','authorization_sha256'} and
        header['schema'] == core.SCHEMA and header['kind'] == 'HEADER' and header['status'] == 'READY' and
        header['source_path'] == core.SOURCE and header['authorization_sha256'] == AUTH_SHA,'EXACT_STREAM_HEADER')
    size = header['body_bytes']
    require(type(size) is int and 0 < size <= core.INT64,'NONEMPTY_INT64_DECLARED_SIZE')
    checked_identity(header['identity'],size)
    runtime = header['runtime']
    require(type(runtime) is dict and set(runtime) == {'hostname','uid','boot_id','python_version','remote_start_monotonic',
        'sampled_peak_rss_swap_bytes','child_launches','source_writes','environment_reads','tessent_launches','training_release'} and
        runtime['hostname'] == 'bupt-vncs2' and type(runtime['uid']) is int and runtime['uid'] == 1047 and
        type(runtime['boot_id']) is str and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',runtime['boot_id']) is not None,
        'STREAM_HOST_RUNTIME')
    require(type(runtime['python_version']) is list and len(runtime['python_version']) == 3 and
        all(type(n) is int and n >= 0 for n in runtime['python_version']) and
        all(type(runtime[k]) is int and runtime[k] == 0 for k in ('child_launches','source_writes','environment_reads','tessent_launches')) and
        runtime['training_release'] is False and type(runtime['sampled_peak_rss_swap_bytes']) is int and
        0 <= runtime['sampled_peak_rss_swap_bytes'] <= 536870912,'READ_ONLY_STREAM_RUNTIME')
    free = shutil.disk_usage(str(phase)).free if disk_free is None else disk_free()
    require(type(free) is int and free >= size+core.RESERVE,'DECLARED_SIZE_PLUS_DISK_RESERVE')
    partial = phase/'reference.partial'
    digest,remaining,magic = hashlib.sha256(),size,b''
    with partial.open('xb') as saved:
        before = os.fstat(saved.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,'EXCLUSIVE_LOCAL_PARTIAL')
        while remaining:
            tick()
            count = min(remaining,core.CHUNK)
            raw = stream.read(count)
            require(type(raw) is bytes and 0 < len(raw) <= count,'SHORT_PDF_BODY')
            require(saved.write(raw) == len(raw),'LOCAL_PARTIAL_SHORT_WRITE')
            if len(magic) < 4:
                magic = (magic+raw)[:4]
                require(b'%PDF'.startswith(magic),'REFERENCE_PDF_MAGIC')
            digest.update(raw)
            remaining -= len(raw)
        require(magic == b'%PDF','REFERENCE_PDF_MAGIC')
        saved.flush()
        os.fsync(saved.fileno())
        after = os.fstat(saved.fileno())
        require((before.st_dev,before.st_ino) == (after.st_dev,after.st_ino) and
            stat.S_ISREG(after.st_mode) and after.st_nlink == 1 and after.st_size == size,'LOCAL_PARTIAL_IDENTITY')
    footer = read_frame(stream,phase/'footer.frame',tick)
    require(type(footer) is dict and set(footer) == {'schema','kind','status','body_bytes','sha256','identity','parent_identity',
        'whole_file_hashed','file_identity_stable','parent_anchor_stable','remote_end_monotonic','sampled_peak_rss_swap_bytes'} and
        footer['schema'] == core.SCHEMA and footer['kind'] == 'FOOTER' and footer['status'] == 'COMPLETE' and
        type(footer['body_bytes']) is int and footer['body_bytes'] == size and footer['identity'] == header['identity'] and
        all(footer[k] is True for k in ('whole_file_hashed','file_identity_stable','parent_anchor_stable')) and
        footer['sha256'] == digest.hexdigest(),'FULL_STREAM_FOOTER_SHA_STABILITY')
    parent = footer['parent_identity']
    require(type(parent) is dict and set(parent) == set(core.FIELDS) and
        all(type(n) is int and 0 <= n <= core.INT64 for n in parent.values()) and stat.S_ISDIR(parent['st_mode']),
        'REFERENCE_PARENT_METADATA')
    start,end = runtime['remote_start_monotonic'],footer['remote_end_monotonic']
    require(all(type(n) in (int,float) and math.isfinite(n) and n >= 0 for n in (start,end)) and
        start <= end < start+60 and type(footer['sampled_peak_rss_swap_bytes']) is int and
        0 <= footer['sampled_peak_rss_swap_bytes'] <= 536870912,'REFERENCE_REMOTE_TIME_MEMORY')
    tick()
    require(not stream.read(1),'TRAILING_STREAM_BYTES')
    # Reopen and hash disk in chunks; no readall and no whole-PDF resident copy.
    named = partial.lstat()
    require(stat.S_ISREG(named.st_mode) and named.st_nlink == 1 and
        (named.st_dev,named.st_ino,named.st_size) == (after.st_dev,after.st_ino,size),'PARTIAL_PATH_CHANGED')
    rehash,total = hashlib.sha256(),0
    with partial.open('rb') as saved:
        opened = os.fstat(saved.fileno())
        require(local_identity(opened) == local_identity(named),'PARTIAL_REOPEN_CHANGED')
        while True:
            tick()
            raw = saved.read(core.CHUNK)
            if not raw:
                break
            total += len(raw)
            require(total <= size,'PARTIAL_DISK_GREW')
            rehash.update(raw)
        require(local_identity(os.fstat(saved.fileno())) == local_identity(named),'PARTIAL_DISK_CHANGED')
    require(total == size and rehash.hexdigest() == digest.hexdigest() and
        local_identity(partial.lstat()) == local_identity(named),'FULL_DISK_REHASH')
    tick()
    return dict(bytes=size,sha256=digest.hexdigest(),partial_identity=local_identity(named),
        source_identity=header['identity'],boot_id=runtime['boot_id'],whole_disk_rehashed=True)


def stream_transport(command,payload,phase,deadline,cleanup_deadline=None):
    """Exactly one local SSH process; bounded metadata, streaming body on disk."""
    error,done,stop = [],threading.Event(),threading.Event()
    outcome = dict(exit_code=None,timeout=False,stderr_overflow=False,write_failed=False,threads_incomplete=False,
        remote_termination_verified=False,local_ssh_cleanup_verified=False,validation=None,error=None)
    if cleanup_deadline is None:
        cleanup_deadline = deadline
    require(deadline <= cleanup_deadline,'CLEANUP_DEADLINE_ORDER')
    proc = subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    def kill():
        try:
            proc.kill()
        except OSError:
            pass
    def tick():
        require(not stop.is_set() and time.monotonic() < deadline,'LOCAL_STREAM_DEADLINE_OR_STOP')
    def consumer():
        try:
            outcome['validation'] = receive(proc.stdout,phase,tick)
        except BaseException as exc:
            error.append(dict(type=type(exc).__name__,code=str(exc) if type(exc) is ValueError else 'STREAM_RECEIVE_FAILED'))
            stop.set()
            kill()
        finally:
            done.set()
    def stderr_reader():
        try:
            total = 0
            with (phase/'stderr.log').open('xb') as saved:
                while True:
                    raw = proc.stderr.read(core.CHUNK)
                    if not raw:
                        break
                    room = core.META-total
                    saved.write(raw[:max(0,room)])
                    total += len(raw)
                    if total > core.META:
                        outcome['stderr_overflow'] = True
                        stop.set()
                        kill()
                        break
                saved.flush()
                os.fsync(saved.fileno())
        except BaseException:
            outcome['stderr_overflow'] = True
            stop.set()
            kill()
    def writer():
        try:
            view = memoryview(payload)
            while view:
                tick()
                count = proc.stdin.write(view[:core.CHUNK])
                require(type(count) is int and 0 < count <= min(len(view),core.CHUNK),'PAYLOAD_WRITE_FAILED')
                view = view[count:]
            proc.stdin.close()
        except BaseException:
            outcome['write_failed'] = True
            stop.set()
            kill()
    threads = [threading.Thread(target=fn,daemon=True) for fn in (consumer,stderr_reader,writer)]
    try:
        for thread in threads:
            thread.start()
        while proc.poll() is None or any(t.is_alive() for t in threads):
            if time.monotonic() >= deadline:
                outcome['timeout'] = True
                stop.set()
                kill()
                break
            if stop.is_set():
                kill()
                break
            done.wait(.02) if not done.is_set() else stop.wait(.02)
        left = cleanup_deadline-time.monotonic()
        if left > 0:
            try:
                proc.wait(timeout=min(2.,left))
            except subprocess.TimeoutExpired:
                kill()
                left = cleanup_deadline-time.monotonic()
                if left > 0:
                    proc.wait(timeout=min(2.,left))
        outcome['local_ssh_cleanup_verified'] = proc.poll() is not None
    except BaseException as exc:
        stop.set()
        kill()
        outcome['error'] = dict(type=type(exc).__name__,code='LOCAL_TRANSPORT_FAILED')
    finally:
        for thread in threads:
            thread.join(timeout=max(0.,min(.5,cleanup_deadline-time.monotonic())))
        outcome['threads_incomplete'] = any(t.is_alive() for t in threads)
        outcome['exit_code'] = proc.poll()
        if error:
            outcome['error'] = error[0]
        if not outcome['threads_incomplete']:
            for stream in (proc.stdin,proc.stdout,proc.stderr):
                try:
                    stream.close()
                except OSError:
                    pass
    return outcome


def publish(phase,receipt,tick):
    partial = phase/'reference.partial'
    tick()
    require(local_identity(partial.lstat()) == receipt['partial_identity'],'PARTIAL_BEFORE_PUBLICATION_CHANGED')
    target = phase/(receipt['sha256']+'.pdf')
    # Exclusive link fails if target exists; never replace or overwrite a file.
    os.link(str(partial),str(target))
    linked = target.lstat()
    require(stat.S_ISREG(linked.st_mode) and linked.st_nlink == 2 and
        linked.st_mtime_ns == receipt['partial_identity']['st_mtime_ns'] and
        (linked.st_dev,linked.st_ino,linked.st_size) ==
        (receipt['partial_identity']['st_dev'],receipt['partial_identity']['st_ino'],receipt['bytes']),
        'EXCLUSIVE_PUBLICATION_IDENTITY')
    require(local_identity(partial.lstat()) == local_identity(linked),'PARTIAL_LINK_IDENTITY')
    # Also rehash the exclusive linked target before removing the owned partial.
    digest,total = hashlib.sha256(),0
    with target.open('rb') as saved:
        require(local_identity(os.fstat(saved.fileno())) == local_identity(linked),'PUBLICATION_OPEN_IDENTITY')
        while True:
            tick()
            raw = saved.read(core.CHUNK)
            if not raw:
                break
            total += len(raw)
            require(total <= receipt['bytes'],'PUBLICATION_GREW')
            digest.update(raw)
        require(local_identity(os.fstat(saved.fileno())) == local_identity(linked),'PUBLICATION_BODY_CHANGED')
    require(total == receipt['bytes'] and digest.hexdigest() == receipt['sha256'] and
        local_identity(target.lstat()) == local_identity(linked) == local_identity(partial.lstat()),
        'PUBLICATION_FULL_DISK_SHA')
    tick()
    partial.unlink()
    final = target.lstat()
    require(stat.S_ISREG(final.st_mode) and final.st_nlink == 1 and
        final.st_mtime_ns == receipt['partial_identity']['st_mtime_ns'] and
        (final.st_dev,final.st_ino,final.st_size) == (linked.st_dev,linked.st_ino,linked.st_size),'FINAL_OWNED_PDF_IDENTITY')
    return target


def execute(review_path,payload_sha):
    from scripts import acceptance_transport_e98 as control
    plan = prepare()
    expected = {k:plan[k] for k in REVIEW_KEYS}
    review = decode(Path(review_path).read_bytes())
    require(review.get('status') == 'PASS' and review.get('reviewed') == expected and payload_sha == plan['payload_sha256'],
        'INDEPENDENT_EXACT_STREAM_REVIEW')
    helper = control.load_transport()
    fingerprint = helper.verify_cached_host('A')
    phase = control.STAGING/PHASE
    phase.mkdir(exist_ok=False)
    started = time.monotonic()
    deadline = started+60
    control.write_new(phase/'start.json',control.encode(dict(expected,attempt_consumed=True,connections_max=1,
        automatic_retries=0,host_fingerprint=fingerprint,local_start_monotonic=started,local_deadline_monotonic=deadline,
        local_active_deadline_monotonic=started+50,cleanup_reserve_seconds=10,
        source_file_size_cap=None,E135_reopened=False)))
    try:
        result = stream_transport(helper.command('A'),plan['payload'],phase,started+50,deadline)
    except BaseException as exc:
        control.write_new(phase/'transport.json',control.encode(dict(error_type=type(exc).__name__,
            attempt_consumed=True,remote_termination_verified=False)))
        raise
    evidence = {}
    for name in ('header.frame','footer.frame','stderr.log'):
        path = phase/name
        if path.exists():
            require(path.stat().st_size <= core.META+4,'RAW_METADATA_DISK_BOUND')
            raw = path.read_bytes()
            evidence[name] = dict(bytes=len(raw),sha256=sha(raw))
    partial = phase/'reference.partial'
    result['raw_evidence'] = evidence
    result['partial_bytes'] = partial.stat().st_size if partial.exists() else 0
    control.write_new(phase/'transport.json',control.encode(result))
    require(result['exit_code'] == 0 and result['error'] is None and result['validation'] is not None and
        not any(result[k] for k in ('timeout','stderr_overflow','write_failed','threads_incomplete')),'STREAM_FAILED_NO_RETRY')
    def tick():
        require(started <= time.monotonic() < deadline,'LOCAL_STREAM_DEADLINE')
    tick()
    target = publish(phase,result['validation'],tick)
    tick()
    control.write_new(phase/'validated.json',control.encode(dict(result['validation'],file=target.name,
        publication_method=PROTOCOL['publication'],publication_disk_rehashed=True,
        E135_reopened=False,execution_ready=False,training_release=False)))
    return dict(phase=str(phase),pdf_file=str(target),sha256=result['validation']['sha256'],
        bytes=result['validation']['bytes'],E135_reopened=False,execution_ready=False)
