"""Finite anchored engine metadata/hash sampler. No search or execution grant.

Limits are conservative implementation ceilings, not a claim of disk/memory
quotas. The injected guard must enforce resource sampling and outer deadlines.
Actual boot authentication and source-bundle trust remain the controller's job.
"""
import errno
import hashlib
import math
import os
import re
import stat
from . import physical_engine_selector_e137 as selector
from .physical_replay_source_reader_e135 import require,sha,canonical,decode,identity

AUTH_SHA256 = PACKET_SHA256 = CONTEXT_SHA256 = None
ACTUAL_AUTH_SHA256 = '49f000fe45de6cfc029ad8a9c1ead5e09edd24321de6062039d638436cce4969'
SELECTOR_SHA256 = 'efcf80e98b4a26051d057320e4dc75882929545fbd42be41be4336a2586d5d73'
MAX_FILE,MAX_TOTAL,CHUNK,MAX_RESPONSE = 2147483648,4294967296,65536,65536
CHAIN = (selector.LAUNCHER,selector.ROOT+'/lib/scripts/tessent_functions',selector.ROOT+'/lib/scripts/tessent_shell')
PINS = {CHAIN[0]:(3658,'d92e81eaacf0727fd18d4cafa67d7c9a066069c6d8f7fc05caaf1252c3e44905'),
    CHAIN[1]:(12306,selector.FUNCTIONS_SHA),CHAIN[2]:(49725,selector.SHELL_SHA)}
PATHS = tuple(selector.CANDIDATES)+CHAIN


def _directory(path):
    require(type(path) is str and path.startswith('/') and all(p not in ('','.','..') for p in path.split('/')[1:]),'ENGINE_ANCHOR_PATH')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        require(_safe_dir(os.fstat(fd)),'ENGINE_ROOT_DIRECTORY_OWNER')
        for part in path.split('/')[1:]:
            named=os.stat(part,dir_fd=fd,follow_symlinks=False)
            require(_safe_dir(named),'ENGINE_PARENT_TYPE_OWNER_PERMISSIONS')
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            try:
                require(identity(os.fstat(child)) == identity(named),'ENGINE_PARENT_OPEN_CHANGED')
            except BaseException:
                os.close(child);raise
            os.close(fd);fd=child
        return fd
    except BaseException:
        os.close(fd);raise


def _safe_dir(info):
    return stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_nlink >= 1 and not info.st_mode & 0o022


def _same_anchor(path,held,before):
    require(identity(os.fstat(held)) == before,'ENGINE_HELD_PARENT_CHANGED')
    fresh=_directory(path)
    try:
        require(identity(os.fstat(fresh)) == before == identity(os.fstat(held)),'ENGINE_NAMED_PARENT_REPLACED')
    finally:
        os.close(fresh)


def sample_path(path,tick,budget):
    require(path in PATHS,'ENGINE_FINITE_PATH_ONLY')
    tick()
    root=_directory(selector.ROOT)
    parent,name=path.rsplit('/',1)
    held,fd=None,None
    try:
        root_id=identity(os.fstat(root))
        try:
            held=_directory(parent)
        except OSError as exc:
            if exc.errno != errno.ENOENT:raise
            _same_anchor(selector.ROOT,root,root_id)
            return dict(state='MISSING')
        parent_id=identity(os.fstat(held))
        try:
            named=os.stat(name,dir_fd=held,follow_symlinks=False)
        except OSError as exc:
            if exc.errno != errno.ENOENT:raise
            _same_anchor(parent,held,parent_id);_same_anchor(selector.ROOT,root,root_id)
            return dict(state='MISSING')
        directory=path in selector.TCL.values()
        require(named.st_uid == 0 and not named.st_mode & 0o022 and
            (_safe_dir(named) if directory else stat.S_ISREG(named.st_mode) and named.st_nlink == 1 and named.st_size > 0),
            'ENGINE_SELECTED_OBJECT_TYPE_OWNER_LINKS')
        if directory:
            fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=held)
            digest=None
        else:
            require(named.st_size <= MAX_FILE and budget[0]+named.st_size <= MAX_TOTAL,'ENGINE_HASH_BYTE_LIMIT')
            if path in PINS:require((named.st_size) == PINS[path][0],'ENGINE_VENDOR_SIZE_PIN')
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=held)
            require(identity(os.fstat(fd)) == identity(named),'ENGINE_FILE_OPEN_CHANGED')
            left,digest=named.st_size,hashlib.sha256()
            while left:
                tick();count=min(left,CHUNK);raw=os.read(fd,count)
                require(type(raw) is bytes and 0 < len(raw) <= count,'ENGINE_SHORT_READ')
                digest.update(raw);left-=len(raw);budget[0]+=len(raw)
            require(not os.read(fd,1),'ENGINE_FILE_GREW')
            digest=digest.hexdigest()
            if path in PINS:require(digest == PINS[path][1],'ENGINE_VENDOR_SHA_PIN')
        tick()
        require(identity(os.fstat(fd)) == identity(named) == identity(os.stat(name,dir_fd=held,follow_symlinks=False)),
            'ENGINE_OBJECT_CHANGED')
        _same_anchor(parent,held,parent_id);_same_anchor(selector.ROOT,root,root_id)
        return dict(state='PRESENT',identity=identity(named),sha256=digest,whole_file_hashed=not directory)
    finally:
        if fd is not None:os.close(fd)
        if held is not None:os.close(held)
        os.close(root)


def collect(authority,packet,context,runtime_boot_id,plan,tick,monotonic,utc_now):
    # No callback or physical IO occurs until all independently frozen pins match.
    require(AUTH_SHA256 == ACTUAL_AUTH_SHA256 and type(PACKET_SHA256) is str and type(CONTEXT_SHA256) is str,
        'ENGINE_EVIDENCE_TRUST_NOT_FROZEN')
    require(all(type(raw) is bytes and len(raw) <= 65536 and sha(raw) == pin for raw,pin in
        ((authority,AUTH_SHA256),(packet,PACKET_SHA256),(context,CONTEXT_SHA256))),'ENGINE_EVIDENCE_EXACT_TRUST_BYTES')
    grant,p,c=decode(authority),decode(packet),decode(context)
    require(grant.get('user_reply') == '\u90a3\u5c31\u6279\u51c6' and grant.get('approved_package') == 'E137' and
        grant.get('user_authorization_received') is True and p == dict(role='execution',authorization_sha256=AUTH_SHA256,
        context_sha256=CONTEXT_SHA256,selector_sha256=SELECTOR_SHA256) and
        getattr(selector,'__source_sha256__',None) == SELECTOR_SHA256,'ENGINE_EVIDENCE_PACKET_CONTEXT')
    require(set(c) == {'role','authorization_sha256','boot_id','package_start','package_end','connection_start','utc_end'} and
        c['role'] == 'execution' and c['authorization_sha256'] == AUTH_SHA256 and type(runtime_boot_id) is str and
        runtime_boot_id == c['boot_id'] and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',runtime_boot_id) is not None,
        'ENGINE_ORIGINAL_RUNTIME_BOOT')
    require(all(type(c[k]) in (int,float) and math.isfinite(c[k]) for k in ('package_start','package_end','connection_start','utc_end')) and
        c['package_end'] == c['package_start']+3600,'ENGINE_ORIGINAL_PACKAGE_CLOCK')
    start=monotonic()
    require(type(start) in (int,float) and math.isfinite(start) and start >= 0,'ENGINE_EVIDENCE_CLOCK_TYPE')
    end=min(c['package_end'],c['connection_start']+2400);last=[start]
    def guard():
        now,utc=monotonic(),utc_now()
        require(all(type(n) in (int,float) and math.isfinite(n) for n in (now,utc)) and
            c['package_start'] <= c['connection_start'] <= start <= last[0] <= now < end and utc < c['utc_end'],'ENGINE_EVIDENCE_DEADLINE')
        last[0]=now
        tick()
        now,utc=monotonic(),utc_now()
        require(all(type(n) in (int,float) and math.isfinite(n) for n in (now,utc)) and
            last[0] <= now < end and utc < c['utc_end'],'ENGINE_EVIDENCE_DEADLINE');last[0]=now
    guard();selector._validate_plan(plan)
    budget=[0];rows={path:sample_path(path,guard,budget) for path in PATHS}
    require(all(rows[path]['state'] == 'PRESENT' for path in CHAIN),'ENGINE_VENDOR_CHAIN_MISSING')
    candidates={path:{k:v for k,v in rows[path].items() if k in ('state','identity')} for path in selector.CANDIDATES}
    classification=selector.classify(plan,candidates)
    require(classification['status'] == 'CONDITIONALLY_SELECTED','ENGINE_OBSERVED_BRANCH_NOT_VIABLE')
    result=dict(schema='e137-finite-engine-evidence-v1',files=rows,classification=classification,bytes_hashed=budget[0],
        plan=selector.redact_plan(plan),packet_context_pins_matched=True,physical_metadata_observed=True,
        runtime_boot_observed_here=False,memory_enforcement_verified=False,engine_identity_authenticated=False,
        dynamic_library_closure_verified=False,ldd_behavior_verified=False,execution_ready=False)
    require(len(canonical(result)) <= MAX_RESPONSE,'ENGINE_EVIDENCE_RESPONSE_BOUND');guard()
    return result
