"""Default-disabled E138 capture/execution dispatch; no transport.

FROZEN is installed by a future independently reviewed trusted entrypoint,
never copied from wire data. Source loader and component raw bytes must match
that freeze before compilation. Readback dispatch is not implemented here.
The loader is single-worker isolation, not an untrusted-code sandbox.
"""
import base64
import copy
import datetime
import hashlib
import json
import math
import os
import platform
import time
import types

FROZEN=None
_USED=False
_STAGE='ADMISSION'
STAGES=frozenset(('ADMISSION','SOURCE_LOAD','AUTHORITY','CAPTURE','ASSEMBLY_BIND','EXECUTION','SERIALIZE'))
PUBLIC_CODES=frozenset(('E138_WORKER_EXTERNAL_FREEZE_REQUIRED','E138_WORKER_EXACT_INTENT',
    'E138_WORKER_CONNECTION_START','E138_WORKER_INPUT_BYTES','E138_WORKER_LOADER_PIN',
    'E138_WORKER_SOURCE_ROSTER','E138_WORKER_SOURCE_ROW','E138_WORKER_SOURCE_PIN',
    'E138_WORKER_NATIVE_SOURCE_ROSTER','E138_WORKER_ROLE_INPUTS','E138_WORKER_FIXED_A_LINUX',
    'E138_WORKER_CAPTURE_DEADLINE','E138_WORKER_CAPTURE_RESOURCES','E138_WORKER_CAPTURE_BOOT_CHANGED',
    'E138_WORKER_ASSEMBLY_FREEZE_JOIN','E138_WORKER_RESPONSE_BOUND'))
FIELDS=frozenset(('role','payload_sha256','loader_sha256','source_sha256','source_order',
    'input_sha256','authorization_sha256','proposal_sha256','assembly'))


class WorkerFailure(ValueError):
    pass


def require(ok,code):
    if not ok:raise WorkerFailure(code)


def sha(raw):return hashlib.sha256(raw).hexdigest()
def _hex(value):return type(value) is str and len(value)==64 and all(c in '0123456789abcdef' for c in value)
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def _preflight(package,rows,loader_raw,intent,payload_sha,started):
    f=FROZEN
    require(not _USED and type(f) is dict and set(f)==FIELDS and f['role'] in ('capture','execution') and
        all(_hex(f[key]) for key in ('payload_sha256','loader_sha256','authorization_sha256','proposal_sha256')) and
        type(f['source_sha256']) is dict and 1<=len(f['source_sha256'])<=96 and
        all(type(name) is str and _hex(pin) for name,pin in f['source_sha256'].items()) and
        type(f['source_order']) is tuple and len(f['source_order'])==len(f['source_sha256']) and
        all(type(name) is str for name in f['source_order']) and
        len(set(f['source_order']))==len(f['source_order']) and set(f['source_order'])==set(f['source_sha256']) and
        type(f['input_sha256']) is dict and all(type(k) is str and _hex(v) for k,v in f['input_sha256'].items()),
        'E138_WORKER_EXTERNAL_FREEZE_REQUIRED')
    require(type(payload_sha) is str and payload_sha==f['payload_sha256'] and
        type(intent) is dict and set(intent)=={'role','attempt_consumed','role_index','connections_max',
            'automatic_retries','payload_sha256'} and intent['role']==f['role'] and intent['attempt_consumed'] is True and
        type(intent['role_index']) is int and intent['role_index']==('capture','execution').index(f['role'])+1 and
        type(intent['connections_max']) is int and intent['connections_max']==3 and
        type(intent['automatic_retries']) is int and intent['automatic_retries']==0 and
        intent['payload_sha256']==payload_sha,'E138_WORKER_EXACT_INTENT')
    require(type(started) in (int,float) and math.isfinite(started) and started>=0,'E138_WORKER_CONNECTION_START')
    require(type(package) is dict and set(package)==set(f['input_sha256']) and
        all(type(raw) is bytes and len(raw)<=6291456 and sha(raw)==f['input_sha256'][key]
            for key,raw in package.items()) and sum(map(len,package.values()))<=10485760 and
        {'authority','proposal'}<=set(package) and sha(package['authority'])==f['authorization_sha256'] and
        sha(package['proposal'])==f['proposal_sha256'],'E138_WORKER_INPUT_BYTES')
    require(type(loader_raw) is bytes and 0<len(loader_raw)<=65536 and sha(loader_raw)==f['loader_sha256'],
        'E138_WORKER_LOADER_PIN')
    require(type(rows) is list and len(rows)==len(f['source_order']),'E138_WORKER_SOURCE_ROSTER')
    sources={};total=0
    for row,name in zip(rows,f['source_order']):
        require(type(row) is dict and set(row)=={'name','sha256','body_base64'} and row['name']==name and
            row['sha256']==f['source_sha256'][name] and type(row['body_base64']) is str and
            len(row['body_base64'])<=349528,'E138_WORKER_SOURCE_ROW')
        raw=base64.b64decode(row['body_base64'],validate=True);total+=len(raw)
        require(0<len(raw)<=262144 and total<=4194304 and sha(raw)==row['sha256'],'E138_WORKER_SOURCE_PIN')
        sources[name]=raw
    needed={'physical_e138_contract','physical_replay_capture_e138','physical_e138_runtime_primitives'}
    if f['role']=='execution':needed.add('physical_e138_batch_assembler')
    require(needed<=set(sources),'E138_WORKER_NATIVE_SOURCE_ROSTER')
    require((f['role']=='capture' and set(package)=={'authority','proposal'} and f['assembly'] is None) or
        (f['role']=='execution' and type(f['assembly']) is dict),'E138_WORKER_ROLE_INPUTS')
    return copy.deepcopy(f),sources


def _capture(loaded,package,started):
    c=loaded['physical_replay_capture_e138'];runtime=loaded['physical_e138_runtime_primitives']
    require(platform.node()=='bupt-vncs2' and os.getuid()==1047 and platform.system()=='Linux',
        'E138_WORKER_FIXED_A_LINUX')
    boot=runtime.legacy.process._boot_id();domain=runtime.legacy.direct.Descendants();last=[started]
    def tick():
        now=time.monotonic()
        require(type(now) in (int,float) and math.isfinite(now) and last[0]<=now<started+60,
            'E138_WORKER_CAPTURE_DEADLINE')
        last[0]=now
        require(not domain.sample() and domain.peak<=536870912,'E138_WORKER_CAPTURE_RESOURCES')
        require(runtime.legacy.process._boot_id()==boot,'E138_WORKER_CAPTURE_BOOT_CHANGED')
        after=time.monotonic()
        require(type(after) in (int,float) and math.isfinite(after) and last[0]<=after<started+60,
            'E138_WORKER_CAPTURE_DEADLINE')
        last[0]=after
    tick()
    value=c.capture(package['authority'],package['proposal'],started+60,tick,time.monotonic)
    tick()
    return dict(role='capture',capture=value,boot_id=boot,remote_start_monotonic=started,
        remote_sample_monotonic=time.monotonic(),
        remote_utc_sample=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f%z'),
        execution_ready=False)


def dispatch(package,rows,loader_raw,intent,payload_sha,connection_start):
    global _USED,_STAGE
    # Reject default authority, all input/source drift and unsupported readback
    # before loader compilation, clocks, host checks or component callbacks.
    _STAGE='ADMISSION'
    frozen,sources=_preflight(package,rows,loader_raw,intent,payload_sha,connection_start)
    _USED=True;_STAGE='SOURCE_LOAD'
    loader=types.ModuleType('_e138_reviewed_source_session')
    exec(compile(loader_raw,'<e138-reviewed-source-session>','exec'),loader.__dict__)
    loader.FROZEN_SOURCE_SHA256=frozen['source_sha256'];loader.FROZEN_SOURCE_ORDER=frozen['source_order']
    with loader.source_session(rows) as loaded:
        _STAGE='AUTHORITY'
        contract=loaded['physical_e138_contract'];capture=loaded['physical_replay_capture_e138']
        contract.check_authority(package['authority'],package['proposal'],frozen['authorization_sha256'],frozen['proposal_sha256'])
        capture.AUTH_SHA=frozen['authorization_sha256'];capture.PROPOSAL_SHA=frozen['proposal_sha256']
        if frozen['role']=='capture':
            capture.check_authority(package['authority'],package['proposal'])
            _STAGE='CAPTURE'
            value=_capture(loaded,package,connection_start)
        else:
            _STAGE='ASSEMBLY_BIND'
            assembly=frozen['assembly']
            require(set(assembly)==contract.FREEZE_KEYS and assembly['authorization_sha256']==frozen['authorization_sha256'] and
                assembly['proposal_sha256']==frozen['proposal_sha256'] and assembly['payload_sha256']==payload_sha and
                assembly['input_sha256']==frozen['input_sha256'] and assembly['source_sha256']==frozen['source_sha256'] and
                assembly['source_order']==frozen['source_order'] and
                package.get('role2_intent')==canonical(intent),'E138_WORKER_ASSEMBLY_FREEZE_JOIN')
            contract.FROZEN=assembly;contract.LOADED_SOURCE_ORDER=frozen['source_order']
            assembler=loaded['physical_e138_batch_assembler']
            assembler.AUTH_SHA256=frozen['authorization_sha256'];assembler.PROPOSAL_SHA256=frozen['proposal_sha256']
            assembler.POLICY_SHA256=assembly['policy_sha256'];assembler.PAYLOAD_SHA256=payload_sha
            assembler.FROZEN_INPUT_SHA256=frozen['input_sha256'];assembler.FROZEN_SOURCE_SHA256=frozen['source_sha256']
            _STAGE='EXECUTION'
            value=assembler.execute(package,sources,connection_start)
        # Ordinary bounded JSON only; no callable/module/private environment can
        # escape the session through the result. Bytes are returned for raw save.
        _STAGE='SERIALIZE'
        raw=canonical(value)
        require(len(raw)<=6291456,'E138_WORKER_RESPONSE_BOUND')
        return raw


def safe_dispatch(package,rows,loader_raw,intent,payload_sha,connection_start):
    """One bounded public frame. Caller writes it once, without traceback.

    This is not a transport wrapper: reviewed sources must also avoid printing
    private data, and the controller must enforce raw output/transport bounds.
    No arbitrary exception text, class name or traceback enters this frame.
    """
    code='E138_WORKER_REDACTED_FAILURE';failed=False;raw=None
    try:
        raw=dispatch(package,rows,loader_raw,intent,payload_sha,connection_start)
    except BaseException as exc:
        failed=True
        if type(exc) is WorkerFailure and len(exc.args)==1 and type(exc.args[0]) is str and exc.args[0] in PUBLIC_CODES:
            code=exc.args[0]
    if failed:
        raw=canonical(dict(schema='e138-safe-worker-failure-v1',status='STOPPED_FIRST_FAILURE',
            stage=_STAGE if type(_STAGE) is str and _STAGE in STAGES else 'ADMISSION',
            error_code=code,attempt_consumed=_USED is True,execution_ready=False,
            physical_d95_verified=False,training_release=False))
    return raw
