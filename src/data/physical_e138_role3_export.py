"""Native E138 default-disabled fixed exporter; no transport or writes.

Derived from the reviewed E137 anchored read and ordered-prefix algorithm,
not its authority, root, clock parser or raw qualification decision.

The genuine role2 ownership emitter/authenticator is NOT implemented here.
Future reviewed bootstrap must authenticate all source bytes and genuine raw
receipts before filling None gates. Function source attributes are bindings,
not proof of consent or authenticity by themselves. This module cannot make
an arbitrary caller-supplied callback trusted.

Success uses the existing four-key readback schema. ExportFailure retains only
an ordered completed prefix in partial_result (or None before ownership/boot
verification). A future reviewed wrapper MUST serialize ONE bounded partial
frame on error and persist raw transport before validation. Exception retention
is not durable publication, remote cleanup or an execution permission.
"""
import base64
import copy
import datetime
import hashlib
import math
import os
import re
import stat

from . import physical_e138_contract as contract
from . import physical_e138_runtime_primitives as runtime
from . import physical_replay_source_reader_e135 as reader
from . import prospective_acceptance_materializer_v1 as anchored
from .physical_replay_source_reader_e135 import canonical, decode, identity, sha, FIELDS

ROOT = contract.ROOT
PROPOSAL_SHA = SOURCE_PINS = None
JOURNAL = ('recipe_artifacts.json','dependency_validation.json','launch_intent.json','spawn_identity.json',
    'observation.json','stdout.log','stdout_ack.json','observation_exception.json')+tuple(
    case+'_'+suffix for case in ('success','timeout','setsid_child') for suffix in
    ('intent.json','observation.json','output.log','receipt.json'))
OUTPUTS = (ROOT+'.initial_intent.json',ROOT+'/code/replay.tcl',ROOT+'/code/expected_baseline.tcl',ROOT+'/tool.log')+tuple(
    ROOT+'/journal/'+name for name in JOURNAL)+tuple(ROOT+'/snapshots/'+stage+'.'+suffix
    for stage in ('baseline','imported','simulated') for suffix in ('statistics.rpt','faults.rpt','faults.mtfi'))+(
    ROOT+'/snapshots/loaded.patterns.rpt',ROOT+'/snapshots/simulated.patterns.rpt')
MAX_TOTAL,MAX_RESPONSE,CHUNK = 16777216,25165824,65536
AUTH_SHA256 = ORIGINAL_CLOCK_SHA256 = None
ROLE2_STDOUT_SHA256 = ROLE2_STDERR_SHA256 = ROLE2_TRANSPORT_SHA256 = None
ROLE2_INTENT_SHA256 = ROLE2_PAYLOAD_SHA256 = ROLE3_INTENT_SHA256 = ROLE3_PAYLOAD_SHA256 = None
CAPABILITY_PINS = None
ROLE2_AUTHENTICATOR = BOOT_READER = MONOTONIC_READER = UTC_READER = RESOURCE_GUARD = None
_USED = False
PINNED_DEPENDENCIES = {
    'prospective_acceptance_materializer_v1':'a04127c07227814e331ede4268c6f8d5df4def4d7041c0c69ec048378216cab9',
    'physical_replay_source_reader_e135':'6d6f86341eca23d5b473f8e323a0440d50ea44d177032576f196b9b417690818',
}


# Fixed public codes only; never format an arbitrary exception.
PUBLIC_CODES = frozenset((
    'ROLE3_OWNED_IDENTITY_REQUIRED',
    'ROLE3_RESULT_SCHEMA_OR_PREFIX',
    'ROLE3_ORDERED_FIXED_PREFIX',
    'ROLE3_MISSING_ROW_SHAPE',
    'ROLE3_FILE_ROW_SHAPE',
    'ROLE3_RETAINED_BODY_HASH',
    'ROLE3_TOTAL_OR_RESPONSE_BOUND',
    'ROLE3_EXACT_CONSUMED_ROLE_INTENT',
    'ROLE3_FROZEN_CAPABILITIES_AND_GENUINE_RAW_PINS_REQUIRED',
    'ROLE3_EXACT_RAW_PACKAGE',
    'ROLE3_RAW_ROLE2_TRANSPORT_JOIN',
    'ROLE3_AUTHENTICATED_INSTANCE_CONTEXT_REQUIRED',
    'ROLE3_ROOT_CHANGED',
    'ROLE3_HELD_PARENT_CHANGED',
    'ROLE3_PARENT_REPLACED',
    'ROLE3_ROOT_REPLACED',
    'ROLE3_FIXED_PATH_ONLY',
    'ROLE3_FILE_OR_TOTAL_CAP',
    'ROLE3_OPEN_CHANGED',
    'ROLE3_SHORT_READ',
    'ROLE3_OUTPUT_GREW',
    'ROLE3_OUTPUT_CHANGED',
    'ROLE3_REMOTE_START_EXPIRED',
    'ROLE3_ORIGINAL_REMOTE_BOOT_OR_DEADLINE',
    'ROLE3_MEMORY_OR_CHILD_STOP',
    'ROLE3_GUARD_OVERRUN_OR_CLOCK_RESET',
    'ROLE3_RESPONSE_CHARGE_CAP',
    'ROLE3_CAPABILITY_OR_IO_FAILED',
))

class _Stop(ValueError):
    pass


def _require(ok,code):
    if not ok:
        raise _Stop(code)


def _hex(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None


def _number(value):
    return type(value) in (int,float) and math.isfinite(value) and value >= 0


def _cap(path):
    name = path.rsplit('/',1)[1]
    return 8388608 if name.endswith(('faults.rpt','faults.mtfi')) else 2097152 if name in ('tool.log','stdout.log') else 65536


def _file_identity(info,size,directory=False):
    _require(type(info) is dict and set(info) == set(FIELDS) and
        all(type(v) is int and 0 <= v < 2**64 for v in info.values()) and info['st_uid'] == 1047 and
        (stat.S_ISDIR(info['st_mode']) and info['st_nlink'] >= 1 if directory else
         stat.S_ISREG(info['st_mode']) and info['st_nlink'] == 1 and info['st_size'] == size),
        'ROLE3_OWNED_IDENTITY_REQUIRED')


def validate_result(value,complete=False):
    """Pure validation of a full result or exact ordered prefix; never authority."""
    _require(type(complete) is bool and type(value) is dict and
        set(value) == {'role','files','boot_id','execution_ready'} and value['role'] == 'readback' and
        value['execution_ready'] is False and type(value['boot_id']) is str and
        re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value['boot_id']) and
        type(value['files']) is list and len(value['files']) <= len(OUTPUTS) and
        (not complete or len(value['files']) == len(OUTPUTS)),'ROLE3_RESULT_SCHEMA_OR_PREFIX')
    total = 0
    for path,row in zip(OUTPUTS,value['files']):
        _require(type(row) is dict and row.get('path') == path,'ROLE3_ORDERED_FIXED_PREFIX')
        if row.get('missing') is True:
            _require(set(row) in ({'path','missing'},{'path','missing','reason'}) and
                ('reason' not in row or row['reason'] == 'FIXED_PARENT_ABSENT'),'ROLE3_MISSING_ROW_SHAPE')
        else:
            _require(set(row) == {'path','bytes','sha256','identity','body_base64'} and type(row['bytes']) is int and
                0 <= row['bytes'] <= _cap(path) and _hex(row['sha256']) and type(row['body_base64']) is str and
                len(row['body_base64']) <= 4*((row['bytes']+2)//3),'ROLE3_FILE_ROW_SHAPE')
            _file_identity(row['identity'],row['bytes'])
            body = base64.b64decode(row['body_base64'],validate=True)
            _require(len(body) == row['bytes'] and sha(body) == row['sha256'],'ROLE3_RETAINED_BODY_HASH')
            total += len(body)
    _require(total <= MAX_TOTAL and len(canonical(value))+1024 <= MAX_RESPONSE,'ROLE3_TOTAL_OR_RESPONSE_BOUND')
    return value


class ExportFailure(ValueError):
    """Completed rows retained in RAM; wrapper still owes one raw error frame."""
    def __init__(self,code,partial_result):
        super(ExportFailure,self).__init__(code)
        self.code = code
        self.partial_result = partial_result
        self.durable_publication_verified = False


def _intent(raw,role,payload):
    value = decode(raw)
    _require(type(value) is dict and set(value) == {'role','attempt_consumed','role_index','connections_max',
        'automatic_retries','payload_sha256'} and value['role'] == role and value['attempt_consumed'] is True and
        type(value['role_index']) is int and value['role_index'] == (2 if role == 'execution' else 3) and
        type(value['connections_max']) is int and value['connections_max'] == 3 and
        type(value['automatic_retries']) is int and value['automatic_retries'] == 0 and
        value['payload_sha256'] == payload,'ROLE3_EXACT_CONSUMED_ROLE_INTENT')


def _sources_match():
    # A separately reviewed loader must verify bytes before supplying these
    # tags/pins. They do not protect against trusted-code Python mutation.
    modules = dict(contract=contract,runtime=runtime,anchored=anchored,reader=reader)
    return (type(SOURCE_PINS) is dict and set(SOURCE_PINS) == set(modules)|{'self'} and
        all(_hex(pin) for pin in SOURCE_PINS.values()) and
        SOURCE_PINS['anchored'] == PINNED_DEPENDENCIES['prospective_acceptance_materializer_v1'] and
        SOURCE_PINS['reader'] == PINNED_DEPENDENCIES['physical_replay_source_reader_e135'] and
        globals().get('__source_sha256__') == SOURCE_PINS['self'] and
        all(getattr(module,'__source_sha256__',None) == SOURCE_PINS[name]
            for name,module in modules.items()))


def _preflight(package):
    global _USED
    # All default denial checks precede a callback, filesystem, tick or clock.
    pins = (AUTH_SHA256,PROPOSAL_SHA,ORIGINAL_CLOCK_SHA256,ROLE2_STDOUT_SHA256,ROLE2_STDERR_SHA256,
        ROLE2_TRANSPORT_SHA256,ROLE2_INTENT_SHA256,ROLE2_PAYLOAD_SHA256,ROLE3_INTENT_SHA256,ROLE3_PAYLOAD_SHA256)
    callbacks = dict(authenticate=ROLE2_AUTHENTICATOR,boot=BOOT_READER,monotonic=MONOTONIC_READER,
        utc=UTC_READER,sample=RESOURCE_GUARD)
    _require(not _USED and all(_hex(p) for p in pins) and AUTH_SHA256 != contract.OLD_AUTH_SHA256 and
        _sources_match() and
        type(CAPABILITY_PINS) is dict and set(CAPABILITY_PINS) == set(callbacks) and
        all(_hex(CAPABILITY_PINS[k]) and callable(fn) and getattr(fn,'__source_sha256__',None) == CAPABILITY_PINS[k]
            for k,fn in callbacks.items()),'ROLE3_FROZEN_CAPABILITIES_AND_GENUINE_RAW_PINS_REQUIRED')
    _USED = True  # Once enabled, even rejected raw input consumes this instance.
    expected = dict(authority=(AUTH_SHA256,65536),proposal=(PROPOSAL_SHA,65536),
        original_clock=(ORIGINAL_CLOCK_SHA256,4096),role2_stdout=(ROLE2_STDOUT_SHA256,6291456),
        role2_stderr=(ROLE2_STDERR_SHA256,65536),role2_transport=(ROLE2_TRANSPORT_SHA256,65536),
        role2_intent=(ROLE2_INTENT_SHA256,4096),role3_intent=(ROLE3_INTENT_SHA256,4096))
    _require(type(package) is dict and set(package) == set(expected),'ROLE3_EXACT_RAW_PACKAGE')
    for name,(pin,cap) in expected.items():
        raw = package[name]
        _require(type(raw) is bytes and len(raw) <= cap and sha(raw) == pin,'ROLE3_TRUSTED_RAW_BYTES_'+name.upper())
    contract.check_authority(package['authority'],package['proposal'],AUTH_SHA256,PROPOSAL_SHA)
    _intent(package['role2_intent'],'execution',ROLE2_PAYLOAD_SHA256)
    _intent(package['role3_intent'],'readback',ROLE3_PAYLOAD_SHA256)
    transport = decode(package['role2_transport'])
    _require(type(transport) is dict and type(transport.get('stdout_bytes')) is int and
        transport['stdout_bytes'] == len(package['role2_stdout']) and transport.get('stdout_sha256') == ROLE2_STDOUT_SHA256 and
        type(transport.get('stderr_bytes')) is int and transport['stderr_bytes'] == len(package['role2_stderr']) and
        transport.get('stderr_sha256') == ROLE2_STDERR_SHA256 and
        all(transport.get(k) is False for k in ('timeout','overflow','write_failed','threads_incomplete')) and
        type(transport.get('exit_code')) is int and transport['exit_code'] == 0 and
        package['role2_stderr'] == b'',
        'ROLE3_RAW_ROLE2_TRANSPORT_JOIN')
    return _clock(package['original_clock'])


def _clock(raw):
    value = runtime.package_clock(raw,AUTH_SHA256,PROPOSAL_SHA,ORIGINAL_CLOCK_SHA256)
    epoch = datetime.datetime.strptime(value['remote_utc_sample'],'%Y-%m-%dT%H:%M:%S.%f%z').timestamp()
    return dict(boot_id=value['boot_id'],start=value['remote_start_monotonic'],
        end=value['monotonic_end'],sample=value['remote_clock_sample_monotonic'],
        utc_sample=epoch,utc_end=value['utc_end'])


def _authenticated_context(context,clock):
    hashes = dict(authorization_sha256=AUTH_SHA256,proposal_sha256=PROPOSAL_SHA,original_clock_sha256=ORIGINAL_CLOCK_SHA256,
        role2_stdout_sha256=ROLE2_STDOUT_SHA256,role2_stderr_sha256=ROLE2_STDERR_SHA256,
        role2_transport_sha256=ROLE2_TRANSPORT_SHA256,role2_intent_sha256=ROLE2_INTENT_SHA256,
        role2_payload_sha256=ROLE2_PAYLOAD_SHA256,role3_intent_sha256=ROLE3_INTENT_SHA256,
        role3_payload_sha256=ROLE3_PAYLOAD_SHA256)
    _require(type(context) is dict and set(context) == set(hashes)|{'schema','root','identity','boot_id'} and
        context['schema'] == 'e138-authenticated-role2-owned-root-context-v1' and context['root'] == ROOT and
        context['boot_id'] == clock['boot_id'] and all(context[k] == v for k,v in hashes.items()),
        'ROLE3_AUTHENTICATED_INSTANCE_CONTEXT_REQUIRED')
    _file_identity(context['identity'],0,directory=True)
    return copy.deepcopy(context['identity'])


def _anchor(fd,root_identity,parent=None,parent_fd=None,parent_identity=None):
    _require(identity(os.fstat(fd)) == root_identity,'ROLE3_ROOT_CHANGED')
    if parent_fd is not None:
        _require(identity(os.fstat(parent_fd)) == parent_identity,'ROLE3_HELD_PARENT_CHANGED')
        fresh = anchored._directory(parent)
        try:
            _require(identity(os.fstat(fresh)) == parent_identity and identity(os.fstat(parent_fd)) == parent_identity,
                'ROLE3_PARENT_REPLACED')
        finally:
            os.close(fresh)
    fresh = anchored._directory(ROOT)
    try:
        _require(identity(os.fstat(fresh)) == root_identity == identity(os.fstat(fd)),'ROLE3_ROOT_REPLACED')
    finally:
        os.close(fresh)


def _read(path,root_fd,root_identity,tick,total):
    _require(path in OUTPUTS,'ROLE3_FIXED_PATH_ONLY')
    tick();_anchor(root_fd,root_identity)
    parent,name = path.rsplit('/',1)
    try:
        held = anchored._directory(parent)
    except FileNotFoundError:
        _anchor(root_fd,root_identity);tick()
        return dict(path=path,missing=True,reason='FIXED_PARENT_ABSENT')
    fd = None
    try:
        pi = identity(os.fstat(held))
        try:
            named = os.stat(name,dir_fd=held,follow_symlinks=False)
        except FileNotFoundError:
            _anchor(root_fd,root_identity,parent,held,pi);tick()
            return dict(path=path,missing=True)
        before = identity(named)
        _file_identity(before,named.st_size)
        _require(0 <= named.st_size <= _cap(path) and total[0]+named.st_size <= MAX_TOTAL,'ROLE3_FILE_OR_TOTAL_CAP')
        fd = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=held)
        _require(identity(os.fstat(fd)) == before,'ROLE3_OPEN_CHANGED')
        chunks,left,digest = [],named.st_size,hashlib.sha256()
        while left:
            tick()
            count = min(CHUNK,left)
            raw = os.read(fd,count)
            _require(type(raw) is bytes and 0 < len(raw) <= count,'ROLE3_SHORT_READ')
            chunks.append(raw);digest.update(raw);left -= len(raw);total[0] += len(raw)
        tick()
        _require(os.read(fd,1) == b'','ROLE3_OUTPUT_GREW')
        _require(identity(os.fstat(fd)) == before == identity(os.stat(name,dir_fd=held,follow_symlinks=False)),
            'ROLE3_OUTPUT_CHANGED')
        _anchor(root_fd,root_identity,parent,held,pi);tick()
        return dict(path=path,bytes=named.st_size,sha256=digest.hexdigest(),identity=before,
            body_base64=base64.b64encode(b''.join(chunks)).decode('ascii'))
    finally:
        if fd is not None:
            os.close(fd)
        os.close(held)


def collect(package):
    """One evidence-only invocation. Actual authenticated emitter still absent."""
    global _USED
    clock = _preflight(package)
    result,root_fd,partial,code = None,None,None,None
    try:
        started = MONOTONIC_READER()
        _require(_number(started) and clock['start'] <= started < clock['end'],'ROLE3_REMOTE_START_EXPIRED')
        context = ROLE2_AUTHENTICATOR(copy.deepcopy(package))
        root_identity = _authenticated_context(context,clock)
        last = [started,None]
        deadline = min(started+60,clock['end'])
        def tick():
            boot,now,utc = BOOT_READER(),MONOTONIC_READER(),UTC_READER()
            _require(boot == clock['boot_id'] and _number(now) and _number(utc) and
                started <= last[0] <= now < deadline and utc < clock['utc_end'] and
                (last[1] is None or last[1] <= utc) and
                abs((utc-clock['utc_sample'])-(now-clock['sample'])) <= 5,'ROLE3_ORIGINAL_REMOTE_BOOT_OR_DEADLINE')
            last[:] = [now,utc]
            sample = RESOURCE_GUARD()
            _require(type(sample) is dict and set(sample) == {'rss_swap_bytes','children'} and
                type(sample['rss_swap_bytes']) is int and 0 <= sample['rss_swap_bytes'] <= 536870912 and
                type(sample['children']) is int and sample['children'] == 0,'ROLE3_MEMORY_OR_CHILD_STOP')
            after,utc_after = MONOTONIC_READER(),UTC_READER()
            _require(_number(after) and _number(utc_after) and now <= after < deadline and
                utc <= utc_after < clock['utc_end'] and
                abs((utc_after-clock['utc_sample'])-(after-clock['sample'])) <= 5,
                'ROLE3_GUARD_OVERRUN_OR_CLOCK_RESET')
            last[:] = [after,utc_after]
        tick()
        result = dict(role='readback',files=[],boot_id=clock['boot_id'],execution_ready=False)
        root_fd = anchored._directory(ROOT)
        _anchor(root_fd,root_identity)
        total,response_charge = [0],512
        for path in OUTPUTS:
            row = _read(path,root_fd,root_identity,tick,total)
            response_charge += len(canonical(row))+1
            _require(response_charge+1024 <= MAX_RESPONSE,'ROLE3_RESPONSE_CHARGE_CAP')
            result['files'].append(row)
        _anchor(root_fd,root_identity);tick()
        validate_result(result,complete=True);tick()
    except BaseException as exc:
        args = exc.args if type(exc) is _Stop else ()
        code = args[0] if type(args) is tuple and len(args) == 1 and type(args[0]) is str and args[0] in PUBLIC_CODES else 'ROLE3_CAPABILITY_OR_IO_FAILED'
        # Never put a callback/OS exception message, env or arbitrary path in output.
        partial = validate_result(result,complete=False) if result is not None else None
    finally:
        if root_fd is not None:
            try:
                os.close(root_fd)
            except BaseException:
                code = 'ROLE3_CAPABILITY_OR_IO_FAILED'
                partial = validate_result(result,complete=False) if result is not None else None
    # Outside the exception handler: no private exception cause/context.
    if code is not None:
        raise ExportFailure(code,partial) from None
    return result
