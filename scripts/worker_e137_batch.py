"""Fixed inert source loader and capture/batch dispatch; no transport."""
import base64
import datetime
import hashlib
import json
import math
import os
import platform
import sys
import types


def sha(raw):return hashlib.sha256(raw).hexdigest()


def require(ok,code):
    if not ok:raise ValueError(code)


def load_sources(rows,expected):
    """Verify ALL bodies before exec; never resolve a cached src.* child."""
    require(type(rows) is list and type(expected) is dict and len(rows)==len(expected),'SOURCE_ROSTER')
    decoded=[];seen=set();total=0
    for row in rows:
        require(type(row) is dict and set(row)=={'name','sha256','body'} and row['name'] in expected and
            row['name'] not in seen and row['sha256']==expected[row['name']],'SOURCE_ROW')
        raw=base64.b64decode(row['body'],validate=True);total+=len(raw)
        require(total<=4194304 and sha(raw)==row['sha256'],'SOURCE_BODY_SHA')
        seen.add(row['name']);decoded.append((row['name'],raw,row['sha256']))
    require(seen==set(expected),'SOURCE_EXACT_SET')
    for name in list(sys.modules):
        if name=='src' or name.startswith('src.'):del sys.modules[name]
    for name in ('src','src.data'):
        module=types.ModuleType(name);module.__path__=[];sys.modules[name]=module
        if name=='src.data':sys.modules['src'].data=module
    modules={}
    for name,raw,digest in decoded:
        module=types.ModuleType('src.data.'+name);module.__package__='src.data'
        sys.modules[module.__name__]=module;setattr(sys.modules['src.data'],name,module)
        exec(compile(raw,'<e137-frozen-'+name+'>','exec'),module.__dict__)
        module.__source_sha256__=digest;modules[name]=module
    return modules


def dispatch(packet,intent,payload_sha,started):
    require(type(intent) is dict and set(intent)=={'role','attempt_consumed','role_index','connections_max',
        'automatic_retries','payload_sha256'} and intent['role']==packet['role'] and intent['attempt_consumed'] is True and
        type(intent['role_index']) is int and intent['role_index']==('capture','execution').index(packet['role'])+1 and
        type(intent['connections_max']) is int and intent['connections_max']==3 and
        type(intent['automatic_retries']) is int and intent['automatic_retries']==0 and
        intent['payload_sha256']==payload_sha,'EXACT_ARGUMENT_DEBIT')
    modules=load_sources(packet['sources'],packet['source_sha256'])
    capture=modules['physical_replay_capture_e137'];execution=modules['physical_f_replay_execution_e137']
    raw={k:base64.b64decode(v,validate=True) for k,v in packet['inputs'].items()}
    require(all(sha(raw[k])==pin for k,pin in packet['input_sha256'].items()) and
        set(raw)==set(packet['input_sha256']),'EXACT_PACKET_INPUTS')
    namespace=dict(vars(capture),AUTH_SHA=packet['authorization_sha256'])
    for name in ('check_authority','validate_receipt','capture'):
        fn=getattr(capture,name);namespace[name]=types.FunctionType(fn.__code__,namespace,name,fn.__defaults__,fn.__closure__)
    namespace['check_authority'](raw['authority'],raw['proposal'])
    if packet['role']=='execution':
        batch=modules['physical_e137_batch_execution'];raw['role2_intent']=capture.canonical(intent)
        batch.AUTH_SHA256=packet['authorization_sha256'];batch.POLICY_SHA256=sha(raw['policy']);batch.PAYLOAD_SHA256=payload_sha
        batch.FROZEN_SOURCE_SHA256=packet['source_sha256'];batch.FROZEN_INPUT_SHA256={k:sha(v) for k,v in raw.items()}
        return batch.execute(raw,started)
    require(platform.node()=='bupt-vncs2' and os.getuid()==1047 and sys.platform.startswith('linux'),'FIXED_A')
    require(type(started) in (int,float) and math.isfinite(started) and started>=0,'ORIGINAL_START')
    import time
    boot=execution.process._boot_id();domain=execution.direct.Descendants()
    def tick():
        require(started<=time.monotonic()<started+60,'CAPTURE_DEADLINE')
        require(not domain.sample() and domain.peak<=536870912,'CAPTURE_MEMORY_OR_CHILD')
    value=namespace['capture'](raw['authority'],raw['proposal'],started+60,tick,time.monotonic)
    tick()
    return dict(role='capture',capture=value,boot_id=boot,remote_start_monotonic=started,
        remote_sample_monotonic=time.monotonic(),remote_utc_sample=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f%z'),
        execution_ready=False)
