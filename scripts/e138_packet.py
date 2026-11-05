"""Pure reviewed-byte packet compiler, not a controller or execution release.

EXPECTED pins are installed from independent local packet preparation, never
learned from candidate material. No remote IO, role debit or clock creation.
Complete payload and exact invocation still require independent review.
"""
import ast
import base64
import hashlib
import json
from pathlib import Path

EXPECTED=None
KEYS=frozenset(('compiler_sha256','worker_sha256','loader_sha256','envelope_sha256',
    'template_sha256','source_sha256','source_order','input_sha256'))


def require(ok,code):
    if not ok:raise ValueError(code)


def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
def _hex(value):return type(value) is str and len(value)==64 and all(c in '0123456789abcdef' for c in value)
def _b64(raw):return base64.b64encode(raw).decode('ascii')


def prepare(template,inputs,sources,worker_raw,loader_raw,envelope_raw):
    f=EXPECTED
    require(type(f) is dict and set(f)==KEYS and
        all(_hex(f[key]) for key in ('compiler_sha256','worker_sha256','loader_sha256','envelope_sha256','template_sha256')) and
        type(f['source_sha256']) is dict and 1<=len(f['source_sha256'])<=96 and
        all(type(k) is str and _hex(v) for k,v in f['source_sha256'].items()) and
        type(f['input_sha256']) is dict and all(type(k) is str and _hex(v) for k,v in f['input_sha256'].items()) and
        type(f['source_order']) is tuple and all(type(name) is str for name in f['source_order']) and
        len(set(f['source_order']))==len(f['source_order'])==len(f['source_sha256']) and
        set(f['source_order'])==set(f['source_sha256']),'E138_PACKET_EXTERNAL_PINS_REQUIRED')
    require(type(template) is dict and sha(canonical(template))==f['template_sha256'] and
        type(inputs) is dict and set(inputs)==set(f['input_sha256']) and
        all(type(raw) is bytes and len(raw)<=6291456 and sha(raw)==f['input_sha256'][key] for key,raw in inputs.items()) and
        sum(map(len,inputs.values()))<=10485760,'E138_PACKET_STATIC_INPUTS')
    require(type(sources) is dict and set(sources)==set(f['source_sha256']) and
        all(type(raw) is bytes and 0<len(raw)<=262144 and sha(raw)==f['source_sha256'][name] for name,raw in sources.items()) and
        sum(map(len,sources.values()))<=4194304 and
        template.get('source_sha256')==f['source_sha256'] and template.get('source_order')==f['source_order'] and
        template.get('input_sha256')==f['input_sha256'] and template.get('loader_sha256')==f['loader_sha256'],
        'E138_PACKET_STATIC_SOURCE_JOIN')
    require(all(type(raw) is bytes and 0<len(raw)<=65536 and sha(raw)==f[key] for key,raw in
        (('worker_sha256',worker_raw),('loader_sha256',loader_raw),('envelope_sha256',envelope_raw))),
        'E138_PACKET_ENTRY_SOURCE_PIN')
    # No compiler self-read until default denial and all supplied-byte checks.
    compiler=Path(__file__).read_bytes()
    require(0<len(compiler)<=65536 and sha(compiler)==f['compiler_sha256'],'E138_PACKET_COMPILER_DRIFT')
    for raw in list(sources.values())+[worker_raw,loader_raw,envelope_raw]:
        ast.parse(raw.decode('utf-8'),feature_version=(3,6))
    namespace={};exec(compile(envelope_raw,'<e138-pinned-envelope>','exec'),namespace)
    role=template.get('role');probe=namespace['intent'](role,'0'*64)
    namespace['derive'](template,inputs,probe,'0'*64)  # Pure shape check, not consent.
    wire=canonical(dict(template=template,sources=[dict(name=name,sha256=f['source_sha256'][name],body_base64=_b64(sources[name]))
        for name in f['source_order']],inputs={key:_b64(raw) for key,raw in inputs.items()})).decode('ascii')
    # Values interpolated below are JSON/base64 strings produced by this exact
    # compiler, never caller-supplied Python expressions or repr hooks.
    payload=('import sys,base64,hashlib,json\n'
        'frame=None\n'
        'try:\n'
        ' envelope=base64.b64decode('+repr(_b64(envelope_raw))+',validate=True)\n'
        ' if hashlib.sha256(envelope).hexdigest()!='+repr(f['envelope_sha256'])+':raise ValueError("ENTRY_SOURCE_CHANGED")\n'
        ' ens={};exec(compile(envelope,"<e138-pinned-envelope>","exec"),ens)\n'
        ' worker=base64.b64decode('+repr(_b64(worker_raw))+',validate=True)\n'
        ' if hashlib.sha256(worker).hexdigest()!='+repr(f['worker_sha256'])+':raise ValueError("ENTRY_SOURCE_CHANGED")\n'
        ' wns={};exec(compile(worker,"<e138-pinned-worker>","exec"),wns)\n'
        ' data=json.loads('+repr(wire)+')\n'
        ' template=data["template"];template["source_order"]=tuple(template["source_order"])\n'
        ' if template["role"]=="execution":template["assembly"]["source_order"]=tuple(template["assembly"]["source_order"])\n'
        ' if template["role"]=="readback":template["readback"]["source_order"]=tuple(template["readback"]["source_order"])\n'
        ' package={key:base64.b64decode(value,validate=True) for key,value in data["inputs"].items()}\n'
        ' frozen,package=ens["derive"](template,package,__role_intent__,__payload_sha256__)\n'
        ' wns["FROZEN"]=frozen\n'
        ' loader=base64.b64decode('+repr(_b64(loader_raw))+',validate=True)\n'
        ' frame=wns["safe_dispatch"](package,data["sources"],loader,__role_intent__,__payload_sha256__,__connection_start__)\n'
        ' if type(frame) is not bytes or len(frame)>'+str(25165824 if role=='readback' else 6291456)+':raise ValueError("FRAME_BOUND")\n'
        'except BaseException:\n'
        ' frame=b\'{"schema":"e138-entrypoint-failure-v1","error_code":"E138_ENTRYPOINT_FAILED","execution_ready":false}\'\n'
        'write_failed=False\n'
        'try:\n'
        ' if sys.stdout.buffer.write(frame)!=len(frame):write_failed=True\n'
        ' sys.stdout.buffer.flush()\n'
        'except BaseException:\n'
        ' write_failed=True\n'
        'if write_failed:raise SystemExit(73)\n').encode('ascii')
    ast.parse(payload.decode('ascii'),feature_version=(3,6))
    plan=namespace['invocation'](role,payload)
    projection=dict(schema='e138-exact-packet-projection-v1',role=role,
        compiler_sha256=f['compiler_sha256'],worker_sha256=f['worker_sha256'],loader_sha256=f['loader_sha256'],
        envelope_sha256=f['envelope_sha256'],template_sha256=f['template_sha256'],
        source_sha256=dict(f['source_sha256']),source_order=list(f['source_order']),input_sha256=dict(f['input_sha256']),
        authorization_sha256=template['authorization_sha256'],proposal_sha256=template['proposal_sha256'],
        payload_sha256=plan['payload_sha256'],invocation_sha256=plan['invocation_sha256'],
        bootstrap_sha256=plan['bootstrap_sha256'])
    return dict(payload=payload,remote_command=plan['remote_command'],projection=projection,
        projection_sha256=sha(canonical(projection)),execution_ready=False)
