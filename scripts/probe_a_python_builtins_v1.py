"""Single read-only version/builtins diagnostic; sends NO project source.

Generic two-builtin expression only, not the E127 function or a replay test.
No files written on A, no child process, no retries, no E139 resumption.
"""
import hashlib
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[1]
HELPER_PIN = 'e0b1e62352781f96dc7d0e5a2a1a27e7f278b63c8aaaa07dbd946c1795c0f434'
BODY = b'''import sys,socket,json,types,builtins
assert socket.gethostname()=='bupt-vncs2'
code=compile('def f(): return repr(min([2,1]))','<generic-builtins-probe>','exec').co_consts[0]
results={}
for mode in ('omitted','explicit_nine'):
 ns={}
 if mode=='explicit_nine':ns['__builtins__']={n:getattr(builtins,n) for n in ('repr','min','len','type','bytes','dict','set','Exception','ValueError')}
 fn=types.FunctionType(code,ns,'f')
 try:results[mode]='BUILTINS_AVAILABLE' if fn()=='1' else 'OTHER_RESULT'
 except NameError as e:
  msg=str(e);results[mode]='MISSING_REPR' if "'repr'" in msg else 'MISSING_MIN' if "'min'" in msg else 'OTHER_NAME_ERROR'
 except Exception:results[mode]='OTHER_FAILURE'
print(json.dumps(dict(schema='a-python-builtins-minimal-probe-v1',host=socket.gethostname(),version=list(sys.version_info[:3]),implementation=sys.implementation.name,executable=sys.executable,results=results,children_created=0,project_source_sent=False),sort_keys=True))
'''


def payload():return BODY


def run():
    if sys.flags.optimize:raise ValueError('PROBE_OPTIMIZED_MODE_REFUSED')
    helper=REPO/'scripts/run_prospective_metadata_v1.py'
    raw=helper.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=HELPER_PIN:raise ValueError('HELPER_PIN_DRIFT')
    ns=dict(__name__='_fixed_readonly_transport',__file__=str(helper))
    exec(compile(raw,str(helper),'exec'),ns)
    ns['TIMEOUT']=30;ns['verify_cached_host']('A')
    observed=ns['transport'](ns['command']('A'),BODY,32768)
    result=dict(payload_sha256=hashlib.sha256(BODY).hexdigest(),payload_bytes=len(BODY),
        timing_scope='KEY_QUERY_10S_THEN_SSH_HELPER_WAIT_30S_PLUS_CLEANUP_NOT_WHOLE_HARD_LIMIT',
        transport={k:v for k,v in observed.items() if k not in ('stdout','stderr')},
        streams={k:dict(bytes=len(observed[k]),sha256=hashlib.sha256(observed[k]).hexdigest()) for k in ('stdout','stderr')})
    if observed['exit_code']!=0 or observed['stderr'] or any(observed[k] is not False for k in ('timeout','overflow','write_failed','threads_incomplete')):
        return dict(result,status='TRANSPORT_FAILED_NO_RETRY')
    try:
        v=ns['decode'](observed['stdout'])
        assert type(v) is dict and set(v)=={'schema','host','version','implementation','executable','results','children_created','project_source_sent'}
        assert v['schema']=='a-python-builtins-minimal-probe-v1' and v['host']=='bupt-vncs2'
        assert type(v['version']) is list and len(v['version'])==3 and all(type(x) is int and 0<=x<=1000 for x in v['version'])
        assert v['implementation']=='cpython' and v['executable']=='/usr/bin/python3'
        assert type(v['children_created']) is int and v['children_created']==0 and v['project_source_sent'] is False
        assert type(v['results']) is dict and set(v['results'])=={'omitted','explicit_nine'}
        assert all(x in {'BUILTINS_AVAILABLE','MISSING_REPR','MISSING_MIN','OTHER_NAME_ERROR','OTHER_RESULT','OTHER_FAILURE'} for x in v['results'].values())
    except (ValueError,TypeError,KeyError,AssertionError,UnicodeError):
        return dict(result,status='INVALID_RESPONSE_NO_RETRY')
    return dict(result,status='VALIDATED_READONLY_PROBE',observation=v)


if __name__=='__main__':print(json.dumps(run(),sort_keys=True))
