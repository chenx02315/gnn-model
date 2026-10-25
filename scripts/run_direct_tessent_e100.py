"""Prepare or execute one frozen direct package; no scheduler operations."""
import base64
import hashlib
import json
from pathlib import Path
import sys

from scripts import acceptance_transport_e98 as control

ROOT = Path(__file__).resolve().parents[1]
MODULES = (
    'prospective_tessent_acceptance_v1', 'prospective_fault_translation_v2',
    'prospective_lsf_memory_preflight_v1', 'prospective_acceptance_materializer_v1',
    'prospective_acceptance_scratch_v1', 'direct_tessent_acceptance_e100')
AUTH = 'contracts/direct_tessent_authorization_e100_20261025.json'
E85 = 'data/manifests/ranking_v6_e85_input_observation_20261023_r1.json'
E93 = 'data/manifests/ranking_v6_e93_input_observation_20261023_r1.json'


def prepare():
    sources = [(name,(ROOT/'src/data'/ (name+'.py')).read_bytes()) for name in MODULES]
    authority=(ROOT/AUTH).read_bytes()
    e85=(ROOT/E85).read_bytes();e93=(ROOT/E93).read_bytes()
    pins={name:control.sha(raw) for name,raw in sources}
    package=dict(sources=[dict(name=name,sha256=pins[name],
        body=base64.b64encode(raw).decode('ascii')) for name,raw in sources],
        authority=base64.b64encode(authority).decode('ascii'),
        e85=base64.b64encode(e85).decode('ascii'),e93=base64.b64encode(e93).decode('ascii'))
    payload=('import base64,hashlib,json,platform,sys,types\n'
        'assert platform.node()=="bupt-vncs2" and sys.platform.startswith("linux")\n'
        'p=json.loads('+repr(json.dumps(package,separators=(',',':')))+')\n'
        'for name in ("src","src.data"):\n'
        ' m=types.ModuleType(name);m.__path__=[];sys.modules[name]=m\n'
        ' if name=="src.data":sys.modules["src"].data=m\n'
        'for row in p["sources"]:\n'
        ' raw=base64.b64decode(row["body"],validate=True)\n'
        ' assert hashlib.sha256(raw).hexdigest()==row["sha256"]\n'
        ' name="src.data."+row["name"];m=types.ModuleType(name);m.__package__="src.data"\n'
        ' sys.modules[name]=m;setattr(sys.modules["src.data"],row["name"],m)\n'
        ' exec(compile(raw,"<frozen-"+row["name"]+">","exec"),m.__dict__)\n'
        'm=sys.modules["src.data.direct_tessent_acceptance_e100"]\n'
        'result=m.execute(base64.b64decode(p["e85"]),base64.b64decode(p["e93"]),base64.b64decode(p["authority"]))\n'
        'print(json.dumps(result,sort_keys=True),flush=True)\n').encode('ascii')
    compile(payload,'<direct-fixed-payload>','exec')
    if len(payload)>524288:
        raise ValueError('PAYLOAD_BOUND')
    return dict(payload=payload,payload_sha256=control.sha(payload),payload_bytes=len(payload),
        source_sha256=pins,authorization_sha256=control.sha(authority),
        input_sha256=dict(e85=control.sha(e85),e93=control.sha(e93)))


def main():
    plan=prepare()
    if sys.argv[1:]==['prepare']:
        print(json.dumps({k:v for k,v in plan.items() if k!='payload'},sort_keys=True));return
    if len(sys.argv)!=3 or sys.argv[1]!='execute' or sys.argv[2]!=plan['payload_sha256']:
        raise ValueError('REVIEWED_EXACT_PAYLOAD_REQUIRED')
    transport=control.load_transport();transport.TIMEOUT=2760
    fingerprint=transport.verify_cached_host('A')
    phase=control.STAGING/'v6_e100_direct_acceptance_20261025_r1'
    phase.mkdir(exist_ok=False)
    control.write_new(phase/'start.json',control.encode(dict(
        {k:v for k,v in plan.items() if k!='payload'},host_fingerprint=fingerprint,
        execution_attempt_consumed=True,automatic_retries=0,lsf_used=False)))
    result=transport.transport(transport.command('A'),plan['payload'],65536)
    control.write_new(phase/'stdout.json',result['stdout'])
    control.write_new(phase/'stderr.log',result['stderr'])
    receipt={k:v for k,v in result.items() if k not in ('stdout','stderr')}
    receipt.update(stdout_sha256=control.sha(result['stdout']),stdout_bytes=len(result['stdout']),
        stderr_sha256=control.sha(result['stderr']),stderr_bytes=len(result['stderr']))
    control.write_new(phase/'transport.json',control.encode(receipt))
    print(json.dumps(receipt,sort_keys=True))
    if result['exit_code']!=0 or any(result[k] for k in ('timeout','overflow','write_failed','threads_incomplete')):
        raise ValueError('DIRECT_EXECUTION_FAILED_OR_UNKNOWN_NO_RETRY')
    summary=json.loads(result['stdout'].decode('ascii'))
    if summary.get('schema')!='direct-tessent-acceptance-e100-v1' or summary.get('root')!='/temp/jiangchuanc/multimode_ate_direct_e100_20261025_r1':
        raise ValueError('DIRECT_RESULT_IDENTITY')
    print(json.dumps(summary,sort_keys=True))


if __name__=='__main__':main()
