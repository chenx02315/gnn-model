"""Offline preparation and one explicit E101 run, gated on a new reply record."""
import base64
import json
from pathlib import Path
import re
import sys

from scripts import acceptance_transport_e98 as control
from src.data import direct_tessent_acceptance_e101 as repair

ROOT=Path(__file__).resolve().parents[1]
AUTH='contracts/direct_tessent_repair_authorization_e101_20261025.json'
E85='data/manifests/ranking_v6_e85_input_observation_20261023_r1.json'
E93='data/manifests/ranking_v6_e93_input_observation_20261023_r1.json'
PINS=(
 ('prospective_tessent_acceptance_v1','6d4b45d303a4be34f03914b8f9cb4aad2d9fe73c41c666a6c12058c43ef5aac2'),
 ('prospective_fault_translation_v2','2488abc20cf6e55aabb5d80317615645ed9bbaf80eb97d75f05920befd8b1961'),
 ('prospective_lsf_memory_preflight_v1','c63e8d9dea1aefef2061de2c3147c574f9dc2881e9b97dd89d585bfaf4fa46dd'),
 ('prospective_acceptance_materializer_v1','a04127c07227814e331ede4268c6f8d5df4def4d7041c0c69ec048378216cab9'),
 ('prospective_acceptance_scratch_v1','ddf332e6d78a81cf2369bdcdee9e60c1ee3b9b1c22008bf7a77beaedee39cb86'),
 ('direct_tessent_acceptance_e100',repair.BASE_SHA),
 ('direct_memory_sample_e101',repair.SAMPLER_SHA),
 ('direct_tessent_acceptance_e101','e01c19f2025df4a962314c0c7a4cca50ee0b108a460e386861d92518535bb72c'))


def prepare(authority_raw=None):
    if authority_raw is None:
        if not (ROOT/AUTH).is_file():
            raise PermissionError('EXPLICIT_NEW_USER_REPLY_NOT_RECORDED')
        authority_raw=(ROOT/AUTH).read_bytes()
    repair.validate_authority(authority_raw)
    failed=(ROOT/'data/manifests/ranking_v6_e100_execution_response_20261025_r1.json').read_bytes()
    if control.sha(failed)!=repair.FAILED_RESPONSE_SHA:
        raise ValueError('FAILED_PREDECESSOR_EVIDENCE_CHANGED')
    sources=[]
    for name,pin in PINS:
        raw=(ROOT/'src/data'/(name+'.py')).read_bytes()
        if control.sha(raw)!=pin:
            raise ValueError('REVIEWED_COMPONENT_CHANGED')
        sources.append(dict(name=name,sha256=pin,body=base64.b64encode(raw).decode('ascii')))
    raw85=(ROOT/E85).read_bytes();raw93=(ROOT/E93).read_bytes()
    if control.sha(raw85)!=repair.base.recipe.E85_SHA256 or control.sha(raw93)!=repair.base.recipe.E93_SHA256:
        raise ValueError('FROZEN_INPUT_CHANGED')
    package=dict(sources=sources,authority=base64.b64encode(authority_raw).decode('ascii'),
        e85=base64.b64encode(raw85).decode('ascii'),e93=base64.b64encode(raw93).decode('ascii'))
    payload=('import base64,hashlib,json,os,platform,sys,types\n'
        'assert platform.node()=="bupt-vncs2" and sys.platform.startswith("linux") and os.getuid()==1047\n'
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
        ' m.__source_sha256__=row["sha256"]\n'
        'm=sys.modules["src.data.direct_tessent_acceptance_e101"]\n'
        'result=m.execute(base64.b64decode(p["e85"]),base64.b64decode(p["e93"]),base64.b64decode(p["authority"]))\n'
        'print(json.dumps(result,sort_keys=True),flush=True)\n').encode('ascii')
    if len(payload)>524288:raise ValueError('PAYLOAD_BOUND')
    compile(payload,'<E101-prepared-not-executed>','exec')
    return dict(payload=payload,payload_bytes=len(payload),payload_sha256=control.sha(payload),
        authorization_sha256=control.sha(authority_raw),source_sha256=dict(PINS),
        input_sha256=dict(e85=control.sha(raw85),e93=control.sha(raw93)))


def main():
    args=sys.argv[1:]
    if args==['prepare']:
        try:plan=prepare()
        except PermissionError:
            print(json.dumps(dict(status='PENDING_EXPLICIT_NEW_USER_REPLY',execution_ready=False,payload_prepared=False)));return
        print(json.dumps({k:v for k,v in plan.items() if k!='payload'},sort_keys=True));return
    if len(args)!=2 or args[0]!='execute' or re.fullmatch('[0-9a-f]{64}',args[1]) is None:
        raise ValueError('REVIEWED_EXACT_PAYLOAD_REQUIRED')
    plan=prepare()  # Missing/invalid actual reply fails before any network or phase creation.
    if args[1]!=plan['payload_sha256']:raise ValueError('REVIEWED_EXACT_PAYLOAD_CHANGED')
    transport=control.load_transport();transport.TIMEOUT=2760
    fingerprint=transport.verify_cached_host('A')
    phase=control.STAGING/'v6_e101_direct_acceptance_20261025_r1'
    phase.mkdir(exist_ok=False)
    control.write_new(phase/'start.json',control.encode(dict(
        {k:v for k,v in plan.items() if k!='payload'},host_fingerprint=fingerprint,
        execution_attempt_consumed=True,automatic_retries=0,lsf_used=False)))
    result=transport.transport(transport.command('A'),plan['payload'],65536)
    control.write_new(phase/'stdout.json',result['stdout']);control.write_new(phase/'stderr.log',result['stderr'])
    receipt={k:v for k,v in result.items() if k not in ('stdout','stderr')}
    receipt.update(stdout_bytes=len(result['stdout']),stdout_sha256=control.sha(result['stdout']),
        stderr_bytes=len(result['stderr']),stderr_sha256=control.sha(result['stderr']))
    control.write_new(phase/'transport.json',control.encode(receipt))
    print(json.dumps(receipt,sort_keys=True))
    if result['exit_code']!=0 or any(result[k] for k in ('timeout','overflow','write_failed','threads_incomplete')):
        raise ValueError('E101_EXECUTION_FAILED_OR_UNKNOWN_NO_RETRY')
    summary=json.loads(result['stdout'].decode('ascii'))
    if summary.get('schema')!='direct-tessent-acceptance-e100-v1' or summary.get('root')!=repair.ROOT:
        raise ValueError('E101_RESULT_IDENTITY')
    print(json.dumps(summary,sort_keys=True))


if __name__=='__main__':main()
