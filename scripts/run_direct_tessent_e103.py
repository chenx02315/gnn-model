"""Offline preparation and one explicit E103 run, gated on a new reply record."""
import base64
import json
from pathlib import Path
import re
import sys

from scripts import acceptance_transport_e98 as control
from src.data import direct_tessent_acceptance_e103 as repair

ROOT=Path(__file__).resolve().parents[1]
AUTH='contracts/direct_tessent_repair_authorization_e103_20261025.json'
E85='data/manifests/ranking_v6_e85_input_observation_20261023_r1.json'
E93='data/manifests/ranking_v6_e93_input_observation_20261023_r1.json'
AUTH_SHA='269c02b6ac6bfd8f012320f8ebb734daad8059e3db0de0bf05acec46b2fd6a75'
POLICY_SHA='9bc6d42d5863da84fe05a05e9984f488e97955de9fd0a2c0b87d83739ca32b06'
PINS=(
 ('prospective_tessent_acceptance_v1','6d4b45d303a4be34f03914b8f9cb4aad2d9fe73c41c666a6c12058c43ef5aac2'),
 ('prospective_fault_translation_v2','2488abc20cf6e55aabb5d80317615645ed9bbaf80eb97d75f05920befd8b1961'),
 ('prospective_lsf_memory_preflight_v1','c63e8d9dea1aefef2061de2c3147c574f9dc2881e9b97dd89d585bfaf4fa46dd'),
 ('prospective_acceptance_materializer_v1','a04127c07227814e331ede4268c6f8d5df4def4d7041c0c69ec048378216cab9'),
 ('prospective_acceptance_scratch_v1','ddf332e6d78a81cf2369bdcdee9e60c1ee3b9b1c22008bf7a77beaedee39cb86'),
 ('direct_tessent_acceptance_e100','92f9915bc431483ba73cc38829356ca315a16ae39713b021b2025d0ce744fb58'),
 ('direct_memory_sample_e101','8a4e81fb3ef50cb3ad7fcd720d7f205ba7df6228b2af34dd87c0986968a22009'),
 ('direct_memory_sample_e103','17e4522849a386a268f7135f870e8d49bb190c032b819cf69f037fd27ee13cbb'),
 ('direct_runtime_compatibility_e102','2ec8387acec97e38604141ea5e108149dbc310823c23684da1d7fb194f8d71c1'),
 ('direct_scratch_monitor_e102','8ef6652bcf18867f3a5db44aad103f3734ff7b886a3d04912274c5ed150b4174'),
 ('direct_observation_journal_e102','e53e1d3b32f237519adf52b8d1005f7c592b428150e8b8e91bbe46878437c027'),
 ('direct_diagnostic_policy_e102','67dbbd601cdcd667c06bc8b0c238016da2c6689a9549f0601b5f6a0fc7010ff0'),
 ('direct_tessent_acceptance_e103','cdb3080f571bd706c24a6414cac4a2b67027ee888169aef879b3312235bcf097'),
)


def prepare(authority_raw=None):
    if authority_raw is None:
        if not (ROOT/AUTH).is_file():
            raise PermissionError('EXPLICIT_NEW_USER_REPLY_NOT_RECORDED')
        authority_raw=(ROOT/AUTH).read_bytes()
    if control.sha(authority_raw)!=AUTH_SHA:
        raise PermissionError('EXPLICIT_PACKAGE_REPLY_RECORD_CHANGED')
    repair.validate_authority(authority_raw)
    if control.sha((ROOT/'contracts/direct_tessent_startup_exceptions_e102_v1.json').read_bytes())!=POLICY_SHA:
        raise ValueError('REVIEWED_DIAGNOSTIC_POLICY_CHANGED')
    failed=(ROOT/'data/manifests/ranking_v6_e102_execution_response_20261025_r1.json').read_bytes()
    if control.sha(failed)!='c19f095ba00657f408ebf6b1ef322024b2c544413dcd45bcc69faf31645fed0f':
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
        'm=sys.modules["src.data.direct_tessent_acceptance_e103"]\n'
        'result=m.execute(base64.b64decode(p["e85"]),base64.b64decode(p["e93"]),base64.b64decode(p["authority"]))\n'
        'print(json.dumps(result,sort_keys=True),flush=True)\n').encode('ascii')
    if len(payload)>524288:raise ValueError('PAYLOAD_BOUND')
    compile(payload,'<E103-prepared-not-executed>','exec')
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
    phase=control.STAGING/'v6_e103_direct_acceptance_20261025_r1'
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
        raise ValueError('E103_EXECUTION_FAILED_OR_UNKNOWN_NO_RETRY')
    summary=json.loads(result['stdout'].decode('ascii'))
    if summary.get('schema')!='direct-tessent-acceptance-e103-v1' or summary.get('root')!=repair.ROOT:
        raise ValueError('E103_RESULT_IDENTITY')
    print(json.dumps(summary,sort_keys=True))
    if summary.get('passed') is not True:
        raise ValueError('E103_FIRST_FAILURE_STOP_NO_AUTOMATIC_RETRY')


if __name__=='__main__':main()
