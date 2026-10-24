"""Reviewed retirement control for old Job 394230 only; no registration."""
import base64
import json
from pathlib import Path
import sys
from scripts import acceptance_transport_e98 as control

SOURCE=control.ROOT/'scripts/retire_acceptance_job_e98.py'
BASE=control.ROOT/'scripts/register_acceptance_job_e97.py'
BASE_SHA='d9a30b7e94cfa3ed4fcff4306f09f147ada4c615210ecb5a2954362ad8e09a3a'
OBS=control.STAGING/'v6_e98_retire_observe_20261024_r1/stdout.json'
REVIEW=control.ROOT/'data/manifests/ranking_v6_e98_retirement_review_20261024_r1.json'
IMPORT_LINE='from scripts import register_acceptance_job_e97 as base'


def prepare(operation,helper_sha,review_sha=None):
    if operation not in ('retire_observe','retire_execute','retire_confirm'):
        raise ValueError('FIXED_RETIREMENT_OPERATION')
    raw=SOURCE.read_bytes()
    base=BASE.read_bytes()
    if len(raw)>32768 or control.sha(raw)!=helper_sha or control.sha(base)!=BASE_SHA:
        raise ValueError('REVIEWED_SOURCE_CHANGED')
    core=raw.decode('ascii')
    if core.count(IMPORT_LINE)!=1: raise ValueError('FIXED_BASE_IMPORT')
    core=core.replace(IMPORT_LINE,'')
    config=dict(operation=operation)
    if operation=='retire_execute':
        obs=OBS.read_bytes(); review=REVIEW.read_bytes()
        if len(obs)>32768 or len(review)>8192 or control.sha(review)!=review_sha:
            raise ValueError('REVIEW_BINDING')
        config.update(observation=json.loads(obs.decode('ascii')),
            review_b64=base64.b64encode(review).decode('ascii'),review_sha=review_sha)
    payload='''import base64,json,resource,types,sys
for kind,cap in ((resource.RLIMIT_AS,268435456),(resource.RLIMIT_CPU,20)):
 soft,hard=resource.getrlimit(kind)
 chosen=min([cap]+[v for v in (soft,hard) if v!=resource.RLIM_INFINITY])
 resource.setrlimit(kind,(chosen,chosen))
base=types.ModuleType('e98_retirement_base')
exec(base64.b64decode(%r),base.__dict__)
core={'base':base,'__name__':'e98_retirement_core'}
exec(base64.b64decode(%r),core)
config=json.loads(%r)
try:
 if config['operation']=='retire_observe': result=core['observe']()
 elif config['operation']=='retire_confirm': result=core['finalize_terminal']()
 else: result=core['retire_once'](config['observation'],base64.b64decode(config['review_b64']),config['review_sha'])
 raw=core['canonical'](result)
 if len(raw)>32768: raise ValueError('OUTPUT_BOUND')
 sys.stdout.buffer.write(raw+b'\\n')
except Exception as exc:
 code=str(exc)
 if not code or len(code)>128 or not all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789' for c in code): code='FAILED_OR_UNKNOWN_NO_RETRY'
 sys.stdout.write(json.dumps({'schema':'e98-retirement-failure-v1','status':code,'automatic_retries':0},sort_keys=True)+'\\n')
 sys.exit(1)
'''%(base64.b64encode(base).decode('ascii'),base64.b64encode(core.encode('ascii')).decode('ascii'),json.dumps(config,sort_keys=True))
    value=payload.encode('ascii')
    if len(value)>131072: raise ValueError('PAYLOAD_BOUND')
    compile(value,'<e98-retirement>','exec')
    return value


def main():
    if len(sys.argv) not in (4,5): raise ValueError('OP_HELPER_SHA_REVIEWED_PAYLOAD_SHA_REQUIRED')
    operation,helper_sha,payload_sha=sys.argv[1:4]
    review_sha=sys.argv[4] if len(sys.argv)==5 else None
    result=control.execute_phase(operation,prepare(operation,helper_sha,review_sha),payload_sha,32768)
    print(json.dumps(result['response'],sort_keys=True))


if __name__=='__main__': main()
