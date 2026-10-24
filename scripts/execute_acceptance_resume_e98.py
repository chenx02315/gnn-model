"""Fixed E98 observation and one-shot resume integration; no submission."""
import base64
import json
import sys
from scripts import acceptance_transport_e98 as control

SOURCE=control.ROOT/'scripts/prepare_acceptance_resume_e98.py'
BASE=control.ROOT/'scripts/register_acceptance_job_e98.py'
BASE_SHA='a1dfbfae37df48b9c2284a01e58f7e2ac1ca220519e7ed16403827bb143adfba'
OBS=control.STAGING/'v6_e98_pre_resume_observation_20261024_r1/stdout.json'
REVIEWS={name:control.ROOT/('data/manifests/ranking_v6_e98_'+name+'_review_20261024_r1.json') for name in ('registration','pre_resume')}
IMPORT_LINE='from scripts import register_acceptance_job_e98 as base'


def prepare(operation,reviewed_core_sha,review_pins=None):
    if operation not in ('registration_review','pre_resume_observation','resume'):
        raise ValueError('FIXED_E98_RESUME_OPERATION')
    raw=SOURCE.read_bytes();base=BASE.read_bytes()
    if len(raw)>32768 or control.sha(raw)!=reviewed_core_sha or control.sha(base)!=BASE_SHA:
        raise ValueError('REVIEWED_SOURCE_CHANGED')
    core=raw.decode('ascii')
    if core.count(IMPORT_LINE)!=1: raise ValueError('FIXED_BASE_IMPORT')
    core=core.replace(IMPORT_LINE,'')
    config=dict(operation=operation)
    if operation=='resume':
        if type(review_pins) is not dict or set(review_pins)!=set(REVIEWS):
            raise ValueError('INDEPENDENT_REVIEW_PINS_REQUIRED')
        obs=OBS.read_bytes()
        if len(obs)>16384: raise ValueError('OBSERVATION_BOUND')
        config.update(observation=json.loads(obs.decode('ascii')),reviews={},review_pins=review_pins)
        for name,path in REVIEWS.items():
            raw_review=path.read_bytes()
            if len(raw_review)>16384 or control.sha(raw_review)!=review_pins[name]:
                raise ValueError('INDEPENDENT_REVIEW_CHANGED')
            config['reviews'][name]=base64.b64encode(raw_review).decode('ascii')
    payload='''import base64,json,resource,types,sys
for kind,cap in ((resource.RLIMIT_AS,268435456),(resource.RLIMIT_CPU,20)):
 soft,hard=resource.getrlimit(kind)
 chosen=min([cap]+[v for v in (soft,hard) if v!=resource.RLIM_INFINITY])
 resource.setrlimit(kind,(chosen,chosen))
base=types.ModuleType('e98_frozen_registration_base')
exec(base64.b64decode(%r),base.__dict__)
core={'base':base,'__name__':'e98_reviewed_resume_core'}
exec(base64.b64decode(%r),core)
config=json.loads(%r)
try:
 if config['operation']=='resume':
  reviews={k:base64.b64decode(v) for k,v in config['reviews'].items()}
  result=core['resume_once'](config['observation'],reviews['registration'],reviews['pre_resume'],config['review_pins'])
 else: result=core['observe']()
 raw=core['canonical'](result)
 if len(raw)+1>16384: raise ValueError('OUTPUT_BOUND')
 sys.stdout.buffer.write(raw+b'\\n')
except Exception as exc:
 code=str(exc)
 if not code or len(code)>128 or not all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789' for c in code): code='FAILED_OR_UNKNOWN_NO_RETRY'
 sys.stdout.write(json.dumps({'schema':'e98-resume-failure-v1','status':code,'automatic_retries':0},sort_keys=True)+'\\n')
 sys.exit(1)
'''%(base64.b64encode(base).decode('ascii'),base64.b64encode(core.encode('ascii')).decode('ascii'),json.dumps(config,sort_keys=True))
    value=payload.encode('ascii')
    if len(value)>65536: raise ValueError('PAYLOAD_BOUND')
    compile(value,'<e98-reviewed-resume>','exec')
    return value


def main():
    if len(sys.argv) not in (4,6): raise ValueError('OP_CORE_SHA_PAYLOAD_SHA_AND_OPTIONAL_REVIEW_PINS')
    operation,core_sha,payload_sha=sys.argv[1:4]
    if (operation=='resume') != (len(sys.argv)==6): raise ValueError('REVIEW_ARGUMENTS')
    pins=dict(zip(('registration','pre_resume'),sys.argv[4:])) if operation=='resume' else None
    result=control.execute_phase(operation,prepare(operation,core_sha,pins),payload_sha,16384)
    expected='e98-resume-result-v1' if operation=='resume' else 'e98-pre-resume-observation-v1'
    value=result['response']
    if value.get('schema')!=expected or type(value.get('job_id')) is not int or value['job_id']==394230:
        raise ValueError('E98_RESPONSE_IDENTITY')
    print(json.dumps(value,sort_keys=True))


if __name__=='__main__':main()
