"""Fixed E97 observe/review/resume controller; never submits another job."""
import base64
import json
from pathlib import Path
import sys
from scripts import execute_acceptance_register_e97 as transport_base

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / 'scripts/prepare_acceptance_resume_e97.py'
BASE_SHA = 'd9a30b7e94cfa3ed4fcff4306f09f147ada4c615210ecb5a2954362ad8e09a3a'
STAGING = ROOT.parent / 'runtime_training_staging_20260928'
OBS_PHASE = STAGING / 'v6_e97_pre_resume_observation_20261024_r1'
RESUME_PHASE = STAGING / 'v6_e97_resume_20261024_r1'
REVIEWS = {
    name: ROOT / ('data/manifests/ranking_v6_e97_' + name + '_bound_review_20261024_r1.json')
    for name in ('registration', 'pre_resume')
}
IMPORT_LINE = 'from scripts import register_acceptance_job_e97 as base'


def prepare(mode, core_sha, review_pins=None):
    if mode not in ('observe', 'resume'):
        raise ValueError('FIXED_PHASE_REQUIRED')
    core = CORE.read_bytes()
    base = transport_base.SOURCE.read_bytes()
    if len(core) > 32768 or transport_base.sha(core) != core_sha:
        raise ValueError('REVIEWED_CORE_CHANGED')
    if transport_base.sha(base) != BASE_SHA:
        raise ValueError('FROZEN_BASE_CHANGED')
    if (transport_base.sha(transport_base.AUTH.read_bytes()) != transport_base.AUTH_SHA or
            transport_base.sha(transport_base.TRANSPORT.read_bytes()) != transport_base.TRANSPORT_SHA):
        raise ValueError('AUTH_OR_TRANSPORT_CHANGED')
    text = core.decode('ascii')
    if text.count(IMPORT_LINE) != 1:
        raise ValueError('CORE_IMPORT_CHANGED')
    text = text.replace(IMPORT_LINE, '')
    config = dict(mode=mode)
    if mode == 'resume':
        if type(review_pins) is not dict or set(review_pins) != set(REVIEWS):
            raise ValueError('INDEPENDENT_PINS_REQUIRED')
        observation_raw = (OBS_PHASE / 'stdout.json').read_bytes()
        if len(observation_raw) > 16384:
            raise ValueError('OBSERVATION_BOUND')
        observation = json.loads(observation_raw.decode('ascii'))
        config.update(observation=observation, review_pins=review_pins, reviews={})
        for name, path in REVIEWS.items():
            raw = path.read_bytes()
            if len(raw) > 8192 or transport_base.sha(raw) != review_pins[name]:
                raise ValueError('INDEPENDENT_REVIEW_CHANGED')
            config['reviews'][name] = base64.b64encode(raw).decode('ascii')
    payload = '''import base64,json,resource,types,sys
for kind,cap in ((resource.RLIMIT_AS,268435456),(resource.RLIMIT_CPU,20)):
 soft,hard=resource.getrlimit(kind)
 chosen=min([cap]+[v for v in (soft,hard) if v!=resource.RLIM_INFINITY])
 resource.setrlimit(kind,(chosen,chosen))
base=types.ModuleType('e97_frozen_registration_base')
exec(base64.b64decode(%r),base.__dict__)
core={'base':base,'__name__':'e97_reviewed_resume_core'}
exec(base64.b64decode(%r),core)
config=json.loads(%r)
try:
 if config['mode']=='observe':
  result=core['observe']()
 else:
  reviews={k:base64.b64decode(v) for k,v in config['reviews'].items()}
  result=core['resume_once'](config['observation'],reviews,config['review_pins'])
 raw=json.dumps(result,sort_keys=True,ensure_ascii=True,allow_nan=False)
 if len(raw.encode('ascii'))+1>16384: raise ValueError('OUTPUT_BOUND')
 sys.stdout.write(raw+'\\n')
except Exception as exc:
 code=str(exc)
 if not code or len(code)>128 or not all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789' for c in code): code='FAILED_OR_UNKNOWN_NO_RETRY'
 sys.stdout.write(json.dumps({'schema':'e97-resume-controller-failure-v1','status':code,'automatic_retries':0},sort_keys=True)+'\\n')
 sys.exit(1)
''' % (base64.b64encode(base).decode('ascii'),
       base64.b64encode(text.encode('ascii')).decode('ascii'),
       json.dumps(config, sort_keys=True))
    raw = payload.encode('ascii')
    if len(raw) > 65536:
        raise ValueError('PAYLOAD_BOUND')
    compile(raw, '<e97-reviewed-resume>', 'exec')
    return raw


def main():
    if len(sys.argv) not in (3, 5):
        raise ValueError('MODE_AND_REVIEWED_CORE_SHA_REQUIRED')
    mode, core_sha = sys.argv[1:3]
    if (mode == 'observe' and len(sys.argv) != 3) or (mode == 'resume' and len(sys.argv) != 5):
        raise ValueError('PHASE_ARGUMENTS')
    pins = dict(zip(('registration', 'pre_resume'), sys.argv[3:])) if mode == 'resume' else None
    payload = prepare(mode, core_sha, pins)
    helper = transport_base.load_transport()
    fingerprint = helper.verify_cached_host('A')
    phase = OBS_PHASE if mode == 'observe' else RESUME_PHASE
    phase.mkdir(exist_ok=False)
    transport_base.write_new(phase / 'start.json', transport_base.encode(dict(
        mode=mode, job_id=394230, core_sha256=core_sha, review_pins=pins,
        payload_sha256=transport_base.sha(payload), host_fingerprint=fingerprint,
        sessions_max=1, automatic_retries=0, jobs_submitted=0)))
    result = helper.transport(helper.command('A'), payload, 16384)
    transport_base.write_new(phase / 'stdout.json', result['stdout'])
    transport_base.write_new(phase / 'stderr.log', result['stderr'])
    receipt = {k:v for k,v in result.items() if k not in ('stdout', 'stderr')}
    receipt.update(stdout_sha256=transport_base.sha(result['stdout']), stdout_bytes=len(result['stdout']),
        stderr_sha256=transport_base.sha(result['stderr']), stderr_bytes=len(result['stderr']))
    transport_base.write_new(phase / 'transport.json', transport_base.encode(receipt))
    if result['exit_code'] != 0 or any(result[k] for k in ('timeout','overflow','write_failed','threads_incomplete')):
        raise ValueError('REMOTE_FAILED_OR_UNKNOWN_NO_RETRY')
    observation = helper.decode(result['stdout'])
    expected = 'e97-pre-resume-observation-v1' if mode == 'observe' else 'e97-resume-result-v1'
    if observation.get('schema') != expected or observation.get('job_id') != 394230:
        raise ValueError('RESPONSE_IDENTITY')
    print(json.dumps(observation,sort_keys=True))


if __name__ == '__main__':
    main()
