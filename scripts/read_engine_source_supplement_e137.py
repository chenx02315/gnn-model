"""One independently reviewed source discovery call; never resumes E137."""
import ast
import base64
import math
import os
from pathlib import Path
import platform
import time
from src.data import engine_source_discovery_e137 as core

PHASE = 'v6_e137_engine_source_supplement_r1'
AUTH = 'contracts/physical_engine_source_discovery_authorization_e137.json'
PROPOSAL = 'contracts/physical_engine_source_discovery_supplement_e137_v1.json'
REVIEW_KEYS = ('payload_sha256','controller_sha256','source_sha256','authorization_sha256','proposal_sha256')


def collect(spec,started):
    from src.data import direct_tessent_acceptance_e104 as direct
    core.check_authority(base64.b64decode(spec['authority'],validate=True),base64.b64decode(spec['proposal'],validate=True))
    core.require(platform.node() == 'bupt-vncs2' and os.getuid() == 1047 and os.sys.platform.startswith('linux'),'FIXED_A')
    core.require(type(started) in (int,float) and math.isfinite(started) and started >= 0,'CAPTURE_CLOCK')
    domain = direct.Descendants()
    def tick():
        core.require(started <= time.monotonic() < started+60,'SUPPLEMENT_DEADLINE')
        core.require(not domain.sample() and domain.peak <= 536870912,'SUPPLEMENT_MEMORY_OR_CHILD')
    total,rows = [0],[]
    for path in core.PATHS:
        rows.append(core.read_file(path,tick,total))
    value = dict(schema=core.SCHEMA,files=rows,simulation_budget_changed=False)
    tick()
    core.validate(core.canonical(value))
    tick()
    return value


def prepare():
    from scripts.run_direct_tessent_e104 import PINS
    repo = Path(__file__).resolve().parents[1]
    authority,proposal = (repo/AUTH).read_bytes(),(repo/PROPOSAL).read_bytes()
    core.check_authority(authority,proposal)
    sources = []
    for name,pin in list(PINS)+[('physical_replay_source_reader_e135','6d6f86341eca23d5b473f8e323a0440d50ea44d177032576f196b9b417690818'),
            ('engine_source_discovery_e137',None),('_e137_supplement',None)]:
        raw = (Path(__file__) if name == '_e137_supplement' else repo/'src/data'/(name+'.py')).read_bytes()
        core.require(pin is None or core.sha(raw) == pin,'FROZEN_SOURCE')
        ast.parse(raw.decode('utf-8'),feature_version=(3,6))
        sources.append(dict(name=name,sha256=core.sha(raw),body=base64.b64encode(raw).decode('ascii')))
    wire = core.canonical(dict(sources=sources,spec=dict(authority=base64.b64encode(authority).decode('ascii'),
        proposal=base64.b64encode(proposal).decode('ascii')))).decode('ascii')
    payload = ('import time\nstarted=time.monotonic()\nimport base64,hashlib,json,types,sys\np=json.loads('+repr(wire)+')\n'
        'for name in ("src","src.data"):\n m=types.ModuleType(name);m.__path__=[];sys.modules[name]=m\n'
        ' if name=="src.data":sys.modules["src"].data=m\n'
        'for row in p["sources"]:\n raw=base64.b64decode(row["body"],validate=True)\n'
        ' if hashlib.sha256(raw).hexdigest()!=row["sha256"]:raise ValueError("SOURCE_SHA")\n'
        ' name="src.data."+row["name"];m=types.ModuleType(name);m.__package__="src.data";sys.modules[name]=m\n'
        ' setattr(sys.modules["src.data"],row["name"],m);exec(compile(raw,"<supplement>","exec"),m.__dict__)\n'
        'result=sys.modules["src.data._e137_supplement"].collect(p["spec"],started)\n'
        'print(json.dumps(result,sort_keys=True,allow_nan=False),flush=True)\n').encode('ascii')
    ast.parse(payload.decode('ascii'),feature_version=(3,6))
    return dict(payload=payload,payload_sha256=core.sha(payload),controller_sha256=core.sha(Path(__file__).read_bytes()),
        source_sha256={r['name']:r['sha256'] for r in sources},authorization_sha256=core.AUTH_SHA,proposal_sha256=core.PROPOSAL_SHA)


def execute(review_path,payload_sha):
    from scripts import acceptance_transport_e98 as control
    plan = prepare()
    review = core.decode(Path(review_path).read_bytes())
    core.require(review.get('status') == 'PASS' and review.get('reviewed') == {k:plan[k] for k in REVIEW_KEYS} and
        payload_sha == plan['payload_sha256'],'EXACT_SUPPLEMENT_REVIEW')
    helper = control.load_transport()
    fingerprint = helper.verify_cached_host('A')
    phase = control.STAGING/PHASE
    phase.mkdir(exist_ok=False)
    started = time.monotonic()
    control.write_new(phase/'start.json',control.encode(dict(authorization_sha256=core.AUTH_SHA,payload_sha256=payload_sha,
        host_fingerprint=fingerprint,attempt_consumed=True,automatic_retries=0,simulation_budget_changed=False)))
    try:
        helper.TIMEOUT = 50  # Ten seconds remain for local cleanup and qualification.
        result = helper.transport(helper.command('A'),plan['payload'],core.MAX_RESPONSE)
    except BaseException as exc:
        control.write_new(phase/'transport.json',control.encode(dict(error_type=type(exc).__name__,attempt_consumed=True)))
        raise
    control.write_new(phase/'stdout.json',result['stdout'])
    control.write_new(phase/'stderr.log',result['stderr'])
    control.write_new(phase/'transport.json',control.encode({k:v for k,v in result.items() if k not in ('stdout','stderr')}))
    core.require(time.monotonic() < started+60,'LOCAL_SUPPLEMENT_DEADLINE')
    core.require(result['exit_code'] == 0 and not any(result[k] for k in ('timeout','overflow','write_failed','threads_incomplete')),'SUPPLEMENT_TRANSPORT_FAILED')
    value,bodies = core.validate(result['stdout'])
    output = phase/'files'
    output.mkdir(exist_ok=False)
    for row,body in zip(value['files'],bodies):
        core.require(time.monotonic() < started+60,'LOCAL_SUPPLEMENT_DEADLINE')
        path = output/row['sha256']
        control.write_new(path,body)
        core.require(core.sha(path.read_bytes()) == row['sha256'],'LOCAL_DISK_REHASH')
    core.require(time.monotonic() < started+60,'LOCAL_SUPPLEMENT_DEADLINE')
    control.write_new(phase/'validated.json',control.encode(dict(files=[{k:v for k,v in r.items() if k != 'body_base64'}
        for r in value['files']],simulation_budget_changed=False,execution_ready=False)))
    return dict(phase=str(phase),simulation_budget_changed=False,execution_ready=False)
