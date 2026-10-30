"""Offline exact role3 preparation and one independently reviewed readback.

No call occurs on import/prepare. Trusted input origin is the fixed reviewed
local phase producer and pinned SSH host channel, not cache JSON self-hashes.
The exact code/data/invocation projection must be independently reviewed after
role2 while the original package clock still runs. No role1/role2 rerun here.
"""
import ast
import base64
from pathlib import Path
import re
import time

from scripts import acceptance_transport_e98 as control
from scripts import run_physical_f_clean_replay_e137 as ledger
from src.data import physical_e137_role3_binding as binding

sha,canonical,decode,require = binding.sha,binding.canonical,binding.decode,binding.require
ROOT = Path(__file__).resolve().parents[1]
PHASE = 'v6_e137_clean_F_replay_r1'
AUTH = 'contracts/physical_f_clean_replay_authorization_e137.json'
PROPOSAL = 'contracts/physical_f_clean_replay_proposal_e137_v1.json'
FIXED_COMMAND = ['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no',
    '-o','ConnectTimeout=8','-o','HostKeyAlgorithms=ssh-ed25519','vnc.buptic.top','/usr/bin/python3 -I -S -B -']
INPUTS = ('start.json','package_clock.json','capture/intent.json','capture/stdout.json','capture/stderr.log',
    'capture/transport.json','capture/validated.json','execution/intent.json','execution/stdout.json',
    'execution/stderr.log','execution/transport.json','execution/validated.json','execution/source_policy.json',
    'execution/packet_review.json','execution/transport_consumed.json')
REVIEW_KEYS = ('payload_sha256','controller_sha256','source_sha256','input_sha256','authorization_sha256',
    'proposal_sha256','protocol_sha256','intent_sha256','invocation_sha256')


def _bounded(path,cap):
    require(path.is_file() and path.stat().st_size <= cap,'ROLE3_FIXED_LOCAL_INPUT_BOUND')
    raw = path.read_bytes()
    require(len(raw) <= cap,'ROLE3_LOCAL_INPUT_GREW')
    return raw


def _sources():
    """Closed local src.data import closure; no imports/transport during discovery."""
    graph,rows = {},[]
    def visit(name):
        require(type(name) is str and re.fullmatch('[A-Za-z0-9_]+',name),'ROLE3_LOCAL_MODULE_NAME')
        if name in graph:
            require(graph[name] is not None,'ROLE3_SOURCE_IMPORT_CYCLE')
            return
        require(len(graph) < 96,'ROLE3_SOURCE_MODULE_BOUND')
        graph[name] = None
        raw = _bounded(ROOT/'src/data'/(name+'.py'),262144)
        tree = ast.parse(raw.decode('utf-8'),feature_version=(3,6))
        deps = set()
        for node in ast.walk(tree):
            if isinstance(node,ast.ImportFrom):
                if node.level == 1:
                    deps.update([node.module.split('.')[0]] if node.module else [v.name for v in node.names])
                elif node.module == 'src.data':
                    deps.update(v.name for v in node.names)
                elif node.module and node.module.startswith('src.data.'):
                    deps.add(node.module.split('.')[2])
            elif isinstance(node,ast.Import):
                deps.update(v.name.split('.')[2] for v in node.names if v.name.startswith('src.data.'))
        for dep in sorted(deps):
            if (ROOT/'src/data'/(dep+'.py')).is_file():visit(dep)
        graph[name] = sha(raw)
        rows.append(dict(name=name,sha256=sha(raw),body=base64.b64encode(raw).decode('ascii')))
    visit('physical_e137_role3_binding')
    return rows


def prepare():
    phase = control.STAGING/PHASE
    raw = {name:_bounded(phase/name,6291456 if name.endswith('stdout.json') else 262144) for name in INPUTS}
    first = decode(raw['start.json'])
    require(first.get('authorization_sha256') == binding.core.APPROVED_AUTH_SHA,'ROLE3_ORIGINAL_LOCAL_PACKAGE_GRANT')
    # Check cached raw joins, never take validated.json existence/status as proof.
    for role in ('capture','execution'):
        transport = decode(raw[role+'/transport.json'])
        require(transport.get('stdout_sha256') == sha(raw[role+'/stdout.json']) and
            transport.get('stderr_sha256') == sha(raw[role+'/stderr.log']),'ROLE3_PHASE_RAW_CACHE_JOIN')
        intent = decode(raw[role+'/intent.json'])
        expected = dict(schema='e137-local-role-validation-v1',role=role,authorization_sha256=binding.core.APPROVED_AUTH_SHA,
            clock_sha256=sha(raw['start.json']),payload_sha256=intent['payload_sha256'],stdout_sha256=sha(raw[role+'/stdout.json']),
            stderr_sha256=sha(raw[role+'/stderr.log']),transport_sha256=sha(canonical(transport)))
        validated = decode(raw[role+'/validated.json'])
        require(validated == expected,
            'ROLE3_PHASE_VALIDATION_CONTENT_JOIN')
    consumed = decode(raw['execution/transport_consumed.json'])
    require(consumed == dict(attempt_consumed=True,automatic_retries=0,
        payload_sha256=decode(raw['execution/intent.json'])['payload_sha256'],host_fingerprint=binding.HOST_PIN) and
        type(consumed['automatic_retries']) is int,'ROLE3_REVIEWED_HOST_CHANNEL_RECORD_REQUIRED')
    rows = _sources()
    loaded = {r['name']:r['sha256'] for r in rows}
    package = dict(authority=_bounded(ROOT/AUTH,65536),proposal=_bounded(ROOT/PROPOSAL,65536),
        original_clock=raw['package_clock.json'],role2_stdout=raw['execution/stdout.json'],
        role2_stderr=raw['execution/stderr.log'],role2_transport=raw['execution/transport.json'],
        role2_intent=raw['execution/intent.json'])
    config = dict(schema='e137-role3-reviewed-phase-inputs-v1',package={k:base64.b64encode(v).decode('ascii') for k,v in package.items()},
        source_policy=base64.b64encode(raw['execution/source_policy.json']).decode('ascii'),
        role2_packet_review=base64.b64encode(raw['execution/packet_review.json']).decode('ascii'),loaded_source_sha256=loaded)
    config_raw = canonical(config)
    wire = canonical(dict(sources=rows,config=base64.b64encode(config_raw).decode('ascii'),config_sha256=sha(config_raw))).decode('ascii')
    template = ('import time\nbootstrap_started=time.monotonic()\nTEMPLATE=%r\nWIRE=%r\nimport base64,hashlib,json,types,sys\n'
        'p=json.loads(WIRE)\n'
        'for name in ("src","src.data"):\n m=types.ModuleType(name);m.__path__=[];sys.modules[name]=m\n'
        ' if name=="src.data":sys.modules["src"].data=m\n'
        'for row in p["sources"]:\n raw=base64.b64decode(row["body"],validate=True)\n'
        ' if hashlib.sha256(raw).hexdigest()!=row["sha256"]:raise ValueError("SOURCE_SHA")\n'
        ' name="src.data."+row["name"];m=types.ModuleType(name);m.__package__="src.data";sys.modules[name]=m\n'
        ' setattr(sys.modules["src.data"],row["name"],m);exec(compile(raw,"<role3-"+row["name"]+">","exec"),m.__dict__)\n'
        ' m.__source_sha256__=row["sha256"]\n'
        'm=sys.modules["src.data.physical_e137_role3_binding"];m.TRUSTED_CONFIG_SHA256=p["config_sha256"]\n'
        'payload_sha=hashlib.sha256((TEMPLATE%%(TEMPLATE,WIRE)).encode("ascii")).hexdigest()\n'
        'raise SystemExit(m.execute_payload(base64.b64decode(p["config"],validate=True),sys.argv[1:],sys.stdout.buffer,bootstrap_started,payload_sha))\n')
    payload = (template%(template,wire)).encode('ascii')
    require(len(payload) <= 1048576,'ROLE3_PAYLOAD_BOUND')
    ast.parse(payload.decode('ascii'),feature_version=(3,6))
    intent = canonical(dict(role='readback',attempt_consumed=True,role_index=3,connections_max=3,automatic_retries=0,payload_sha256=sha(payload)))
    argument = base64.b64encode(intent).decode('ascii')
    binding.decode_intent_argument([argument])
    binding.authenticate(config,intent,sha(payload))
    command = list(FIXED_COMMAND);command[-1]+=' '+argument
    protocol = dict(schema='e137-role3-single-readback-protocol-v1',outputs=list(binding.core.OUTPUTS),
        result_bytes=16777216,response_bytes=25165824,remote_seconds=60,local_active_seconds=50,
        cleanup_reserve_seconds=10,connections=1,role_index=3,automatic_retries=0,
        intent_transport='ONE_STRICT_BASE64_PYTHON_ARGV_NOT_SELF_HASH_AUTHORITY',
        partial_error_schema='e137-role3-partial-error-v1',trust_origin='REVIEWED_PHASE_CREATOR_AND_PINNED_SSH_CHANNEL')
    inputs = {k:sha(v) for k,v in raw.items()}
    inputs.update(authority=sha(package['authority']),proposal=sha(package['proposal']),
        legacy_local_clock_code=sha(Path(ledger.__file__).read_bytes()))
    return dict(payload=payload,command=command,intent=intent,config=config_raw,
        payload_sha256=sha(payload),controller_sha256=sha(Path(__file__).read_bytes()),source_sha256=loaded,
        input_sha256=inputs,authorization_sha256=binding.core.APPROVED_AUTH_SHA,proposal_sha256=binding.core.PROPOSAL_SHA,
        protocol_sha256=sha(canonical(protocol)),intent_sha256=sha(intent),invocation_sha256=sha(canonical(command)))


def execute(review_path,payload_sha):
    plan = prepare()
    review = decode(_bounded(Path(review_path),262144))
    require(review.get('status') == 'PASS' and review.get('reviewed') == {k:plan[k] for k in REVIEW_KEYS} and
        payload_sha == plan['payload_sha256'],'ROLE3_EXACT_INDEPENDENT_PACKET_AND_INVOCATION_REVIEW')
    phase = control.STAGING/PHASE
    first = decode(_bounded(phase/'start.json',4096))
    active_timeout = ledger.transport_timeout(first,60)
    helper = control.load_transport()
    require(helper.command('A') == FIXED_COMMAND,'ROLE3_FIXED_ACCEPTED_SSH_COMMAND')
    fingerprint = helper.verify_cached_host('A')
    require(fingerprint == binding.HOST_PIN,'ROLE3_ACCEPTED_HOST_PIN')
    directory = phase/'readback';directory.mkdir(exist_ok=False)
    control.write_new(directory/'intent.json',plan['intent'])
    control.write_new(directory/'transport_consumed.json',control.encode(dict(attempt_consumed=True,automatic_retries=0,
        payload_sha256=payload_sha,invocation_sha256=plan['invocation_sha256'],host_fingerprint=fingerprint)))
    started = time.monotonic()
    try:
        helper.TIMEOUT = min(active_timeout,ledger.transport_timeout(first,60))
        result = helper.transport(plan['command'],plan['payload'],binding.core.MAX_RESPONSE)
        control.write_new(directory/'stdout.json',result['stdout'])
        control.write_new(directory/'stderr.log',result['stderr'])
        transport = {k:v for k,v in result.items() if k not in ('stdout','stderr')}
        transport.update(stdout_bytes=len(result['stdout']),stdout_sha256=sha(result['stdout']),
            stderr_bytes=len(result['stderr']),stderr_sha256=sha(result['stderr']))
        control.write_new(directory/'transport.json',control.encode(transport))
        ledger.remaining(first)
        require(time.monotonic() < started+60 and type(result['exit_code']) is int and result['exit_code'] == 0 and
            result['stderr'] == b'' and all(result[k] is False for k in ('timeout','overflow','write_failed','threads_incomplete')),
            'ROLE3_READBACK_FAILED_OR_PARTIAL_NO_RETRY')
        value = decode(result['stdout'])
        binding.core.validate_result(value,complete=True)
        control.write_new(directory/'validated.json',control.encode(dict(schema='e137-role3-validated-raw-v1',
            stdout_sha256=sha(result['stdout']),intent_sha256=plan['intent_sha256'],transport_sha256=sha(control.encode(transport)),
            execution_ready=False,scientific_acceptance_verified=False)))
        return dict(phase=str(directory),files=len(value['files']),execution_ready=False)
    except BaseException:
        # Keep all raw/partial files. This exclusive directory consumes role3.
        if not (directory/'transport.json').exists():
            control.write_new(directory/'transport.json',control.encode(dict(status='TRANSPORT_OR_RAW_PUBLICATION_UNKNOWN',
                attempt_consumed=True,automatic_retries=0,remote_termination_verified=False)))
        control.write_new(directory/'failed.json',control.encode(dict(schema='e137-role3-terminal-failure-v1',
            attempt_consumed=True,automatic_retries=0,scientific_execution_allowed=False,remote_termination_verified=False)))
        raise
