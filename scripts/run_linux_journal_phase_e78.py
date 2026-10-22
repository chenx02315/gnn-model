"""E78 create-once local phase controller; no dispatch at import or build time."""
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import zlib

from scripts import run_prospective_metadata_v1 as io
from scripts import execute_linux_journal_e78 as helper
from src.data import prospective_linux_journal_v3 as journal_v3

ROOT = Path(__file__).resolve().parents[1]
PHASE = ROOT.parent / 'runtime_training_staging_20260928/v6_e78_linux_journal_20261022_r1'
AUTH = 'contracts/prospective_linux_journal_e78_authorization_20261022.json'
PROPOSAL = 'contracts/prospective_linux_journal_v3_execution_request.json'
REVIEW = 'data/manifests/ranking_v6_e78_prerun_review_20261022_r1.json'
SOURCE_PATHS = {'v2.py':'src/data/prospective_lifecycle_journal_v2.py',
                'gate.py':'scripts/verify_prospective_linux_lifecycle_v2.py',
                'v3.py':'src/data/prospective_linux_journal_v3.py'}
HOST_PIN = 'SHA256:IF1uJU6T8bAB/nWJn9HibWGcvuVfiYFdQTECrNQlbPo'
TRANSPORT_SHA = 'e0b1e62352781f96dc7d0e5a2a1a27e7f278b63c8aaaa07dbd946c1795c0f434'
WIRE_CAP = 65536
RETURN_CAP = 14336  # Leave 2048 of approved phase return for exact-ID audit.


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(relative, cap=65536):
    path = ROOT / relative
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= cap,
            'FIXED_SOURCE_FILE')
    raw = path.read_bytes()
    require(len(raw) <= cap, 'SOURCE_READ_CAP')
    return raw


def build_packet():
    """Read-only freeze candidate; return wire plus concrete pins for review."""
    auth = read(AUTH,8192)
    proposal = read(PROPOSAL,8192)
    require(sha(auth)==helper.AUTH_SHA and sha(proposal)==helper.PROPOSAL_SHA,
            'AUTH_PROPOSAL_PIN')
    approval = json.loads(auth.decode('utf-8'))
    require(approval.get('status')=='AUTHORIZED_PENDING_IMPLEMENTATION_AND_INDEPENDENT_PREEXECUTION_REVIEW'
            and approval.get('approved_proposal_sha256')==helper.PROPOSAL_SHA and
            approval.get('exact_existing_image')==helper.IMAGE and
            approval.get('new_output_root')==helper.ROOT, 'APPROVAL_SCOPE')
    sources = {name:read(path,24000) for name,path in SOURCE_PATHS.items()}
    require(sum(map(len,sources.values()))<=65536 and
            all(sha(sources[name])==helper.SOURCES[name] for name in SOURCE_PATHS),
            'SOURCE_PINS')
    request = {'image_id':helper.IMAGE,'auth_sha256':helper.AUTH_SHA,
               'proposal_sha256':helper.PROPOSAL_SHA,
               'sources':{n:base64.b64encode(body).decode('ascii') for n,body in sources.items()}}
    source = read('scripts/execute_linux_journal_e78.py',32768)
    require(sha(read('scripts/run_prospective_metadata_v1.py',32768))==TRANSPORT_SHA,
            'TRANSPORT_DEPENDENCY_PIN')
    bundle = source+b'\nraise SystemExit(main('+repr(request).encode('ascii')+b'))\n'
    require(len(bundle)<=160000,'BUNDLE_BOUND')
    packed = base64.b64encode(zlib.compress(bundle,9)).decode('ascii')
    wire = ('import base64,zlib,hashlib\n'
            'd=zlib.decompressobj()\n'
            's=d.decompress(base64.b64decode(%r),160001)\n'
            'assert d.eof and not d.unconsumed_tail and len(s)<=160000\n'
            'assert hashlib.sha256(s).hexdigest()==%r\n'
            'exec(compile(s,"<reviewed-e78>","exec"),{"__name__":"_e78"})\n'
            )%(packed,sha(bundle))
    wire=wire.encode('ascii')
    require(len(wire)<=WIRE_CAP,'WIRE_BOUND')
    return wire,dict(image_id=helper.IMAGE,authorization_sha256=sha(auth),
                     proposal_sha256=sha(proposal),source_sha256={n:sha(v) for n,v in sources.items()},
                     helper_sha256=sha(source),
                     controller_sha256=sha(read('scripts/run_linux_journal_phase_e78.py',32768)),
                     transport_sha256=TRANSPORT_SHA,
                     payload_sha256=sha(wire),payload_bytes=len(wire),
                     source_bytes=sum(map(len,sources.values())),host_pin=HOST_PIN)


def review(packet_meta):
    raw=read(REVIEW,8192)
    obj=io.decode(raw)
    require(type(obj) is dict and obj.get('verdict')=='PASS_INDEPENDENT_PREEXECUTION_REVIEW',
            'REVIEW_VERDICT')
    require(all(obj.get(key)==value for key,value in packet_meta.items()),'REVIEW_PINS')
    return sha(raw)


def admitted(result, folder):
    require(result['exit_code']==0 and not result['stderr'] and
            not any(result[k] for k in ('timeout','overflow','write_failed','threads_incomplete')),
            'TRANSPORT_FAILURE')
    obj=io.decode(result['stdout'])
    require(type(obj) is dict and obj.get('schema')=='e78-host-execution-v1' and
            obj.get('host')=='bupt-gpus1' and obj.get('image_id')==helper.IMAGE and
            obj.get('auth_sha256')==helper.AUTH_SHA and
            obj.get('proposal_sha256')==helper.PROPOSAL_SHA and
            obj.get('source_sha256')==helper.SOURCES and
            obj.get('status')=='PASS_FIXED_LINUX_JOURNAL_ONLY' and
            obj.get('gate_pass') is True and obj.get('cleanup_verified') is True and
            obj.get('phase')=='COMPLETE' and obj.get('retry_allowed') is False and
            obj.get('execution_ready') is False and obj.get('training_release') is False and
            obj.get('running') is False and obj.get('oom_killed') is False and
            obj.get('container_exit')==0 and obj.get('attach_exit')==0 and
            type(obj.get('read_bytes')) is int and 0<=obj['read_bytes']<=helper.READ_CAP and
            type(obj.get('container_id')) is str and helper.CID.fullmatch(obj['container_id']),
            'HOST_RECEIPT')
    raw=base64.b64decode(obj['journal_b64'],validate=True)
    require(0<len(raw)<=8192 and obj.get('journal_bytes')==len(raw) and
            obj.get('journal_sha256')==sha(raw),'JOURNAL_HASH')
    live=obj['live_summary']
    helper.validate_live(dict(schema='e78-container-live-v1',
                              status='PASS_FIXED_LINUX_JOURNAL_ONLY',live_summary=live,
                              execution_ready=False,training_release=False))
    path=folder/'events.jsonl'
    with path.open('xb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
    replay=journal_v3.load(path)
    intervals=[item['interval_ns'] for item in replay['attempts'].values()]
    require(len(intervals)==3 and all(type(value) is int and value>0 for value in intervals)
            and sum(intervals)==live['observed_interval_ns_sum_or_None'],
            'INTERVAL_REPLAY_MISMATCH')
    require(replay['structural_complete'] is True and
            replay['fsync_acknowledgments_verified'] is False and
            replay['observed_interval_ns_sum_or_None'] is None and
            replay['head_sha256']==live['head_sha256'] and replay['attempts']==live['attempts'] and
            replay['event_count']==9 and replay['observed_identity_records']==3,
            'INDEPENDENT_JOURNAL_REPLAY')
    require(live.get('production_execution_ready') is False and
            live.get('training_release') is False and
            replay.get('production_execution_ready') is False and
            replay.get('training_release') is False,
            'NESTED_RELEASE_FLAG')
    return obj,replay


def run():
    wire,meta=build_packet()
    review_sha=review(meta)
    pin=io.verify_cached_host('B')
    require(pin==HOST_PIN,'HOST_PIN')
    require(not PHASE.exists(),'NO_REPEAT_PHASE_ROOT')
    PHASE.mkdir(parents=False,exist_ok=False)
    io.write_new(PHASE/'anchor.json',dict(schema='e78-phase-anchor-v1',
                 authorization_sha256=helper.AUTH_SHA,proposal_sha256=helper.PROPOSAL_SHA,
                 review_sha256=review_sha,payload_sha256=meta['payload_sha256'],
                 first_read_cap=helper.READ_CAP,second_read_reserve=4096,
                 first_return_cap=RETURN_CAP,second_return_reserve=2048,
                 no_retry=True,execution_ready=False,training_release=False))
    sessions=PHASE/'sessions.jsonl'
    with sessions.open('xb') as stream:
        stream.flush();os.fsync(stream.fileno())
    folder=PHASE/'01_execute'
    folder.mkdir(exist_ok=False)
    io.write_new(folder/'request.json',meta)
    # Durable START consumes the only creation opportunity even if transport disappears.
    io.append_event(sessions,dict(event='START',mode='execute',stdin_bytes=len(wire),
                                  output_cap=RETURN_CAP,payload_sha256=meta['payload_sha256']))
    result=io.transport(io.command('B'),wire,RETURN_CAP)
    require(len(result['stdout'])+len(result['stderr'])<=RETURN_CAP,'RETURN_CAP')
    for key in ('stdout','stderr'):
        with (folder/(key+'.log')).open('xb') as stream:
            stream.write(result[key]);stream.flush();os.fsync(stream.fileno())
    accepted=False;reason=None;receipt=None
    try:
        receipt,_=admitted(result,folder)
        accepted=True
    except (ValueError,KeyError,TypeError,UnicodeError,RecursionError) as exc:
        reason=(type(exc).__name__+':'+str(exc))[:120]
    summary={k:v for k,v in result.items() if k not in ('stdout','stderr')}
    summary.update(accepted=accepted,reason=reason,stdout_sha256=sha(result['stdout']),
                   stderr_sha256=sha(result['stderr']),container_id=(receipt or {}).get('container_id'))
    io.write_new(folder/'transport.json',summary)
    io.append_event(sessions,dict(event='END',mode='execute',accepted=accepted,
                                  return_bytes=len(result['stdout'])+len(result['stderr'])))
    print(json.dumps(dict(accepted=accepted,phase=str(PHASE),
                          execution_ready=False,training_release=False)))
    return 0 if accepted else 2


if __name__=='__main__':
    require(len(sys.argv)==2 and sys.argv[1] in ('build-only','execute'),'FIXED_MODE')
    if sys.argv[1]=='build-only':
        _,meta=build_packet()
        print(json.dumps(meta,sort_keys=True,separators=(',',':')))
    else:
        raise SystemExit(run())
