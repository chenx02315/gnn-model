"""Exact historical-image recovery; continue original quota and single attempt."""
import base64
import hashlib
import json
from pathlib import Path
import sys
import zlib
from scripts import run_prospective_metadata_v1 as io
from scripts import run_linux_lifecycle_phase_e74 as prior

ROOT=Path(__file__).resolve().parents[1]
PHASE=prior.PHASE
IMAGE='sha256:66ec58a325c4165749971d95dbbe1636d8423cc7328be110c5df38ed42ca57e7'
AUTH='contracts/prospective_linux_lifecycle_recovery_e75_20261021.json'
HISTORY='data/manifests/ranking_v6_scorer_synthetic_validation_20261013_r1.json'
HISTORY_SHA='66b679f8ee45d6cdb3cb20ba8e5d450b1d3be93c36d910bb3e80cf826362dd56'
EXEC_SHA='dd5cc32619b3f53d79ba8995ed9f7b002c264bb4f8cd9ae93fa0006970526cfc'
FREEZE='data/manifests/ranking_v6_e75_execution_freeze_20261021_r1.json'
SOURCES={'recover_image':'scripts/probe_linux_lifecycle_image_e75.py',
         'execute':'scripts/execute_linux_lifecycle_e74.py'}
require=prior.require
sha=prior.sha
read=prior.read


def history():
    raw=read(HISTORY,24576)
    require(sha(raw)==HISTORY_SHA,'HISTORY_PIN')
    evidence=io.decode(raw)['evidence']['actual.log']
    body=evidence['raw'].encode('ascii')
    require(sha(body)==evidence['sha256'],'HISTORICAL_RAW_PIN')
    old=io.decode(body)
    require(old['image_id']==IMAGE and old['python']=='3.11.2'
        and old['status']=='PASS_REAL_FACTORY_SYNTHETIC_VJP_ONLY','HISTORICAL_PYTHON_IMAGE')
    return old


def payload(mode):
    require(mode in SOURCES,'FIXED_MODE')
    source=read(SOURCES[mode],20480)
    require(len(source)<=20480,'SOURCE_BOUND')
    call='main()'
    if mode=='execute':
        require(sha(source)==EXEC_SHA,'EXECUTOR_PIN')
        gate=read('scripts/verify_prospective_linux_lifecycle_v2.py')
        require(sha(gate)==prior.GATE_SHA,'GATE_PIN')
        manifest=io.decode(read(FREEZE,4096))
        require(manifest==dict(image_id=IMAGE,source_sha256=prior.GATE_SHA,
            auth_sha256=prior.AUTH_SHA,amendment_sha256=prior.AMEND_SHA),'FREEZE_PINS')
        request=dict(image_id=IMAGE,source_b64=base64.b64encode(gate).decode('ascii'),manifest=manifest)
        call='main(%r)'%request
    # Compress the complete pinned helper+request, not only its source. This
    # avoids re-sending 14 KiB of base64 as an uncompressed request literal.
    bundle=source+b'\nraise SystemExit('+call.encode('ascii')+b')\n'
    require(len(bundle)<=40960,'BUNDLE_BOUND')
    encoded=base64.b64encode(zlib.compress(bundle,9)).decode('ascii')
    wire=('import base64,zlib,hashlib\nd=zlib.decompressobj()\n'
        's=d.decompress(base64.b64decode(%r),40961)\n'
        'assert d.eof and not d.unconsumed_tail and len(s)<=40960\n'
        'assert hashlib.sha256(s).hexdigest()==%r\n'
        'exec(compile(s,"<reviewed-e75>","exec"),{"__name__":"_e75"})\n')%(encoded,sha(bundle))
    return source,wire.encode('ascii')


def usage(events):
    starts={};ends={}
    for event in events:
        require(event.get('event')in('START','END'),'EVENT_SCHEMA')
        group=starts if event['event']=='START'else ends
        require(event['mode']not in group,'DUPLICATE_MODE')
        if event['event']=='END':require(event['mode']in starts,'END_WITHOUT_START')
        group[event['mode']]=event
    require(set(starts)==set(ends),'UNRESOLVED_SESSION_STOP')
    require(ends.get('probe',{}).get('accepted')is True and
        ends.get('image',{}).get('accepted')is True,'PRIOR_PHASE_REQUIRED')
    return starts,ends,sum(x['stdin_bytes']for x in starts.values()),sum(x['return_bytes']for x in ends.values())


def admitted(mode,result):
    require(result['exit_code']==0 and not result['stderr']and not any(result[k]
        for k in('timeout','overflow','write_failed','threads_incomplete')),'TRANSPORT_FAILURE')
    obj=io.decode(result['stdout'])
    require(obj.get('host')=='bupt-gpus1','HOST')
    if mode=='recover_image':
        require(obj.get('schema')=='e75-fixed-historical-image-v1'and
            obj.get('status')=='PASS_FIXED_IMAGE_METADATA'and
            type(obj.get('metadata_bytes'))is int and 0<=obj['metadata_bytes']<=512 and
            obj.get('new_inventory_scan')is False and obj.get('actual_containers_created')==0,
            'IMAGE_RESPONSE')
        rows=obj.get('records')
        require(type(rows)is list and len(rows)==1 and rows[0].get('image_id')==IMAGE
            and rows[0].get('volumes_empty')is True
            and rows[0].get('python_execution_verified')is False,'IMAGE_ADMISSION')
    else:
        # Importing this stdlib-only module does not run Docker; reuse the
        # independently reviewed complete result validator, not a loose subset.
        from scripts import execute_linux_lifecycle_e74 as executor
        executor.gate_valid(obj.get('gate_result'))
        require(obj.get('status')=='PASS_LINUX_SYNTHETIC_GATE'and obj.get('gate_pass')is True
            and obj.get('cleanup_verified')is True and obj.get('running')is False
            and obj.get('container_exit')==0 and type(obj.get('read_bytes'))is int
            and 0<=obj['read_bytes']<=11000,'EXECUTION_RESPONSE')
    return obj


def run(mode):
    history()
    # The fixed local approval quotes Chinese; remote responses remain strict
    # ASCII. Its raw SHA is bound by the independent review before dispatch.
    auth=json.loads(read(AUTH,4096).decode('utf-8'))
    require(auth['target_image_id']==IMAGE and auth['prior_authorization_sha256']==prior.AUTH_SHA,
        'RECOVERY_AUTH')
    require(sha(read(prior.AUTH,4096))==prior.AUTH_SHA and
        sha(read('scripts/run_prospective_metadata_v1.py'))==
        'e0b1e62352781f96dc7d0e5a2a1a27e7f278b63c8aaaa07dbd946c1795c0f434'
        and sha(read('scripts/run_linux_lifecycle_phase_e74.py'))==
        'b916a80da43ead089427b3b19a6b6131269ece9a0417e90214459ea7ef91df86','DEPENDENCY_PINS')
    source,wire=payload(mode)
    review_raw=read('data/manifests/ranking_v6_e75_%s_prerun_review_20261021_r2.json'%mode,4096)
    review=io.decode(review_raw)
    require(review['verdict']=='PASS_INDEPENDENT_PREEXECUTION_REVIEW'and review['mode']==mode
        and review['source_sha256']==sha(source)and review['payload_sha256']==sha(wire)
        and review['controller_sha256']==sha(read('scripts/run_linux_lifecycle_phase_e75.py'))
        and review['recovery_authorization_sha256']==sha(read(AUTH,4096)),'REVIEW_PINS')
    require(io.decode((PHASE/'anchor.json').read_bytes())==dict(authorization_sha256=prior.OLD_AUTH_SHA,
        scope_sha256=prior.SCOPE_SHA,phase='v6_e73_linux_validation_20261021_r1'),'PHASE_ANCHOR')
    with (PHASE/'active.lock').open('xb')as lock:lock.write(b'ACTIVE\n')
    try:
        journal=PHASE/'sessions.jsonl'
        require(journal.stat().st_size<=16384,'JOURNAL_BOUND')
        starts,ends,usedin,usedout=usage([io.decode(x)for x in journal.read_bytes().splitlines()])
        require(mode not in starts and len(starts)<4,'NO_REPEAT_OR_EXTRA_SESSION')
        require(usedin+len(wire)<=32768,'PHASE_INPUT_CAP')
        if mode=='execute':
            require(ends.get('recover_image',{}).get('accepted')is True,'FRESH_IMAGE_REQUIRED')
            raw=(PHASE/'03_recover_image/stdout.log').read_bytes()
            obj=io.decode(raw)
            require(20925+obj['metadata_bytes']+11000<=32768,'PHASE_METADATA_CAP')
            require(review['image_response_sha256']==sha(raw)and
                review['freeze_sha256']==sha(read(FREEZE,4096)),'EXECUTE_REVIEW_PINS')
        cap=2048 if mode=='recover_image'else 8192
        require(usedout+cap<=16384,'PHASE_RETURN_CAP')
        pin=io.verify_cached_host('B')
        folder=PHASE/('%02d_%s'%(len(starts)+1,mode));folder.mkdir(exist_ok=False)
        io.write_new(folder/'request.json',dict(mode=mode,source_sha256=sha(source),payload_sha256=sha(wire),
            controller_sha256=review['controller_sha256'],review_sha256=sha(review_raw),
            authorization_sha256=sha(read(AUTH,4096)),stdin_bytes=len(wire),output_cap=cap,host_pin=pin))
        io.append_event(journal,dict(event='START',mode=mode,stdin_bytes=len(wire),output_cap=cap))
        result=io.transport(io.command('B'),wire,cap)
        for key in('stdout','stderr'):
            with(folder/(key+'.log')).open('xb')as stream:stream.write(result[key])
        accepted=False;reason=None
        try:admitted(mode,result);accepted=True
        except (ValueError,KeyError,TypeError,UnicodeError,RecursionError)as exc:reason=str(exc)[:120]
        receipt={k:v for k,v in result.items()if k not in('stdout','stderr')}
        receipt.update(accepted=accepted,reason=reason,stdout_sha256=sha(result['stdout']),stderr_sha256=sha(result['stderr']))
        io.write_new(folder/'transport.json',receipt)
        io.append_event(journal,dict(event='END',mode=mode,accepted=accepted,
            return_bytes=len(result['stdout'])+len(result['stderr'])))
        print(json.dumps(dict(mode=mode,accepted=accepted,execution_ready=False,training_release=False)))
        return 0 if accepted else 2
    finally:(PHASE/'active.lock').unlink()


if __name__=='__main__':
    require(len(sys.argv)==2,'ONE_FIXED_MODE')
    raise SystemExit(run(sys.argv[1]))
