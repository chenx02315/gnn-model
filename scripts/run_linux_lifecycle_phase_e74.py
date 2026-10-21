"""Continue the existing E73 quota journal under the approved OOM amendment."""
import base64
import hashlib
import json
from pathlib import Path
import sys
import zlib

from scripts import run_prospective_metadata_v1 as io

ROOT=Path(__file__).resolve().parents[1]
PHASE=ROOT.parent/'runtime_training_staging_20260928/v6_e73_linux_validation_20261021_r1'
AUTH='contracts/prospective_linux_lifecycle_authorization_e74_20261021.json'
AUTH_SHA='3c3363fae281a84938ba2d288060cb542afd375345c5d5777bf7ec17b93a7ce1'
OLD_AUTH_SHA='d758c91cd61a0aaa3745387892acf5b82de327c3a27c83dc0db0d623029a1bda'
AMEND_SHA='c656364f5ec261f8039fb0eaa4db8777ebfb243ed2dd70cef02e539d7928577e'
SCOPE_SHA='82fa3c895afbde96935d2c849ca07e5fc7159a0715400fbd2b9f5bde56639dad'
GATE_SHA='3a777175d1f4687e03950c5dd0aa97b8c3cba3a90905be672af274f7c28dea15'
SOURCES={'image':'scripts/probe_linux_lifecycle_images_e74.py','execute':'scripts/execute_linux_lifecycle_e74.py'}
FREEZE='data/manifests/ranking_v6_e74_execution_freeze_20261021_r1.json'


def require(ok,code):
    if not ok:raise ValueError(code)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def read(relative,cap=20480):
    path=ROOT/relative
    require(path.is_file() and not path.is_symlink() and path.stat().st_size<=cap,'FIXED_SMALL_FILE')
    raw=path.read_bytes();require(len(raw)<=cap,'FILE_CAP')
    return raw


def payload(mode,source):
    call='g["main"]()'
    if mode=='execute':
        gate=read('scripts/verify_prospective_linux_lifecycle_v2.py')
        require(sha(gate)==GATE_SHA,'GATE_PIN')
        manifest=io.decode(read(FREEZE,4096))
        require(set(manifest)=={'image_id','source_sha256','auth_sha256','amendment_sha256'},'FREEZE_SCHEMA')
        require(manifest['source_sha256']==GATE_SHA and manifest['auth_sha256']==AUTH_SHA
                and manifest['amendment_sha256']==AMEND_SHA,'FREEZE_PINS')
        observed=read('data/manifests/ranking_v6_e73_environment_20261021_r1.json',8192)
        require(sha(observed)=='a82c28a2923745754be9933b66dee47845d79763eaf6c9a875695373dcabe05f','OBSERVED_IMAGE_PIN')
        require(manifest['image_id']in {row['immutable_id']for row in io.decode(observed)['images']},'OBSERVED_IMAGE_ONLY')
        imagefile=PHASE/'02_image/stdout.log'
        require(imagefile.is_file() and imagefile.stat().st_size<=4096,'IMAGE_METADATA_BOUND')
        metadata=io.decode(imagefile.read_bytes())
        # Cmd/Entrypoint is only a hint; its absence must not be called proof
        # Python is absent. No execution review is issued without admission.
        require(any(row['image_id']==manifest['image_id']and row['volumes_empty']is True
            and row['declared_python_command']is True for row in metadata['records']),'IMAGE_METADATA_ADMISSION')
        request=dict(image_id=manifest['image_id'],source_b64=base64.b64encode(gate).decode('ascii'),manifest=manifest)
        call='g["main"](%r)'%request
    compressed=base64.b64encode(zlib.compress(source,9)).decode('ascii')
    wrapper=('import zlib,base64,hashlib\nd=zlib.decompressobj()\n'
        's=d.decompress(base64.b64decode(%r),20481)\n'
        'assert d.eof and not d.unconsumed_tail and len(s)<=20480\n'
        'assert hashlib.sha256(s).hexdigest()==%r\n'
        'g={"__name__":"_reviewed_e74_payload"}\nexec(compile(s,"<pinned-e74>","exec"),g)\n'
        'raise SystemExit(%s)\n')%(compressed,sha(source),call)
    return wrapper.encode('ascii')


def run(mode):
    require(type(mode)is str and mode in SOURCES,'FIXED_MODE')
    require(sha(read(AUTH,4096))==AUTH_SHA and
        sha(read('contracts/prospective_linux_lifecycle_amendment_e73_v2.json',8192))==AMEND_SHA,'AMENDMENT_AUTH_PIN')
    require(json.loads(read(AUTH,4096).decode('utf-8'))['user_amendment_authorization_received']is True,'AMENDMENT_APPROVAL')
    require(sha(read('scripts/run_prospective_metadata_v1.py'))==
        'e0b1e62352781f96dc7d0e5a2a1a27e7f278b63c8aaaa07dbd946c1795c0f434','TRANSPORT_PIN')
    source=read(SOURCES[mode]);wire=payload(mode,source)
    reviewname='data/manifests/ranking_v6_e74_%s_prerun_review_20261021_r1.json'%mode
    reviewraw=read(reviewname,4096);review=io.decode(reviewraw)
    require(review['verdict']=='PASS_INDEPENDENT_PREEXECUTION_REVIEW' and review['mode']==mode
        and review['source_sha256']==sha(source) and review['payload_sha256']==sha(wire)
        and review['controller_sha256']==sha(read('scripts/run_linux_lifecycle_phase_e74.py'))
        and review['auth_sha256']==AUTH_SHA,'INDEPENDENT_REVIEW_PIN')
    if mode=='execute':
        require(review['freeze_sha256']==sha(read(FREEZE,4096)) and
            review['image_response_sha256']==sha((PHASE/'02_image/stdout.log').read_bytes()),'EXECUTION_FREEZE_REVIEW')
    require(io.decode((PHASE/'anchor.json').read_bytes())==dict(authorization_sha256=OLD_AUTH_SHA,
        scope_sha256=SCOPE_SHA,phase='v6_e73_linux_validation_20261021_r1'),'EXISTING_PHASE_ANCHOR')
    with (PHASE/'active.lock').open('xb') as lock:lock.write(b'ACTIVE\n')
    try:
        journal=PHASE/'sessions.jsonl'
        require(journal.stat().st_size<=16384,'JOURNAL_BOUND')
        events=[io.decode(line) for line in journal.read_bytes().splitlines()]
        starts=[e for e in events if e['event']=='START'];ends={e['mode']:e for e in events if e['event']=='END'}
        require(all(e['mode']in ends for e in starts),'UNRESOLVED_SESSION_STOP')
        require(mode not in {e['mode']for e in starts},'NO_REPEAT_DISPATCH')
        require(ends.get('probe',{}).get('accepted')is True,'PRIOR_PROBE_REQUIRED')
        if mode=='execute':require(ends.get('image',{}).get('accepted')is True,'IMAGE_FREEZE_REQUIRED')
        if mode=='execute':
            image_metadata=io.decode((PHASE/'02_image/stdout.log').read_bytes())
            require(type(image_metadata['metadata_bytes'])is int and
                20650+image_metadata['metadata_bytes']+11000<=32768,'PHASE_METADATA_RESERVE')
        usedin=sum(e['stdin_bytes']for e in starts);usedout=sum(e['return_bytes']for e in ends.values())
        require(len(starts)<4 and usedin+len(wire)<=32768,'PHASE_INPUT_OR_SESSION_CAP')
        cap=min(4096 if mode=='image' else 8192,16384-usedout);require(cap>0,'PHASE_RETURN_CAP')
        pin=io.verify_cached_host('B')
        folder=PHASE/('%02d_%s'%(len(starts)+1,mode));folder.mkdir(exist_ok=False)
        io.write_new(folder/'request.json',dict(mode=mode,source_sha256=sha(source),payload_sha256=sha(wire),
            auth_sha256=AUTH_SHA,review_sha256=sha(reviewraw),stdin_bytes=len(wire),output_cap=cap,host_pin=pin))
        io.append_event(journal,dict(event='START',mode=mode,stdin_bytes=len(wire),output_cap=cap,auth_sha256=AUTH_SHA))
        result=io.transport(io.command('B'),wire,cap)
        for key in ('stdout','stderr'):
            with (folder/(key+'.log')).open('xb')as stream:stream.write(result[key])
        accepted=False
        try:
            obj=io.decode(result['stdout'])
            if mode=='image':
                records=obj.get('records')
                require(obj.get('schema')=='e74-fixed-image-metadata-v1' and type(records)is list
                    and len(records)==2 and {r['image_id']for r in records}=={
                        'sha256:c1702cf77b0857dd202ba298986ffc7942a4847c1b049bdc1f78567d0824df10',
                        'sha256:75456a4ee6ffd0ae32272076d6164622bd4025304053ddab995399d10a9c7743'}
                    and all(type(r['volumes_empty'])is bool and type(r['declared_python_command'])is bool
                        and r['python_execution_verified']is False for r in records)
                    and type(obj.get('metadata_bytes'))is int and 0<=obj['metadata_bytes']<=4096
                    and obj.get('new_inventory_scan')is False,'IMAGE_RESPONSE_SCHEMA')
            else:
                gate=obj.get('gate_result',{});env=gate.get('environment',{});rows=gate.get('profiles',[])
                require(obj.get('gate_pass')is True and gate.get('gate_pass')is True
                    and gate.get('schema')=='prospective-linux-lifecycle-gate-v2'
                    and env.get('platform')=='linux' and env.get('memory_limit_bytes')==134217728
                    and env.get('swap_limit_bytes')==0 and env.get('pids_max')==16
                    and type(env.get('oom_group'))is int and env['oom_group']in(0,1)
                    and [r.get('profile')for r in rows]==['success','failure','timeout_group']
                    and all(r.get('leader_reaped')is True and r.get('observed_group_empty')is True for r in rows),
                    'EXECUTION_RESULT_SCHEMA')
            accepted=(result['exit_code']==0 and not result['stderr'] and not any(result[k]for k in
                ('timeout','overflow','write_failed','threads_incomplete')) and obj['host']=='bupt-gpus1'
                and obj['status']==('PASS_FIXED_IMAGE_METADATA'if mode=='image'else'PASS_LINUX_SYNTHETIC_GATE'))
        except (ValueError,KeyError,TypeError,UnicodeError,RecursionError):pass
        receipt={k:v for k,v in result.items()if k not in ('stdout','stderr')}
        receipt.update(accepted=bool(accepted),stdout_sha256=sha(result['stdout']),stderr_sha256=sha(result['stderr']))
        io.write_new(folder/'transport.json',receipt)
        io.append_event(journal,dict(event='END',mode=mode,accepted=bool(accepted),return_bytes=len(result['stdout'])+len(result['stderr'])))
        print(json.dumps(dict(mode=mode,accepted=bool(accepted),execution_ready=False,training_release=False)))
        return 0 if accepted else 2
    finally:(PHASE/'active.lock').unlink()


if __name__=='__main__':
    require(len(sys.argv)==2,'ONE_FIXED_MODE')
    raise SystemExit(run(sys.argv[1]))
