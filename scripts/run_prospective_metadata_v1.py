"""One approved bounded metadata phase. Never submits jobs or reads checkpoints."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'scripts/read_prospective_metadata_v1.py'
SCOPE = ROOT / 'contracts/prospective_metadata_scope_request_v1.json'
AUTH = ROOT / 'contracts/prospective_metadata_authorization_e70_20261021.json'
A = '/temp/jiangchuanc/multimode_ate_phase4_20260825_A'
B = '/ssd/cjc/gnn_model_ranking_v5_train_20261011_r2'
BUNDLES = {
    'A': dict(role='A', paths=[
        A+'/00_framework/phase4_closure_driver_v2.py',
        A+'/00_framework/stage_mapped_common_atpg_no_tsdb_v2.tcl',
        A+'/00_framework/stage_mapped_incremental_atpg_no_tsdb_v3.tcl',
        A+'/00_framework/run_phase4_closure_batch_v2.sh',
        A+'/10_circuits/aes_core/01_config/config.env',
        A+'/10_circuits/spi/01_config/config.env',
        A+'/10_circuits/aes_core/03_fault_universe/common_aes_core_m16_phase4_v2/manifest.json',
        A+'/10_circuits/spi/03_fault_universe/common_spi_m16_phase4_v2/manifest.json'], inventory_dirs=[]),
    'A_FLOW': dict(role='A', paths=[
        A+'/00_framework/mapped_flow_v2/stage_mapped_common_atpg_no_tsdb_v2.tcl',
        A+'/00_framework/mapped_flow_v2/stage_mapped_incremental_atpg_no_tsdb_v3.tcl'], inventory_dirs=[]),
    'B': dict(role='B', paths=[
        B+'/jit_admission_iwls_aes_core_20260824.json',
        B+'/jit_admission_iwls_spi_20260824.json',
        B+'_iwls_aes_core_20260824.stdout.log.memory.json',
        B+'_iwls_spi_20260824.stdout.log.memory.json',
        B+'/src/models/ranking_v5_train_jit_admission_v3.py',
        B+'/src/models/ranking_v5_freeze_codec_v2.py',
        B+'/src/models/ranking_v5_train_artifact_readback_v2.py',
        B+'/scripts/run_v5_train_single_fit_v3.py'], inventory_dirs=[]),
}
HOSTS = {'A': ('vnc.buptic.top','vnc.buptic.top',
    'SHA256:9+c0w59UN6NMPA6MnG45jtRW63JT9gKLTBxtnnSpJqM'),
    'B': ('cjc@gpuserver.buptic.top','gpuserver.buptic.top',
    'SHA256:IF1uJU6T8bAB/nWJn9HibWGcvuVfiYFdQTECrNQlbPo')}
TIMEOUT = 60
OUTPUT_CAP = 32768
PHASE_NAME = 'v6_e70_metadata_20261021_r1'


def require(ok, code):
    if not ok:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def pairs(items):
        value = {}
        for key,item in items:
            require(key not in value,'DUPLICATE_JSON_KEY')
            value[key]=item
        return value
    def reject(value):
        raise ValueError('NONSTANDARD_JSON')
    return json.loads(raw.decode('ascii'),object_pairs_hook=pairs,parse_constant=reject)


def write_new(path, value):
    raw=(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode('ascii')
    with path.open('xb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())


def append_event(path, value):
    raw=(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode('ascii')
    with path.open('ab') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())


def verify_cached_host(role):
    endpoint, host, expected = HOSTS[role]
    result=subprocess.run(['ssh-keygen','-F',host],stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,timeout=10,check=False)
    require(result.returncode==0 and len(result.stdout)<=16384 and not result.stderr,'CACHED_HOST_KEY_QUERY')
    fingerprints=set()
    for line in result.stdout.decode('ascii').splitlines():
        if line.startswith('#'):
            continue
        fields=line.split()
        if len(fields)>=3 and fields[1]=='ssh-ed25519':
            key=base64.b64decode(fields[2],validate=True)
            fingerprints.add('SHA256:'+base64.b64encode(hashlib.sha256(key).digest()).decode('ascii').rstrip('='))
    require(fingerprints=={expected},'CACHED_ED25519_PIN_MISMATCH')
    return expected


def command(role):
    return ['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
        '-o','UpdateHostKeys=no','-o','ConnectTimeout=8','-o','HostKeyAlgorithms=ssh-ed25519',
        HOSTS[role][0],'/usr/bin/python3 -I -S -B -']


def transport(cmd, payload, cap):
    """Bounded concurrent capture; local SSH cleanup is not remote termination proof."""
    streams={'stdout':bytearray(),'stderr':bytearray()}
    lock=threading.Lock();overflow=threading.Event();write_failed=threading.Event()
    proc=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    def collect(stream,name):
        while True:
            chunk=stream.read(4096)
            if not chunk:
                return
            with lock:
                room=cap-sum(map(len,streams.values()))
                streams[name].extend(chunk[:max(0,room)])
                if len(chunk)>room:
                    overflow.set()
                    try:proc.kill()
                    except OSError:pass
                    return
    def send():
        try:proc.stdin.write(payload);proc.stdin.close()
        except (OSError,ValueError):write_failed.set()
    readers=[threading.Thread(target=collect,args=(proc.stdout,'stdout'),daemon=True),
        threading.Thread(target=collect,args=(proc.stderr,'stderr'),daemon=True)]
    writer=threading.Thread(target=send,daemon=True)
    began=time.monotonic()
    for thread in readers+[writer]:thread.start()
    timed_out=False
    try:
        proc.wait(timeout=max(.01,TIMEOUT-(time.monotonic()-began)))
    except subprocess.TimeoutExpired:
        timed_out=True;proc.kill();proc.wait(timeout=5)
    except BaseException:
        proc.kill();proc.wait(timeout=5);raise
    finally:
        for thread in readers+[writer]:thread.join(timeout=1)
    stuck=any(thread.is_alive() for thread in readers+[writer])
    return dict(exit_code=proc.returncode,timeout=timed_out,overflow=overflow.is_set(),
        write_failed=write_failed.is_set(),threads_incomplete=stuck,
        stdout=bytes(streams['stdout']),stderr=bytes(streams['stderr']),remote_termination_verified=False)


def phase_usage(events):
    starts={};ends={}
    for event in events:
        require(type(event) is dict and event.get('event') in ('START','END'),'PHASE_EVENT_SCHEMA')
        target=starts if event['event']=='START' else ends
        require(event['session'] not in target,'DUPLICATE_PHASE_SESSION')
        target[event['session']]=event
    require(set(ends)<=set(starts),'END_WITHOUT_START')
    used=dict(sessions=len(starts),files=0,body_bytes=0,entries=0,returned_bytes=0)
    requested=set()
    for session,start in starts.items():
        requested.update(start['paths'])
        end=ends.get(session)
        if end and end['accepted']:
            budget=end['budget']
            used['files']+=budget['files_read'];used['body_bytes']+=budget['body_bytes']
            used['entries']+=budget['inventory_entries']
        else:
            used['files']+=len(start['paths']);used['body_bytes']+=131072*len(start['paths'])
            used['entries']+=100 if start['inventory_dirs'] else 0
        used['returned_bytes']+=end['returned_bytes'] if end else start['output_cap']
    return used,requested


def run(bundle, reviewed_sha, phase):
    require(bundle in BUNDLES,'FIXED_BUNDLE_REQUIRED')
    require(re.fullmatch('[a-f0-9]{64}',reviewed_sha or '') is not None,'REVIEWED_SOURCE_SHA')
    raw=SOURCE.read_bytes()
    require(len(raw)<=131072 and sha(raw)==reviewed_sha,'SOURCE_PIN_MISMATCH')
    authorization=decode(AUTH.read_bytes())
    require(authorization['user_authorization_received'] is True and
        authorization['scope_contract_sha256']==sha(SCOPE.read_bytes()),'SCOPE_AUTHORIZATION_BINDING')
    phase=Path(phase).resolve()
    staging=(ROOT.parent/'runtime_training_staging_20260928').resolve()
    require(phase==staging/PHASE_NAME,'FIXED_AUTHORIZATION_PHASE_PATH')
    anchor=dict(authorization_sha256=sha(AUTH.read_bytes()),scope_sha256=sha(SCOPE.read_bytes()),phase=PHASE_NAME)
    if phase.exists():
        require(decode((phase/'phase_authorization.json').read_bytes())==anchor,'PHASE_AUTHORIZATION_ANCHOR')
        require((phase/'sessions.jsonl').is_file(),'PHASE_JOURNAL_MISSING')
    else:
        phase.mkdir(exist_ok=False)
        write_new(phase/'phase_authorization.json',anchor)
        with (phase/'sessions.jsonl').open('xb') as stream:
            stream.flush();os.fsync(stream.fileno())
    lease=phase/'active.lock'
    with lease.open('xb') as stream:stream.write(b'ACTIVE\n');stream.flush();os.fsync(stream.fileno())
    try:
        journal=phase/'sessions.jsonl'
        require(journal.stat().st_size<=65536,'PHASE_JOURNAL_SIZE')
        events=[decode(line) for line in journal.read_bytes().splitlines()]
        used,requested=phase_usage(events)
        request=BUNDLES[bundle]
        require(not (requested & set(request['paths'])),'PATH_ALREADY_ATTEMPTED_NO_REPEAT')
        require(used['sessions']<4 and used['files']+len(request['paths'])<=16
            and used['body_bytes']+131072*len(request['paths'])<=2097152,'PHASE_READ_BUDGET')
        cap=min(OUTPUT_CAP,65536-used['returned_bytes'])
        require(cap>0 and used['entries']+(100 if request['inventory_dirs'] else 0)<=200,'PHASE_OUTPUT_OR_INVENTORY_BUDGET')
        role=request['role']
        pin=verify_cached_host(role)
        spec=importlib.util.spec_from_file_location('_e70_reviewed_payload',SOURCE)
        producer=importlib.util.module_from_spec(spec);spec.loader.exec_module(producer)
        producer.validate_request(request['role'],request['paths'],request['inventory_dirs'])
        session='%02d_%s'%(used['sessions']+1,bundle)
        output=phase/session;output.mkdir(exist_ok=False)
        write_new(output/'request.json',dict(request=request,source_sha256=reviewed_sha,
            scope_sha256=authorization['scope_contract_sha256'],cached_ed25519_pin=pin,
            command=command(role),timeout_s=TIMEOUT,output_cap=cap,automatic_retries=0))
        append_event(journal,dict(event='START',session=session,paths=request['paths'],
            inventory_dirs=request['inventory_dirs'],output_cap=cap))
        payload=raw+b'\nraise SystemExit(main('+json.dumps(request,sort_keys=True).encode('ascii')+b'))\n'
        observed=transport(command(role),payload,cap)
        for name in ('stdout','stderr'):
            with (output/(name+'.log')).open('xb') as stream:stream.write(observed[name])
        accepted=False;response=None
        try:
            response=decode(observed['stdout'])
            accepted=(observed['exit_code']==0 and not any(observed[k] for k in
                ('timeout','overflow','write_failed','threads_incomplete')) and not observed['stderr']
                and producer.validate_response(response,request)
                and (role!='B' or response['host']['hostname']=='bupt-gpus1'))
        except (ValueError,TypeError,UnicodeError,RecursionError,KeyError):
            accepted=False
        receipt={k:v for k,v in observed.items() if k not in ('stdout','stderr')}
        receipt.update(accepted_metadata_receipt=bool(accepted),source_sha256=reviewed_sha,
            stdout_sha256=sha(observed['stdout']),stderr_sha256=sha(observed['stderr']))
        write_new(output/'transport.json',receipt)
        returned=sum(len(observed[k]) for k in ('stdout','stderr'))
        append_event(journal,dict(event='END',session=session,accepted=bool(accepted),
            budget=response['budget'] if accepted else None,returned_bytes=returned))
        print(json.dumps(dict(session=session,accepted=bool(accepted),execution_ready=False)))
        return 0 if accepted else 2
    finally:
        lease.unlink()


if __name__=='__main__':
    require(len(sys.argv)==4,'BUNDLE_SOURCE_SHA_PHASE_DIRECTORY')
    raise SystemExit(run(*sys.argv[1:]))
