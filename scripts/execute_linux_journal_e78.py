"""One E78 fixed Docker attempt on approved B host; never a general runner."""
import base64
import hashlib
import json
import os
import re
import selectors
import stat
import subprocess
import sys
import time

ROOT = '/ssd/cjc/gnn_model_linux_journal_v3_20261022_r1'
NAME = 'gnn-e78-journal-20261022-r1'
IMAGE = 'sha256:66ec58a325c4165749971d95dbbe1636d8423cc7328be110c5df38ed42ca57e7'
AUTH_SHA = '570b599869583a89f4c2666344c6fc8e3cd9915e0bb4eed9189cfa64c399263b'
PROPOSAL_SHA = '24903819e19b5a794bd81f86b149e01e91b9156bc6addfedaab89c4e115e7b68'
SOURCES = {'v2.py': '67861346f3725c479af9061d21869db7f7ecf21d70085df16e80dea17ed1e59e',
           'gate.py': '3a777175d1f4687e03950c5dd0aa97b8c3cba3a90905be672af274f7c28dea15',
           'v3.py': '1077c04f92af8c49937e7489e1ad15063af42eb7a6fa8b231af14ba7477f94b9'}
LABEL = 'gnn.e78.attempt'
MARK = AUTH_SHA[:24]
CID = re.compile(r'[0-9a-f]{64}\Z')
READ_CAP = 28672  # Reserve 4096 of the approved 32768 for same-container audit.
NORMAL_CAP = 24576
SESSION_SECONDS = 55
JOURNAL_COLLECT_CAP = 8192
RECEIPT_CAP = 14000

BOOTSTRAP = '''import hashlib,json,sys,time,types
def pkg(n):
 m=types.ModuleType(n);m.__path__=[];sys.modules[n]=m
pkg("src");pkg("src.data");pkg("scripts")
def load(n,p,h):
 with open(p,"rb") as f:s=f.read(24000)
 assert hashlib.sha256(s).hexdigest()==h
 m=types.ModuleType(n);m.__package__=n.rpartition(".")[0];m.__file__=p;sys.modules[n]=m
 exec(compile(s,p,"exec"),m.__dict__);return m
load("src.data.prospective_lifecycle_journal_v2","/v2.py","67861346f3725c479af9061d21869db7f7ecf21d70085df16e80dea17ed1e59e")
load("scripts.verify_prospective_linux_lifecycle_v2","/gate.py","3a777175d1f4687e03950c5dd0aa97b8c3cba3a90905be672af274f7c28dea15")
m=load("src.data.prospective_linux_journal_v3","/v3.py","1077c04f92af8c49937e7489e1ad15063af42eb7a6fa8b231af14ba7477f94b9")
class Clock:
 def capture(self):return ("e78-fixed-clock",time.monotonic_ns())
with m.Journal.create("/journal/events.jsonl") as j:
 b=m.FixedLinuxBackend();c=Clock()
 for i,p in enumerate(m.FIXED_PROFILES,1):s=j.run("e78-%d"%i,p,b,c)
 print(json.dumps({"schema":"e78-container-live-v1","status":"PASS_FIXED_LINUX_JOURNAL_ONLY","live_summary":s,"execution_ready":False,"training_release":False},sort_keys=True,separators=(",",":"),allow_nan=False))
'''

FIELDS = {'Id': '.Id', 'Image': '.Image', 'AttemptLabel': '(index .Config.Labels "gnn.e78.attempt")',
          'HostConfig.Memory': '.HostConfig.Memory', 'HostConfig.MemorySwap': '.HostConfig.MemorySwap',
          'HostConfig.PidsLimit': '.HostConfig.PidsLimit',
          'HostConfig.ReadonlyRootfs': '.HostConfig.ReadonlyRootfs',
          'HostConfig.Privileged': '.HostConfig.Privileged',
          'HostConfig.NetworkMode': '.HostConfig.NetworkMode',
          'HostConfig.CgroupnsMode': '.HostConfig.CgroupnsMode',
          'HostConfig.CapDrop': '.HostConfig.CapDrop',
          'HostConfig.SecurityOpt': '.HostConfig.SecurityOpt',
          'HostConfig.DeviceRequests': '.HostConfig.DeviceRequests',
          'HostConfig.Devices': '.HostConfig.Devices',
          'HostConfig.Init': '.HostConfig.Init', 'HostConfig.Runtime': '.HostConfig.Runtime',
          'HostConfig.IpcMode': '.HostConfig.IpcMode', 'HostConfig.PidMode': '.HostConfig.PidMode',
          'HostConfig.CgroupParent': '.HostConfig.CgroupParent',
          'HostConfig.Tmpfs': '.HostConfig.Tmpfs',
          'Config.User': '.Config.User', 'Config.Entrypoint': '.Config.Entrypoint',
          'Config.Cmd': '.Config.Cmd', 'Config.WorkingDir': '.Config.WorkingDir',
          'Config.Healthcheck': '.Config.Healthcheck', 'Mounts': '.Mounts',
          'State.Running': '.State.Running', 'State.Status': '.State.Status',
          'State.ExitCode': '.State.ExitCode', 'State.OOMKilled': '.State.OOMKilled'}
FORMAT = '\n'.join('{{json %s}}' % field for field in FIELDS.values())
CLEANUP_FORMAT = ('{{json .Id}}\n{{json .Image}}\n'
                  '{{json (index .Config.Labels "gnn.e78.attempt")}}\n'
                  '{{json .State.Running}}\n{{json .State.ExitCode}}')


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def pairs_unique(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, 'DUPLICATE_JSON_KEY')
        out[key] = value
    return out


def parse(raw):
    return json.loads(raw, object_pairs_hook=pairs_unique,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError('NONFINITE_JSON')))


def encode(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def validate(request):
    require(type(request) is dict and set(request) == {'image_id','auth_sha256','proposal_sha256','sources'},
            'REQUEST_KEYS')
    require(request['image_id'] == IMAGE and request['auth_sha256'] == AUTH_SHA and
            request['proposal_sha256'] == PROPOSAL_SHA, 'REQUEST_PINS')
    rows = request['sources']
    require(type(rows) is dict and set(rows) == set(SOURCES), 'SOURCE_KEYS')
    out = {}
    for name, expected in SOURCES.items():
        value = rows[name]
        require(type(value) is str and len(value) <= 35000, 'SOURCE_B64_BOUND')
        body = base64.b64decode(value, validate=True)
        require(len(body) <= 24000 and sha(body) == expected, 'SOURCE_PIN')
        out[name] = body
    require(sum(map(len,out.values())) <= 65536, 'SOURCE_TOTAL_BOUND')
    return out


class CommandError(ValueError):
    def __init__(self, reason, raw=b''):
        super().__init__(reason)
        self.raw = raw


class Budget:
    def __init__(self):
        self.deadline = time.monotonic() + SESSION_SECONDS
        self.read_bytes = 0

    def timeout(self, requested, cleanup=False):
        remain = self.deadline-time.monotonic()-(0 if cleanup else 15)
        require(remain > 0, 'SESSION_DEADLINE')
        return min(requested, remain)

    def allowance(self, cleanup=False):
        room = (READ_CAP if cleanup else NORMAL_CAP)-self.read_bytes
        require(room > 0, 'CUMULATIVE_READ_CAP')
        return min(1024, room)

    def consume(self, count, cleanup=False):
        self.read_bytes += count
        require(self.read_bytes <= (READ_CAP if cleanup else NORMAL_CAP), 'CUMULATIVE_READ_CAP')


def run(argv, budget, timeout=5, limit=8192, cleanup=False):
    timeout = budget.timeout(timeout, cleanup)
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, close_fds=True, shell=False)
    raw = bytearray()
    deadline = time.monotonic()+timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while selector.get_map():
                require(time.monotonic() < deadline, 'COMMAND_TIMEOUT')
                for key, _ in selector.select(min(.1,max(0,deadline-time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), budget.allowance(cleanup))
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        budget.consume(len(chunk), cleanup)
                        require(len(raw)+len(chunk) <= limit, 'COMMAND_OUTPUT_BOUND')
                        raw.extend(chunk)
            code = proc.wait(timeout=max(.001,deadline-time.monotonic()))
        return code,bytes(raw)
    except Exception as exc:
        raise CommandError(str(exc),bytes(raw)) from exc
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=1)
        proc.stdout.close()


def checked(argv,budget,timeout=5,limit=8192,cleanup=False):
    code,raw=run(argv,budget,timeout,limit,cleanup)
    if code != 0:
        raise CommandError('COMMAND_FAILED',raw)
    return raw


def new_root():
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        parts=ROOT.strip('/').split('/')
        for part in parts[:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child
        os.mkdir(parts[-1],0o700,dir_fd=fd)
        child=os.open(parts[-1],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
        os.fsync(fd)
        return child
    finally:
        os.close(fd)


def write_at(directory,name,body,mode,identity=None):
    require(name in (*SOURCES,'execution_manifest.json'), 'FILE_NAME')
    require(len(body) <= (24000 if name in SOURCES else 14000), 'FILE_BOUND')
    flags=os.O_WRONLY|os.O_NOFOLLOW|(os.O_CREAT|os.O_EXCL if identity is None else 0)
    fd=os.open(name,flags,mode,dir_fd=directory)
    try:
        info=os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink==1,'FILE_IDENTITY')
        found=(info.st_dev,info.st_ino)
        require(identity is None or identity==found,'FILE_CHANGED')
        os.fchmod(fd,mode);os.ftruncate(fd,0)
        view=memoryview(body)
        while view:
            count=os.write(fd,view)
            require(count>0,'SHORT_WRITE')
            view=view[count:]
        os.fsync(fd);os.fsync(directory)
        return found
    finally:
        os.close(fd)


def cid_file(directory):
    try:
        fd=os.open('container.id',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
    except FileNotFoundError:
        return None
    try:
        info=os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=65,'CID_FILE')
        value=os.read(fd,66).decode('ascii').strip()
        require(CID.fullmatch(value),'CID_CONTENT')
        return value
    finally:
        os.close(fd)


def inspect(cid,budget,cleanup=False):
    template=CLEANUP_FORMAT if cleanup else FORMAT
    raw=checked(['docker','container','inspect','--format',template,cid],budget,
                limit=512 if cleanup else 8192,cleanup=cleanup)
    lines=raw.decode('utf-8').splitlines()
    values=[parse(line) for line in lines]
    if cleanup:
        require(len(values)==5 and values[0]==cid,'CLEANUP_PROJECTION')
        return dict(Id=values[0],Image=values[1],AttemptLabel=values[2],
                    running=values[3],exit_code=values[4])
    require(len(values)==len(FIELDS),'INSPECT_FIELDS')
    config=dict(zip(FIELDS,values))
    require(config['Id']==cid,'INSPECT_ID')
    return config


def verify(config,user):
    expected={'Image':IMAGE,'AttemptLabel':MARK,'HostConfig.Memory':134217728,
              'HostConfig.MemorySwap':134217728,'HostConfig.PidsLimit':16,
              'HostConfig.ReadonlyRootfs':True,'HostConfig.Privileged':False,
              'HostConfig.NetworkMode':'none','HostConfig.CgroupnsMode':'private',
              'HostConfig.CapDrop':['ALL'],'HostConfig.SecurityOpt':['no-new-privileges'],
              'HostConfig.Init':False,'HostConfig.Runtime':'runc',
              'HostConfig.IpcMode':'none','HostConfig.PidMode':'',
              'HostConfig.CgroupParent':'','Config.User':user,
              'Config.Entrypoint':['python3'],
              'Config.Cmd':['-I','-S','-B','-c',BOOTSTRAP],
              'Config.WorkingDir':'/tmp',
              'HostConfig.Tmpfs':{'/tmp':'rw,nosuid,nodev,noexec,size=1048576,mode=1777'}}
    require(all(config.get(key)==value for key,value in expected.items()),'CONTAINER_CONFIG')
    require(not config['HostConfig.DeviceRequests'] and not config['HostConfig.Devices'],
            'GPU_OR_DEVICES')
    require(type(config['Config.Healthcheck']) is dict and
            config['Config.Healthcheck'].get('Test')==['NONE'],'HEALTHCHECK')
    mounts=config['Mounts']
    require(type(mounts) is list and len(mounts) in (4,5),'MOUNT_COUNT')
    binds=[m for m in mounts if m.get('Type')=='bind']
    require(len(binds)==4,'BIND_COUNT')
    expected_mounts={(ROOT+'/'+name,'/'+name,False) for name in SOURCES}
    expected_mounts.add((ROOT+'/journal','/journal',True))
    require({(m.get('Source'),m.get('Destination'),m.get('RW')) for m in binds}==
            expected_mounts,'MOUNT_BINDINGS')
    tmp=[m for m in mounts if m.get('Type')=='tmpfs']
    require(len(tmp)==len(mounts)-4 and all(m.get('Destination')=='/tmp' for m in tmp),
            'TMPFS_MOUNT')


def read_journal(directory,budget,cleanup=False):
    sub=os.open('journal',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
    try:
        sub_before=os.fstat(sub)
        sub_path_before=os.stat('journal',dir_fd=directory,follow_symlinks=False)
        require((sub_before.st_dev,sub_before.st_ino)==
                (sub_path_before.st_dev,sub_path_before.st_ino),'JOURNAL_DIR_CHANGED')
        fd=os.open('events.jsonl',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=sub)
        try:
            info=os.fstat(fd)
            path_before=os.stat('events.jsonl',dir_fd=sub,follow_symlinks=False)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and
                    info.st_size<=1048576 and info.st_size<=JOURNAL_COLLECT_CAP,
                    'JOURNAL_COLLECTION_BOUND')
            require((info.st_dev,info.st_ino)==(path_before.st_dev,path_before.st_ino),
                    'JOURNAL_PATH_CHANGED')
            require(info.st_size<=(READ_CAP if cleanup else NORMAL_CAP)-budget.read_bytes,
                    'JOURNAL_READ_BUDGET')
            raw=os.read(fd,info.st_size)
            budget.consume(len(raw),cleanup=cleanup)
            after=os.fstat(fd)
            path_after=os.stat('events.jsonl',dir_fd=sub,follow_symlinks=False)
            sub_after=os.fstat(sub)
            sub_path_after=os.stat('journal',dir_fd=directory,follow_symlinks=False)
            stamp=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
            require(len(raw)==info.st_size and stamp(info)==stamp(after)==
                    stamp(path_before)==stamp(path_after) and
                    stamp(sub_before)==stamp(sub_after)==
                    stamp(sub_path_before)==stamp(sub_path_after),
                    'JOURNAL_CHANGED')
            return raw
        finally:
            os.close(fd)
    finally:
        os.close(sub)


def validate_live(obj):
    require(type(obj) is dict and obj.get('schema')=='e78-container-live-v1' and
            obj.get('status')=='PASS_FIXED_LINUX_JOURNAL_ONLY' and
            obj.get('execution_ready') is False and obj.get('training_release') is False,
            'LIVE_SCHEMA')
    live=obj.get('live_summary')
    require(type(live) is dict and live.get('schema')=='prospective-linux-lifecycle-journal-v3' and
            live.get('complete_live_acknowledged') is True and
            live.get('fsync_acknowledgments_verified') is True and
            live.get('structural_complete') is True and live.get('attempt_count')==3 and
            live.get('event_count')==9 and live.get('observed_identity_records')==3 and
            live.get('launch_attempt_count')==3 and live.get('os_authenticated') is False and
            live.get('real_atpg_jobs')==0 and
            type(live.get('observed_interval_ns_sum_or_None')) is int and
            live['observed_interval_ns_sum_or_None']>0 and
            [a['profile'] for a in live.get('attempts',{}).values()]==
            ['success','failure','timeout_group'],'LIVE_COMPLETE')
    return live


def execute(request):
    sources=validate(request)
    require(sys.platform=='linux' and os.uname().nodename=='bupt-gpus1','B_HOST_ONLY')
    require(os.getuid()!=0,'NONROOT_REQUIRED')
    budget=Budget();began=time.monotonic()
    info=checked(['docker','info','--format',
                  '{{json .CgroupVersion}}\n{{json .OSType}}\n{{if index .Runtimes "runc"}}true{{else}}false{{end}}'],
                 budget,limit=128)
    require(info.decode().splitlines()==['"2"','"linux"','true'],'CGROUP2_RUNC')
    image=checked(['docker','image','inspect','--format',
                   '{{json .Id}}\n{{json .Config.Volumes}}\n{{json .Os}}',IMAGE],
                  budget,limit=1024)
    fields=[parse(line) for line in image.decode().splitlines()]
    require(len(fields)==3 and fields[0]==IMAGE and not fields[1] and fields[2]=='linux',
            'IMAGE_ID_VOLUMES_OS')
    directory=new_root()
    cid=None;journal_identity=None
    receipt=dict(schema='e78-host-execution-v1',host='bupt-gpus1',image_id=IMAGE,
                 status='BLOCKED_OR_FAILED_NO_RETRY',gate_pass=False,phase='ROOT_CREATED',
                 execution_ready=False,training_release=False,retry_allowed=False,
                 auth_sha256=AUTH_SHA,proposal_sha256=PROPOSAL_SHA,source_sha256=SOURCES)
    def persist():
        nonlocal journal_identity
        journal_identity=write_at(directory,'execution_manifest.json',encode(receipt),0o600,
                                  journal_identity)
    try:
        for name,body in sources.items():
            write_at(directory,name,body,0o444)
        os.mkdir('journal',0o700,dir_fd=directory)
        os.fsync(directory)
        receipt['phase']='CREATE_ATTEMPT';persist()
        require(time.monotonic()-began<20,'CREATE_TIME_BUDGET')
        user='%d:%d'%(os.getuid(),os.getgid())
        argv=['docker','create','--pull=never','--cidfile',ROOT+'/container.id',
              '--name',NAME,'--label',LABEL+'='+MARK,'--network','none','--read-only',
              '--cap-drop','ALL','--security-opt','no-new-privileges',
              '--memory','134217728','--memory-swap','134217728','--pids-limit','16',
              '--cgroupns','private','--user',user,
              '--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=1048576,mode=1777']
        for name in SOURCES:
            argv.extend(['--mount','type=bind,src='+ROOT+'/'+name+',dst=/'+name+',readonly'])
        argv.extend(['--mount','type=bind,src='+ROOT+'/journal,dst=/journal',
                     '--entrypoint','python3','--init=false','--no-healthcheck',
                     '--workdir','/tmp','--ipc','none','--runtime','runc',
                     '--env','NVIDIA_VISIBLE_DEVICES=void',IMAGE,
                     '-I','-S','-B','-c',BOOTSTRAP])
        response=checked(argv,budget,limit=128).decode('ascii').strip()
        require(CID.fullmatch(response),'CREATE_RESPONSE_ID')
        cid=cid_file(directory)
        require(cid==response,'CIDFILE_RESPONSE_MISMATCH')
        receipt.update(container_id=cid,phase='CREATED');persist()
        config=inspect(cid,budget)
        verify(config,user)
        require(config['State.Running'] is False and config['State.Status']=='created',
                'CREATED_STATE')
        receipt.update(config_sha256=sha(encode(config)),phase='START_ATTEMPT');persist()
        require(time.monotonic()-began<20,'START_TIME_BUDGET')
        code,output=run(['docker','start','--attach',cid],budget,timeout=30,limit=8192)
        receipt.update(attach_exit=code,output_bytes=len(output),output_sha256=sha(output),
                       output_prefix_b64=base64.b64encode(output[:512]).decode('ascii'))
        state=inspect(cid,budget)
        receipt.update(container_exit=state['State.ExitCode'],running=state['State.Running'],
                       oom_killed=state['State.OOMKilled'])
        require(code==0 and state['State.Running'] is False and state['State.ExitCode']==0 and
                state['State.Status']=='exited' and state['State.OOMKilled'] is False,
                'CONTAINER_EXIT')
        live=validate_live(parse(output.decode('utf-8')))
        raw=read_journal(directory,budget)
        require(len(os.listdir(directory))<=16,'ROOT_ENTRY_CAP')
        receipt.pop('output_prefix_b64',None)
        receipt.update(live_summary=live,journal_bytes=len(raw),journal_sha256=sha(raw),
                       journal_b64=base64.b64encode(raw).decode('ascii'),
                       status='PASS_FIXED_LINUX_JOURNAL_ONLY',gate_pass=True,
                       phase='COMPLETE',cleanup_verified=True)
        require(len(encode(receipt))<=RECEIPT_CAP,'RECEIPT_BOUND')
    except Exception as exc:
        receipt.update(status='BLOCKED_OR_FAILED_NO_RETRY',gate_pass=False,phase='FAILED',
                       reason=type(exc).__name__+':'+str(exc)[:120])
        if isinstance(exc,CommandError):
            receipt.update(output_bytes=len(exc.raw),output_sha256=sha(exc.raw),
                           output_prefix_b64=base64.b64encode(exc.raw[:512]).decode('ascii'))
        if cid is None:
            try:cid=cid_file(directory)
            except Exception:pass
        if cid and CID.fullmatch(cid):
            receipt['container_id']=cid
            try:
                config=inspect(cid,budget,cleanup=True)
                require(config['Image']==IMAGE and config['AttemptLabel']==MARK,
                        'CLEANUP_IDENTITY')
                if config['running'] is True:
                    run(['docker','kill',cid],budget,limit=512,cleanup=True)
                stopped=inspect(cid,budget,cleanup=True)
                require(stopped['running'] is False,'STOP_UNVERIFIED')
                receipt.update(cleanup_verified=True,running=False,
                               container_exit=stopped['exit_code'])
            except Exception:
                receipt['cleanup_verified']=False
        else:
            receipt['cleanup_verified']=False
        try:
            raw=read_journal(directory,budget,cleanup=True)
            receipt.update(journal_bytes=len(raw),journal_sha256=sha(raw),
                           journal_b64=base64.b64encode(raw).decode('ascii'))
        except Exception:
            receipt['journal_collection_verified']=False
    finally:
        receipt['read_bytes']=budget.read_bytes
        try:
            require(len(encode(receipt))<=14000,'REMOTE_MANIFEST_BOUND')
            persist()
        except Exception:
            receipt.update(status='BLOCKED_OR_FAILED_NO_RETRY',gate_pass=False,
                           journal_verified=False)
        os.close(directory)
    return receipt


def main(request=None):
    try:
        require(len(sys.argv)==1,'NO_ARGUMENTS')
        if request is None:
            raw=sys.stdin.buffer.read(131073)
            require(len(raw)<=131072,'REQUEST_BOUND')
            request=parse(raw.decode('ascii'))
        receipt=execute(request)
    except Exception as exc:
        receipt=dict(schema='e78-host-execution-v1',status='BLOCKED_OR_FAILED_NO_RETRY',
                     gate_pass=False,reason=type(exc).__name__+':'+str(exc)[:120],
                     execution_ready=False,training_release=False)
    if len(encode(receipt))>RECEIPT_CAP:
        receipt.pop('journal_b64',None)
        receipt.pop('live_summary',None)
        receipt.update(status='BLOCKED_OR_FAILED_NO_RETRY',gate_pass=False,
                       reason='RECEIPT_RETURN_BOUND')
    print(json.dumps(receipt,sort_keys=True,separators=(',',':'),allow_nan=False))
    return 0 if receipt.get('gate_pass') is True else 2


if __name__=='__main__':
    raise SystemExit(main())
