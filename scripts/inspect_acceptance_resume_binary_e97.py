"""One fixed lstat-only bresume metadata observation, no scheduler execution."""
from scripts import execute_acceptance_register_e97 as common

PHASE = common.ROOT.parent / 'runtime_training_staging_20260928/v6_e97_resume_binary_observation_20261024_r1'


def prepare():
    raw = common.SOURCE.read_bytes()
    if common.sha(raw) != 'd9a30b7e94cfa3ed4fcff4306f09f147ada4c615210ecb5a2954362ad8e09a3a':
        raise ValueError('BASE_CHANGED')
    suffix = '''
import resource
for kind,cap in ((resource.RLIMIT_AS,268435456),(resource.RLIMIT_CPU,20)):
 soft,hard=resource.getrlimit(kind)
 chosen=min([cap]+[v for v in (soft,hard) if v!=resource.RLIM_INFINITY])
 resource.setrlimit(kind,(chosen,chosen))
require(sys.platform.startswith('linux') and platform.node()=='bupt-vncs2','HOST_REQUIRED')
fd=_directory(BINDIR.rstrip('/'))
try:
 info=os.stat('bresume',dir_fd=fd,follow_symlinks=False)
 result=dict(schema='e97-resume-binary-metadata-v1',hostname=platform.node(),observed_at_epoch=int(time.time()),path=BINDIR+'bresume',metadata=dict(dev=info.st_dev,ino=info.st_ino,nlink=info.st_nlink,size=info.st_size,mtime_ns=info.st_mtime_ns,uid=info.st_uid,gid=info.st_gid,st_mode=info.st_mode,mode=stat.S_IMODE(info.st_mode),regular=stat.S_ISREG(info.st_mode),symlink=stat.S_ISLNK(info.st_mode)),programs_launched=0,resume_calls=0,jobs_submitted=0,body_bytes_read=0)
finally:
 os.close(fd)
sys.stdout.write(json.dumps(result,sort_keys=True)+'\\n')
'''
    payload = raw + suffix.encode('ascii')
    compile(payload, '<e97-resume-binary-metadata>', 'exec')
    return payload


def main():
    payload = prepare()
    if common.sha(common.TRANSPORT.read_bytes()) != common.TRANSPORT_SHA:
        raise ValueError('TRANSPORT_CHANGED')
    helper = common.load_transport()
    key = helper.verify_cached_host('A')
    PHASE.mkdir(exist_ok=False)
    common.write_new(PHASE/'start.json',common.encode(dict(payload_sha256=common.sha(payload),host_fingerprint=key,automatic_retries=0)))
    result = helper.transport(helper.command('A'),payload,16384)
    common.write_new(PHASE/'stdout.json',result['stdout'])
    common.write_new(PHASE/'stderr.log',result['stderr'])
    receipt={k:v for k,v in result.items() if k not in ('stdout','stderr')}
    receipt.update(stdout_sha256=common.sha(result['stdout']),stdout_bytes=len(result['stdout']),stderr_bytes=len(result['stderr']))
    common.write_new(PHASE/'transport.json',common.encode(receipt))
    if result['exit_code']!=0 or any(result[k] for k in ('timeout','overflow','write_failed','threads_incomplete')):
        raise ValueError('OBSERVATION_FAILED_NO_RETRY')
    print(result['stdout'].decode('ascii'))


if __name__ == '__main__':
    main()
