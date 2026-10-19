"""E61 interpreter capability observation; no project file/directory probes."""
import json
import os
import sys

MAX_OUTPUT=16384
FALSE_FLAGS=('project_files_opened','project_dirs_listed','remote_files_written',
    'runtime_or_quality_values_accessed','historical_freeze_certified',
    'historical_execution_certified','training_release')


def observe(resource_limits):
    scandir=getattr(os,'scandir',None)
    return dict(status='PASS_FIXED_PYTHON_API_OBSERVATION_ONLY',platform=sys.platform,
        python_version=list(sys.version_info[:3]),str_isascii_available=hasattr(str,'isascii'),
        scandir_fd_advertised=scandir is not None and scandir in getattr(os,'supports_fd',set()),
        resource=resource_limits,**{key:False for key in FALSE_FLAGS})


def validate_response(value):
    keys={'status','platform','python_version','str_isascii_available','scandir_fd_advertised','resource',*FALSE_FLAGS}
    if type(value) is not dict or set(value)!=keys:return False
    if value['status']!='PASS_FIXED_PYTHON_API_OBSERVATION_ONLY' or value['platform']!='linux':return False
    version=value['python_version']
    if type(version) is not list or len(version)!=3 or any(type(x) is not int for x in version):return False
    if not (3<=version[0]<=99 and 0<=version[1]<=99 and 0<=version[2]<=999):return False
    if any(type(value[k]) is not bool for k in ('str_isascii_available','scandir_fd_advertised')):return False
    if any(value[key] is not False for key in FALSE_FLAGS):return False
    resource=value['resource']
    return (type(resource) is dict and set(resource)=={'address_space_limit_bytes','cpu_limit_s','workers'}
        and all(type(x) is int for x in resource.values())
        and 0<resource['address_space_limit_bytes']<=512*1024*1024
        and 0<resource['cpu_limit_s']<=30 and resource['workers']==1)


def main():
    try:
        if sys.platform!='linux' or len(sys.argv)!=1:raise ValueError('LINUX_STDIN_ONLY')
        import resource
        imposed={}
        for kind,cap,key in ((resource.RLIMIT_AS,512*1024*1024,'address_space_limit_bytes'),
                             (resource.RLIMIT_CPU,30,'cpu_limit_s')):
            soft,hard=resource.getrlimit(kind)
            bound=min([cap]+[x for x in (soft,hard) if x!=resource.RLIM_INFINITY])
            resource.setrlimit(kind,(bound,hard));imposed[key]=bound
        imposed['workers']=1
        result=observe(imposed)
        if not validate_response(result):raise ValueError('OUTPUT_SCHEMA')
        raw=json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=True)
        if len(raw.encode('ascii'))+1>MAX_OUTPUT:raise ValueError('OUTPUT_BOUND')
        print(raw)
        return 0
    except Exception:
        print('{"status":"FAIL_CLOSED_PYTHON_API_OBSERVATION","code":"FIXED_CAPABILITY_REJECTED"}')
        return 2


if __name__=='__main__':
    sys.exit(main())
