"""Name/stat-only search for metadata-named direct files at B workspace root."""
import json
import os
import stat
import sys

MAX_ENTRIES=1024
PROTECTED='multimode_ate_gnn_v1'
PREFIXES=('formal_candidate_space','source_provenance','runtime_training_package')
SUFFIXES=('.json','.tsv','.tar.gz','.sha256','.tgz')


def wanted(name):
    return name != PROTECTED and (name == 'receipt_v2.json' or (name.startswith(PREFIXES) and name.endswith(SUFFIXES)))


def classify(names,lookup):
    if len(names)>MAX_ENTRIES or len(set(names))!=len(names):raise ValueError('ENTRY_BOUND')
    files=[];skipped=0
    for name in sorted(names):
        if not wanted(name):continue
        if not 1<=len(name)<=180 or not all(ord(c)<128 and (c.isalnum() or c in '_.-') for c in name):raise ValueError('NAME_SHAPE')
        info=lookup(name)
        if stat.S_ISREG(info.st_mode):files.append(name)
        else:skipped+=1
    return files,skipped


def validate_response(r):
    if type(r)is not dict or set(r)!={'status','hostname','root','entry_count','metadata_named_files','skipped','file_contents_opened','archive_headers_read','protected_directory_visited','remote_files_written','training_release'}:return False
    if r['status']!='PASS_METADATA_BACKUP_NAMES' or r['hostname']!='bupt-gpus1' or r['root']!='/ssd/cjc':return False
    if any(r[k]is not False for k in ('file_contents_opened','archive_headers_read','protected_directory_visited','remote_files_written','training_release')):return False
    if type(r['entry_count'])is not int or not 0<=r['entry_count']<=MAX_ENTRIES:return False
    if type(r['skipped'])is not int or not 0<=r['skipped']<=r['entry_count']:return False
    names=r['metadata_named_files']
    if type(names)is not list or any(type(n)is not str for n in names):return False
    if names!=sorted(set(names)) or len(names)+r['skipped']>r['entry_count']:return False
    return all(wanted(n) and 1<=len(n)<=180 and all(ord(c)<128 and(c.isalnum()or c in'_.-')for c in n) for n in names)


def main():
    fd=None
    try:
        if sys.platform!='linux' or len(sys.argv)!=1:raise ValueError('LINUX_ONLY')
        import resource
        for kind,cap in ((resource.RLIMIT_AS,1024**3),(resource.RLIMIT_CPU,20)):
            soft,hard=resource.getrlimit(kind)
            resource.setrlimit(kind,(min([cap]+[v for v in(soft,hard)if v!=resource.RLIM_INFINITY]),hard))
        flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
        fd=os.open('/',flags)
        for part in('ssd','cjc'):
            child=os.open(part,flags,dir_fd=fd);os.close(fd);fd=child
        names=[]
        with os.scandir(fd) as entries:
            for e in entries:
                if len(names)>=MAX_ENTRIES:raise ValueError('ENTRY_BOUND')
                names.append(e.name)
        files,skipped=classify(names,lambda n:os.stat(n,dir_fd=fd,follow_symlinks=False))
        result=dict(status='PASS_METADATA_BACKUP_NAMES',hostname=os.uname().nodename,root='/ssd/cjc',entry_count=len(names),
            metadata_named_files=files,skipped=skipped,file_contents_opened=False,archive_headers_read=False,
            protected_directory_visited=False,remote_files_written=False,training_release=False)
        if not validate_response(result):raise ValueError('OUTPUT_SCHEMA')
        raw=json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=True)
        if len(raw.encode('ascii'))>65536:raise ValueError('OUTPUT_BOUND')
        print(raw);return 0
    except Exception:
        print('{"status":"FAIL_CLOSED_METADATA_BACKUP_NAMES","code":"FIXED_NAME_PROBE_REJECTED"}');return 2
    finally:
        if fd is not None:os.close(fd)


if __name__=='__main__':sys.exit(main())
