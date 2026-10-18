"""Bounded tar metadata, including PAX/GNU extensions; no ordinary file decoding."""
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile

ARCHIVE=Path(r'C:\Users\86155\Desktop\new lab\runtime_training_staging_20260928\runtime_v2_inputs_98efbd4.tar.gz')
MAX_COMPRESSED=1024**2
EXPECTED_BYTES=350177
MAX_DECOMPRESSED=32*1024**2
MAX_MEMBERS=512
TARGETS={'receipt_v2.json','source_provenance_v2.tsv'}


class LimitedReader:
    def __init__(self,stream,limit):self.stream,self.limit,self.count=stream,limit,0
    def read(self,size=-1):
        size=min(65536 if size<0 else size,self.limit-self.count+1)
        data=self.stream.read(size);self.count+=len(data)
        if self.count>self.limit:raise ValueError('DECOMPRESSED_BOUND')
        return data


def inspect_stream(stream):
    limited=LimitedReader(stream,MAX_DECOMPRESSED)
    matches=[];count=0;seen=set()
    with tarfile.open(fileobj=limited,mode='r|') as archive:
        for member in archive:
            count+=1
            if count>MAX_MEMBERS:raise ValueError('MEMBER_BOUND')
            name=member.name
            path=PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts or '\\' in name or len(name)>1024 or name in seen:
                raise ValueError('MEMBER_PATH')
            seen.add(name)
            if path.name in TARGETS:
                if not member.isreg():raise ValueError('TARGET_NOT_REGULAR')
                matches.append(dict(name=name,bytes=member.size))
            # Do not extractfile or decode any member payload.
    return dict(logical_members_scanned=count,decompressed_stream_bytes=limited.count,metadata_members=matches,
        extension_header_metadata_may_be_decoded=True,physical_header_count_not_reported=True)


def identity(info,cross_api=False):
    fields=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    if cross_api and sys.platform=='win32':fields=fields[:-1]
    return tuple(getattr(info,k)for k in fields)


def verify_identity(path_before,fd_before,path_after,fd_after):
    if (identity(path_before)!=identity(path_after) or identity(fd_before)!=identity(fd_after)
        or identity(path_before,True)!=identity(fd_before,True)
        or identity(path_after,True)!=identity(fd_after,True)):
        raise ValueError('ARCHIVE_CHANGED')


def inspect_fixed():
    original=os.lstat(ARCHIVE)
    if not stat.S_ISREG(original.st_mode)or original.st_nlink!=1 or getattr(original,'st_file_attributes',0)&0x400 or original.st_size!=EXPECTED_BYTES or not 0<original.st_size<=MAX_COMPRESSED:
        raise ValueError('ARCHIVE_FILE_GATE')
    fd=os.open(ARCHIVE,os.O_RDONLY|getattr(os,'O_BINARY',0)|getattr(os,'O_NOFOLLOW',0))
    with os.fdopen(fd,'rb')as stream:
        before=os.fstat(stream.fileno())
        if identity(original,True)!=identity(before,True):raise ValueError('ARCHIVE_CHANGED')
        digest=hashlib.sha256();count=0
        while True:
            chunk=stream.read(65536)
            if not chunk:break
            count+=len(chunk)
            if count>MAX_COMPRESSED:raise ValueError('COMPRESSED_BOUND')
            digest.update(chunk)
        stream.seek(0)
        with gzip.GzipFile(fileobj=stream,mode='rb')as decompressed:
            result=inspect_stream(decompressed)
        verify_identity(original,before,os.lstat(ARCHIVE),os.fstat(stream.fileno()))
        if count!=before.st_size:raise ValueError('ARCHIVE_CHANGED')
    result.update(status='PASS_ONE_ARCHIVE_HEADER_DISCOVERY',path=str(ARCHIVE),compressed_bytes=count,
        archive_sha256=digest.hexdigest(),ordinary_file_payload_decoded=False,member_files_extracted=False,
        skipped_member_bytes_may_be_decompressed=True,source_authentication_claimed=False,training_release=False)
    return result


def main():
    if len(sys.argv)!=1:raise ValueError('FIXED_ARCHIVE_ONLY')
    raw=json.dumps(inspect_fixed(),ensure_ascii=True,sort_keys=True)
    if len(raw.encode('ascii'))>32768:raise ValueError('OUTPUT_BOUND')
    print(raw)


if __name__=='__main__':main()
