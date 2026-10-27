"""Bounded string-alias scandir for an already verified Linux document FD.

Local compatibility implementation only, not an executor, authorization, or
proof of actual Linux/Python 3.6 execution. Caller owns root authentication and
the aggregate multi-directory entry budget; pass its remaining budget as limit.
No listdir, chdir, file body reads, directory traversal, or path-based fallback.
"""
import os
import stat
import sys

FIELDS = ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_size','st_mtime_ns','st_ctime_ns')
DOC_ROOTS = ('doc','docs','help','share/doc','share/help')
SENSITIVE = ('license','credential','secret','password','key','token','auth','user_data','design_data')


def require(ok,code):
    if not ok:
        raise ValueError(code)


def _parts(path):
    return (type(path) is str and 0 < len(path) <= 512 and '\\' not in path and
            not any(ord(c) < 32 or ord(c) == 127 for c in path) and
            all(part not in ('','.','..') for part in path.split('/')))


def _document_directory(relative):
    if not _parts(relative) or any(word in part.lower() for part in relative.split('/') for word in SENSITIVE):
        return False
    roots = [root for root in DOC_ROOTS if relative == root or relative.startswith(root+'/')]
    return bool(roots) and len(relative.split('/'))-len(max(roots,key=len).split('/')) <= 2


def _identity(info):
    return tuple(getattr(info,key) for key in FIELDS)


class BoundedDocumentNames(object):
    """Context-managed iterator yielding <=200 names from one pinned directory.

    `expected_identity` is the full stat snapshot of the verified document FD.
    `verified_installation_root` is its previously authenticated canonical root,
    not an instruction to open that path. Both doc relatives are exact, opaque
    paths; only name classification uses lowercase. The owned dup stays open
    through iterator close and final checks. Reaching the cap is conservatively
    truncated even if the directory happens to contain exactly that many names.
    """
    def __init__(self,directory_fd,expected_identity,verified_installation_root,
                 logical_relative,resolved_relative,tick,limit=200):
        require(type(directory_fd) is int and directory_fd >= 0,'DOCUMENT_FD_REQUIRED')
        require(type(expected_identity) is dict and set(expected_identity) == set(FIELDS) and
            all(type(n) is int and n >= 0 for n in expected_identity.values()) and
            stat.S_ISDIR(expected_identity['st_mode']) and expected_identity['st_nlink'] >= 1,
            'VERIFIED_DOCUMENT_DIRECTORY_SNAPSHOT')
        require(type(verified_installation_root) is str and verified_installation_root.startswith('/cad/mentor/') and
            _parts(verified_installation_root[1:]),'VERIFIED_CANONICAL_INSTALLATION_ROOT')
        require(_document_directory(logical_relative) and _document_directory(resolved_relative),
            'LOGICAL_AND_RESOLVED_DOCUMENT_DIRECTORY_SCOPE')
        require(callable(tick) and type(limit) is int and 1 <= limit <= 200,'BOUNDED_DOCUMENT_NAME_BUDGET')
        self._source_fd = directory_fd
        self._expected = tuple(expected_identity[key] for key in FIELDS)
        self._target = verified_installation_root+'/'+resolved_relative
        self._tick,self._limit = tick,limit
        self._fd,self._stream,self._iterator,self._alias = None,None,None,None
        self._used,self._closed = False,False
        self.scanned_names = 0
        self.truncated,self.exhausted,self.post_identity_verified = False,False,False

    def _check(self):
        self._tick()
        info = os.fstat(self._fd)
        require(stat.S_ISDIR(info.st_mode) and _identity(info) == self._expected,
                'PINNED_DOCUMENT_DIRECTORY_CHANGED')
        require(os.readlink(self._alias) == self._target,'DOCUMENT_FD_ALIAS_TARGET_CHANGED')
        named = os.stat(self._alias,follow_symlinks=True)
        require(stat.S_ISDIR(named.st_mode) and _identity(named) == self._expected,
                'DOCUMENT_FD_ALIAS_IDENTITY_CHANGED')
        require(_identity(os.fstat(self._fd)) == self._expected,'PINNED_DOCUMENT_DIRECTORY_CHANGED')
        self._tick()

    def __enter__(self):
        require(not self._used,'ONE_DOCUMENT_DIRECTORY_ITERATION')
        self._used = True
        require(sys.platform.startswith('linux'),'LINUX_PROC_FD_REQUIRED')
        self._tick()
        self._fd = os.dup(self._source_fd)
        self._alias = '/proc/self/fd/%d'%self._fd
        try:
            self._check()
            # Python 3.6 compatibility: use the verified string alias, never int FD.
            self._stream = os.scandir(self._alias)
            self._iterator = iter(self._stream)
            self._check()
            return self
        except BaseException:
            try:
                if self._stream is not None:
                    self._stream.close()
            finally:
                os.close(self._fd)
                self._fd = None
                self._closed = True
            raise

    def __iter__(self):
        return self

    def __next__(self):
        require(self._fd is not None and not self._closed,'DOCUMENT_ITERATOR_NOT_ACTIVE')
        if self.scanned_names >= self._limit:
            self.truncated = True
            raise StopIteration
        self._check()
        try:
            entry = next(self._iterator)
        except StopIteration:
            self.exhausted = True
            self._check()
            raise
        self.scanned_names += 1
        name = entry.name
        require(type(name) is str and 0 < len(name) <= 255 and name not in ('.','..') and
            '/' not in name and '\\' not in name and not any(ord(c) < 32 or ord(c) == 127 for c in name),
            'SAFE_SINGLE_DOCUMENT_ENTRY_NAME')
        self._check()
        if self.scanned_names == self._limit:
            self.truncated = True
        return name

    def __exit__(self,exc_type,exc,tb):
        try:
            if self._fd is not None:
                self._check()
                self.post_identity_verified = True
        finally:
            try:
                if self._stream is not None:
                    self._stream.close()
            finally:
                if self._fd is not None:
                    os.close(self._fd)
                    self._fd = None
                self._closed = True
        return False
