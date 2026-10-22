"""Durable local *debit protocol* around v1's declared synthetic task budget.

This is no task runner and returns no execution authority. A caller-selected
path is only a namespace anchor: another directory cannot be globally stopped
from creating a fresh quota. Fsync ACK is live-process evidence, not proof of
power-loss survival. Windows tests do not establish Linux filesystem behavior.
"""
import copy
import hashlib
import json
import os
import stat
import threading

from src.data import prospective_stage_budget_v1 as base

SCHEMA = 'prospective-stage-budget-journal-v2'
MAX_EVENTS = 256
MAX_LINE = 16384
MAX_TOTAL = 1048576
ZERO = '0'*64


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),
                      ensure_ascii=True,allow_nan=False).encode('ascii')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def parse(raw):
    def unique(pairs):
        out={}
        for key,value in pairs:
            require(key not in out,'DUPLICATE_JSON_KEY')
            out[key]=value
        return out
    return json.loads(raw,object_pairs_hook=unique,
                      parse_constant=lambda _:(_ for _ in ()).throw(ValueError('NONFINITE_JSON')))


def exact(value,keys,reason):
    require(type(value) is dict and set(value)==set(keys),reason)


def header(plan,max_tessent_calls,max_translation_calls,phase_envelope_ns):
    # v1 performs all strict types, dependency and cap checks before any write.
    base.DeclaredTaskBudget(plan,max_tessent_calls,max_translation_calls,phase_envelope_ns)
    body=dict(kind='HEADER',schema=SCHEMA,plan=copy.deepcopy(plan),
              max_tessent_calls=max_tessent_calls,
              max_translation_calls=max_translation_calls,
              phase_envelope_ns=phase_envelope_ns,prev=ZERO)
    return dict(body,sha256=digest(canonical(body)))


def _path(path):
    value=os.fspath(path)
    require(type(value) is str and os.path.isabs(value),'ABSOLUTE_JOURNAL_PATH')
    value=os.path.normpath(value)
    parent=os.path.dirname(value)
    require(parent!=value and os.path.basename(value) not in ('','.','..'),
            'JOURNAL_BASENAME')
    current=parent
    while True:
        info=os.lstat(current)
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
                'SYMLINK_OR_NONDIRECTORY_ANCESTOR')
        next_parent=os.path.dirname(current)
        if next_parent==current:
            break
        current=next_parent
    return value,parent


def _identity(info):
    # Windows may report different ctime_ns for the same open handle and
    # pathname immediately after creation; POSIX ctime remains a useful
    # same-size mutation signal. Other identity/size/mtime fields stay strict.
    core=(info.st_dev,info.st_ino,info.st_mode,info.st_nlink,
          info.st_size,info.st_mtime_ns)
    return core+(info.st_ctime_ns,) if os.name=='posix' else core


def _footer(value,live):
    result=dict(value)
    result.update(schema=SCHEMA,
                  state_kind=('LIVE_LOCAL_FSYNC_ACK_ONLY' if live else
                              'STRUCTURAL_REPLAY_ONLY_NO_HISTORICAL_ACK'),
                  durable_debit_ack_verified=bool(live and
                      sum(value['consumed_counts'].values())>0),
                  fsync_acknowledgments_verified=bool(live),
                  asserted_elapsed_ns_sum=(value['asserted_elapsed_ns_sum'] if live else None),
                  OS_power_loss_durability_proved=False,
                  namespace_global_quota_proved=False,
                  OS_resource_limits_enforced=False,launch_authorized=False,
                  execution_ready=False,training_release=False)
    return result


class Journal:
    """Private single writer; create once, never reopen from replay."""
    def __init__(self):
        raise TypeError('USE_CREATE')

    @classmethod
    def create(cls,path,plan,*,max_tessent_calls,max_translation_calls,phase_envelope_ns):
        row=header(plan,max_tessent_calls,max_translation_calls,phase_envelope_ns)
        raw=canonical(row)+b'\n'
        require(len(raw)<=MAX_LINE and len(raw)<=MAX_TOTAL,'HEADER_BOUND')
        fixed,parent=_path(path)
        flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_BINARY',0)
        fd=os.open(fixed,flags,0o600)
        try:
            require(os.write(fd,raw)==len(raw),'SHORT_WRITE')
            os.fsync(fd)
            if os.name=='posix':
                parent_fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0))
                try:os.fsync(parent_fd)
                finally:os.close(parent_fd)
            instance=object.__new__(cls)
            instance._path=fixed
            instance._fd=fd
            # Caller-owned plan may mutate during I/O; live RAM must use the
            # frozen header values that replay will see.
            instance._budget=base.DeclaredTaskBudget(row['plan'],row['max_tessent_calls'],
                                                        row['max_translation_calls'],row['phase_envelope_ns'])
            instance._head=row['sha256']
            instance._events=0
            instance._size=len(raw)
            instance._identity=_identity(os.fstat(fd))
            instance._poisoned=False
            instance._closed=False
            instance._busy=False
            instance._lock=threading.RLock()
            instance._check()
            return instance
        except BaseException:
            os.close(fd)
            raise

    def _check(self):
        observed=os.fstat(self._fd)
        path=os.stat(self._path,follow_symlinks=False)
        require(stat.S_ISREG(observed.st_mode) and observed.st_nlink==1 and
                _identity(observed)==self._identity==_identity(path) and
                observed.st_size==self._size,'JOURNAL_IDENTITY_CHANGED')

    def _available(self):
        require(not self._closed and not self._poisoned,'JOURNAL_UNAVAILABLE')

    def _begin(self):
        if self._busy:
            self._poisoned=True
            raise ValueError('JOURNAL_REENTRANT_OPERATION')
        self._available()
        self._busy=True

    def _append(self,kind,payload):
        try:
            self._check()
            require(self._events<MAX_EVENTS,'EVENT_BOUND')
            body=dict(seq=self._events+1,kind=kind,payload=copy.deepcopy(payload),prev=self._head)
            row=dict(body,sha256=digest(canonical(body)))
            raw=canonical(row)+b'\n'
            require(len(raw)<=MAX_LINE and self._size+len(raw)<=MAX_TOTAL,'JOURNAL_BYTE_BOUND')
            require(os.write(self._fd,raw)==len(raw),'SHORT_WRITE')
            os.fsync(self._fd)
            self._available()  # A reentrant callback may have poisoned us.
            observed=os.fstat(self._fd)
            require(observed.st_size==self._size+len(raw),'JOURNAL_SIZE_CHANGED')
            self._size=observed.st_size
            self._identity=_identity(observed)
            self._check()
            self._available()
            self._head=row['sha256']
            self._events+=1
        except BaseException:
            self._poisoned=True
            raise

    def reserve(self,task_uid):
        with self._lock:
            acquired=False
            try:
                self._begin()
                acquired=True
                trial=copy.deepcopy(self._budget)
                try:
                    token=trial.reserve(task_uid)
                except ValueError as exc:
                    if str(exc)=='CENSORED_DECLARED_BUDGET_EXHAUSTED':
                        self._append('DENIED',dict(task_uid=task_uid,reason=str(exc)))
                        self._available()
                        self._budget=trial
                    raise
                self._append('DEBIT',dict(task_uid=task_uid,token=token))
                self._available()
                self._budget=trial
                return copy.deepcopy(token)
            finally:
                if acquired:self._busy=False

    def settle(self,token,status,elapsed_ns,cleanup_verified):
        with self._lock:
            acquired=False
            try:
                self._begin()
                acquired=True
                trial=copy.deepcopy(self._budget)
                value=trial.settle(token,status,elapsed_ns,cleanup_verified)
                self._append('SETTLE',dict(token=copy.deepcopy(token),status=status,
                                           elapsed_ns=elapsed_ns,
                                           cleanup_verified=cleanup_verified))
                self._available()
                self._budget=trial
                return _footer(value,True)
            finally:
                if acquired:self._busy=False

    def snapshot(self):
        with self._lock:
            if self._busy:
                self._poisoned=True
            if not self._closed and not self._poisoned:
                try:self._check()
                except BaseException:self._poisoned=True
            value=_footer(self._budget.snapshot(),not self._closed and not self._poisoned)
            value.update(head_sha256=self._head,event_count=self._events,
                         writer_poisoned=self._poisoned)
            return value

    def close(self):
        with self._lock:
            if self._busy:
                self._poisoned=True
                raise ValueError('JOURNAL_REENTRANT_OPERATION')
            if not self._closed:
                self._closed=True
                try:os.close(self._fd)
                except BaseException:
                    self._poisoned=True
                    raise

    def __enter__(self):
        return self

    def __exit__(self,_type,_value,_traceback):
        self.close()


def load(path):
    """Strict bounded structural replay, never an ACK or writer-resume proof."""
    fixed,_=_path(path)
    # A FIFO substituted before open must not block the reader. The lstat is
    # an early rejection, while NONBLOCK and the fd/path check cover its race.
    preliminary=os.lstat(fixed)
    require(stat.S_ISREG(preliminary.st_mode) and preliminary.st_nlink==1 and
            preliminary.st_size<=MAX_TOTAL,'REPLAY_FILE_IDENTITY')
    fd=os.open(fixed,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|
               getattr(os,'O_NONBLOCK',0)|getattr(os,'O_BINARY',0))
    try:
        before=os.fstat(fd)
        named=os.stat(fixed,follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and
                before.st_size<=MAX_TOTAL and _identity(before)==_identity(named),
                'REPLAY_FILE_IDENTITY')
        raw=os.read(fd,before.st_size)
        after=os.fstat(fd)
        named_after=os.stat(fixed,follow_symlinks=False)
        require(len(raw)==before.st_size and _identity(before)==_identity(after)==
                _identity(named)==_identity(named_after),'REPLAY_FILE_CHANGED')
    finally:
        os.close(fd)
    lines=raw.splitlines(keepends=True)
    require(lines and all(line.endswith(b'\n') and len(line)<=MAX_LINE for line in lines),
            'TORN_OR_OVERSIZE_LINE')
    rows=[]
    for line in lines:
        value=parse(line)
        require(canonical(value)+b'\n'==line,'NONCANONICAL_ROW')
        rows.append(value)
    top=rows[0]
    exact(top,('kind','schema','plan','max_tessent_calls','max_translation_calls',
               'phase_envelope_ns','prev','sha256'),'HEADER_KEYS')
    require(top['kind']=='HEADER' and top['schema']==SCHEMA and top['prev']==ZERO and
            top==header(top['plan'],top['max_tessent_calls'],
                        top['max_translation_calls'],top['phase_envelope_ns']),
            'HEADER_PIN')
    require(len(rows)-1<=MAX_EVENTS,'EVENT_BOUND')
    budget=base.DeclaredTaskBudget(top['plan'],top['max_tessent_calls'],
                                   top['max_translation_calls'],top['phase_envelope_ns'])
    head=top['sha256']
    for index,row in enumerate(rows[1:],1):
        exact(row,('seq','kind','payload','prev','sha256'),'EVENT_KEYS')
        body={key:row[key] for key in ('seq','kind','payload','prev')}
        require(type(row['seq']) is int and row['seq']==index and row['prev']==head and
                row['sha256']==digest(canonical(body)),'EVENT_CHAIN')
        payload=row['payload']
        if row['kind']=='DEBIT':
            exact(payload,('task_uid','token'),'DEBIT_KEYS')
            token=budget.reserve(payload['task_uid'])
            require(canonical(token)==canonical(payload['token']),'DEBIT_TOKEN')
        elif row['kind']=='SETTLE':
            exact(payload,('token','status','elapsed_ns','cleanup_verified'),'SETTLE_KEYS')
            budget.settle(payload['token'],payload['status'],payload['elapsed_ns'],
                          payload['cleanup_verified'])
        elif row['kind']=='DENIED':
            exact(payload,('task_uid','reason'),'DENIED_KEYS')
            try:budget.reserve(payload['task_uid'])
            except ValueError as exc:
                require(str(exc)==payload['reason']=='CENSORED_DECLARED_BUDGET_EXHAUSTED',
                        'DENIED_REASON')
            else:raise ValueError('FALSE_DENIAL')
        else:
            raise ValueError('EVENT_KIND')
        head=row['sha256']
    value=_footer(budget.snapshot(),False)
    value.update(head_sha256=head,event_count=len(rows)-1,writer_poisoned=None,
                 structural_replay_valid=True)
    return value
