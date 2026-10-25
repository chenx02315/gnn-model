"""Narrow proof of an exiting task that has released its user address space.

No missing live RSS is filled with zero. The exceptional row remains None and
does not assert OS termination; the existing owner-tree cleanup still applies.
Linux 3.10 proc/array.c and sched.h define the proof fields used here.
"""
import re
import os
from . import direct_memory_sample_e101 as original


def _threads(pid):
    found=[]
    with os.scandir('/proc/%d/task'%pid) as entries:
        for entry in entries:
            if len(found)>=1024 or not entry.name.isdigit():
                raise ValueError('MEMORY_THREAD_BOUND')
            found.append(int(entry.name))
    return sorted(found)


def _confirmed_exit(pid,start,read_identity,read_threads):
    try:
        before=read_identity(pid)
        if before[:2]!=(pid,start):raise ValueError('MEMORY_PID_CHANGED')
        first=read_threads(pid);last=read_threads(pid)
        after=read_identity(pid)
    except (FileNotFoundError,ProcessLookupError):
        try:now=read_identity(pid)
        except (FileNotFoundError,ProcessLookupError):return True
        if now[:2]!=(pid,start):raise ValueError('MEMORY_PID_CHANGED')
        return False
    if after[:2]!=before[:2]:raise ValueError('MEMORY_PID_CHANGED')
    return (first==[pid] and last==[pid] and
            any(s in ('Z','X','x') for s in (before[2],after[2])))


def _exit_mm_proof(pid, start, read_identity, read_aux, read_threads):
    before=read_identity(pid)
    if before[:2]!=(pid,start):raise ValueError('MEMORY_PID_CHANGED')
    threads_before=read_threads(pid)
    raw=read_aux('/proc/%d/stat'%pid)
    statm=read_aux('/proc/%d/statm'%pid)
    status=read_aux('/proc/%d/status'%pid)
    threads_after=read_threads(pid)
    after=read_identity(pid)
    if after[:2]!=before[:2]:raise ValueError('MEMORY_PID_CHANGED')
    if any(type(x) is not bytes or len(x)>65536 for x in (raw,statm,status)):
        raise ValueError('MEMORY_STATUS_BOUND')
    end=raw.rfind(b') ')
    fields=raw[end+2:].split()
    if (end<0 or raw.split(b' ',1)[0]!=str(pid).encode('ascii') or len(fields)<22 or
            not all(fields[i].isdigit() for i in (6,19,20,21))):
        return None
    if int(fields[19])!=start:raise ValueError('MEMORY_PID_CHANGED')
    states=re.findall(rb'^State:\s+([A-Za-z])(?:\s|$)',status,re.M)
    if len(states)!=1:raise ValueError('MEMORY_STATUS_STATE')
    valid_states=('R','S','D','T','t','Z','X','x','K','W','P')
    if (any(state not in valid_states for state in
            (before[2],after[2],states[0].decode('ascii'))) or
            fields[0] not in tuple(state.encode('ascii') for state in valid_states)):
        raise ValueError('MEMORY_STATUS_STATE')
    if any(x in ('Z','X','x') for x in (before[2],after[2],states[0].decode('ascii'))):
        if threads_before==[pid] and threads_after==[pid]:
            return dict(kind='EXITED_DURING_SAMPLE',rss_swap_bytes=None,reads=3)
        return None
    # Both fields must be wholly absent, not malformed, duplicated or partial.
    absent=not re.search(rb'^\s*(?:VmRSS|VmSwap)\b',status,re.M|re.I)
    zeros=statm.split()
    flags=int(fields[6])
    threads=re.findall(rb'^Threads:\s+([0-9]+)\s*$',status,re.M)
    if (absent and flags & 4 and int(fields[20])==0 and int(fields[21])==0 and
            len(zeros)==7 and all(x==b'0' for x in zeros) and
            threads==[b'1'] and threads_before==[pid] and threads_after==[pid]):
        return dict(kind='EXITING_MM_RELEASED',rss_swap_bytes=None,reads=3,
                    pid=pid,start_ticks=start,flags=flags,pf_exiting=True,
                    stat_vsize=0,stat_rss=0,statm_fields=[0]*7,
                    before_state=before[2],after_state=after[2],
                    status_state=states[0].decode('ascii'),
                    task_ids_before=threads_before,task_ids_after=threads_after,
                    os_termination_attested=False)
    return None


def measure_owned(pid,start,read_identity,read_status,pause=original.time.sleep,
                  read_threads=_threads):
    try:
        result=original.measure_owned(pid,start,read_identity,read_status,pause)
        if result['kind']=='EXITED_DURING_SAMPLE' and not _confirmed_exit(
                pid,start,read_identity,read_threads):
            raise ValueError('MEMORY_STATUS_LIVE_FIELDS_MISSING')
        return result
    except ValueError as exc:
        if str(exc)!='MEMORY_STATUS_LIVE_FIELDS_MISSING':raise
        try:
            proof=_exit_mm_proof(pid,start,read_identity,read_status,read_threads)
        except (FileNotFoundError,ProcessLookupError):
            if _confirmed_exit(pid,start,read_identity,read_threads):
                return dict(kind='EXITED_DURING_SAMPLE',rss_swap_bytes=None,reads=3)
            raise ValueError('MEMORY_STATUS_LIVE_FIELDS_MISSING')
        if proof is not None:return proof
        raise ValueError('MEMORY_STATUS_LIVE_FIELDS_MISSING')


def sample_descendants(domain,read_identity,read_status):
    processes=domain.snapshot()
    expected=dict(processes);expected[domain.pid]=domain.identity
    measurements=[measure_owned(pid,identity[1],read_identity,read_status)
                  for pid,identity in expected.items()]
    total=sum(r['rss_swap_bytes'] for r in measurements if r['kind']=='LIVE_MEASURED')
    domain.peak=max(domain.peak,total)
    proofs=[r for r in measurements if r['kind']=='EXITING_MM_RELEASED']
    if not hasattr(domain,'exit_mm_proofs'):domain.exit_mm_proofs={}
    for proof in proofs:
        key=(proof['pid'],proof['start_ticks'])
        domain.exit_mm_proofs[key]=proof
        if len(domain.exit_mm_proofs)>64:raise ValueError('EXIT_MM_PROOF_BOUND')
    domain.last_memory_sample=dict(live_measured=sum(r['kind']=='LIVE_MEASURED' for r in measurements),
        exited_during_sample=sum(r['kind']=='EXITED_DURING_SAMPLE' for r in measurements),
        exiting_mm_released=len(proofs),sampled_rss_swap_bytes=total,
        missing_values_imputed=False,sampling_is_hard_memory_guarantee=False)
    if total>536870912:raise ValueError('SAMPLED_MEMORY_STOP')
    return processes
