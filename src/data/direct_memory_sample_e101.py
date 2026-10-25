"""Bounded exit-race-aware sampling; not a kernel memory guarantee.

This module launches nothing. Exited processes produce missing measurements,
not fabricated zero-valued live RSS. A persistent live parse failure still stops.
"""
import re
import time


def measure_owned(pid, expected_start_ticks, read_identity, read_status, pause=time.sleep):
    for attempt in range(2):
        try:
            before=read_identity(pid)
            if before[0]!=pid or before[1]!=expected_start_ticks:
                raise ValueError('MEMORY_PID_CHANGED')
            raw=read_status('/proc/%d/status'%pid)
            after=read_identity(pid)
        except (FileNotFoundError,ProcessLookupError):
            return dict(kind='EXITED_DURING_SAMPLE',rss_swap_bytes=None,reads=attempt+1)
        if before[:2]!=after[:2]:
            raise ValueError('MEMORY_PID_CHANGED')
        if type(raw) is not bytes or len(raw)>65536:
            raise ValueError('MEMORY_STATUS_BOUND')
        states=re.findall(rb'^State:\s+([A-Za-z])(?:\s|$)',raw,re.M)
        if len(states)!=1:
            raise ValueError('MEMORY_STATUS_STATE')
        state=states[0].decode('ascii')
        if any(x in ('Z','X','x') for x in (before[2],after[2],state)):
            return dict(kind='EXITED_DURING_SAMPLE',rss_swap_bytes=None,reads=attempt+1,
                        before_state=before[2],after_state=after[2],status_state=state)
        values=[re.findall(rb'^'+key+rb':\s+([0-9]+)\s+kB\s*$',raw,re.M)
                for key in (b'VmRSS',b'VmSwap')]
        if all(len(x)==1 for x in values):
            return dict(kind='LIVE_MEASURED',rss_swap_bytes=sum(int(x[0])*1024 for x in values),
                        reads=attempt+1,before_state=before[2],after_state=after[2],status_state=state)
        if attempt==0:
            pause(.005)  # One bounded metadata recheck, never a tool retry.
    raise ValueError('MEMORY_STATUS_LIVE_FIELDS_MISSING')


def sample_descendants(domain, read_identity, read_status):
    processes=domain.snapshot()
    expected=dict(processes);expected[domain.pid]=domain.identity
    measurements=[measure_owned(pid,identity[1],read_identity,read_status)
                  for pid,identity in expected.items()]
    total=sum(row['rss_swap_bytes'] for row in measurements if row['kind']=='LIVE_MEASURED')
    domain.peak=max(domain.peak,total)
    domain.last_memory_sample=dict(live_measured=sum(row['kind']=='LIVE_MEASURED' for row in measurements),
        exited_during_sample=sum(row['kind']=='EXITED_DURING_SAMPLE' for row in measurements),
        sampled_rss_swap_bytes=total,sampling_is_hard_memory_guarantee=False)
    if total>536870912:
        raise ValueError('SAMPLED_MEMORY_STOP')
    return processes
