"""Direct, serial Tessent acceptance. No LSF or kernel-memory admission.

RSS+swap and scratch are sampled stop thresholds, not hard containment.
Fresh subreaper owns only its own descendants, including setsid children.
"""
import ctypes
import hashlib
import json
import os
import platform
import re
import selectors
import shlex
import signal
import subprocess
import sys
import time

from . import prospective_tessent_acceptance_v1 as recipe
from . import prospective_acceptance_materializer_v1 as material
from .prospective_acceptance_scratch_v1 import ScratchMonitor

ROOT = '/temp/jiangchuanc/multimode_ate_direct_e100_20261025_r1'
SAMPLE_STOP = 536870912
OUTPUT_CAP = 16777216
require = recipe.require


def validate_authority(raw):
    value = json.loads(raw.decode('utf-8'))
    require(value.get('schema') == 'direct-tessent-authorization-e100-v1' and
            value.get('user_instruction') == '撤掉保护吧' and
            value.get('kernel_memory_cap_required') is False and
            value.get('sampling_is_hard_memory_guarantee') is False and
            value.get('lsf_allowed') is False and value.get('workers') == 1 and
            value.get('cases_max') == 4 and value.get('automatic_retries') == 0 and
            value.get('sampled_rss_plus_swap_stop_bytes') == SAMPLE_STOP and
            value.get('per_case_seconds_including_cleanup') == 600 and
            value.get('session_seconds') == 2700 and value.get('combined_output_bytes') == OUTPUT_CAP and
            value.get('process_count_stop_threshold') == 64 and
            value.get('scratch_stop_threshold_bytes') == 134217728 and
            value.get('root') == ROOT and
            value.get('scope') == 'FOUR_TRANSLATED_STATUS_ACCEPTANCE_NO_PATTERN_GENERATION' and
            all(value.get(k) is False for k in ('atpg_generation_allowed','training_allowed','blind_allowed')),
            'DIRECT_AUTHORITY_REQUIRED')
    return value


def _small(path, cap=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        raw = os.read(fd, cap + 1)
        require(len(raw) <= cap, 'PROC_READ_BOUND')
        return raw
    finally:
        os.close(fd)


def _identity(pid):
    raw = _small('/proc/%d/stat' % pid).decode('ascii')
    end = raw.rfind(') ')
    fields = raw[end + 2:].split()
    require(end > 0 and raw.split(' ',1)[0] == str(pid) and len(fields) >= 20, 'PROC_IDENTITY')
    require(os.stat('/proc/%d' % pid).st_uid == os.getuid(), 'FOREIGN_UID')
    return (pid, int(fields[19]), fields[0], int(fields[1]), int(fields[2]), int(fields[3]))


def _children(pid):
    found = set()
    count = 0
    with os.scandir('/proc/%d/task' % pid) as tasks:
        for task in tasks:
            count += 1
            require(count <= 1024 and task.name.isdigit(), 'TASK_ENUMERATION_BOUND')
            try:
                raw = _small('/proc/%d/task/%s/children' % (pid,task.name),4096)
            except FileNotFoundError:
                continue
            require(all(x.isdigit() for x in raw.split()), 'CHILD_PID_FORMAT')
            found.update(int(x) for x in raw.split())
            require(len(found) <= 64, 'PROCESS_STOP_THRESHOLD')
    return found


class Descendants:
    def __init__(self):
        self.pid = os.getpid()
        require(not _children(self.pid), 'PREEXISTING_CHILDREN')
        require(re.search(rb'^Threads:\s+1\s*$',_small('/proc/self/status'),re.M) is not None,
                'SINGLE_THREAD_SUPERVISOR')
        self.identity = _identity(self.pid)
        libc = ctypes.CDLL(None, use_errno=True)
        require(libc.prctl(36,1,0,0,0) == 0, 'SUBREAPER_SET')
        enabled = ctypes.c_int()
        require(libc.prctl(37,ctypes.byref(enabled),0,0,0) == 0 and enabled.value == 1,
                'SUBREAPER_VERIFY')
        self.peak = 0

    def snapshot(self):
        todo, result = [self.identity], {}
        while todo:
            parent_identity = todo.pop()
            parent = parent_identity[0]
            try:
                require(_identity(parent)[:2] == parent_identity[:2], 'PARENT_IDENTITY_CHANGED')
                children = _children(parent)
                require(_identity(parent)[:2] == parent_identity[:2], 'PARENT_IDENTITY_CHANGED')
            except (FileNotFoundError,ProcessLookupError):
                continue
            for pid in children:
                require(pid != self.pid, 'CHILD_CYCLE')
                if pid in result:
                    continue
                require(len(result) < 64, 'PROCESS_STOP_THRESHOLD')
                try:
                    child = _identity(pid)
                    # Never adopt a PID number on UID alone. Reparenting races
                    # are rediscovered from the exclusive subreaper next sample.
                    if child[3] != parent:
                        continue
                    require(_identity(parent)[:2] == parent_identity[:2], 'PARENT_IDENTITY_CHANGED')
                    require(_identity(pid)[:2] == child[:2], 'CHILD_IDENTITY_CHANGED')
                    result[pid] = child
                except (FileNotFoundError,ProcessLookupError):
                    continue
                todo.append(result[pid])
        return result

    def sample(self):
        processes = self.snapshot()
        total = 0
        for pid in list(processes) + [self.pid]:
            try:
                before=_identity(pid)
                status = _small('/proc/%d/status' % pid)
                require(_identity(pid)[:2]==before[:2],'MEMORY_PID_CHANGED')
            except (FileNotFoundError,ProcessLookupError):
                continue
            if before[2] in ('Z','X','x'):
                continue
            for key in (b'VmRSS',b'VmSwap'):
                values = re.findall(rb'^'+key+rb':\s+([0-9]+)\s+kB\s*$',status,re.M)
                require(len(values) == 1, 'MEMORY_STATUS')
                total += int(values[0])*1024
        self.peak = max(self.peak,total)
        require(total <= SAMPLE_STOP, 'SAMPLED_MEMORY_STOP')
        return processes

    def _direct_batch(self):
        # Cleanup does NOT reuse the monitoring 64-process/1024-task bound.
        # Killing direct children causes their descendants (even setsid) to be
        # adopted here. Drain bounded batches until empty or cleanup deadline.
        require(_identity(self.pid)[:2] == self.identity[:2], 'SUPERVISOR_IDENTITY_CHANGED')
        fd=os.open('/proc/self/task/%d/children'%self.pid,os.O_RDONLY|os.O_NOFOLLOW)
        try: raw=os.read(fd,65536)
        finally: os.close(fd)
        truncated=len(raw)==65536
        if truncated:raw=raw.rsplit(b' ',1)[0]
        fields=raw.split()
        require(all(x.isdigit() for x in fields),'CLEANUP_CHILD_PID_FORMAT')
        return [int(x) for x in fields[:256]],truncated or len(fields)>256

    def cleanup(self, proc, end):
        while time.monotonic() < end:
            proc.poll()
            children,more=self._direct_batch()
            for pid in children:
                try:
                    identity = _identity(pid)
                    now = _identity(pid)
                    require(now[:2] == identity[:2] and now[3] == self.pid,
                            'CLEANUP_NOT_OWN_CHILD')
                    if now[2] != 'Z':
                        os.kill(pid,signal.SIGKILL)
                    elif pid != proc.pid:
                        os.waitpid(pid,os.WNOHANG)
                except (FileNotFoundError,ProcessLookupError):
                    pass
                except ChildProcessError:
                    pass
            proc.poll()
            remaining,more=self._direct_batch()
            if proc.returncode is not None and not remaining and not more:
                return True
            time.sleep(.02)
        return False


def supervise(argv, cwd, end, domain, output_budget, scratch=None, ready_check=None):
    """Private primitive; production supplies only fixed recipe/module argv."""
    proc, output, cleaned, failure = None, bytearray(), False, None
    launch_attempted=False;readiness=None
    try:
        require(time.monotonic() < end-10, 'PRELAUNCH_TIMEOUT')
        require(output_budget[0]>0,'OUTPUT_STOP')
        domain.sample()
        if scratch is not None:scratch.sample()
        require(time.monotonic() < end-10,'PRELAUNCH_TIMEOUT')
        launch_attempted=True
        proc = subprocess.Popen(argv,cwd=cwd,stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,close_fds=True,start_new_session=True)
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout,selectors.EVENT_READ)
            next_scratch = 0
            while selector.get_map() or proc.poll() is None:
                require(time.monotonic() < end-10,'CASE_TIMEOUT')
                domain.sample()
                if scratch is not None and time.monotonic() >= next_scratch:
                    scratch.sample();next_scratch=time.monotonic()+1
                for key,_ in selector.select(.05):
                    require(output_budget[0]>0,'OUTPUT_STOP')
                    raw = os.read(key.fileobj.fileno(),min(65536,output_budget[0]))
                    if raw:
                        output_budget[0] -= len(raw);output.extend(raw)
                        if ready_check is not None and readiness is None:
                            readiness=ready_check(bytes(output),domain)
                    else:
                        selector.unregister(key.fileobj)
            proc.wait(timeout=max(.001,end-10-time.monotonic()))
    except Exception as exc:
        failure = str(exc) if isinstance(exc,ValueError) else type(exc).__name__
    finally:
        if proc is not None:
            try: cleaned=domain.cleanup(proc,end)
            except Exception: cleaned=False
            if proc.stdout is not None: proc.stdout.close()
        else:
            try:
                remaining,more=domain._direct_batch();cleaned=not remaining and not more
            except Exception:cleaned=False
    require(cleaned,'CLEANUP_UNCONFIRMED')
    return dict(returncode=proc.returncode if proc is not None else None,cleaned=cleaned,failure=failure,
        output=bytes(output),sampled_peak_rss_swap_bytes=domain.peak,
        launch_attempted=launch_attempted,readiness=readiness,
        streams_combined=True,stderr_separately_validated=False)


def _setsid_readiness(output,domain):
    matches=re.findall(rb'^DIRECT_SETSID_READY ([1-9][0-9]*)\s*$',output,re.M)
    if not matches:return None
    require(len(matches)==1,'SYNTHETIC_READINESS_DUPLICATE')
    pid=int(matches[0]);members=domain.snapshot()
    require(pid in members,'SYNTHETIC_READINESS_NOT_DESCENDANT')
    identity=_identity(pid)
    require(identity[:2]==members[pid][:2] and identity[4]==pid and identity[5]==pid,
            'SYNTHETIC_READINESS_NOT_SETSID')
    return dict(pid=pid,start_ticks=identity[1],pgrp=pid,session=pid,
                observed_from_own_descendant_tree=True)


def synthetic_gate(domain):
    cases = (
        ('success','print("DIRECT_SYNTHETIC_OK")',True),
        ('timeout','import time;time.sleep(5)',False),
        ('setsid_child','import os,time\np=os.fork()\nif p==0:\n os.setsid();print("DIRECT_SETSID_READY %d"%os.getpid(),flush=True);time.sleep(30)\nelse:\n time.sleep(30)',False))
    receipts=[]
    for name,code,success in cases:
        result=supervise([sys.executable,'-I','-S','-B','-c',code],ROOT,
            time.monotonic()+(15 if success else (13 if name=='setsid_child' else 10.5)),domain,[65536],
            ready_check=_setsid_readiness if name=='setsid_child' else None)
        require(result['cleaned'] and ((result['returncode']==0 and result['failure'] is None)
                if success else result['failure']=='CASE_TIMEOUT'),'DIRECT_SYNTHETIC_FAILED')
        require(name!='setsid_child' or result['readiness'] is not None,'SYNTHETIC_READINESS_MISSING')
        receipts.append(dict(name=name,cleaned=True,expected_success=success,readiness=result['readiness']))
    return receipts


class DirectMaterializer(material.Materializer):
    """Reuse anchored copy/translation only, no fake Job ID or preflight proof."""
    def __init__(self,raw85,raw93,authority):
        self.authorization=validate_authority(authority)
        recipe.ROOT=ROOT
        self.recipe=recipe.compile_acceptance(raw85,raw93,recipe.E85_SHA256,recipe.E93_SHA256)
        material.RECIPE_SHA256=self.recipe['recipe_sha256']
        self.e85=json.loads(raw85.decode('ascii'));self.e93=json.loads(raw93.decode('ascii'))
        self.root_fd=self.scratch_fd=None;self.failed=False

    def _preflight(self):
        return dict(mode='DIRECT_USER_REMOVED_KERNEL_MEMORY_REQUIREMENT',lsf_used=False,
            kernel_memory_cap_enforced=False,sampled_memory_stop_bytes=SAMPLE_STOP,
            sampling_is_hard_memory_guarantee=False)


def accepts_log(log,marker):
    return (sum(line.strip()==marker for line in log.splitlines())==1 and
        not re.search(rb'(?<![a-z0-9_])(?:error|fatal|warning)(?![a-z0-9_])|invalid pin_pathname',log,re.I))


def execute(raw85,raw93,authority):
    require(sys.platform.startswith('linux') and platform.node()=='bupt-vncs2','FIXED_LINUX_HOST')
    end=time.monotonic()+2700
    maker=DirectMaterializer(raw85,raw93,authority)
    plan=maker.initialize_bundle()  # Exclusive new root; consumes this invocation.
    results=[]
    try:
        domain=Descendants()
        gate=synthetic_gate(domain)
        material._publish(maker.root_fd,'synthetic_gate.json',recipe.canonical(dict(passed=True,cases=gate))+b'\n')
        shared=[OUTPUT_CAP]
        for row in plan['items']:
            case_started=time.monotonic()
            case_end=min(end,case_started+600)
            item=maker.materialize_item(row['circuit'],row['transition'])
            scratch=ScratchMonitor(case_end)
            command='module load mentor/tessent2021 && export HOME=%s TMPDIR=%s && exec %s' % (
                shlex.quote(item['cwd']),shlex.quote(item['cwd']),
                ' '.join(shlex.quote(x) for x in item['argv']))
            material._publish(maker.root_fd,'started_%s_%s.json'%(row['circuit'],row['target_mode']),
                recipe.canonical(dict(circuit=row['circuit'],transition=row['transition'],
                    consumed=True,automatic_retries=0,kernel_memory_cap_enforced=False))+b'\n')
            observed=supervise(['/bin/bash','-lc',command],item['cwd'],case_end,domain,shared,scratch)
            log=observed.pop('output')
            log_fd=material._directory(item['cwd'])
            try: material._publish(log_fd,'direct_tessent.log',log)
            finally: os.close(log_fd)
            scratch.sample()
            require(time.monotonic()<=case_end,'CASE_DEADLINE_AFTER_LOGS')
            marker=('E94_TRANSLATED_STATUS_ACCEPTANCE=PASS %s %s'%(row['circuit'],row['transition'])).encode('ascii')
            passed=(observed['returncode']==0 and observed['failure'] is None and
                accepts_log(log,marker))
            receipt=dict(observed,circuit=row['circuit'],transition=row['transition'],passed=passed,
                log_sha256=hashlib.sha256(log).hexdigest(),log_bytes=len(log),
                kernel_memory_cap_enforced=False,atpg_calls=0,training_runs=0,
                elapsed_before_receipt_seconds=time.monotonic()-case_started)
            results.append(receipt)
            material._publish(maker.root_fd,'result_%s_%s.json'%(row['circuit'],row['target_mode']),recipe.canonical(receipt)+b'\n')
            scratch.sample()
            require(time.monotonic()<=case_end,'CASE_DEADLINE_AFTER_RECEIPT')
            if not passed: break
        summary=dict(schema='direct-tessent-acceptance-e100-v1',root=ROOT,
            cases=results,passed=len(results)==4 and all(r['passed'] for r in results),
            kernel_memory_cap_enforced=False,lsf_used=False,automatic_retries=0,
            tessent_launch_attempts=sum(bool(r['launch_attempted']) for r in results),
            actual_tessent_execution_observed=sum(bool(r['passed']) for r in results),
            atpg_calls=0,training_runs=0,blind_release=False)
        material._publish(maker.root_fd,'summary.json',recipe.canonical(summary)+b'\n')
        require(time.monotonic()<=end,'SESSION_DEADLINE_AFTER_SUMMARY')
        return summary
    except Exception as exc:
        material._publish(maker.root_fd,'failure.json',recipe.canonical(dict(
            error_type=type(exc).__name__,code=str(exc) if isinstance(exc,ValueError) else 'DIRECT_STAGE_FAILED',
            cases_completed=len(results),no_retry=True))+b'\n')
        raise
    finally:
        maker.close()
