"""Local synthetic integration of E84/E86/E87 with the unchanged E83 bridge.

No CLI, real process backend, admission grant or training-label release. Callback
flags and output authentication are assertions, not a sandbox or OS evidence.
The budget projection's legacy request_sha256 is an INTENT digest, never the
late-bound actual request digest. E86 continues to enforce both semantic parents.
"""
import copy
import os
import re
import stat
import threading
from contextlib import contextmanager

from . import prospective_acquisition_pilot_v1 as pilot
from . import prospective_acquisition_binding_v1 as semantic
from . import prospective_acquisition_request_v1 as requests
from . import prospective_task_lifecycle_bridge_v1 as paired

SCHEMA='prospective-acquisition-synthetic-integration-e105-v1'
MAX_RECEIPT=65536
MAX_TOTAL=4*1024*1024
CAP_KEYS={'timeout_ns','cleanup_ns','phase_reservation_ns','setup_timeout_ns'}
canonical=semantic.canonical
sha=semantic.sha
require=semantic.require


def budget_projection(plan,circuit,caps):
    pilot.validate_plan(plan)
    require(circuit in pilot.CIRCUITS and type(caps) is dict and set(caps)==CAP_KEYS,'CAPS_CIRCUIT')
    require(all(type(v) is int and 0<v<=86400*10**9 for v in caps.values()),'DECLARED_LOCAL_CAPS')
    phase=next(p for p in plan['phases'] if p['circuit']==circuit)
    projected=[]
    for node in phase['tasks']:
        target=(node if node['kind']=='TESSENT' else
                next(n for n in phase['tasks'] if node['task_uid'] in n['depends_on']))
        intent=sha(canonical(dict(schema='e105-budget-intent-not-actual-request-v1',
                                  plan_sha256=plan['plan_sha256'],circuit=circuit,node=target)))
        projected.append(dict(task_uid=node['task_uid'],kind=(
            'TESSENT_STAGE' if node['kind']=='TESSENT' else 'STATUS_TRANSLATION'),
            stage=node.get('stage',node.get('target_mode')),request_sha256=intent,
            depends_on=(node['depends_on'][1:] if node['kind']=='TESSENT' else []),
            timeout_ns=caps['timeout_ns'],cleanup_ns=caps['cleanup_ns']))
    # Reuse the old strict checker without changing its dependency schema.
    paired.budget.base.DeclaredTaskBudget(projected,24,15,caps['phase_reservation_ns'])
    require(len(projected)==39,'EXACT_39_TASKS')
    return projected


class _Clock:
    def __init__(self,owner):self.owner=owner
    def capture(self):return self.owner._session,self.owner._now()


class Package:
    """One exclusive namespace, two fixed synthetic phases; never resumes."""
    def __init__(self):raise TypeError('USE_CREATE')

    @classmethod
    def create(cls,root,phase_uid,plan,freezes,caps,profiles,clock_session,clock):
        # Snapshot once, before validation or any I/O/callback can yield back
        # to a caller still holding the original dictionaries.
        plan=copy.deepcopy(plan);freezes=copy.deepcopy(freezes)
        caps=copy.deepcopy(caps);profiles=copy.deepcopy(profiles)
        pilot.validate_plan(plan)
        require(type(phase_uid) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,39}',phase_uid), 'PHASE_UID')
        require(type(freezes) is dict and set(freezes)==set(pilot.CIRCUITS) and
                type(profiles) is dict and set(profiles)==set(pilot.CIRCUITS),'EXACT_TWO_PHASES')
        binders={};manifests={};projection={}
        for circuit in pilot.CIRCUITS:
            freeze=requests.validate_freeze(freezes[circuit],plan)
            require(freeze['circuit']==circuit,'FREEZE_CIRCUIT')
            binders[circuit]=semantic.Binder(plan,circuit,freeze,phase_uid+'_'+circuit)
            projection[circuit]=budget_projection(plan,circuit,caps)
            manifests[circuit]=paired.binding(phase_uid+'_'+circuit,projection[circuit],dict(
                max_tessent_calls=24,max_translation_calls=15,
                phase_envelope_ns=caps['phase_reservation_ns']),profiles[circuit],clock_session)
        fixed=paired._root(root,False)
        header=dict(schema=SCHEMA,plan=copy.deepcopy(plan),freezes=copy.deepcopy(freezes),
                    caps=copy.deepcopy(caps),profiles=copy.deepcopy(profiles),
                    phase_binding_sha256={c:manifests[c]['sha256'] for c in pilot.CIRCUITS},
                    global_tessent_cap=48,global_translation_cap=30,
                    phase_caps=dict(tessent=24,translation=15),
                    budget_request_field_is_intent_digest=True,synthetic_only=True,
                    clock_session=clock_session,resource_limits_enforced=False,
                    execution_ready=False,training_release=False)
        require(len(canonical(header))<=MAX_RECEIPT,'PACKAGE_HEADER_BOUND')
        os.mkdir(fixed,0o700)
        self=object.__new__(cls)
        self._root=fixed;self._root_id=self._root_identity()
        self._header=header;self._clock=clock;self._session=clock_session;self._last=None
        self._bridges={};self._binders=binders;self._manifests=manifests
        self._lock=threading.Lock();self._poisoned=False;self._closed=False
        self._phase=0;self._ready=set();self._setup_active=None;self._active=None
        self._records={};self._known={};self._setup={};self._bytes=0;self._published={}
        self._finished=None
        self._host_boot=None;self._identities=set()
        try:
            self._start=self._now()
            self._publish('package.json',header)
            self._header_raw=canonical(header)+b'\n'
            for circuit in pilot.CIRCUITS:
                self._bridges[circuit]=paired.Bridge.create(os.path.join(fixed,circuit),
                    phase_uid+'_'+circuit,projection[circuit],max_tessent_calls=24,
                    max_translation_calls=15,phase_envelope_ns=caps['phase_reservation_ns'],
                    profiles=profiles[circuit],clock_session=clock_session)
                require(self._bridges[circuit].snapshot()['binding_sha256']==manifests[circuit]['sha256'],
                        'PHASE_BINDING_CHANGED')
            return self
        except BaseException:
            self._poisoned=True
            self.close()
            raise

    def _root_identity(self):
        s=os.lstat(self._root)
        require(stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode),'ROOT_IDENTITY')
        return s.st_dev,s.st_ino,s.st_mode

    def _now(self):
        session,value=self._clock.capture()
        require(not self._poisoned and session==self._session and type(value) is int and 0<=value<2**63 and
                (self._last is None or value>=self._last),'PACKAGE_CLOCK')
        self._last=value
        return value

    def _publish(self,name,value):
        require(self._root_identity()==self._root_id and not self._poisoned,'PACKAGE_UNAVAILABLE')
        raw=canonical(value)+b'\n'
        require(len(raw)<=MAX_RECEIPT and self._bytes+len(raw)<=MAX_TOTAL,'RECEIPT_BOUND')
        path=os.path.join(self._root,name)
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_BINARY',0),0o600)
        try:
            require(os.write(fd,raw)==len(raw),'SHORT_RECEIPT_WRITE')
            os.fsync(fd)
        finally:os.close(fd)
        if os.name=='posix':
            parent=os.open(self._root,os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0))
            try:os.fsync(parent)
            finally:os.close(parent)
        self._published[name]=sha(raw);self._bytes+=len(raw)

    @contextmanager
    def _operation(self):
        if not self._lock.acquire(False):
            self._poisoned=True
            raise ValueError('PACKAGE_REENTRANT')
        try:
            require(not self._closed and not self._poisoned and self._finished is None,'PACKAGE_UNAVAILABLE')
            self._verify_storage()
            yield
        except BaseException:
            self._poisoned=True
            raise
        finally:self._lock.release()

    def _verify_receipts(self):
        require(self._root_identity()==self._root_id,'ROOT_CHANGED')
        for name,pin in self._published.items():
            require(sha(paired._read(os.path.join(self._root,name),MAX_RECEIPT))==pin,'RECEIPT_CHANGED')

    def _phase_states(self):
        states={}
        for circuit in pilot.CIRCUITS:
            try:
                state=paired.load(os.path.join(self._root,circuit))
                require(state['structural_paired_prefix_valid'] and
                        state['binding_sha256']==self._manifests[circuit]['sha256'],'PHASE_STORAGE_CHANGED')
                states[circuit]=state
            except (OSError,ValueError):states[circuit]=None
        return states

    def _verify_storage(self):
        self._verify_receipts()
        states=self._phase_states()
        require(all(state is not None for state in states.values()),'PHASE_STORAGE_UNCERTAIN')

    def _current(self,circuit):
        require(self._phase<len(pilot.CIRCUITS) and pilot.CIRCUITS[self._phase]==circuit,'EXACT_CURRENT_CIRCUIT')

    def begin_setup(self,circuit):
        with self._operation():
            self._current(circuit)
            require(self._setup_active is None and circuit not in self._setup,'SETUP_ONCE')
            start=self._now()
            self._publish('setup_'+circuit+'_intent.json',dict(circuit=circuit,start_ns=start,
                setup_is_caller_observed_not_authenticated=True))
            self._setup_active=(circuit,start)

    def end_setup(self,circuit,status,cleanup_verified):
        with self._operation():
            self._current(circuit)
            require(self._setup_active is not None and self._setup_active[0]==circuit and
                    status in ('SUCCESS','FAILED','UNKNOWN') and type(cleanup_verified) is bool,'SETUP_SETTLEMENT')
            end=self._now();elapsed=end-self._setup_active[1]
            record=dict(circuit=circuit,status=status,elapsed_ns=elapsed,
                        cleanup_verified_claim=cleanup_verified,
                        overrun=elapsed>self._header['caps']['setup_timeout_ns'])
            self._publish('setup_'+circuit+'_result.json',record)
            self._setup[circuit]=record;self._setup_active=None
            if status=='UNKNOWN' or not cleanup_verified:self._poisoned=True
            elif status!='SUCCESS' or record['overrun']:self._phase+=1
            else:self._ready.add(circuit)
            return copy.deepcopy(record)

    def run(self,circuit,task_uid,backend,output_provider):
        """Run only an unchanged E83 SYNTHETIC callback, not an ATPG adapter."""
        with self._operation():
            self._current(circuit)
            require(circuit in self._ready and self._setup_active is None and self._active is None,'SETUP_OR_ACTIVE')
            require(callable(output_provider),'OUTPUT_PROVIDER_REQUIRED')
            require(getattr(backend,'synthetic_only',None) is True and
                    getattr(backend,'os_authenticated',None) is False and
                    type(getattr(backend,'actual_processes',None)) is int and backend.actual_processes==0,
                    'SYNTHETIC_BACKEND_ONLY')
            binding=self._binders[circuit].bind_next(task_uid)
            slot=binding['slot'];profile=self._header['profiles'][circuit][task_uid]
            prefix=circuit+'_%02d'%slot
            self._publish(prefix+'_intent.json',dict(binding=binding,
                budget_request_field_is_intent_digest=True,execution_ready=False))
            self._active=task_uid
            try:
                state=self._bridges[circuit].run(task_uid,profile,backend,_Clock(self))
            except ValueError as exc:
                if str(exc)!='CENSORED_DECLARED_BUDGET_EXHAUSTED':raise
                # Only the owned live budget ACK can establish a prelaunch
                # denial; matching exception text from a backend is not enough.
                observed=self._bridges[circuit]._budget.snapshot()
                require(observed['fsync_acknowledgments_verified'] and
                        observed['stopped_reason']==str(exc) and observed['active_slot'] is None,
                        'UNVERIFIED_BUDGET_DENIAL')
                record=dict(task_uid=task_uid,circuit=circuit,slot=slot,
                    status='NOT_ATTEMPTED',observed_interval_ns=None,
                    stopped_reason=str(exc),synthetic_only=True,execution_ready=False)
                self._publish(prefix+'_result.json',record)
                self._records[task_uid]=record;self._active=None;self._phase+=1
                return copy.deepcopy(record)
            require(not self._poisoned,'PACKAGE_UNAVAILABLE')
            aid=self._manifests[circuit]['attempts'][slot]['attempt_id']
            attempt=state['lifecycle']['attempts'][aid]
            require(attempt['phase']=='REAPED' and state['paired_task_count']==slot+1,'PAIRED_TERMINAL_REQUIRED')
            self._known[task_uid]=attempt['interval_ns']
            identity=attempt['identity']
            host_boot=(identity['host'],identity['boot_id'])
            key=tuple(identity[k] for k in ('host','boot_id','pid','start_ticks'))
            require((self._host_boot is None or self._host_boot==host_boot) and
                    key not in self._identities,'PACKAGE_IDENTITY_REUSE_OR_COHORT_CHANGE')
            self._host_boot=host_boot;self._identities.add(key)
            status={'success':'SUCCESS','failure':'FAILED','timeout_group':'TIMEOUT'}[profile]
            receipt=None;data=None;trial=None
            if status=='SUCCESS' and not state['phase_failed_or_stopped']:
                receipt,data=output_provider(copy.deepcopy(binding),copy.deepcopy(attempt))
                trial=copy.deepcopy(self._binders[circuit])
                trial.commit_next(binding,receipt,data)
            effective=(status if status!='SUCCESS' or not state['phase_failed_or_stopped'] else 'STOPPED_BUDGET')
            record=dict(task_uid=task_uid,circuit=circuit,slot=slot,status=effective,
                reported_synthetic_profile_status=status,
                binding_sha256=binding['binding_sha256'],attempt=attempt,
                observed_interval_ns=attempt['interval_ns'],output_claim_receipt=receipt,
                output_reference_sha256=(None if data is None else sha(data)),
                stopped_reason=state['budget']['stopped_reason'],
                synthetic_only=True,os_authenticated=False,training_release=False)
            self._publish(prefix+'_result.json',record)
            self._records[task_uid]=record;self._active=None
            if trial is not None:self._binders[circuit]=trial
            if status!='SUCCESS' or state['phase_failed_or_stopped']:self._phase+=1
            elif self._binders[circuit].snapshot()['next_slot']==39:self._phase+=1
            return copy.deepcopy(record)

    def finish(self):
        with self._operation():
            require(self._phase==2 and self._active is None and self._setup_active is None,'PACKAGE_INCOMPLETE')
            end=self._now()
            self._publish('session.json',dict(start_ns=self._start,end_ns=end,
                interval_ns=end-self._start,
                scope='SYNTHETIC_PRE_HEADER_TO_POST_LAST_TASK_RECEIPT_PRE_SESSION_ACK'))
            self._finished=end-self._start
        return self.snapshot()

    def snapshot(self):
        if not self._lock.acquire(False):
            self._poisoned=True
            return dict(schema=SCHEMA,poisoned=True,execution_ready=False,training_release=False)
        try:
            try:
                self._verify_receipts()
            except (OSError,ValueError):self._poisoned=True
            return self._snapshot_locked(self._phase_states())
        finally:self._lock.release()

    def _snapshot_locked(self,states):
        counts={c:(None if state is None else state['budget']['consumed_counts'])
                for c,state in states.items()}
        counts_unknown=any(value is None for value in counts.values())
        if counts_unknown:self._poisoned=True
        task_status={n['task_uid']:(self._records[n['task_uid']]['status']
                    if n['task_uid'] in self._records else
                    'UNRESOLVED' if n['task_uid']==self._active else 'NOT_ATTEMPTED')
                    for p in self._header['plan']['phases'] for n in p['tasks']}
        actions={}
        for phase in self._header['plan']['phases']:
            for action in phase['requested_roster']:
                states=[task_status[n['task_uid']] for n in phase['tasks'] if n['action_uid']==action['action_uid']]
                status=('SUCCESS_SYNTHETIC_ONLY' if all(s=='SUCCESS' for s in states) else
                        'UNKNOWN' if 'UNRESOLVED' in states else
                        'TIMEOUT' if 'TIMEOUT' in states else
                        'FAILED' if any(s in ('FAILED','STOPPED_BUDGET') for s in states) else
                        'NOT_ATTEMPTED' if all(s=='NOT_ATTEMPTED' for s in states) else 'PARTIAL')
                actions[action['action_uid']]=status
        return dict(schema=SCHEMA,synthetic_only=True,poisoned=self._poisoned,
            task_status=task_status,action_status=actions,consumed_counts=counts,counts_unknown=counts_unknown,
            observed_task_intervals_ns_sum=sum(self._known.values()),
            setup=copy.deepcopy(self._setup),recorded_synthetic_session_ns=(None if self._poisoned else self._finished),
            full_cost_qualified=False,actual_atpg_runtime_ns=None,
            budget_projection_is_not_actual_request_identity=True,
            real_processes_launched_by_module=0,callback_process_counts_unverified=True,
            execution_ready=False,training_release=False,
            os_authenticated=False,power_loss_durability_proven=False,
            namespace_global_quota_proven=False,writer_resume_supported=False)

    def close(self):
        if not self._lock.acquire(False):
            self._poisoned=True
            raise ValueError('PACKAGE_REENTRANT')
        try:
            errors=[]
            for writer in self._bridges.values():
                try:writer.close()
                except BaseException as exc:errors.append(exc)
            self._closed=True
            if errors:self._poisoned=True;raise errors[0]
        finally:self._lock.release()

    def __enter__(self):return self
    def __exit__(self,*args):self.close()
