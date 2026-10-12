"""Pure synthetic verifier-parent tests: no ML, package/model/remote access."""
from contextlib import nullcontext
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from scripts import run_v5_existing_train_verify_parent as parent


def policy():
    return dict(max_concurrent_workers=1,combined_rss_cap_bytes=1073741824,
        child_address_space_cap_bytes=8589934592,reserve_min_bytes=4294967296,
        reserve_fraction=.1,poll_seconds=.25,timeout_seconds=1800,retries=0,
        limitation='RSS is sampled; brief overshoot can occur. RLIMIT_AS caps address space, not RSS.')


def check_available(total,available):
    reserve=max(4294967296,int(total*.1+.999999))
    if type(total) is not int or type(available) is not int or available<=reserve:raise RuntimeError('pressure')
    return reserve


def expected():
    metrics=dict(hit_at_10=1,hit_found=True,attempt_count=2,charged_runtime_s=1.5,
        best_cycle_regret_at_10=0.,freeze_sha256='f'*64)
    worker=dict(boundary_receipt=dict(freeze_sha256='f'*64,metrics=metrics))
    return dict(worker_receipt_raw=parent.canonical(worker),file_sha256={
        'model.pt':'1'*64,'freeze.json':'2'*64,'fitting.jsonl':'3'*64,'worker_receipt.json':'4'*64})


def result(family,seed,plan_sha='a'*64):
    e=expected();b=parent.decode(e['worker_receipt_raw'])['boundary_receipt']
    return dict(schema='v5-existing-train-numerical-verification-v1',
        status='PASS_EXISTING_TRAIN_PREDICTIONS_AND_METRICS_EXACT',family=family,seed=seed,
        training_root=parent.TRAIN_ROOT,verification_root=parent.ROOT,artifact_receipt_sha256=parent.ARTIFACT_SHA,
        file_sha256=e['file_sha256'],freeze_sha256=b['freeze_sha256'],held_candidate_count=100,
        weights_only=True,state_tensor_count=6,predictions_exact=True,freeze_payload_order_digest_exact=True,
        original_metrics_exact=True,metrics=b['metrics'],checkpoint_loads=1,optimizer_invocations=0,
        train_fit_invocations=0,automatic_retries=0,parent_guard_enforcement_proven_by_this_child=False,
        controlled_runtime_context_completed=True,verification_jit_source_sha256=parent.JIT_SHA,
        authorization_sha256=parent.AUTH_SHA,plan_sha256=plan_sha,legacy_trust_sha256=parent.LEGACY_TRUST_SHA,
        old_artifact_hashes_unchanged=True,postchecked_count=4)


def fresh(bundle,now=None):
    now=now or datetime.now(timezone.utc)
    return dict(schema='v5-existing-train-readonly-fresh-gate-v1',
        status='PASS_READONLY_EXISTING_TRAIN_REPLAY_FRESH_GATE',verification_root=parent.ROOT,
        plan_sha256=bundle['plan_sha'],source_binding_sha256=bundle['digest'],
        authorization_sha256=parent.AUTH_SHA,artifact_receipt_sha256=parent.ARTIFACT_SHA,
        legacy_trust_sha256=parent.LEGACY_TRUST_SHA,fresh_utc=now.strftime('%Y-%m-%dT%H:%M:%SZ'),
        source_count_verified=48,model_deserializations=0,training_invocations=0,once_absent=True,
        absent_output_count=40,global_lock_acquired_and_released=True,memory_policy=policy(),
        effective_total_bytes=16*1024**3,initial_available_bytes=12*1024**3,reserve_bytes=4*1024**3,
        runtime_metadata_status='PASS_FIXED_RUNTIME_METADATA_ONLY',runtime_distribution_count=31)


def bundle():
    plan=dict(source_sha256={p:'c'*64 for p in parent.NEW_FILES})
    b=dict(plan=plan,plan_sha='a'*64,review_sha='b'*64,digest='d'*64,
        new={p:b'fake-source' for p in parent.NEW_FILES},expected={t:expected() for t in parent.tasks()})
    b['fresh']=fresh(b)
    return b


class ParentTests(unittest.TestCase):
    def harness(self,*,fail_index=None,bad_child=None,guard_validation_error=False,source_drift=False,once_exists=False,startup_failure=False):
        b=bundle();calls=[];writes=[];checks=[];events=[];reads=[]
        receipt=dict(status='PASS_BOUNDED_WORKER',memory_policy=policy(),
            initial_available_bytes=12*1024**3,effective_total_bytes=16*1024**3,reserve_bytes=4*1024**3,
            sample_count=2,peak_group_rss_bytes=100,peak_combined_rss_bytes=200,exit_code=0,
            process_group=123,elapsed_seconds=.5)
        def run_bounded(argv,log,env):
            task=parent.tasks()[len(calls)];calls.append((task,argv,log,env));events.append('guard')
            if fail_index==len(calls)-1:raise RuntimeError('synthetic child failure')
            return deepcopy(receipt)
        guard=SimpleNamespace(policy=policy,check_available=check_available,
            available_memory=lambda:(16*1024**3,12*1024**3),run_bounded=run_bounded)
        def validate(returned,reread):
            events.append('guard-validation')
            if guard_validation_error:raise ValueError('synthetic invalid guard')
            if returned!=reread:raise AssertionError('mismatch')
        validator=SimpleNamespace(validate_parent_guard_receipt=validate)
        def read(path,cap):
            path=str(path);reads.append(path)
            if path.endswith('.memory.json'):return parent.canonical(receipt)
            task=next(t for t in parent.tasks() if parent.log_path(*t)==path)
            value=result(*task)
            if bad_child:bad_child(value)
            events.append('child-read')
            return parent.canonical(value)
        def write(path,payload):writes.append((str(path),deepcopy(payload)));events.append('write')
        def pinned(path,digest,cap):
            return b'changed' if source_drift else b['new'][str(path)[len(parent.ROOT)+1:]]
        def absent(path):
            checks.append(str(path))
            if once_exists and str(path)==parent.ONCE:raise ValueError('synthetic existing verification once')
        info=SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=1000)
        with patch.object(parent,'runtime'),patch.object(parent,'load',return_value=b),\
             patch.object(parent,'authenticated_core',return_value=nullcontext((guard,validator))),\
             patch.object(parent,'worker_lock',return_value=nullcontext()),\
             patch.object(parent.Path,'lstat',return_value=info),patch.object(parent.os,'getuid',return_value=1000,create=True),\
             patch.object(parent,'absent',side_effect=absent),\
             patch.object(parent,'pinned',side_effect=pinned),patch.object(parent,'write_once',side_effect=write),\
             patch.object(parent,'private_jit_roots',side_effect=RuntimeError('synthetic startup failure') if startup_failure else None),\
             patch.object(parent,'read',side_effect=read):
            if source_drift or once_exists:
                with self.assertRaises(ValueError):
                    parent.run(parent.ROOT,trusted_plan_sha256='a'*64,trusted_review_sha256='b'*64,
                        trusted_authorization_sha256=parent.AUTH_SHA)
                final=None
            else:
                final=parent.run(parent.ROOT,trusted_plan_sha256='a'*64,trusted_review_sha256='b'*64,
                    trusted_authorization_sha256=parent.AUTH_SHA)
        return final,calls,writes,checks,events,reads

    def test_all18_exact_order_resource_flags_and_new_only_once(self):
        final,calls,writes,checks,events,reads=self.harness()
        self.assertEqual(final['status'],'PASS_EXISTING_18_TRAIN_NUMERICAL_VERIFICATION')
        self.assertEqual(final['completed_count'],18);self.assertEqual(final['remaining_count'],0)
        self.assertEqual([c[0] for c in calls],list(parent.tasks()))
        self.assertEqual(writes[0][0],parent.ONCE)
        self.assertTrue(all(p.startswith(parent.ROOT+'/') for p,_ in writes))
        self.assertTrue(all(p.startswith(parent.ROOT+'/') for p in checks))
        self.assertFalse(any('.authorization_' in p for p in checks))
        self.assertEqual(events[:3],['write','write','guard'])
        for (family,seed),argv,log,env in calls:
            self.assertEqual(argv[:4],[parent.INTERPRETER,'-I','-S','-B'])
            self.assertIn(repr(list(parent.SEARCH_PATHS)),argv[5])
            self.assertIn('__file__='+repr(parent.ROOT+'/'+parent.CHILD),argv[5])
            self.assertEqual(argv[argv.index('--trusted-authorization-sha256')+1],parent.AUTH_SHA)
            self.assertEqual(env['TMPDIR'],parent.ROOT+'/jit_tmp/'+family+'_'+str(seed))
            self.assertNotIn('TMP',env);self.assertNotIn('TEMP',env);self.assertNotIn('PYTHONPATH',env)
            self.assertEqual(env['CUDA_VISIBLE_DEVICES'],'')
        self.assertEqual(final['train_fit_invocations'],0);self.assertEqual(final['optimizer_invocations'],0)
        self.assertLess(len(parent.canonical(final)),parent.JSON_CAP)

    def test_first_failure_stops_zero_retry(self):
        for index in (0,2,17):
            with self.subTest(index=index):
                final,calls,_,_,_,_=self.harness(fail_index=index)
                self.assertEqual(len(calls),index+1);self.assertEqual(final['completed_count'],index)
                self.assertEqual(final['failed_index'],index);self.assertEqual(final['remaining_count'],17-index)
                self.assertEqual(final['automatic_retries'],0);self.assertEqual(final['status'],'STOPPED_NO_RETRY')

    def test_startup_failure_reports_zero_attempts_and_all18_remaining(self):
        final,calls,_,_,_,_=self.harness(startup_failure=True)
        self.assertEqual(calls,[])
        self.assertEqual(final['child_invocations_attempted'],0)
        self.assertEqual(final['completed_count'],0)
        self.assertEqual(final['remaining_count'],18)
        self.assertEqual(final['status'],'STOPPED_NO_RETRY')

    def test_guard_failure_is_before_child_stdout_acceptance(self):
        final,calls,_,_,events,reads=self.harness(guard_validation_error=True)
        self.assertEqual(final['completed_count'],0);self.assertEqual(len(calls),1)
        self.assertNotIn('child-read',events);self.assertTrue(all(p.endswith('.memory.json') for p in reads))

    def test_child_exact_bindings_and_no_fit_fail_closed(self):
        changes=[
            lambda v:v.update(family='wrong'),lambda v:v.update(seed=True),
            lambda v:v.update(predictions_exact=False),lambda v:v.update(checkpoint_loads=2),
            lambda v:v.update(train_fit_invocations=1),lambda v:v.update(controlled_runtime_context_completed=False),
            lambda v:v.update(plan_sha256='0'*64),lambda v:v['metrics'].update(hit_at_10=0),
            lambda v:v.update(unapproved_field=True)]
        for change in changes:
            with self.subTest(change=change):
                final,calls,_,_,_,_=self.harness(bad_child=change)
                self.assertEqual(final['completed_count'],0);self.assertEqual(len(calls),1)

    def test_source_drift_before_once_and_child(self):
        _,calls,writes,_,_,_=self.harness(source_drift=True)
        self.assertEqual(calls,[]);self.assertEqual(writes,[])

    def test_consumed_verification_once_never_reused(self):
        _,calls,writes,checks,_,_=self.harness(once_exists=True)
        self.assertEqual(calls,[]);self.assertEqual(writes,[])
        self.assertEqual(checks,[parent.ONCE])

    def test_core_byte_drift_rejected_before_fence_compilation(self):
        old={p:b'x' for p in parent.CORE_FILES|{parent.FENCE}}
        pins={p:parent.sha(raw) for p,raw in old.items()}
        b=dict(old=old,legacy=dict(source_sha256=pins))
        with patch.object(parent,'external') as compile_:
            with self.assertRaisesRegex(ValueError,'CORE_BEFORE_COMPILE'):
                with parent.authenticated_core(b):self.fail('entered')
            compile_.assert_not_called()

    def test_wrong_roots_or_missing_external_pins_zero_io(self):
        with patch.object(parent,'read') as read,patch.object(parent.Path,'lstat') as stat_,\
             patch.object(parent,'runtime') as runtime:
            for root in ('/ssd/cjc/multimode_ate_gnn_v1',parent.TRAIN_ROOT,parent.ROOT+'_bad'):
                with self.assertRaises(ValueError):
                    parent.run(root,trusted_plan_sha256='a'*64,trusted_review_sha256='b'*64,
                        trusted_authorization_sha256=parent.AUTH_SHA)
            for args in [(None,'b'*64,parent.AUTH_SHA),('a'*64,None,parent.AUTH_SHA),
                         ('a'*64,'b'*64,'0'*64)]:
                with self.assertRaises(ValueError):
                    parent.load(parent.ROOT,*args)
            read.assert_not_called();stat_.assert_not_called();runtime.assert_not_called()

    def test_authorization_and_plan_strict_external_bytes(self):
        raw=parent.canonical(parent.EXPECTED_AUTH)
        # Real contract bytes include whitespace; only independently pinned raw can pass.
        with self.assertRaises(ValueError):parent.validate_authorization(raw,parent.AUTH_SHA)
        repo=Path(__file__).resolve().parents[1]
        real=(repo/'contracts/ranking_v5_existing_train_replay_authorization_20261012_r1.json').read_bytes()
        self.assertEqual(parent.validate_authorization(real,parent.AUTH_SHA),parent.EXPECTED_AUTH)
        p=dict(schema='v5-existing-train-verify-plan-v1',verification_root=parent.ROOT,
            artifact_root=parent.TRAIN_ROOT,package_root=parent.PACKAGE_ROOT,authorization_sha256=parent.AUTH_SHA,
            artifact_receipt_sha256=parent.ARTIFACT_SHA,legacy_trust_sha256=parent.LEGACY_TRUST_SHA,
            families=list(parent.FAMILIES),seeds=list(parent.SEEDS),
            source_sha256={n:parent.JIT_SHA if n==parent.JIT else 'a'*64 for n in parent.NEW_FILES})
        raw=parent.canonical(p);self.assertEqual(parent.validate_plan(raw,parent.sha(raw)),p)
        for key,bad in [('families',list(reversed(parent.FAMILIES))),('artifact_root',parent.ROOT),('seeds',[True])]:
            value=deepcopy(p);value[key]=bad;raw=parent.canonical(value)
            with self.assertRaises(ValueError):parent.validate_plan(raw,parent.sha(raw))
        p['source_sha256']['extra.py']='a'*64;raw=parent.canonical(p)
        with self.assertRaises(ValueError):parent.validate_plan(raw,parent.sha(raw))

    def test_fresh_ttl_types_and_fixed_scope(self):
        b=bundle();guard=SimpleNamespace(policy=policy,check_available=check_available)
        now=datetime(2026,10,12,0,0,0,tzinfo=timezone.utc)
        parent.validate_fresh(fresh(b,now-timedelta(seconds=600)),b,guard,now)
        for bad in [fresh(b,now-timedelta(seconds=601)),fresh(b,now+timedelta(seconds=1))]:
            with self.assertRaises(ValueError):parent.validate_fresh(bad,b,guard,now)
        for k,v in [('once_absent',1),('model_deserializations',True),('absent_output_count',75),
                    ('source_count_verified',45),('initial_available_bytes',True)]:
            bad=fresh(b,now);bad[k]=v
            with self.assertRaises(ValueError):parent.validate_fresh(bad,b,guard,now)

    def test_load_source_sha_failure_before_any_compile(self):
        b=bundle()
        p=dict(schema='v5-existing-train-verify-plan-v1',verification_root=parent.ROOT,
            artifact_root=parent.TRAIN_ROOT,package_root=parent.PACKAGE_ROOT,authorization_sha256=parent.AUTH_SHA,
            artifact_receipt_sha256=parent.ARTIFACT_SHA,legacy_trust_sha256=parent.LEGACY_TRUST_SHA,
            families=list(parent.FAMILIES),seeds=list(parent.SEEDS),
            source_sha256={n:parent.JIT_SHA if n==parent.JIT else 'a'*64 for n in parent.NEW_FILES})
        raw=parent.canonical(p);plan_sha=parent.sha(raw)
        review=dict(schema='v5-existing-train-verify-independent-review-v1',
            status='PASS_EXISTING_TRAIN_VERIFY_IMPLEMENTATION_AND_GATES',plan_sha256=plan_sha,
            source_binding_sha256=parent.sha(parent.canonical(p['source_sha256'])),
            authorization_sha256=parent.AUTH_SHA,artifact_receipt_sha256=parent.ARTIFACT_SHA,
            full_regression_sha256='f'*64,linux_unit_sha256='e'*64,fresh_gate_receipt_sha256='d'*64)
        def pinned(path,digest,cap):
            name=str(path).split(parent.ROOT+'/',1)[1]
            if name=='authorization.json':return parent.canonical(parent.EXPECTED_AUTH)
            if name=='plan.json':return raw
            if name=='review.json':return parent.canonical(review)
            if name=='fresh_gate.json':return parent.canonical(b['fresh'])
            if name=='legacy_trust.json':
                return parent.canonical(dict(source_sha256={n:parent.FENCE_SHA if n==parent.FENCE
                    else parent.GUARD_SHA if n==parent.GUARD else 'a'*64 for n in parent.LEGACY_FILES},
                    evidence_sha256={str(i):'a'*64 for i in range(15)}))
            raise ValueError('synthetic pinned source mismatch')
        with patch.object(parent,'pinned',side_effect=pinned),\
             patch.object(parent,'validate_authorization',return_value=parent.EXPECTED_AUTH),\
             patch.object(parent,'external') as compile_:
            with self.assertRaises(ValueError):parent.load(parent.ROOT,plan_sha,'b'*64,parent.AUTH_SHA)
            compile_.assert_not_called()

    @unittest.skipIf(os.name=='nt','POSIX mode assertion')
    def test_once_exclusive_private_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temp,patch.object(parent,'ROOT',Path(temp).as_posix()):
            path=Path(temp)/'verification.once.json'
            old=os.umask(0)
            try:parent.write_once(path,{'only_verification':True})
            finally:os.umask(old)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
            original=path.read_bytes()
            with self.assertRaises(FileExistsError):parent.write_once(path,{'overwrite':True})
            self.assertEqual(path.read_bytes(),original)

    @unittest.skipIf(os.name=='nt','POSIX mode assertion')
    def test_jit_roots_private_new_only_and_never_reuse(self):
        with tempfile.TemporaryDirectory() as temp,patch.object(parent,'ROOT',Path(temp).as_posix()):
            parent.private_jit_roots()
            base=Path(temp)/'jit_tmp'
            self.assertEqual(stat.S_IMODE(base.stat().st_mode),0o700)
            for family,seed in parent.tasks():
                path=base/(family+'_'+str(seed))
                self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o700)
            with self.assertRaises(FileExistsError):parent.private_jit_roots()

    def test_existing_lock_open_readonly_never_create(self):
        fake=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_nlink=1,st_size=0,st_uid=1000,st_dev=1,st_ino=2)
        parent_info=SimpleNamespace(st_mode=stat.S_IFDIR|0o700)
        fcntl=SimpleNamespace(LOCK_EX=2,LOCK_NB=4,LOCK_UN=8,flock=Mock())
        def lstat(path):
            return fake if path.as_posix()==parent.GLOBAL_LOCK else parent_info
        with patch.dict('sys.modules',{'fcntl':fcntl}),\
             patch.object(parent.Path,'lstat',lstat),patch.object(parent.os,'getuid',return_value=1000,create=True),\
             patch.object(parent.os,'open',return_value=123) as opened,patch.object(parent.os,'fstat',return_value=fake),\
             patch.object(parent.os,'close') as close:
            with parent.worker_lock():pass
        self.assertEqual(opened.call_args.args[1]&os.O_CREAT,0)
        self.assertEqual(opened.call_args.args[1]&os.O_WRONLY,0)
        self.assertEqual(opened.call_args.args[1]&os.O_RDWR,0)
        close.assert_called_once_with(123)
        self.assertEqual(fcntl.flock.call_count,2)


if __name__=='__main__':unittest.main()
