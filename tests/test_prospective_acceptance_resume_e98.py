"""Queue-safe E98 resume unit tests, all scheduler/filesystem activity mocked."""
import ast
from contextlib import ExitStack
import importlib.util
import json
from pathlib import Path
import stat
import sys
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / 'scripts/prepare_acceptance_resume_e98.py'
SPEC = importlib.util.spec_from_file_location('resume_e98_test', str(PATH))
m = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(m)
JOB = 123456


def job_text(job_id=JOB):
    return ('Job <%s>, Job Name <gnn_e98_acceptance_r1>, Status <PSUSP>, Queue <normal>, '
        'Command <%sblaunch /usr/bin/python3 -I -S -B %s/scripts/run_acceptance_job_e98.py>\n'
        'Submitted with hold, Specified CWD <%s>, Not Re-runnable, Specified Hosts <bupt-vncs2>;\n'
        ' RUNLIMIT\n 45.0 min of bupt-vncs2\n MEMLIMIT\n 512 M \n' %
        (job_id, m.base.BINDIR, m.ROOT, m.ROOT)).encode('ascii')


def observation():
    registration = dict(job_id=JOB, intent_sha256='a'*64, result_sha256='b'*64,
        submission_stdout_sha256='c'*64, requested_workers=1, requested_nonarray=True,
        worker_LSB_JOBINDEX_check_pending=True)
    return dict(schema='e98-pre-resume-observation-v1', job_id=JOB, observed_at_epoch=1000,
        bjobs_stdout_sha256=m.sha(job_text()), analysis=m.analyze_bjobs(job_text(), JOB),
        registration=registration, registration_evidence_sha256=m.sha(m.canonical(registration)),
        manifest_sha256=m.base.MANIFEST_SHA256, authorization_sha256=m.base.AUTH_SHA256,
        recipe_sha256=m.RECIPE_SHA256, config_sha256=m.base.CONFIG_SHA256)


def reviews(obs):
    output = []
    for stage in ('registration', 'pre_resume'):
        output.append(m.canonical(dict(schema='e98-independent-review-v1', stage=stage,
            job_id=JOB, passed=True, independent=True, reviewer='external-reviewer',
            reviewed_at_epoch=100 if stage == 'registration' else 1010,
            authorization_sha256=m.base.AUTH_SHA256, code_manifest_sha256=m.base.MANIFEST_SHA256,
            recipe_sha256=m.RECIPE_SHA256,
            registration_evidence_sha256=obs['registration_evidence_sha256'],
            observation_sha256='e'*64 if stage == 'registration' else m.sha(m.canonical(obs)))))
    return output[0], output[1], dict(registration=m.sha(output[0]), pre_resume=m.sha(output[1]))


def registration_files(job_id=JOB, receipt_id=None):
    result = dict(schema='e98-held-registration-result-v1', job_id=job_id, jobs_submitted=1,
        submission_attempted=True, submission_status='CLIENT_COMPLETE', submission_returncode=0,
        status='REGISTERED_HELD_REVIEW_PENDING', manifest_sha256=m.base.MANIFEST_SHA256)
    intent = dict(schema='e98-registration-intent-v1', argv=m.base._argv(),
        manifest_sha256=m.base.MANIFEST_SHA256, fresh_config_sha256=m.base.CONFIG_SHA256,
        only_attempt_consumed_before_spawn=True, automatic_retries=0)
    receipt = ('Job <%s> is submitted to queue <normal>.\n' %
               (job_id if receipt_id is None else receipt_id)).encode('ascii')
    return [(m.canonical(result), None), (m.canonical(intent), None), (receipt, None)]


class ResumeTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(m.base, 'MANIFEST_SHA256', 'a'*64)
        patcher.start(); self.addCleanup(patcher.stop)

    def test_job_comes_from_fixed_registered_result_and_strict_receipt(self):
        with mock.patch.object(m.base, '_read', side_effect=registration_files()) as read:
            evidence = m._registration_evidence()
        self.assertEqual(evidence['job_id'], JOB)
        self.assertEqual(read.call_args_list[0], mock.call(m.ROOT+'/registration/result.json', 16384))
        self.assertEqual(evidence['requested_workers'], 1)
        self.assertTrue(evidence['worker_LSB_JOBINDEX_check_pending'])

    def test_old_boolean_invalid_or_mismatched_job_id_rejected(self):
        for job_id in (394230, True, 0, -1):
            with mock.patch.object(m.base, '_read', side_effect=registration_files(job_id)):
                with self.assertRaises(m.ResumeError):
                    m._registration_evidence()
        with mock.patch.object(m.base, '_read', side_effect=registration_files(receipt_id=JOB+1)):
            with self.assertRaisesRegex(m.ResumeError, 'STRICT_REGISTRATION_JOB_ID'):
                m._registration_evidence()

    def test_current_observation_only_one_exact_query_no_mutation(self):
        with mock.patch.object(m, '_host'), mock.patch.object(m.base, '_verify') as verify, \
                mock.patch.object(m.base, '_read', side_effect=registration_files()), \
                mock.patch.object(m.base, '_client', return_value=dict(status='CLIENT_COMPLETE',
                    returncode=0, stdout=job_text(), stderr=b'')) as client, \
                mock.patch.object(m.base, '_persist') as persist:
            obs = m.observe()
        verify.assert_called_once(); persist.assert_not_called()
        client.assert_called_once_with([m.base.BINDIR+'bjobs', '-l', str(JOB)])
        self.assertEqual(obs['registration_evidence_sha256'], m.sha(m.canonical(obs['registration'])))
        self.assertFalse(obs['analysis']['actual_worker_count_verified'])

    def test_missing_scheduler_fields_are_gaps_not_defaults(self):
        for old, new in ((b'PSUSP', b'PEND'), (b'45.0', b'60.0'), (b'512 M', b'1024 M'),
                          (b'bupt-vncs2', b'other'), (b'Not Re-runnable', b'')):
            self.assertTrue(m.analyze_bjobs(job_text().replace(old, new), JOB)['gaps'])

    def test_external_registration_old_snapshot_and_fresh_pre_resume(self):
        obs=observation(); reg, pre, pins=reviews(obs)
        with mock.patch.object(m.time, 'time', return_value=1020):
            self.assertEqual(m.validate_reviews(obs, reg, pre, pins), m.sha(m.canonical(obs)))

    def test_missing_wrong_or_selfasserted_review_rejected(self):
        obs=observation(); reg, pre, pins=reviews(obs)
        with mock.patch.object(m.time, 'time', return_value=1020):
            with self.assertRaises(m.ResumeError):
                m.validate_reviews(obs, reg, pre, {})
            with self.assertRaises(m.ResumeError):
                m.validate_reviews(obs, reg+b' ', pre, pins)
            changed=json.loads(pre.decode('ascii')); changed['independent']=False
            pre=m.canonical(changed); pins['pre_resume']=m.sha(pre)
            with self.assertRaises(m.ResumeError):
                m.validate_reviews(obs, reg, pre, pins)

    def test_stale_review_or_changed_evidence_rejected(self):
        obs=observation(); reg, pre, pins=reviews(obs)
        with mock.patch.object(m.time, 'time', return_value=1311):
            with self.assertRaises(m.ResumeError):
                m.validate_reviews(obs, reg, pre, pins)
        obs['registration']['requested_workers']=2
        with mock.patch.object(m.time, 'time', return_value=1020):
            with self.assertRaises(m.ResumeError):
                m.validate_reviews(obs, reg, pre, pins)

    def run_resume(self, changed=False, collision=False, unknown=False):
        obs=observation(); reg, pre, pins=reviews(obs); events=[]
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(m.time, 'time', return_value=1020))
            for name in ('_host', '_verify_resume_binary'):
                stack.enter_context(mock.patch.object(m, name))
            stack.enter_context(mock.patch.object(m.base, '_verify'))
            stack.enter_context(mock.patch.object(m, '_registration_evidence', return_value=obs['registration']))
            stack.enter_context(mock.patch.object(m, '_query', return_value=b'changed' if changed else job_text()))
            stack.enter_context(mock.patch.object(m.base, '_directory', return_value=10))
            stack.enter_context(mock.patch.object(m.os, 'O_DIRECTORY', 1, create=True))
            stack.enter_context(mock.patch.object(m.os, 'O_NOFOLLOW', 2, create=True))
            stack.enter_context(mock.patch.object(m.os, 'mkdir', side_effect=FileExistsError() if collision else None))
            stack.enter_context(mock.patch.object(m.os, 'fsync'))
            stack.enter_context(mock.patch.object(m.os, 'open', return_value=11))
            stack.enter_context(mock.patch.object(m.os, 'fstat', return_value=types.SimpleNamespace(
                st_mode=stat.S_IFDIR|0o700, st_uid=1000)))
            stack.enter_context(mock.patch.object(m.os, 'getuid', return_value=1000, create=True))
            stack.enter_context(mock.patch.object(m.os, 'close'))
            stack.enter_context(mock.patch.object(m.base, '_persist', side_effect=lambda fd,name,raw:
                events.append((name,raw))))
            client=stack.enter_context(mock.patch.object(m.base, '_client', return_value=dict(
                status='CLIENT_FAILURE_UNKNOWN' if unknown else 'CLIENT_COMPLETE',
                returncode=None if unknown else 0,
                stdout=b'partial' if unknown else ('Job <%s> is being resumed\n'%JOB).encode('ascii'), stderr=b'')))
            if changed or collision:
                with self.assertRaises((m.ResumeError, FileExistsError)):
                    m.resume_once(obs, reg, pre, pins)
                client.assert_not_called(); return
            result=m.resume_once(obs, reg, pre, pins)
            client.assert_called_once_with([m.base.BINDIR+'bresume', str(JOB)])
        return result, events, reg, pre

    def test_exact_once_resume_after_intent_and_four_root_artifacts(self):
        result,events,_,_=self.run_resume()
        self.assertTrue(result['resume_acknowledged'])
        self.assertEqual([name for name,_ in events[:5]], ['intent.json', 'e98_registration_review.json',
            'e98_pre_resume_review.json','e98_resume_intent.json','e98_resume_permit.json'])

    def test_entry_accepts_exact_chain_and_lease_is_not_reset(self):
        _,events,reg,pre=self.run_resume(); artifacts=dict(events)
        permit=json.loads(artifacts['e98_resume_permit.json'].decode('ascii'))
        intent=artifacts['e98_resume_intent.json']
        spec=importlib.util.spec_from_file_location('e98_entry_chain_test', str(ROOT/'scripts/run_acceptance_job_e98.py'))
        entry=importlib.util.module_from_spec(spec); spec.loader.exec_module(entry)
        entry.validate_review_chain(permit,reg,pre,intent)
        self.assertEqual(permit['issued_at_epoch'],1020)
        self.assertEqual(permit['queue_start_lease_seconds'],86400)

    def test_unknown_resume_is_consumed_not_retried(self):
        result,events,_,_=self.run_resume(unknown=True)
        self.assertEqual(result['status'],'UNKNOWN_RESUME_CONSUMED_NO_RETRY')
        self.assertEqual(events[-1][0],'result.json')

    def test_changed_latest_job_or_collision_never_resumes(self):
        self.run_resume(changed=True); self.run_resume(collision=True)

    def test_exact_observed_bresume_metadata_four_links(self):
        info=dict(st_mode=stat.S_IFREG|0o755,st_nlink=4,st_dev=43,st_ino=1049102,
            st_size=3021440,st_mtime_ns=1404504463000000000,st_uid=0,st_gid=10007)
        for links in (4,1,3,5):
            info['st_nlink']=links
            with mock.patch.object(m.base,'_directory',return_value=10), \
                    mock.patch.object(m.os,'stat',return_value=types.SimpleNamespace(**info)), \
                    mock.patch.object(m.os,'close'):
                if links==4: m._verify_resume_binary()
                else:
                    with self.assertRaises(m.ResumeError): m._verify_resume_binary()

    def test_python36_no_automatic_entry(self):
        kwargs={'feature_version':(3,6)} if sys.version_info>=(3,8) else {}
        source=PATH.read_text(); ast.parse(source,**kwargs)
        self.assertNotIn('__main__',source)


if __name__=='__main__':
    unittest.main()
