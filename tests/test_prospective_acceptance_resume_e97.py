"""Mock-only resume core; no scheduler, remote execution, or job changes."""
import ast
import importlib.util
import json
from pathlib import Path
import stat
import sys
import types
import unittest
from unittest import mock
from contextlib import ExitStack

PATH = Path(__file__).resolve().parents[1] / 'scripts/prepare_acceptance_resume_e97.py'
SPEC = importlib.util.spec_from_file_location('resume_e97_test', str(PATH))
m = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(m)


def query_bytes():
    return ('Job <394230>, Job Name <gnn_e97_acceptance_r1>, Status <PSUSP>, Queue <normal>, '
        'Command <' + m.base.BINDIR + 'blaunch /usr/bin/python3 -I -S -B ' + m.ROOT +
        '/scripts/run_acceptance_job_e97.py>\nSubmitted with hold, Specified CWD <' + m.ROOT +
        '>, Not Re-runnable, Specified Hosts <bupt-vncs2>;\n RUNLIMIT\n 45.0 min of bupt-vncs2\n'
        ' MEMLIMIT\n 512 M \n').encode('ascii')


def observation():
    raw = query_bytes()
    return dict(schema='e97-pre-resume-observation-v1', job_id=394230, observed_at_epoch=1000,
        bjobs_stdout_sha256=m.sha(raw), analysis=m.analyze_bjobs(raw), registration={'pinned': True},
        manifest_sha256=m.base.MANIFEST_SHA256, authorization_sha256=m.base.AUTH_SHA256,
        config_sha256=m.base.CONFIG_SHA256, resume_calls=0, reviews_granted=False)


def reviews(obs):
    values = {}
    for stage in ('registration', 'pre_resume'):
        values[stage] = m.canonical(dict(schema='e97-independent-resume-review-v1', stage=stage,
            job_id=394230, passed=True, independent=True, reviewer='external-reviewer',
            issued_at_epoch=1010, observation_sha256=m.sha(m.canonical(obs)),
            composite_requested_worker_nonarray_accepted=True))
    return values, {key: m.sha(raw) for key, raw in values.items()}


class ResumeTests(unittest.TestCase):
    def test_observed_resume_binary_exact_metadata_and_four_links(self):
        # Read-only observation: v6_e97_resume_binary_observation_20261024_r1.
        observed = dict(st_mode=stat.S_IFREG | 0o755, st_nlink=4, st_dev=43,
            st_ino=1049102, st_size=3021440, st_mtime_ns=1404504463000000000,
            st_uid=0, st_gid=10007)
        variants = [({}, True)]
        variants.extend(({'st_nlink': value}, False) for value in (1, 3, 5))
        variants.extend((change, False) for change in (
            {'st_dev': 44}, {'st_ino': 1049103}, {'st_size': 3021441},
            {'st_mtime_ns': 1404504463000000001}, {'st_uid': 1},
            {'st_gid': 10008}, {'st_mode': stat.S_IFREG | 0o775},
            {'st_mode': stat.S_IFDIR | 0o755}, {'st_mode': stat.S_IFLNK | 0o755}))
        for changes, accepted in variants:
            fixture = dict(observed); fixture.update(changes)
            with mock.patch.object(m.base, '_directory', return_value=10), \
                    mock.patch.object(m.os, 'stat', return_value=types.SimpleNamespace(**fixture)), \
                    mock.patch.object(m.os, 'close'):
                if accepted:
                    m._verify_resume_binary()
                else:
                    with self.assertRaisesRegex(m.ResumeError, 'RESUME_BINARY_PIN'):
                        m._verify_resume_binary()

    def test_explicit_state_and_layered_worker_evidence(self):
        parsed = m.analyze_bjobs(query_bytes())
        self.assertEqual(parsed['gaps'], [])
        self.assertFalse(parsed['requested_worker_count_directly_observed'])
        self.assertFalse(parsed['nonarray_directly_observed'])
        self.assertFalse(parsed['actual_job_memory_proof'])

    def test_changed_missing_or_ambiguous_fields_report_gaps(self):
        for old, new in ((b'PSUSP', b'RUN'), (b'45.0', b'60.0'), (b'bupt-vncs2', b'other'),
                          (b'Not Re-runnable', b''), (b'394230', b'394230[1]')):
            self.assertTrue(m.analyze_bjobs(query_bytes().replace(old, new))['gaps'])
        self.assertTrue(m.analyze_bjobs(query_bytes() * 2)['gaps'])

    def test_valid_external_receipts(self):
        obs = observation(); raw, pins = reviews(obs)
        with mock.patch.object(m.time, 'time', return_value=1020):
            self.assertEqual(m.validate_reviews(obs, raw, pins), m.sha(m.canonical(obs)))

    def test_no_implicit_review_pass(self):
        obs = observation()
        with mock.patch.object(m.time, 'time', return_value=1020):
            with self.assertRaises(m.ResumeError):
                m.validate_reviews(obs, {}, {})
            raw, pins = reviews(obs)
            pins['registration'] = '0' * 64
            with self.assertRaisesRegex(m.ResumeError, 'REVIEW_PIN'):
                m.validate_reviews(obs, raw, pins)

    def test_reject_failed_nonindependent_wrongid_and_unaccepted_composite(self):
        for key, value in (('passed', False), ('independent', False), ('job_id', True),
                           ('composite_requested_worker_nonarray_accepted', False)):
            obs = observation(); raw, pins = reviews(obs)
            receipt = json.loads(raw['pre_resume'].decode('ascii')); receipt[key] = value
            raw['pre_resume'] = m.canonical(receipt); pins['pre_resume'] = m.sha(raw['pre_resume'])
            with mock.patch.object(m.time, 'time', return_value=1020):
                with self.assertRaises(m.ResumeError):
                    m.validate_reviews(obs, raw, pins)

    def test_stale_future_and_changed_observation(self):
        obs = observation(); raw, pins = reviews(obs)
        for now in (999, 1301):
            with mock.patch.object(m.time, 'time', return_value=now):
                with self.assertRaises(m.ResumeError):
                    m.validate_reviews(obs, raw, pins)
        obs['config_sha256'] = '0' * 64
        with mock.patch.object(m.time, 'time', return_value=1020):
            with self.assertRaises(m.ResumeError):
                m.validate_reviews(obs, raw, pins)

    def test_observe_never_resumes_or_writes(self):
        with mock.patch.object(m, '_host'), mock.patch.object(m.base, '_verify'), \
                mock.patch.object(m, '_registration_evidence', return_value={}), \
                mock.patch.object(m, '_query', return_value=query_bytes()), \
                mock.patch.object(m.base, '_persist') as persist, \
                mock.patch.object(m.base, '_client') as client:
            self.assertFalse(m.observe()['reviews_granted'])
            persist.assert_not_called(); client.assert_not_called()

    def test_composite_evidence_requires_exact_durable_argv_and_job(self):
        intent = dict(schema='e97-registration-intent-v1', argv=m.base._argv(),
            manifest_sha256=m.base.MANIFEST_SHA256, fresh_config_sha256=m.base.CONFIG_SHA256,
            only_attempt_consumed_before_spawn=True, automatic_retries=0)
        output = b'Job <394230> is submitted to queue <normal>.\n'
        with mock.patch.object(m.base, '_read', side_effect=[(m.canonical(intent), None), (output, None)]):
            evidence = m._registration_evidence()
        self.assertEqual(evidence['requested_workers'], 1)
        self.assertTrue(evidence['worker_LSB_JOBINDEX_check_pending'])
        intent['argv'][intent['argv'].index('-n') + 1] = '2'
        with mock.patch.object(m.base, '_read', return_value=(m.canonical(intent), None)):
            with self.assertRaisesRegex(m.ResumeError, 'INTENT'):
                m._registration_evidence()

    def run_resume(self, outcome, changed=False, collision=False):
        obs = observation(); raw, pins = reviews(obs)
        events = []
        info = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=1000)
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(m.time, 'time', return_value=1020))
            for name in ('_host', '_verify_resume_binary'):
                stack.enter_context(mock.patch.object(m, name))
            stack.enter_context(mock.patch.object(m.base, '_verify'))
            stack.enter_context(mock.patch.object(m, '_registration_evidence', return_value=obs['registration']))
            stack.enter_context(mock.patch.object(m, '_query', return_value=b'changed' if changed else query_bytes()))
            stack.enter_context(mock.patch.object(m.base, '_directory', return_value=10))
            stack.enter_context(mock.patch.object(m.os, 'O_DIRECTORY', 1, create=True))
            stack.enter_context(mock.patch.object(m.os, 'O_NOFOLLOW', 2, create=True))
            stack.enter_context(mock.patch.object(m.os, 'mkdir', side_effect=FileExistsError() if collision else None))
            stack.enter_context(mock.patch.object(m.os, 'fsync'))
            stack.enter_context(mock.patch.object(m.os, 'open', return_value=11))
            stack.enter_context(mock.patch.object(m.os, 'fstat', return_value=info))
            stack.enter_context(mock.patch.object(m.os, 'getuid', return_value=1000, create=True))
            stack.enter_context(mock.patch.object(m.os, 'close'))
            stack.enter_context(mock.patch.object(m.base, '_persist', side_effect=lambda fd, name, data:
                events.append((name, data))))
            client = stack.enter_context(mock.patch.object(m.base, '_client', side_effect=lambda argv:
                events.append(('client', argv)) or outcome))
            if changed or collision:
                with self.assertRaises((m.ResumeError, FileExistsError)):
                    m.resume_once(obs, raw, pins)
                client.assert_not_called()
                return
            result = m.resume_once(obs, raw, pins)
            self.assertEqual(client.call_count, 1)
        return result, events

    def test_once_exact_id_after_durable_intent_and_exact_permit(self):
        outcome = dict(status='CLIENT_COMPLETE', returncode=0,
            stdout=b'Job <394230> is being resumed\n', stderr=b'')
        result, events = self.run_resume(outcome)
        self.assertTrue(result['resume_acknowledged'])
        self.assertEqual([name for name, _ in events[:3]], ['intent.json', 'e97_resume_permit.json', 'client'])
        self.assertEqual(events[2][1], [m.base.BINDIR + 'bresume', '394230'])
        permit = json.loads(events[1][1].decode('ascii'))
        self.assertEqual(set(permit), {'schema', 'job_id', 'registration_review_passed',
            'pre_resume_review_passed', 'authorization_sha256', 'code_manifest_sha256', 'issued_at_epoch'})
        self.assertEqual(permit['job_id'], 394230)

    def test_unknown_resume_preserved_without_retry(self):
        result, events = self.run_resume(dict(status='CLIENT_FAILURE_UNKNOWN', returncode=None,
            stdout=b'partial', stderr=b'failed'))
        self.assertEqual(result['status'], 'UNKNOWN_RESUME_CONSUMED_NO_RETRY')
        self.assertEqual(events[-1][0], 'result.json')

    def test_changed_job_and_existing_intent_never_resume(self):
        self.run_resume({}, changed=True)
        self.run_resume({}, collision=True)

    def test_python36_no_automatic_entry(self):
        source = PATH.read_text()
        kwargs = {'feature_version': (3, 6)} if sys.version_info >= (3, 8) else {}
        ast.parse(source, **kwargs)
        self.assertNotIn('__main__', source)
        self.assertNotIn("BINDIR + 'bsub'", source)


if __name__ == '__main__':
    unittest.main()
