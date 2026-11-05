"""Native receipt and clock parsers with virtual capture inputs only."""
import copy
import datetime
import unittest
from scripts import e138_controller_clock as m


class Tests(unittest.TestCase):
    def setUp(self):
        from tests.test_physical_replay_capture_e138 import CaptureTests
        self.case=CaptureTests();self.addCleanup(self.case.doCleanups);self.case.setUp()
        self.utc=datetime.datetime(2026,11,5,tzinfo=datetime.timezone.utc)
        self.domain=dict(host='synthetic-local',clock='synthetic-monotonic')
        self.start=dict(schema='e138-local-original-clock-v1',authorization_sha256=m.sha(self.case.authority),
            proposal_sha256=m.sha(self.case.proposal),start=1000.,end=4600.,domain=self.domain,
            utc_start=self.utc.strftime('%Y-%m-%dT%H:%M:%S.%f%z'),
            utc_end=(self.utc+datetime.timedelta(seconds=3600)).strftime('%Y-%m-%dT%H:%M:%S.%f%z'))
        self.frame=dict(role='capture',capture=self.case.capture(),boot_id='3ebeb9bb-410c-476c-a000-5c625f590473',
            remote_start_monotonic=50000.,remote_sample_monotonic=50001.,
            remote_utc_sample=(self.utc+datetime.timedelta(seconds=1)).strftime('%Y-%m-%dT%H:%M:%S.%f%z'),execution_ready=False)

    def build(self,**changes):
        kwargs=dict(role1_raw=m.canonical(self.frame),start_raw=m.canonical(self.start),payload_sha='a'*64,
            authority=self.case.authority,proposal=self.case.proposal,auth_pin=m.sha(self.case.authority),
            proposal_pin=m.sha(self.case.proposal),now=1002.,utc_now=self.utc.timestamp()+2,domain=self.domain)
        kwargs.update(changes);return m.build(**kwargs)

    def test_different_monotonic_domains_preserve_both_original_starts(self):
        original=m.capture.AUTH_SHA;clock=m.decode(self.build())
        self.assertEqual(clock['remote_deadline_monotonic'],53600.)
        self.assertEqual(clock['local_monotonic_deadline'],4600.)
        self.assertEqual(m.capture.AUTH_SHA,original)

    def test_missing_authority_domain_swap_expiry_and_skew_reject(self):
        for changes in (dict(auth_pin=None),dict(domain=dict(host='other',clock='other')),dict(now=4601.),
                dict(utc_now=self.utc.timestamp()+99),dict(now=True)):
            with self.subTest(changes=changes),self.assertRaises(ValueError):self.build(**changes)

    def test_remote_clock_cannot_reopen_window_or_use_boolean_start(self):
        for changes in (dict(remote_sample_monotonic=50060.),dict(remote_start_monotonic=True),dict(execution_ready=True)):
            original=copy.deepcopy(self.frame);self.frame.update(changes)
            with self.assertRaises(ValueError):self.build()
            self.frame=original

    def test_remote_start_cannot_predate_local_connection(self):
        self.frame['remote_sample_monotonic']=50059.
        with self.assertRaisesRegex(ValueError,'SKEW_OR_EXPIRED'):self.build()

    def test_exact_ten_second_cleanup_reserve_is_not_available(self):
        with self.assertRaisesRegex(ValueError,'SKEW_OR_EXPIRED'):
            self.build(now=4590.,utc_now=self.utc.timestamp()+3590)


if __name__=='__main__':unittest.main()
