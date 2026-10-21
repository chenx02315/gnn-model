"""Local single-worker barrier; no subprocess, thread, Docker or remote."""
from pathlib import Path
import tempfile
import unittest
from src.data import prospective_lifecycle_journal_v2 as m
from scripts.demo_prospective_lifecycle_journal_v2 import FixtureBackend,FixtureClock


class WorkerBarrierTests(unittest.TestCase):
    def test_nested_identity_payload_and_returned_event_are_detached(self):
        with tempfile.TemporaryDirectory()as root:
            path=str(Path(root)/'journal.jsonl')
            with m.Journal.create(path)as journal:
                journal.append('INTENT','fixture',dict(profile='success',clock_session='fixture-clock',prelaunch_ns=1))
                identity=dict(host='synthetic-fixture',boot_id='fixture-boot',pid=10,start_ticks=100)
                row=journal.append('LAUNCHED','fixture',dict(identity=identity))
                identity['pid']=99
                row['payload']['identity']['pid']=88
                self.assertEqual(journal.snapshot()['attempts']['fixture']['identity']['pid'],10)
            self.assertEqual(m.load(path)['attempts']['fixture']['identity']['pid'],10)

    def test_nested_second_journal_cannot_launch_a_worker(self):
        with tempfile.TemporaryDirectory()as root:
            with m.Journal.create(str(Path(root)/'first.jsonl'))as first, \
                 m.Journal.create(str(Path(root)/'second.jsonl'))as second:
                extra=FixtureBackend()
                test=self
                class Nested(FixtureBackend):
                    def finish(self,handle,profile):
                        with test.assertRaisesRegex(ValueError,'SINGLE_WORKER_BUSY'):
                            second.run('nested','success',extra,FixtureClock())
                        return super().finish(handle,profile)
                out=first.run('outer','success',Nested(),FixtureClock())
                self.assertTrue(out['complete_live_acknowledged'])
                self.assertEqual(extra.launches,0)
                self.assertEqual(second.snapshot()['attempt_count'],0)


if __name__=='__main__':unittest.main()
