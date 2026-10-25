import ast
from pathlib import Path
import unittest
from unittest.mock import Mock
from src.data import direct_memory_sample_e101 as m


class Tests(unittest.TestCase):
    def live(self,state='S',start=9):return (101,start,state,100,101,101)
    def test_live_complete(self):
        pause=Mock()
        result=m.measure_owned(101,9,Mock(return_value=self.live()),
            Mock(return_value=b'State: S (sleeping)\nVmRSS: 10 kB\nVmSwap: 2 kB\n'),pause)
        self.assertEqual(result['rss_swap_bytes'],12*1024);pause.assert_not_called()

    def test_after_stat_zombie_does_not_turn_missing_vm_into_live_error(self):
        result=m.measure_owned(101,9,Mock(side_effect=[self.live(),self.live('Z')]),
            Mock(return_value=b'State: Z (zombie)\n'))
        self.assertEqual(result['kind'],'EXITED_DURING_SAMPLE')
        self.assertIsNone(result['rss_swap_bytes'])

    def test_exit_between_reads_is_missing_not_zero(self):
        result=m.measure_owned(101,9,Mock(side_effect=FileNotFoundError()),Mock())
        self.assertIsNone(result['rss_swap_bytes'])

    def test_missing_live_fields_one_recheck_then_exit(self):
        identities=Mock(side_effect=[self.live(),self.live(),self.live(),self.live('Z')])
        pause=Mock()
        result=m.measure_owned(101,9,identities,Mock(side_effect=[b'State: R\n',b'State: Z\n']),pause)
        self.assertEqual(result['kind'],'EXITED_DURING_SAMPLE');pause.assert_called_once_with(.005)

    def test_persistent_live_missing_fields_still_rejected(self):
        pause=Mock()
        with self.assertRaisesRegex(ValueError,'LIVE_FIELDS_MISSING'):
            m.measure_owned(101,9,Mock(return_value=self.live()),Mock(return_value=b'State: S\n'),pause)
        pause.assert_called_once_with(.005)

    def test_identity_change_never_measures_reused_pid(self):
        for rows in ([self.live(start=10)], [self.live(),self.live(start=10)]):
            with self.assertRaisesRegex(ValueError,'MEMORY_PID_CHANGED'):
                m.measure_owned(101,9,Mock(side_effect=rows),Mock(return_value=b'State: S\n'))

    def test_live_and_exited_aggregate_are_distinct(self):
        domain=Mock();domain.pid=100;domain.identity=(100,1,'S',1,100,100)
        domain.peak=0;domain.snapshot.return_value={101:self.live()}
        def identity(pid):return self.live('Z') if pid==101 else domain.identity
        def status(path):return b'State: Z\n' if '/101/' in path else b'State: S\nVmRSS: 10 kB\nVmSwap: 0 kB\n'
        m.sample_descendants(domain,identity,status)
        self.assertEqual(domain.peak,10*1024)
        self.assertEqual(domain.last_memory_sample['exited_during_sample'],1)

    def test_python36(self):ast.parse(Path(m.__file__).read_text(encoding='utf-8'),feature_version=(3,6))


if __name__=='__main__':unittest.main()
