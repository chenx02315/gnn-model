import ast
from pathlib import Path
import unittest
from unittest.mock import Mock
from unittest.mock import patch
from types import SimpleNamespace
from src.data import direct_memory_sample_e103 as m


class Tests(unittest.TestCase):
    def identity(self):return (101,9,'R',100,101,101)

    def raw_stat(self,flags=4,start=9,vsize=0,rss=0):
        fields=['R']+['0']*21
        for i,v in ((6,flags),(19,start),(20,vsize),(21,rss)):fields[i]=str(v)
        return ('101 (name with spaces) '+' '.join(fields)+'\n').encode('ascii')

    def reader(self,flags=4,start=9,vsize=0,rss=0,statm=b'0 0 0 0 0 0 0\n',status=b'State: R\nThreads: 1\n'):
        def read(path):
            if path.endswith('/stat'):return self.raw_stat(flags,start,vsize,rss)
            if path.endswith('/statm'):return statm
            return status
        return read

    def test_three_independent_exit_mm_conditions_not_fake_zero(self):
        result=m.measure_owned(101,9,Mock(return_value=self.identity()),self.reader(),Mock(),Mock(return_value=[101]))
        self.assertEqual(result['kind'],'EXITING_MM_RELEASED')
        self.assertIsNone(result['rss_swap_bytes'])
        self.assertFalse(result['os_termination_attested'])

    def test_non_exiting_or_nonempty_address_space_rejected(self):
        for kwargs in (dict(flags=0),dict(vsize=4096),dict(rss=1),
                       dict(statm=b'1 0 0 0 0 0 0\n'),dict(statm=b'0 0\n')):
            with self.subTest(kwargs=kwargs),self.assertRaisesRegex(ValueError,'LIVE_FIELDS_MISSING'):
                m.measure_owned(101,9,Mock(return_value=self.identity()),self.reader(**kwargs),Mock(),Mock(return_value=[101]))

    def test_partial_or_malformed_status_does_not_use_proof(self):
        for status in (b'State: R\nVmRSS: bad\n',b'State: R\nVmSwap: 0 kB\n',
                       b'State: R\nThreads: 1\nVmRSS : bad\n'):
            with self.assertRaisesRegex(ValueError,'LIVE_FIELDS_MISSING'):
                m.measure_owned(101,9,Mock(return_value=self.identity()),self.reader(status=status),Mock(),Mock(return_value=[101]))

    def test_pid_reuse_in_aux_stat_rejected(self):
        with self.assertRaisesRegex(ValueError,'PID_CHANGED'):
            m.measure_owned(101,9,Mock(return_value=self.identity()),self.reader(start=10),Mock(),Mock(return_value=[101]))

    def test_live_fields_still_measure_and_no_aux_read(self):
        read=Mock(return_value=b'State: R\nVmRSS: 10 kB\nVmSwap: 2 kB\n')
        value=m.measure_owned(101,9,Mock(return_value=self.identity()),read,Mock())
        self.assertEqual(value['rss_swap_bytes'],12288)
        read.assert_called_once_with('/proc/101/status')

    def test_aux_read_denied_not_ignored(self):
        read=self.reader()
        def denied(path):
            if path.endswith('/statm'):raise PermissionError('denied')
            return read(path)
        with self.assertRaises(PermissionError):
            m.measure_owned(101,9,Mock(return_value=self.identity()),denied,Mock(),Mock(return_value=[101]))

    def test_other_live_threads_forbid_leader_no_mm_exception(self):
        for threads in ([101,102],[102],[]):
            with self.subTest(threads=threads),self.assertRaisesRegex(ValueError,'LIVE_FIELDS_MISSING'):
                m.measure_owned(101,9,Mock(return_value=self.identity()),self.reader(),Mock(),Mock(return_value=threads))

    def test_unknown_status_or_raw_stat_state_rejected(self):
        with self.assertRaisesRegex(ValueError,'STATUS_STATE'):
            m.measure_owned(101,9,Mock(return_value=self.identity()),
                            self.reader(status=b'State: Q\nThreads: 1\n'),Mock(),Mock(return_value=[101]))
        read=self.reader()
        def bad_stat(path):
            value=read(path)
            return value.replace(b') R ',b') Q ') if path.endswith('/stat') else value
        with self.assertRaisesRegex(ValueError,'STATUS_STATE'):
            m.measure_owned(101,9,Mock(return_value=self.identity()),bad_stat,Mock(),Mock(return_value=[101]))

    def test_missing_aux_does_not_fake_exit_if_identity_still_live(self):
        with self.assertRaisesRegex(ValueError,'LIVE_FIELDS_MISSING'):
            m.measure_owned(101,9,Mock(return_value=self.identity()),self.reader(),Mock(),
                            Mock(side_effect=FileNotFoundError()))

    def test_aux_zombie_does_not_skip_other_live_threads(self):
        statuses=[b'State: R\n',b'State: R\n',b'State: Z\nThreads: 2\n']
        ordinary=self.reader()
        def read(path):
            return statuses.pop(0) if path.endswith('/status') else ordinary(path)
        with self.assertRaisesRegex(ValueError,'LIVE_FIELDS_MISSING'):
            m.measure_owned(101,9,Mock(return_value=self.identity()),read,Mock(),
                            Mock(return_value=[101,102]))

    def test_original_zombie_fast_path_also_requires_single_task(self):
        zombie=(101,9,'Z',100,101,101)
        with self.assertRaisesRegex(ValueError,'LIVE_FIELDS_MISSING'):
            m.measure_owned(101,9,Mock(return_value=zombie),self.reader(),Mock(),
                            Mock(return_value=[101,102]))
        row=m.measure_owned(101,9,Mock(return_value=zombie),self.reader(),Mock(),
                            Mock(return_value=[101]))
        self.assertEqual(row['kind'],'EXITED_DURING_SAMPLE')

    def test_python36(self):
        ast.parse(Path(m.__file__).read_text(encoding='utf-8'),feature_version=(3,6))

    def test_aggregate_records_proof_without_imputation_and_keeps_threshold(self):
        domain=SimpleNamespace(pid=100,identity=(100,1,'S',1,100,100),peak=0,
                               snapshot=lambda:{101:self.identity()})
        proof=dict(kind='EXITING_MM_RELEASED',rss_swap_bytes=None,pid=101,start_ticks=9)
        with patch.object(m,'measure_owned',side_effect=[proof,dict(kind='LIVE_MEASURED',rss_swap_bytes=12288)]):
            m.sample_descendants(domain,Mock(),Mock())
        self.assertEqual(domain.peak,12288)
        self.assertEqual(domain.last_memory_sample['exiting_mm_released'],1)
        self.assertFalse(domain.last_memory_sample['missing_values_imputed'])
        with patch.object(m,'measure_owned',return_value=dict(kind='LIVE_MEASURED',rss_swap_bytes=536870913)):
            with self.assertRaisesRegex(ValueError,'SAMPLED_MEMORY_STOP'):
                m.sample_descendants(domain,Mock(),Mock())


if __name__=='__main__':unittest.main()
