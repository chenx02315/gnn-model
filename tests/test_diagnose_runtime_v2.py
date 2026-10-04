import hashlib
import tempfile
import unittest
from pathlib import Path
from src.audit.diagnose_runtime_v2 import auc, ranks, spearman, read_verified


class DiagnosticTests(unittest.TestCase):
    def test_auc_ties(self):
        rows = [{'hit':1,'p':.5},{'hit':0,'p':.5}]
        self.assertEqual(auc(rows,'p'),.5)

    def test_auc_perfect_and_reverse(self):
        self.assertEqual(auc([{'hit':1,'p':1},{'hit':0,'p':0}],'p'),1)
        self.assertEqual(auc([{'hit':1,'p':0},{'hit':0,'p':1}],'p'),0)

    def test_no_positives(self):
        self.assertIsNone(auc([{'hit':0,'p':1}],'p'))

    def test_spearman_ties_and_constant(self):
        self.assertEqual(ranks([3,1,1]),[3,1.5,1.5])
        self.assertAlmostEqual(spearman([1,2,3],[3,2,1]),-1)
        self.assertIsNone(spearman([1,1],[2,3]))

    def test_hash_mismatch_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'fixture.tsv'
            path.write_bytes(b'a\tb\n1\t2\n')
            self.assertEqual(read_verified(path,hashlib.sha256(path.read_bytes()).hexdigest())[0]['a'],'1')
            with self.assertRaises(ValueError):
                read_verified(path,'0'*64)


if __name__ == '__main__':
    unittest.main()
