import json
import stat
import types
import unittest
from scripts import probe_ranking_v6_e48_metadata_backup_names as p
from scripts import run_ranking_v6_e48_metadata_backup_names as t


class BackupNamesTests(unittest.TestCase):
    def test_no_stat_protected_quality_environment(self):
        seen=[]
        def lookup(n):seen.append(n);return types.SimpleNamespace(st_mode=stat.S_IFREG)
        files,skip=p.classify(['multimode_ate_gnn_v1','outcomes.tsv','checkpoint.pt','runtime_training_package_v2.tar.gz'],lookup)
        self.assertEqual(seen,['runtime_training_package_v2.tar.gz']);self.assertEqual(files,seen);self.assertEqual(skip,0)

    def test_symlink_not_followed(self):
        self.assertEqual(p.classify(['source_provenance_v2.tsv'],lambda n:types.SimpleNamespace(st_mode=stat.S_IFLNK)),([],1))

    def test_bound_and_traversal(self):
        for names in (['receipt_v2.json']*2,['x'+str(i)for i in range(1025)],['formal_candidate_space/../x.json']):
            with self.assertRaises(ValueError):p.classify(names,lambda n:None)

    def test_empty_result_and_strict_schema(self):
        r=dict(status='PASS_METADATA_BACKUP_NAMES',hostname='bupt-gpus1',root='/ssd/cjc',entry_count=138,metadata_named_files=[],skipped=0,
            file_contents_opened=False,archive_headers_read=False,protected_directory_visited=False,remote_files_written=False,training_release=False)
        self.assertTrue(t.validate_response(json.dumps(r).encode()))
        r['archive_headers_read']=True;self.assertFalse(t.validate_response(json.dumps(r).encode()))
        r['archive_headers_read']=False;r['metadata_named_files']=['checkpoint.pt'];self.assertFalse(t.validate_response(json.dumps(r).encode()))


if __name__=='__main__':unittest.main()
