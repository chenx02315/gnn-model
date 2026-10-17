import copy
import json
import stat
import types
import unittest
from scripts import probe_ranking_v6_e46_metadata_locations as probe
from scripts import run_ranking_v6_e46_metadata_locations as transport


def payload():
    return dict(status='PASS_FIXED_METADATA_LOCATIONS',hostname='bupt-gpus1',
        roots=[dict(root='/ssd/cjc/'+r,entry_count=0,directories=[],named_files=[],skipped=0) for r in probe.ROOTS],
        file_contents_opened=False,recursive_walk=False,protected_directory_visited=False,
        remote_files_written=False,training_release=False)


class LocationTests(unittest.TestCase):
    def test_unselected_and_protected_never_stat(self):
        seen=[]
        def lookup(n):
            seen.append(n)
            return types.SimpleNamespace(st_mode=stat.S_IFDIR)
        dirs, files, skipped = probe.classify(['multimode_ate_gnn_v1','checkpoints','venv','formal_candidate_space_v2_r1'],lookup)
        self.assertEqual(seen,['formal_candidate_space_v2_r1'])
        self.assertEqual(dirs,seen)
        self.assertEqual((files,skipped),([],0))

    def test_symlink_not_followed(self):
        self.assertEqual(probe.classify(['data'],lambda n:types.SimpleNamespace(st_mode=stat.S_IFLNK)),([],[],1))

    def test_bound_duplicate_and_traversal_rejected(self):
        for names in (['data']*2, ['x'+str(i) for i in range(2049)], ['formal_candidate_space/../x']):
            with self.assertRaises(ValueError): probe.classify(names,lambda n:None)

    def test_fixed_response(self):
        self.assertTrue(transport.validate_response(json.dumps(payload()).encode()))
        for key,value in (('hostname','other'),('file_contents_opened',True),('extra_quality',1)):
            row=payload();row[key]=value
            self.assertFalse(transport.validate_response(json.dumps(row).encode()))
        self.assertEqual(transport.COMMAND[-2],'cjc@gpuserver.buptic.top')

    def test_scope_and_count_tamper(self):
        for key,value in (('root','/ssd/cjc/multimode_ate_gnn_v1'),('entry_count',True),('directories',['checkpoints']),('directories',['data','data']),('named_files',['outcomes.tsv']),('skipped',1)):
            data=payload();data['roots'][0][key]=value
            self.assertFalse(probe.validate_response(data))

    def test_named_files_only(self):
        dirs,files,skip=probe.classify(['source_provenance_v2.tsv','outcomes.tsv'],lambda n:types.SimpleNamespace(st_mode=stat.S_IFREG))
        self.assertEqual((dirs,files,skip),([],['source_provenance_v2.tsv'],0))


if __name__ == '__main__': unittest.main()
