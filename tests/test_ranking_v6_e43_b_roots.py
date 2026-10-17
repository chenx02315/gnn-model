import copy
import json
import stat
import types
import unittest
from unittest.mock import patch
from scripts import probe_ranking_v6_e43_b_metadata_roots as probe
from scripts import run_ranking_v6_e43_b_roots as transport


def payload():
    return dict(status='PASS_B_ROOT_NAMES_ONLY',root='/ssd/cjc',entry_count=4,
        project_roots=['/ssd/cjc/gnn_model_runtime_v2_example'],non_directory_candidates_skipped=0,
        hostname='fixture',uid=1000,resource=dict(workers=1,cpu_limit_s=20,address_space_limit_bytes=1024**3),
        file_contents_opened=False,recursive_walk=False,remote_files_written=False,
        protected_directory_visited=False,training_release=False)


class RootTests(unittest.TestCase):
    def test_protected_and_unselected_excluded_before_stat(self):
        seen=[]
        def lookup(name):
            self.assertNotEqual(name, probe.PROTECTED)
            self.assertNotEqual(name, 'unrelated')
            seen.append(name)
            return types.SimpleNamespace(st_mode=stat.S_IFDIR)
        roots, skipped=probe.collect([probe.PROTECTED,'unrelated','gnn_model_runtime_v2_example'],lookup)
        self.assertEqual(roots,['/ssd/cjc/gnn_model_runtime_v2_example'])
        self.assertEqual(seen,['gnn_model_runtime_v2_example'])
        self.assertEqual(skipped,0)

    def test_symlinks_and_files_not_followed(self):
        names=['gnn_model_link','gnn_model_file']
        roots, skipped=probe.collect(names,lambda n:types.SimpleNamespace(st_mode=stat.S_IFLNK if n.endswith('link') else stat.S_IFREG))
        self.assertEqual(roots,[])
        self.assertEqual(skipped,2)

    def test_entry_name_and_root_bounds_fail_closed(self):
        lookup=lambda n:types.SimpleNamespace(st_mode=stat.S_IFDIR)
        for names in (['gnn_model_bad/../path'], ['gnn_model_a','gnn_model_a'], ['unrelated'+str(i) for i in range(1025)],
                      ['gnn_model_'+str(i) for i in range(513)]):
            with self.assertRaises(ValueError): probe.collect(names,lookup)

    def test_positive_response_does_not_open_files_or_network(self):
        with patch('os.open',side_effect=AssertionError('NO_READ')),patch('subprocess.Popen',side_effect=AssertionError('NO_SSH')):
            self.assertTrue(transport.validate_response(json.dumps(payload()).encode()))
        self.assertEqual(transport.SOURCE.name,'probe_ranking_v6_e43_b_metadata_roots.py')
        self.assertEqual(transport.COMMAND[-2],'work.buptic.top')

    def test_response_rejects_protected_extra_bad_types_and_flags(self):
        for key,value in (('entry_count',True),('file_contents_opened',True),('training_release',True),('extra_quality',1),
                          ('project_roots',['/ssd/cjc/'+probe.PROTECTED]),('project_roots',['/ssd/cjc/gnn_model_x/nested'])):
            data=copy.deepcopy(payload());data[key]=value
            self.assertFalse(transport.validate_response(json.dumps(data).encode()))

    def test_duplicate_json_and_oversize_rejected(self):
        raw=json.dumps(payload()).encode()
        self.assertFalse(transport.validate_response(raw.replace(b'"status":',b'"status":0,"status":',1)))
        self.assertFalse(transport.validate_response(b'{"status":NaN}'))
        self.assertFalse(transport.validate_response(b' '*65537))

    def test_directory_plus_skipped_count_cannot_exceed_inventory(self):
        data=payload();data['entry_count']=1;data['non_directory_candidates_skipped']=1
        self.assertFalse(transport.validate_response(json.dumps(data).encode()))

    def test_source_hash_mismatch_before_ssh(self):
        with patch('subprocess.Popen',side_effect=AssertionError('NO_SSH')):
            with self.assertRaisesRegex(ValueError,'REVIEWED_SOURCE_SHA_MISMATCH'):
                transport.run('0'*64,'unused')


if __name__=='__main__': unittest.main()
