"""Injected synthetic stat objects only; never probe actual staged paths."""
import collections
import copy
import json
import stat
import types
import unittest
from unittest.mock import patch

from scripts import probe_ranking_v6_e37_source_paths as paths
from scripts import run_ranking_v6_e37_readonly as transport


def directory():
    return types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_nlink=2, st_size=0)


def ordinary(size=100, links=1, mode=None):
    return types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600 if mode is None else mode,
                                 st_nlink=links, st_size=size)


class SourcePathStatTests(unittest.TestCase):
    def setUp(self):
        self.files={spec[3] for spec in paths.SPECS}
        self.calls=collections.Counter()

    def fake_stat(self,path):
        self.calls[path]+=1
        return ordinary() if path in self.files else directory()

    def test_fixed_32_paths_eight_roots_six_train_both_phase2_versions(self):
        self.assertEqual(len(paths.SPECS),32)
        self.assertEqual(len(self.files),32)
        self.assertEqual(len({root for circuit,root in paths.ROOTS}),8)
        self.assertEqual({circuit for circuit,root in paths.ROOTS},
                         {'aes_core','s13207','s15850','s35932','s38417','spi'})
        for circuit in ('s35932','s38417'):
            roots=[root for name,root in paths.ROOTS if name==circuit]
            self.assertEqual(len(roots),2)
            self.assertTrue(any(root.endswith('/10_coverage95_v1') for root in roots))
            self.assertTrue(any(root.endswith('/10_coverage95_v2_merge_reclassify') for root in roots))
        expected_aliases={'hf_coarse','hmf_coarse','hf_refine','hmf_refine'}
        for circuit,root in paths.ROOTS:
            specs=[spec for spec in paths.SPECS if spec[1]==root]
            self.assertEqual({spec[2] for spec in specs},expected_aliases)
            self.assertTrue(all(spec[0]==circuit and spec[3].startswith(root+'/') for spec in specs))
        for forbidden in ('s5378','tv80','s9234','s38584','wb_dma','BLIND'):
            self.assertFalse(any(forbidden in spec[3] for spec in paths.SPECS))

    def test_all_present_injected_stats_no_content_open_and_qualified_flags(self):
        with patch('builtins.open',side_effect=AssertionError('CONTENT_OPEN')), \
                patch('os.open',side_effect=AssertionError('FD_OPEN')), \
                patch.object(paths.os,'lstat',side_effect=AssertionError('REAL_STAT')), \
                patch('socket.socket',side_effect=AssertionError('NETWORK')):
            result=paths.probe(lstat_fn=self.fake_stat)
        self.assertEqual(result['status'],'PASS_PATH_STAT_ONLY')
        self.assertEqual(result['present_ordinary_size_bounded'],32)
        self.assertEqual(result['roots'],8)
        self.assertEqual(result['files'],32)
        self.assertTrue(all(row['status']=='PRESENT_ORDINARY_SIZE_BOUNDED' for row in result['results']))
        for flag in ('source_file_contents_opened','quality_values_accessed','source_rows_projected',
                     'remote_task_files_written','source_hashes_verified','formal_builder_roots_certified',
                     'complete_roster_certified','training_release'):
            self.assertIs(result[flag],False)
        for path,count in self.calls.items():
            self.assertEqual(count,1,'each cached parent/file should have one synthetic stat')
        self.assertLess(len(json.dumps(result,separators=(',',':')).encode('ascii')),paths.MAX_OUTPUT)

    def test_missing_denied_and_os_error_fail_closed_without_raw_error_text(self):
        target=paths.SPECS[0][3]
        for error,status in ((FileNotFoundError('SECRET_PATH'),'MISSING'),
                             (PermissionError('SECRET_PATH'),'DENIED'),
                             (OSError('SECRET_PATH'),'OS_ERROR')):
            def fake(path):
                if path==target: raise error
                return self.fake_stat(path)
            result=paths.probe(lstat_fn=fake)
            self.assertEqual(result['status'],'PARTIAL_PATH_STAT_ONLY')
            self.assertEqual(result['present_ordinary_size_bounded'],31)
            row=next(row for row in result['results'] if row['path']==target)
            self.assertEqual(row['status'],status)
            self.assertNotIn('SECRET_PATH',json.dumps(result))

    def test_parent_symlink_or_non_directory_rejected(self):
        unsafe_parent=paths.SPECS[0][1]
        for mode in (stat.S_IFLNK | 0o777,stat.S_IFREG | 0o600):
            def fake(path):
                if path==unsafe_parent: return ordinary(mode=mode)
                return self.fake_stat(path)
            with patch('builtins.open',side_effect=AssertionError('CONTENT_OPEN')):
                result=paths.probe(lstat_fn=fake)
            self.assertEqual(result['status'],'PARTIAL_PATH_STAT_ONLY')
            affected=[row for row in result['results'] if row['coverage_root']==unsafe_parent]
            self.assertEqual(len(affected),4)
            self.assertTrue(all(row['status']=='UNSAFE_ANCESTOR' for row in affected))

    def test_file_symlink_directory_and_hardlink_rejected(self):
        target=paths.SPECS[0][3]
        for info in (ordinary(mode=stat.S_IFLNK | 0o777),directory(),ordinary(links=2)):
            def fake(path): return info if path==target else self.fake_stat(path)
            result=paths.probe(lstat_fn=fake)
            row=next(row for row in result['results'] if row['path']==target)
            self.assertEqual(row['status'],'NOT_REGULAR_SINGLE_LINK')
            self.assertEqual(result['status'],'PARTIAL_PATH_STAT_ONLY')

    def test_empty_oversize_and_exact_bound(self):
        target=paths.SPECS[0][3]
        for size,expected in ((0,'SOURCE_SIZE_BOUND'),(8*1024*1024+1,'SOURCE_SIZE_BOUND'),
                              (8*1024*1024,'PRESENT_ORDINARY_SIZE_BOUNDED')):
            def fake(path): return ordinary(size=size) if path==target else self.fake_stat(path)
            result=paths.probe(lstat_fn=fake)
            row=next(row for row in result['results'] if row['path']==target)
            self.assertEqual(row['status'],expected)
            self.assertEqual(result['status'],'PASS_PATH_STAT_ONLY' if size==8*1024*1024 else 'PARTIAL_PATH_STAT_ONLY')


class SourcePathResponseTests(unittest.TestCase):
    def setUp(self):
        fixed_files={spec[3] for spec in paths.SPECS}
        self.payload=paths.probe(lstat_fn=lambda path:ordinary() if path in fixed_files else directory())
        self.payload['resource']=dict(address_space_limit_bytes=1073741824,cpu_limit_s=20,workers=1)

    def valid(self,payload=None):
        return transport.validate_response(json.dumps(self.payload if payload is None else payload,
                                                      separators=(',',':')).encode('ascii'))

    def test_synthetic_linux_resource_response_valid_no_ssh_content_or_cli(self):
        with patch('builtins.open',side_effect=AssertionError('CONTENT_OPEN')), \
                patch('os.open',side_effect=AssertionError('FD_OPEN')), \
                patch('subprocess.Popen',side_effect=AssertionError('SSH')), \
                patch('socket.socket',side_effect=AssertionError('NETWORK')):
            self.assertTrue(self.valid())

    def test_valid_partial_present_count_and_rows_strict(self):
        self.payload['results'][0].update(status='MISSING')
        del self.payload['results'][0]['size_bytes']
        self.payload.update(status='PARTIAL_PATH_STAT_ONLY',present_ordinary_size_bounded=31)
        self.assertTrue(self.valid())
        self.payload['results'][0]['size_bytes']=0
        self.assertFalse(self.valid())

    def test_altered_fixed_path_duplicate_row_and_quality_fields_rejected(self):
        for mutation in ('path','root','circuit','alias','duplicate','row_quality','top_quality'):
            changed=copy.deepcopy(self.payload)
            row=changed['results'][0]
            if mutation=='path': row['path']+='/elsewhere'
            elif mutation=='root': row['coverage_root']+='_other'
            elif mutation=='circuit': row['circuit']='s9234'
            elif mutation=='alias': row['stage_alias']='unknown'
            elif mutation=='duplicate': changed['results'][1]=dict(row)
            elif mutation=='row_quality': row['total_cycles']=123
            else: changed['quality_values']=[123]
            with self.subTest(mutation=mutation): self.assertFalse(self.valid(changed))

    def test_scope_flags_counts_status_and_boolean_resource_rejected(self):
        flags=('source_file_contents_opened','quality_values_accessed','source_rows_projected',
               'remote_task_files_written','source_hashes_verified','formal_builder_roots_certified',
               'complete_roster_certified','training_release')
        for flag in flags:
            for value in (True,0,None):
                changed=copy.deepcopy(self.payload)
                changed[flag]=value
                with self.subTest(flag=flag,value=value): self.assertFalse(self.valid(changed))
        for key,value in (('files',31),('files',True),('roots',7),('roots',True),
                          ('present_ordinary_size_bounded',31),('present_ordinary_size_bounded',True),
                          ('status','PARTIAL_PATH_STAT_ONLY'),('status','PASS_FULL_ROSTER')):
            changed=copy.deepcopy(self.payload)
            changed[key]=value
            with self.subTest(key=key,value=value): self.assertFalse(self.valid(changed))
        for key in ('address_space_limit_bytes','cpu_limit_s','workers'):
            changed=copy.deepcopy(self.payload)
            changed['resource'][key]=True
            with self.subTest(resource_key=key): self.assertFalse(self.valid(changed))
        for key,value in (('address_space_limit_bytes',1073741825),('cpu_limit_s',21),('workers',2)):
            changed=copy.deepcopy(self.payload)
            changed['resource'][key]=value
            self.assertFalse(self.valid(changed))

    def test_duplicate_json_nonstandard_constants_and_wrong_row_status(self):
        encoded=json.dumps(self.payload,separators=(',',':')).encode('ascii')
        duplicate=encoded.replace(b'"status":',b'"status":"PASS_PATH_STAT_ONLY","status":',1)
        self.assertFalse(transport.validate_response(duplicate))
        self.assertFalse(transport.validate_response(b'{"status":NaN}'))
        self.assertFalse(transport.validate_response(b'{"status":Infinity}'))
        changed=copy.deepcopy(self.payload)
        changed['results'][0]['status']='CERTIFIED_SOURCE_CONTENT'
        self.assertFalse(self.valid(changed))


if __name__=='__main__': unittest.main()
