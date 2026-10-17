"""Byte fixtures only; never reads actual 32 source paths or remote files."""
import ast
import copy
import hashlib
import os
import json
import stat
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from scripts import project_ranking_v6_e38_roster as producer
from scripts import run_ranking_v6_e38_readonly as transport


class SelectedProjectionTests(unittest.TestCase):
    def test_selected_metadata_only_invalid_utf8_quality_quoted_tabs_newlines_quotes(self):
        raw=(b'candidate\th_patterns\tm_patterns\tresult_status\tf_result\r\n'
             b'1\t64\t0\t"\xff\tFAIL\r\nopaque"\t"a""b"\r\n'
             b'2\t32\t\tPASS\t\xfe\n')
        with patch('builtins.open',side_effect=AssertionError('FILE')), \
                patch('os.open',side_effect=AssertionError('FD')):
            rows=producer.project_bytes(raw,'HF')
        self.assertEqual(rows,[[2,'1','64','0','explicit_candidate'],[3,'2','32','','explicit_candidate']])
        self.assertNotIn('PASS',repr(rows))
        self.assertNotIn('FAIL',repr(rows))

    def test_legacy_strip_preserves_leading_zeros_and_candidate_fallback_all_aliases(self):
        raw=b'candidate\th_patterns\tm_patterns\n 001 \t 064 \t 000 \n   \t 032 \t \n'
        self.assertEqual(producer.project_bytes(raw,'HF'),
            [[2,'001','064','000','explicit_candidate'],[3,'2','032','','one_based_data_row']])
        for alias,scheme,suffix in producer.LAYOUT:
            raw=b'h_patterns\tm_patterns\n64\t16\n' if scheme=='HMF' else b'h_patterns\n64\n'
            result=producer.project_bytes(raw,scheme)
            self.assertEqual(result[0][0:3],[2,'1','64'])
            self.assertEqual(result[0][-1],'one_based_data_row')

    def test_header_sha_exact_bytes_and_eof_without_record_terminator(self):
        header=b'"candidate"\th_patterns\tm_patterns\r\n'
        rows,digest=producer._project(header+b'"0"\t64\t16','HMF')
        self.assertEqual(rows,[[2,'0','64','16','explicit_candidate']])
        self.assertEqual(digest,hashlib.sha256(header).hexdigest())
        self.assertEqual(producer.project_bytes(b'h_patterns\n','HF'),[])

    def test_unknown_duplicate_missing_nonascii_headers_and_selected_decimal(self):
        invalid=[(b'candidate\th_patterns\tunknown_new_quality\n1\t64\tx\n','HF'),
                 (b'h_patterns\th_patterns\n64\t64\n','HF'),
                 (b'candidate\n1\n','HF'),(b'h_patterns\n64\n','HMF'),
                 (b'h_patterns\t\xff\n64\tx\n','HF'),
                 (b'h_patterns\n\xff\n','HF'),(b'h_patterns\n1e2\n','HF'),
                 (b'h_patterns\n12345678901\n','HF'),
                 (b'h_patterns\tm_patterns\n64\t1\n','HF')]
        for raw,scheme in invalid:
            with self.subTest(raw=raw[:30],scheme=scheme),self.assertRaises(producer.ProjectionError):
                producer.project_bytes(raw,scheme)

    def test_malformed_quotes_width_blank_records_and_lone_cr_rejected(self):
        invalid=[b'h_patterns\n"64\n',b'h_patterns\n6"4\n',b'h_patterns\n"64"x\n',
                 b'h_patterns\n64\textra\n',b'candidate\th_patterns\n1\n',
                 b'h_patterns\n\n64\n',b'h_patterns\n64\r',b'']
        for raw in invalid:
            with self.subTest(raw=raw),self.assertRaises(producer.ProjectionError):
                producer.project_bytes(raw,'HF')

    def test_low_bounds_and_builtin_input_types(self):
        for name,cap,raw in (('MAX_FILE_BYTES',1,b'h_patterns\n64\n'),
                             ('MAX_RECORD_BYTES',5,b'h_patterns\n64\n'),
                             ('MAX_FIELD_BYTES',12,b'h_patterns\tf_result\n64\t'+b'X'*13+b'\n'),
                             ('MAX_ROWS',1,b'h_patterns\n64\n32\n')):
            with patch.object(producer,name,cap),self.subTest(name=name),self.assertRaises(producer.ProjectionError):
                producer.project_bytes(raw,'HF')
        for raw in (bytearray(b'h_patterns\n64'), 'h_patterns\n64', None):
            with self.assertRaises(producer.ProjectionError): producer.project_bytes(raw,'HF')

    def test_fixed_versions_roots_schemes_and_python36_standalone_source(self):
        self.assertEqual(len(producer.ROOTS),8)
        self.assertEqual(len(producer.SPECS),32)
        self.assertEqual(len({row[0] for row in producer.ROOTS}),6)
        self.assertEqual(sum(row[0]=='s38417' for row in producer.ROOTS),2)
        self.assertEqual(sum(row[0]=='s35932' for row in producer.ROOTS),2)
        self.assertTrue(all(row[0] not in ('s5378','tv80','s9234','s38584','wb_dma') for row in producer.SPECS))
        source=Path(producer.__file__).read_text()
        tree=ast.parse(source,feature_version=(3,6))
        self.assertFalse(any(isinstance(node,ast.ImportFrom) and node.module and
                            node.module.startswith(('scripts','src')) for node in ast.walk(tree)))


class ProjectionResponseTests(unittest.TestCase):
    def setUp(self):
        files=[]
        for circuit,root,alias,scheme,path in producer.SPECS:
            raw=(b'candidate\th_patterns\tm_patterns\n001\t064\t0\n' if scheme=='HF'
                 else b'candidate\th_patterns\tm_patterns\n \t064\t016\n')
            rows,header=producer._project(raw,scheme)
            files.append(dict(circuit=circuit,coverage_root=root,stage_alias=alias,path=path,
                              sha256=hashlib.sha256(raw).hexdigest(),byte_count=len(raw),header_sha256=header,rows=rows))
        self.payload=dict(status='PASS_SELECTED_CONFIG_METADATA_PROJECTION_ONLY',files=files,file_count=32,
            coverage_root_count=8,total_bytes=sum(row['byte_count'] for row in files),total_rows=32,
            source_identity_scope='circuit+coverage_root+stage_alias+candidate_raw',
            source_file_bytes_read_for_sha_and_structure=True,
            resource=dict(address_space_limit_bytes=1073741824,cpu_limit_s=20,workers=1))
        for flag in ('nonselected_values_decoded','nonselected_values_captured','quality_evaluated',
                     'PASS_or_eligibility_filter_applied','coverage_versions_merged','pre_outcome_certified',
                     'formal_builder_roots_certified','training_release','E36_inventory_emitted',
                     'physical_files_written','raw_source_tables_persisted'):
            self.payload[flag]=False

    def valid(self,payload=None):
        return transport.validate_response(json.dumps(self.payload if payload is None else payload,
                                                      separators=(',',':')).encode('ascii'))

    def test_valid_compact_metadata_response_without_transport_or_actual_files(self):
        self.assertEqual(transport.SOURCE.name,'project_ranking_v6_e38_roster.py')
        with patch('builtins.open',side_effect=AssertionError('CONTENT')), \
                patch('os.open',side_effect=AssertionError('FD')), \
                patch('subprocess.Popen',side_effect=AssertionError('SSH')), \
                patch('socket.socket',side_effect=AssertionError('NETWORK')):
            self.assertTrue(self.valid())

    def test_path_scope_duplicate_quality_fields_sha_and_counts_rejected(self):
        for kind in ('path','scope','duplicate','quality_row','quality_top','file_sha','header_sha',
                     'file_count','root_count','total_bytes','total_rows'):
            changed=copy.deepcopy(self.payload)
            if kind=='path': changed['files'][0]['path']+='_other'
            elif kind=='scope': changed['source_identity_scope']='merged_versions'
            elif kind=='duplicate': changed['files'][1]=copy.deepcopy(changed['files'][0])
            elif kind=='quality_row': changed['files'][0]['total_cycles']=123
            elif kind=='quality_top': changed['quality_values']=[123]
            elif kind=='file_sha': changed['files'][0]['sha256']='A'*64
            elif kind=='header_sha': changed['files'][0]['header_sha256']='bad'
            elif kind=='file_count': changed['file_count']=31
            elif kind=='root_count': changed['coverage_root_count']=7
            else: changed[kind]+=1
            with self.subTest(kind=kind): self.assertFalse(self.valid(changed))

    def test_row_ordinal_fallback_exact_types_and_hf_hmf_m_rejected(self):
        for kind in ('ordinal','bool_ordinal','candidate','h_type','origin','fallback','hf_m','hmf_m','width'):
            changed=copy.deepcopy(self.payload)
            row=changed['files'][0]['rows'][0]
            if kind=='ordinal': row[0]=3
            elif kind=='bool_ordinal': row[0]=True
            elif kind=='candidate': row[1]='1e2'
            elif kind=='h_type': row[2]=64
            elif kind=='origin': row[4]='renumbered'
            elif kind=='fallback': row[4]='one_based_data_row'
            elif kind=='hf_m': row[3]='16'
            elif kind=='hmf_m': changed['files'][1]['rows'][0][3]=''
            else: row.append('quality')
            with self.subTest(kind=kind): self.assertFalse(self.valid(changed))

    def test_flags_resources_duplicates_and_nonstandard_json_rejected(self):
        for key,value in (('training_release',True),('quality_evaluated',0),
                          ('source_file_bytes_read_for_sha_and_structure',False),
                          ('raw_source_tables_persisted',True)):
            changed=copy.deepcopy(self.payload)
            changed[key]=value
            self.assertFalse(self.valid(changed))
        for key,value in (('workers',True),('workers',2),('cpu_limit_s',21),
                          ('address_space_limit_bytes',True),('address_space_limit_bytes',1073741825)):
            changed=copy.deepcopy(self.payload)
            changed['resource'][key]=value
            self.assertFalse(self.valid(changed))
        raw=json.dumps(self.payload,separators=(',',':')).encode('ascii')
        duplicated=raw.replace(b'"status":',b'"status":"duplicate","status":',1)
        self.assertFalse(transport.validate_response(duplicated))
        self.assertFalse(transport.validate_response(b'{"status":NaN}'))


class InjectedDescriptorTests(unittest.TestCase):
    """Simulated POSIX FD API on Windows; never actual Linux evidence."""
    def injected(self,kind='stable'):
        raw=b'abc'
        def info(mode=stat.S_IFREG|0o600,ino=2,links=1,size=3):
            return types.SimpleNamespace(st_dev=1,st_ino=ino,st_mode=mode,st_nlink=links,st_size=size,
                                          st_mtime=1,st_ctime=1,st_mtime_ns=11,st_ctime_ns=12)
        file=info()
        directory=info(mode=stat.S_IFDIR|0o700,ino=1,links=2,size=0)
        stats=[0]
        fstats=[0]
        def fake_stat(name,**kwargs):
            stats[0]+=1
            if kind=='file_link': return info(mode=stat.S_IFLNK|0o777)
            if kind=='hardlink': return info(links=2)
            if kind=='path_change' and stats[0]>1: return info(ino=99)
            return file
        def fake_open(name,flags,**kwargs):
            return {'/':10,'fixture':11,'source.tsv':12}[name]
        def fake_fstat(fd):
            if fd!=12:
                return info(mode=stat.S_IFLNK|0o777) if kind=='parent_link' else directory
            fstats[0]+=1
            if kind=='fd_change' and fstats[0]>1: return info(ino=99)
            if kind=='open_change': return info(ino=99)
            return file
        reads=iter([raw+b'overflow' if kind=='overread' else raw,b''])
        with patch.object(producer.os,'name','posix'), \
                patch.object(producer.os,'O_DIRECTORY',65536,create=True), \
                patch.object(producer.os,'O_NOFOLLOW',131072,create=True), \
                patch.object(producer.os,'stat',side_effect=fake_stat), \
                patch.object(producer.os,'open',side_effect=fake_open), \
                patch.object(producer.os,'fstat',side_effect=fake_fstat), \
                patch.object(producer.os,'read',side_effect=lambda fd,n:next(reads)), \
                patch.object(producer.os,'close') as closed, \
                patch('builtins.open',side_effect=AssertionError('CONTENT_OPEN')):
            try:
                result=producer._read('/fixture/source.tsv',3)
                return result
            finally:
                # Root and current parent descriptors must close on every path;
                # any opened file descriptor closes even when checks fail.
                self.assertIn(unittest.mock.call(10),closed.call_args_list)
                self.assertIn(unittest.mock.call(11),closed.call_args_list)
                if fstats[0]: self.assertIn(unittest.mock.call(12),closed.call_args_list)

    def test_injected_stable_descriptor_bytes_and_sha(self):
        raw,digest=self.injected()
        self.assertEqual(raw,b'abc')
        self.assertEqual(digest,hashlib.sha256(b'abc').hexdigest())

    def test_injected_changed_identity_links_and_overread_fail_closed(self):
        for kind in ('file_link','hardlink','parent_link','path_change','fd_change','open_change','overread'):
            with self.subTest(kind=kind),self.assertRaises(producer.ProjectionError): self.injected(kind)


@unittest.skipUnless(os.name=='posix','POSIX descriptor helper unavailable on Windows; no actual source paths read')
class DescriptorReadTests(unittest.TestCase):
    def test_ordinary_temporary_file_sha_link_and_size_bounds(self):
        with tempfile.TemporaryDirectory(prefix='e38_fixture_') as directory:
            path=Path(directory)/'metadata.tsv'
            path.write_bytes(b'h_patterns\n64\n')
            raw,digest=producer._read(str(path),100)
            self.assertEqual(raw,b'h_patterns\n64\n')
            self.assertEqual(digest,hashlib.sha256(raw).hexdigest())
            with self.assertRaises(producer.ProjectionError): producer._read(str(path),1)
            alias=Path(directory)/'link.tsv'
            alias.symlink_to(path)
            with self.assertRaises(producer.ProjectionError): producer._read(str(alias),100)
            alias.unlink()
            os.link(str(path),str(alias))
            with self.assertRaises(producer.ProjectionError): producer._read(str(path),100)


if __name__=='__main__': unittest.main()
