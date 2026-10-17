"""Fabricated bytes only: no frozen source table or result file is opened."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import types
import unittest
from unittest import mock

SOURCE=Path(__file__).resolve().parents[1]/'scripts'/'project_ranking_v6_e40_result_paths.py'
spec=importlib.util.spec_from_file_location('e40_producer_test',str(SOURCE))
p=importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def pin(raw,targets,rows=2):
    result=copy.deepcopy(p.SPECS[0])
    result.update(byte_count=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
        header_sha256=hashlib.sha256(raw[:raw.index(b'\n')+1]).hexdigest(),
        expected_rows=rows,targets=targets)
    return result


HEADER=b'candidate\th_patterns\tm_patterns\th_result\tf_result\tresult_status\n'
TARGET=[[2,'01','09','0','explicit_candidate']]


def fixture(h=b' /declared/h ',f=b'results/f',other=b'\xff'):
    return HEADER+b' 01 \t 09 \t0\t'+h+b'\t'+f+b'\t"ignored\tquality\n""bytes"""\n'+other+b'\t'+other+b'\t'+other+b'\t'+other+b'\t'+other+b'\t'+other+b'\n'


def synthetic_bundle():
    specs=[]
    raws=[]
    for original in p.SPECS:
        s=copy.deepcopy(original)
        explicit=s['targets'][0][4]=='explicit_candidate'
        header=(b'candidate\t' if explicit else b'')+b'h_patterns\tm_patterns\th_result\tf_result\tresult_status\n'
        targets={r[0]:r for r in s['targets']}
        lines=[]
        pad_index=None
        for ordinal in range(2,s['expected_rows']+2):
            if ordinal in targets:
                _,candidate,h,m,_=targets[ordinal]
                cells=([candidate.encode()] if explicit else [])+[h.encode(),m.encode(),b'/declared/h',b'relative/f',b'\xff']
            else:
                cells=([b'\xff'] if explicit else [])+[b'\xff',b'\xff',b'\xff',b'\xff',b'']
                if pad_index is None: pad_index=len(lines)
            lines.append(b'\t'.join(cells)+b'\n')
        raw=header+b''.join(lines)
        padding=s['byte_count']-len(raw)
        assert padding>=0
        lines[pad_index]=lines[pad_index][:-1]+b'x'*padding+b'\n'
        raw=header+b''.join(lines)
        s.update(sha256=hashlib.sha256(raw).hexdigest(),header_sha256=hashlib.sha256(header).hexdigest())
        specs.append(s)
        raws.append(raw)
    return tuple(specs),raws


def payload(specs,raws):
    return dict(status='PASS_TARGET_RESULT_PATH_METADATA_ONLY',files=[p.project_bytes(raw,s) for s,raw in zip(specs,raws)],
        file_count=4,total_bytes=32919,total_rows=73,target_rows=8,
        source_file_bytes_read_for_sha_and_structure=True,quality_evaluated=False,result_files_opened=False,
        source_origin_assigned=False,training_release=False,physical_files_written=False,
        resource=dict(address_space_limit_bytes=1024**3,cpu_limit_s=20,workers=1))


class ProjectionTests(unittest.TestCase):
    def test_frozen_roster(self):
        self.assertEqual(len(p.SPECS),4)
        self.assertEqual(sum(s['byte_count'] for s in p.SPECS),32919)
        self.assertEqual(sum(s['expected_rows'] for s in p.SPECS),73)
        self.assertEqual(sum(len(s['targets']) for s in p.SPECS),8)
        self.assertTrue(all(s['stage_alias']=='hf_refine' for s in p.SPECS))

    def test_dialect_ignored_invalid_utf8_and_trim(self):
        raw=fixture()
        with mock.patch('builtins.open',side_effect=AssertionError('NO_OPEN')):
            result=p.project_bytes(raw,pin(raw,TARGET))
        self.assertEqual(result['row_count'],2)
        self.assertEqual(result['rows'],[dict(source_row=2,candidate='01',h_patterns='09',m_patterns='0',
            candidate_origin='explicit_candidate',h_result='/declared/h',f_result='results/f')])

    def test_quotes_crlf_eof_and_empty_paths(self):
        raw=HEADER.replace(b'\n',b'\r\n')+b'01\t09\t0\t"a""b"\t\tignored'
        result=p.project_bytes(raw,pin(raw,TARGET,1))
        self.assertEqual(result['rows'][0]['h_result'],'a"b')
        self.assertEqual(result['rows'][0]['f_result'],'')

    def test_fallback_preserves_logical_row(self):
        raw=b'h_patterns\th_result\tf_result\n\xff\t\xff\t\xff\n 9 \t\t\n'
        result=p.project_bytes(raw,pin(raw,[[3,'2','9','','one_based_data_row']]))
        self.assertEqual(result['rows'][0]['source_row'],3)
        self.assertEqual(result['rows'][0]['candidate'],'2')

    def test_paths_fail_closed_only_on_targets(self):
        for value in (b'../secret',b'a/./b',b'a\\b',b'a\x01',b'\xff',b'C:/a',b'x'*4097,b'"a\tb"',b'"a\nb"'):
            raw=fixture(h=value)
            with self.subTest(value=value[:16]),self.assertRaises(p.ProjectionError):
                p.project_bytes(raw,pin(raw,TARGET))

    def test_bad_schema_structure_config_and_pins(self):
        base=fixture()
        bads=[base.replace(b'result_status',b'quality_unknown'),base.replace(b'f_result',b'h_result'),
            base.replace(b'f_result',b'm_result'),base+b'\n',base.replace(b' 01 ',b' 02 ',1),
            base.replace(b' 09 ',b'no',1),base.replace(b'\t0\t',b'\t1\t',1),
            base.replace(b'results/f',b'"unterminated'),base.replace(b'results/f',b'a"b'),
            base.replace(b'results/f',b'"a"x'),base.replace(b'results/f',b'a\tb')]
        for raw in bads:
            with self.subTest(raw=raw[:32]),self.assertRaises(p.ProjectionError): p.project_bytes(raw,pin(raw,TARGET))
        for key,value in [('sha256','0'*64),('header_sha256','0'*64),('byte_count',1),('expected_rows',3),('targets',[[4,'3','9','','one_based_data_row']])]:
            s=pin(base,TARGET);s[key]=value
            with self.subTest(key=key),self.assertRaises(p.ProjectionError):p.project_bytes(base,s)
        s=pin(base,TARGET);s['targets']=[[3,'2','9','','one_based_data_row']]+TARGET
        with self.assertRaisesRegex(p.ProjectionError,'TARGET_ROW_ORDER'):p.project_bytes(base,s)

    def test_low_bounds(self):
        raw=fixture()
        for name,value in [('MAX_FILE_BYTES',10),('MAX_FIELD_BYTES',3),('MAX_RECORD_BYTES',4),('MAX_ROWS',1)]:
            with mock.patch.object(p,name,value),self.assertRaises(p.ProjectionError):p.project_bytes(raw,pin(raw,TARGET))

    def test_response_strict_schema_types_order_paths(self):
        specs,raws=synthetic_bundle()
        with mock.patch.object(p,'SPECS',specs):
            good=payload(specs,raws)
            self.assertTrue(p.validate_response(good))
            mutations=[lambda r:r.update(quality_evaluated=True),lambda r:r.update(total_rows=True),
                lambda r:r.update(extra_quality=1),lambda r:r['files'].reverse(),
                lambda r:r['files'][0].update(sha256='0'*64),lambda r:r['files'][0].update(byte_count=True),
                lambda r:r['files'][0]['rows'][0].update(candidate='2'),lambda r:r['files'][0]['rows'][0].update(h_result='../a'),
                lambda r:r['files'][0]['rows'][0].update(f_result=' a '),lambda r:r['files'][0]['rows'][0].update(source_row=True),
                lambda r:r['files'][2]['rows'].reverse(),lambda r:r['resource'].update(workers=True),
                lambda r:r['resource'].update(cpu_limit_s=21),lambda r:r['resource'].update(address_space_limit_bytes=2**31)]
            for mutate in mutations:
                bad=copy.deepcopy(good);mutate(bad)
                self.assertFalse(p.validate_response(bad))

    def test_main_mocked_four_reads_and_no_result_open(self):
        specs,raws=synthetic_bundle()
        fake=types.SimpleNamespace(RLIMIT_AS=1,RLIMIT_CPU=2,RLIM_INFINITY=-1,
            getrlimit=lambda key:(-1,-1),setrlimit=mock.Mock())
        output=io.StringIO()
        with mock.patch.object(p,'SPECS',specs),mock.patch.object(p,'_read',side_effect=[(r,hashlib.sha256(r).hexdigest()) for r in raws]) as reader,\
             mock.patch.object(sys,'argv',['-']),mock.patch.object(sys,'platform','linux'),\
             mock.patch.dict(sys.modules,{'resource':fake}),mock.patch.object(sys,'stdout',output),\
             mock.patch('builtins.open',side_effect=AssertionError('NO_FILE_OPEN')):
            self.assertEqual(p.main(),0)
            result=json.loads(output.getvalue())
            self.assertTrue(p.validate_response(result))
        self.assertEqual([c.args[0] for c in reader.call_args_list],[s['path'] for s in specs])
        self.assertEqual(reader.call_count,4)
        self.assertEqual(fake.setrlimit.call_count,2)

    def test_main_failure_no_partial_result_or_raw_error(self):
        output=io.StringIO()
        fake=types.SimpleNamespace(RLIMIT_AS=1,RLIMIT_CPU=2,RLIM_INFINITY=-1,getrlimit=lambda key:(-1,-1),setrlimit=lambda *a:None)
        with mock.patch.object(sys,'argv',['-']),mock.patch.object(sys,'platform','linux'),mock.patch.dict(sys.modules,{'resource':fake}),\
             mock.patch.object(p,'_read',side_effect=OSError('SECRET_PATH')),mock.patch.object(sys,'stdout',output):
            self.assertEqual(p.main(),2)
        self.assertEqual(json.loads(output.getvalue()),dict(status='FAIL_CLOSED',code='PROJECTION_FAILURE',file_index=0))


class DescriptorTests(unittest.TestCase):
    def info(self,mode=stat.S_IFREG|0o600,nlink=1,size=3,ino=9):
        return types.SimpleNamespace(st_dev=1,st_ino=ino,st_mode=mode,st_nlink=nlink,st_size=size,st_mtime=1,st_ctime=1,st_mtime_ns=1,st_ctime_ns=1)

    def run_reader(self,path_infos=None,fd_infos=None,chunks=None):
        regular=self.info();directory=self.info(mode=stat.S_IFDIR|0o700)
        # Inject descriptor APIs on Windows: does not assert a Linux filesystem run.
        patches=[mock.patch.object(p.os,'name','posix'),mock.patch.object(p.os,'O_NOFOLLOW',131072,create=True),
            mock.patch.object(p.os,'O_DIRECTORY',65536,create=True),mock.patch.object(p.os,'open',side_effect=[10,11,12]),
            mock.patch.object(p.os,'close'),mock.patch.object(p.os,'stat',side_effect=path_infos or [regular,regular]),
            mock.patch.object(p.os,'fstat',side_effect=[directory]+(fd_infos or [regular,regular])),
            mock.patch.object(p.os,'read',side_effect=chunks or [b'abc',b''])]
        import contextlib
        with contextlib.ExitStack() as stack:
            for item in patches:stack.enter_context(item)
            return p._read('/fixture/table.tsv',p.MAX_TOTAL_BYTES)

    def test_mocked_stable_descriptor(self):
        self.assertEqual(self.run_reader(),(b'abc',hashlib.sha256(b'abc').hexdigest()))

    def test_mocked_link_identity_and_overread_rejected(self):
        cases=[dict(path_infos=[self.info(nlink=2)]),dict(path_infos=[self.info(mode=stat.S_IFLNK|0o777)]),
            dict(fd_infos=[self.info(ino=10)]),dict(path_infos=[self.info(),self.info(ino=11)]),dict(chunks=[b'abcd',b''])]
        for kwargs in cases:
            with self.subTest(kwargs=kwargs),self.assertRaises(p.ProjectionError):self.run_reader(**kwargs)


if __name__=='__main__':unittest.main()
