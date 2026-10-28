"""Virtual source IO only; no actual PDF read, network or tool."""
import io
from pathlib import Path
import stat
import struct
import unittest
from unittest import mock

from src.data import reference_stream_e135_r2 as m
from src.data import prospective_acceptance_materializer_v1 as anchored
from src.data import direct_tessent_acceptance_e104 as direct
from tests.test_hf_credit_artifact_reader_e134 import Files

AUTHORITY = (Path(__file__).resolve().parents[1]/'contracts/reference_size_gate_exception_e135_r2.json').read_bytes()
BOOT = '3ebeb9bb-410c-476c-a000-5c625f590473'


def runtime():
    return dict(hostname='bupt-vncs2',uid=1047,boot_id=BOOT,python_version=[3,6,8],remote_start_monotonic=1000.,
        sampled_peak_rss_swap_bytes=123,child_launches=0,source_writes=0,environment_reads=0,tessent_launches=0,training_release=False)


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.body = b'%PDF-synthetic\n'+b'abc'*30000
        self.fs = Files([dict(path=m.SOURCE)],[self.body])
        self.fs.info[m.SOURCE].st_uid = 0
        self.domain = mock.Mock(peak=123)
        self.domain.sample.return_value = {}
        for patch in (
            mock.patch.object(anchored,'_directory',side_effect=self.fs.directory),
            mock.patch.object(m.os,'stat',side_effect=self.fs.stat),mock.patch.object(m.os,'fstat',side_effect=self.fs.fstat),
            mock.patch.object(m.os,'open',side_effect=self.fs.open),mock.patch.object(m.os,'read',side_effect=self.fs.read),
            mock.patch.object(m.os,'close',side_effect=self.fs.close),mock.patch.object(m.os,'getuid',return_value=1047,create=True),
            mock.patch.object(m.os,'O_NOFOLLOW',131072,create=True),mock.patch.object(m.os,'O_NONBLOCK',262144,create=True),
            mock.patch.object(m.sys,'platform','linux'),mock.patch.object(m.platform,'node',return_value='bupt-vncs2'),
            mock.patch.object(m.time,'monotonic',return_value=1001.),mock.patch.object(direct,'Descendants',return_value=self.domain),
            mock.patch.object(direct.base,'_small',return_value=BOOT.encode('ascii'))):
            patch.start()
            self.addCleanup(patch.stop)
        self.addCleanup(lambda:self.assertEqual(self.fs.handles,{}))

    def stream(self):
        output,error = io.BytesIO(),io.BytesIO()
        ok = m.run(AUTHORITY,output,error,1000.)
        return ok,output.getvalue(),error.getvalue()

    def test_exact_binary_frames_full_sha_no_base64_or_launch(self):
        with mock.patch('subprocess.Popen') as launch,mock.patch.object(m.os,'scandir') as scan:
            ok,raw,error = self.stream()
        launch.assert_not_called()
        scan.assert_not_called()
        self.assertTrue(ok,error)
        n = struct.unpack('!I',raw[:4])[0]
        header = m.decode(raw[4:4+n])
        self.assertEqual(header['body_bytes'],len(self.body))
        self.assertEqual(raw[4+n:4+n+len(self.body)],self.body)
        offset = 4+n+len(self.body)
        length = struct.unpack('!I',raw[offset:offset+4])[0]
        footer = m.decode(raw[offset+4:offset+4+length])
        self.assertEqual(footer['sha256'],m.sha(self.body))
        self.assertEqual(len(raw),offset+4+length)
        self.assertEqual(self.fs.opened,[m.SOURCE])

    def test_preopen_types_links_uid_and_nonempty_even_without_size_cap(self):
        info = self.fs.info[m.SOURCE]
        for key,value in [('st_mode',v) for v in (stat.S_IFLNK,stat.S_IFCHR,stat.S_IFBLK,stat.S_IFIFO,stat.S_IFSOCK,stat.S_IFDIR)]+[
                ('st_nlink',2),('st_uid',1047),('st_size',0)]:
            old = getattr(info,key)
            setattr(info,key,value)
            ok,raw,error = self.stream()
            self.assertFalse(ok)
            diagnostic = m.decode(error.strip())
            self.assertEqual(diagnostic['observed_identity']['st_size'],info.st_size)
            self.assertFalse(diagnostic['header_started'])
            setattr(info,key,old)
        self.assertEqual(self.fs.opened,[])

    def test_short_read_mutation_deadline_memory_and_bad_authority(self):
        self.fs.body[m.SOURCE] = b''
        ok,raw,error = self.stream()
        self.assertFalse(ok)
        self.assertEqual(m.decode(error.strip())['code'],'REFERENCE_SHORT_READ')
        self.assertTrue(m.decode(error.strip())['header_started'])
        self.fs.body[m.SOURCE] = self.body
        self.fs.read_hook = lambda p:setattr(self.fs.info[p],'st_ctime_ns',101)
        self.assertEqual(m.decode(self.stream()[2].strip())['code'],'REFERENCE_CHANGED')
        self.fs.read_hook = None
        self.domain.peak = 536870913
        self.assertFalse(self.stream()[0])
        self.domain.peak = 123
        self.domain.sample.return_value = {7:'child'}
        self.assertFalse(self.stream()[0])
        self.domain.sample.return_value = {}
        with mock.patch.object(m.time,'monotonic',return_value=1060.):
            self.assertFalse(self.stream()[0])
        self.fs.opened.clear()
        self.assertFalse(m.run(AUTHORITY+b' ',io.BytesIO(),io.BytesIO(),1000.))
        self.assertEqual(self.fs.opened,[])

    def test_generated_over32mib_uses_bounded_chunks_counter_sink(self):
        size = 33*1048576+7
        self.fs.info[m.SOURCE].st_size = size
        offsets,max_read,writes = {},[0],[]
        def generated(fd,count):
            max_read[0] = max(max_read[0],count)
            used = offsets.get(fd,0)
            count = min(count,size-used)
            raw = b'x'*count
            if used == 0 and count:
                raw = b'%PDF'+raw[4:]
            offsets[fd] = used+count
            return raw
        def sink(raw):
            writes.append(len(raw))
            return len(raw)
        with mock.patch.object(m.os,'read',side_effect=generated):
            footer = m.stream_file(sink,mock.Mock(),runtime(),{})
        self.assertEqual(footer['body_bytes'],size)
        self.assertLessEqual(max_read[0],65536)
        self.assertLessEqual(max(writes),65536)
        self.assertGreater(sum(writes),size)
        self.assertGreater(len(writes),500)

    def test_exact_scope_reply_and_bounded_error_frame(self):
        m.check_authority(AUTHORITY)
        auth = m.decode(AUTHORITY)
        self.assertEqual(auth['user_reply'],'\u90a3\u5c31\u628a\u95e8\u7981\u5148\u6682\u65f6\u5173\u95ed')
        auth['scope']['source_path'] = '/wrong'
        raw = m.canonical(auth)
        with mock.patch.object(m,'AUTH_SHA',m.sha(raw)):
            with self.assertRaisesRegex(ValueError,'EXACT_ONE_READ_SCOPE'):
                m.check_authority(raw)
        with self.assertRaisesRegex(ValueError,'STREAM_METADATA_CAP'):
            m.frame(mock.Mock(),dict(data='x'*65536),mock.Mock())

    def test_source_parent_replacement_open_flags_and_partial_writes(self):
        parent = m.SOURCE.rsplit('/',1)[0]
        self.fs.read_hook = lambda p:setattr(self.fs.info[parent],'st_ino',999)
        self.assertEqual(m.decode(self.stream()[2].strip())['code'],'REFERENCE_HELD_PARENT_CHANGED')
        self.fs.read_hook = None
        original = self.fs.open
        with mock.patch.object(m.os,'open',side_effect=original) as opened:
            self.assertTrue(self.stream()[0])
        self.assertEqual(opened.call_args[0][1],m.os.O_RDONLY|m.os.O_NOFOLLOW|m.os.O_NONBLOCK)
        count = [0]
        def short_writer(raw):
            n = min(7,len(raw))
            count[0] += n
            return n
        m.send(short_writer,b'x'*100,mock.Mock())
        self.assertEqual(count[0],100)


if __name__ == '__main__':
    unittest.main()
