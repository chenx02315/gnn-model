"""Synthetic wire/disk fixtures and mocked Popen only; never contact A."""
import ast
import copy
import hashlib
import io
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from scripts import stream_reference_e135_r2 as m
from scripts import acceptance_transport_e98 as control
from tests.test_reference_stream_e135_r2 import runtime


def frames(size,digest):
    identity = dict(st_dev=1,st_ino=2,st_mode=stat.S_IFREG|0o600,st_nlink=1,st_uid=0,
        st_size=size,st_mtime_ns=3,st_ctime_ns=3)
    header = dict(schema=m.core.SCHEMA,kind='HEADER',status='READY',source_path=m.core.SOURCE,
        body_bytes=size,identity=identity,runtime=runtime(),authorization_sha256=m.AUTH_SHA)
    parent = dict(identity,st_mode=stat.S_IFDIR|0o755,st_size=4096,st_ino=1,st_nlink=2)
    footer = dict(schema=m.core.SCHEMA,kind='FOOTER',status='COMPLETE',body_bytes=size,sha256=digest,
        identity=identity,parent_identity=parent,whole_file_hashed=True,file_identity_stable=True,
        parent_anchor_stable=True,remote_end_monotonic=1001.,sampled_peak_rss_swap_bytes=123)
    return header,footer


def frame(value):
    raw = m.canonical(value)
    return struct.pack('!I',len(raw))+raw


def wire(body=b'%PDF-synthetic-body',mutate=None):
    header,footer = frames(len(body),m.sha(body))
    if mutate:
        mutate(header,footer)
    return frame(header)+body+frame(footer)


class GeneratedWire(object):
    """Generate >32MiB without a single allocation larger than a wire chunk."""
    def __init__(self,size):
        digest = hashlib.sha256()
        used = 0
        while used < size:
            raw = self.body(used,min(65536,size-used))
            digest.update(raw)
            used += len(raw)
        header,footer = frames(size,digest.hexdigest())
        self.header,self.footer = frame(header),frame(footer)
        self.size,self.offset,self.max_request = size,0,0
    @staticmethod
    def body(offset,count):
        prefix = b'%PDF'
        if offset < 4:
            part = prefix[offset:min(4,offset+count)]
            return part+b'x'*(count-len(part))
        return b'x'*count
    def read(self,count):
        self.max_request = max(self.max_request,count)
        if self.offset < len(self.header):
            raw = self.header[self.offset:self.offset+count]
        elif self.offset < len(self.header)+self.size:
            offset = self.offset-len(self.header)
            raw = self.body(offset,min(count,self.size-offset))
        else:
            offset = self.offset-len(self.header)-self.size
            raw = self.footer[offset:offset+count]
        self.offset += len(raw)
        return raw


class FakeProcess(object):
    def __init__(self,raw,stderr=b''):
        self.stdin,self.stdout,self.stderr = io.BytesIO(),io.BytesIO(raw),io.BytesIO(stderr)
        self.returncode = 0
        self.killed = False
    def poll(self):
        return self.returncode
    def wait(self,timeout=None):
        return self.returncode
    def kill(self):
        self.killed = True
        self.returncode = -9


class ReceiveTests(unittest.TestCase):
    def test_complete_receive_disk_rehash_exclusive_publication(self):
        body = b'%PDF-synthetic-body'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = m.receive(io.BytesIO(wire(body)),root,mock.Mock(),lambda:len(body)+m.core.RESERVE)
            self.assertTrue(result['whole_disk_rehashed'])
            self.assertEqual((root/'reference.partial').read_bytes(),body)
            target = m.publish(root,result,mock.Mock())
            self.assertEqual(target.name,m.sha(body)+'.pdf')
            self.assertEqual(target.read_bytes(),body)
            self.assertFalse((root/'reference.partial').exists())
            self.assertEqual(target.stat().st_nlink,1)
            self.assertTrue((root/'header.frame').exists())
            self.assertTrue((root/'footer.frame').exists())

    def test_over32mib_generated_bounded_stream_and_disk_hash(self):
        size = 33*1048576+11
        generated = GeneratedWire(size)
        with tempfile.TemporaryDirectory() as tmp:
            result = m.receive(generated,Path(tmp),mock.Mock(),lambda:size+m.core.RESERVE)
            self.assertEqual(result['bytes'],size)
            self.assertEqual((Path(tmp)/'reference.partial').stat().st_size,size)
        self.assertLessEqual(generated.max_request,65536)

    def test_header_path_uid_types_size_and_low_disk_before_body(self):
        changes = [lambda h,f:h.update(source_path='/other'),lambda h,f:h['identity'].update(st_uid=1047),
            lambda h,f:h['identity'].update(st_nlink=2),lambda h,f:h['identity'].update(st_mode=stat.S_IFIFO),
            lambda h,f:h.update(body_bytes=0),lambda h,f:h.update(body_bytes=True),
            lambda h,f:h.update(body_bytes=m.core.INT64+1),lambda h,f:h['runtime'].update(python_version=[3,True,8])]
        for change in changes:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                with self.assertRaises(ValueError):
                    m.receive(io.BytesIO(wire(mutate=change)),root,mock.Mock(),lambda:10**18)
                self.assertTrue((root/'header.frame').exists())
                self.assertFalse((root/'reference.partial').exists())
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(ValueError,'DECLARED_SIZE_PLUS_DISK_RESERVE'):
                m.receive(io.BytesIO(wire()),root,mock.Mock(),lambda:m.core.RESERVE)
            self.assertFalse((root/'reference.partial').exists())

    def test_magic_short_footer_hash_trailing_and_frames_preserved(self):
        bad = [wire(body=b'not-a-PDF'),wire()[:1000],wire(mutate=lambda h,f:f.update(sha256='0'*64)),
            wire()+b'extra',struct.pack('!I',65537),struct.pack('!I',4)+b'{']
        for raw in bad:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                with self.assertRaises(ValueError):
                    m.receive(io.BytesIO(raw),root,mock.Mock(),lambda:10**18)
                self.assertTrue((root/'header.frame').exists())
                self.assertEqual(list(root.glob('*.pdf')),[])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(ValueError,'REFERENCE_PDF_MAGIC'):
                m.receive(io.BytesIO(wire(body=b'NOTPDF')),root,mock.Mock(),lambda:10**18)
            self.assertEqual((root/'reference.partial').read_bytes(),b'NOTPDF')

    def test_existing_hash_target_retains_partial_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = m.receive(io.BytesIO(wire()),root,mock.Mock(),lambda:10**18)
            target = root/(result['sha256']+'.pdf')
            control.write_new(target,b'preserve-existing')
            with self.assertRaises(FileExistsError):
                m.publish(root,result,mock.Mock())
            self.assertEqual(target.read_bytes(),b'preserve-existing')
            self.assertTrue((root/'reference.partial').exists())

    def test_disk_mutation_and_deadline_never_publish(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            class Mutating(io.BytesIO):
                def read(self,count):
                    raw = super(Mutating,self).read(count)
                    if not raw and (root/'reference.partial').exists():
                        with (root/'reference.partial').open('r+b') as saved:
                            saved.write(b'!')
                    return raw
            with self.assertRaisesRegex(ValueError,'FULL_DISK_REHASH'):
                m.receive(Mutating(wire()),root,mock.Mock(),lambda:10**18)
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError,'DEADLINE'):
                m.receive(io.BytesIO(wire()),Path(tmp),mock.Mock(side_effect=ValueError('DEADLINE')),lambda:10**18)

    def test_publication_race_rejects_changed_inode_body_retains_partial(self):
        for preserve_mtime in (False,True):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                result = m.receive(io.BytesIO(wire()),root,mock.Mock(),lambda:10**18)
                link = os.link
                def raced(source,target):
                    link(source,target)
                    with open(target,'r+b') as saved:
                        saved.write(b'!')
                    old = result['partial_identity']['st_mtime_ns']
                    os.utime(target,ns=(old,old if preserve_mtime else old+10000))
                with mock.patch.object(m.os,'link',side_effect=raced):
                    code = 'PUBLICATION_FULL_DISK_SHA' if preserve_mtime else 'EXCLUSIVE_PUBLICATION_IDENTITY'
                    with self.assertRaisesRegex(ValueError,code):
                        m.publish(root,result,mock.Mock())
                self.assertTrue((root/'reference.partial').exists())
                self.assertFalse((root/'validated.json').exists())


class TransportTests(unittest.TestCase):
    def test_mocked_process_streams_and_stderr_cap(self):
        for stderr,valid in [(b'',True),(b'e'*65537,False)]:
            proc = FakeProcess(wire(),stderr)
            with tempfile.TemporaryDirectory() as tmp,mock.patch.object(m.subprocess,'Popen',return_value=proc) as launch:
                result = m.stream_transport(['fixed-mocked-ssh'],b'inert',Path(tmp),time.monotonic()+60)
                self.assertEqual(launch.call_count,1)
                self.assertEqual(launch.call_args[1]['creationflags'],getattr(m.subprocess,'CREATE_NO_WINDOW',0))
                self.assertFalse(result['remote_termination_verified'])
                self.assertFalse(result['threads_incomplete'])
                self.assertEqual(result['stderr_overflow'],not valid)
                self.assertLessEqual((Path(tmp)/'stderr.log').stat().st_size,65536)
                if valid:
                    self.assertIsNotNone(result['validation'])
                    self.assertIsNone(result['error'])

    def test_parse_error_kills_only_known_process_no_retry(self):
        proc = FakeProcess(struct.pack('!I',65537))
        with tempfile.TemporaryDirectory() as tmp,mock.patch.object(m.subprocess,'Popen',return_value=proc) as launch:
            result = m.stream_transport(['mock'],b'inert',Path(tmp),time.monotonic()+60)
        self.assertTrue(proc.killed)
        self.assertIsNotNone(result['error'])
        self.assertEqual(launch.call_count,1)

    def test_timeout_kills_known_handle_retains_failed_evidence(self):
        event = threading.Event()
        class Blocked(io.BytesIO):
            def read(self,count):
                event.wait(2)
                return b''
        proc = FakeProcess(b'')
        proc.stdout,proc.stderr = Blocked(),Blocked()
        proc.returncode = None
        def kill():
            proc.killed = True
            proc.returncode = -9
            event.set()
        proc.kill = kill
        with tempfile.TemporaryDirectory() as tmp,mock.patch.object(m.subprocess,'Popen',return_value=proc) as launch:
            now = time.monotonic()
            result = m.stream_transport(['mock-only'],b'inert',Path(tmp),now+.03,now+1.)
        self.assertTrue(result['timeout'])
        self.assertTrue(proc.killed)
        self.assertFalse(result['threads_incomplete'])
        self.assertFalse(result['remote_termination_verified'])
        self.assertEqual(launch.call_count,1)

    def test_bad_review_prevents_process_or_transport_loading(self):
        plan = {key:'pin' for key in m.REVIEW_KEYS}
        plan['payload'] = b'inert'
        with tempfile.TemporaryDirectory() as tmp:
            review = Path(tmp)/'review.json'
            control.write_new(review,control.encode(dict(status='PASS',reviewed={})))
            with mock.patch.object(m,'prepare',return_value=plan),mock.patch.object(control,'load_transport') as load,\
                    mock.patch.object(m.subprocess,'Popen') as launch:
                with self.assertRaisesRegex(ValueError,'INDEPENDENT_EXACT_STREAM_REVIEW'):
                    m.execute(review,'pin')
            load.assert_not_called()
            launch.assert_not_called()

    def test_execute_exact_review_single_intent_and_no_buffered_transport(self):
        plan = {k:'synthetic-pin' for k in m.REVIEW_KEYS}
        plan.update(payload=b'inert',authorization_sha256=m.AUTH_SHA)
        proc = FakeProcess(wire())
        helper = mock.Mock()
        helper.verify_cached_host.return_value = 'cached-A'
        helper.command.return_value = ['fixed-mocked-ssh']
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review = root/'review.json'
            control.write_new(review,control.encode(dict(status='PASS',reviewed={k:plan[k] for k in m.REVIEW_KEYS})))
            def spawn(*args,**kwargs):
                self.assertTrue((root/m.PHASE/'start.json').exists())
                first = m.decode((root/m.PHASE/'start.json').read_bytes())
                self.assertEqual(first['local_deadline_monotonic']-first['local_active_deadline_monotonic'],10.)
                return proc
            with mock.patch.object(m,'prepare',return_value=plan),mock.patch.object(control,'STAGING',root),\
                    mock.patch.object(control,'load_transport',return_value=helper),mock.patch.object(m.subprocess,'Popen',side_effect=spawn) as launch:
                result = m.execute(review,plan['payload_sha256'])
                self.assertEqual(Path(result['pdf_file']).read_bytes(),b'%PDF-synthetic-body')
                with self.assertRaises(FileExistsError):
                    m.execute(review,plan['payload_sha256'])
                self.assertEqual(launch.call_count,1)
            helper.transport.assert_not_called()
            self.assertTrue((root/m.PHASE/'transport.json').exists())
            self.assertTrue((root/m.PHASE/'validated.json').exists())

    def test_prepare_inert_pinned_bundle_ast36(self):
        with mock.patch.object(control,'load_transport') as transport,mock.patch('subprocess.Popen') as launch:
            plan = m.prepare()
        transport.assert_not_called()
        launch.assert_not_called()
        self.assertEqual(len(plan['source_sha256']),16)
        ast.parse(plan['payload'].decode('ascii'),feature_version=(3,6))
        repo = Path(__file__).resolve().parents[1]
        for path in (Path(m.__file__),repo/'src/data/reference_stream_e135_r2.py',Path(__file__),repo/'tests/test_reference_stream_e135_r2.py'):
            ast.parse(path.read_text(encoding='utf-8'),feature_version=(3,6))
        saved = {name:module for name,module in sys.modules.items() if name == 'src' or name.startswith('src.')}
        try:
            with mock.patch('builtins.open') as opened,mock.patch('subprocess.Popen') as launch:
                exec(compile(plan['payload'].decode('ascii').split('ok=sys.modules')[0],'<inert-exact-stream-sources>','exec'),{})
            opened.assert_not_called()
            launch.assert_not_called()
        finally:
            for name in list(sys.modules):
                if name == 'src' or name.startswith('src.'):
                    del sys.modules[name]
            sys.modules.update(saved)


if __name__ == '__main__':
    unittest.main()
