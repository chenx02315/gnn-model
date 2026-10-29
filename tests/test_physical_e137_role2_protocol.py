import ast
import io
from pathlib import Path
import struct
import unittest
from unittest import mock
from src.data import physical_e137_role2_protocol as m


class Tests(unittest.TestCase):
    def test_default_denies_before_all_callbacks(self):
        callback=mock.Mock()
        with self.assertRaisesRegex(ValueError,'ROLE2_ACTUAL_AUTHORITY_NOT_FROZEN'):
            m.Session().run({},callback,callback,callback,callback,callback,callback,callback,callback)
        callback.assert_not_called()

    def test_frames_bounds_eof_raw_first(self):
        stream=io.BytesIO();m.write_frame(stream,b'{invalid',mock.Mock());wire=stream.getvalue()
        saved=[]
        self.assertEqual(m.read_frame(io.BytesIO(wire),mock.Mock(),saved.append),b'{invalid')
        self.assertEqual(saved,[wire])
        self.assertEqual(m.decode_frame_bytes(wire),b'{invalid')
        for raw in (wire+b'extra',wire[:-1],struct.pack('!I',65537)):
            with self.assertRaises(ValueError):m.decode_frame_bytes(raw)
        with self.assertRaisesRegex(ValueError,'ROLE2_FRAME_BOUND'):
            m.read_frame(io.BytesIO(struct.pack('!I',65537)),mock.Mock(),saved.append)

    def test_synthetic_instance_ack_then_one_worker_no_secret_export(self):
        persisted={};seen=[]
        def verifier(package):
            return dict(authorization_sha256='1'*64,clock_sha256='2'*64,role2_payload_sha256='3'*64,
                remote_start=1000.,remote_end=4600.,utc_end=5000.,nonce='4'*64)
        def assembler(package,clock,environment,observed,tick):
            return dict(environment=environment,synthetic=True),b'{"redacted":true}'
        verifier.__source_sha256__='5'*64;assembler.__source_sha256__='6'*64
        def persist(name,raw):
            self.assertNotIn(name,persisted);persisted[name]=raw
        def emit(evidence,redacted,tick):
            self.assertNotIn(b'SECRET',evidence+redacted);seen.append(evidence)
        def review(tick):
            evidence=seen[-1];context=m.ack.evidence_context(evidence)
            raw=m.canonical(dict(schema='e137-engine-instance-review-v1',status='PASS',
                reviewed=dict(context,evidence_sha256=m.sha(evidence))))
            return m.ack.make_ack(evidence),raw,m.sha(raw) # synthetic trusted-channel fixture only
        worker=mock.Mock(return_value={'synthetic':True})
        bootstrap=mock.Mock(return_value=({'PATH':'/usr/bin','LM_LICENSE_FILE':'SECRET'},
            dict(output_bytes=123,output_sha256='7'*64,values_disclosed=False,bootstrap_children=1)))
        session=m.Session()
        with mock.patch.object(m,'AUTH_SHA256','1'*64),mock.patch.object(m,'FIRST_CALL_VERIFIER',verifier),\
                mock.patch.object(m,'FIRST_CALL_VERIFIER_SHA256','5'*64),mock.patch.object(m,'INSTANCE_ASSEMBLER',assembler),\
                mock.patch.object(m,'INSTANCE_ASSEMBLER_SHA256','6'*64):
            args=({},lambda:2000.,lambda:3000.,bootstrap,lambda paths,tick:{},emit,review,persist,worker)
            self.assertEqual(session.run(*args),{'synthetic':True})
            with self.assertRaisesRegex(ValueError,'ROLE2_ONE_ATTEMPT_NO_RETRY'):session.run(*args)
        self.assertEqual(bootstrap.call_count,1);self.assertEqual(worker.call_count,1)
        self.assertIn('instance_consumed.json',persisted)
        self.assertTrue(all(b'SECRET' not in raw for raw in persisted.values()))
        self.assertEqual(worker.call_args.args[2],4400.)

    def test_inert_ast_and_no_release_claim(self):
        raw=Path(m.__file__).read_bytes();ast.parse(raw.decode('utf-8'),feature_version=(3,6))
        ast.parse(Path(__file__).read_text(encoding='utf-8'),feature_version=(3,6))
        with mock.patch('builtins.open') as opened:
            scope=dict(__package__='src.data');exec(compile(raw,'<inert-role2>','exec'),scope)
        opened.assert_not_called();self.assertIsNone(scope['INSTANCE_ASSEMBLER'])
