import ast
import io
from pathlib import Path
import struct
import base64
import sys
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

    def test_actual_fixed_bundle_hashes_inert_and_restore(self):
        from scripts import run_physical_f_clean_replay_e137 as controller
        repo=Path(__file__).resolve().parents[1]
        order=controller.SOURCES+('physical_engine_ack_e137','physical_engine_selector_e137',
            'physical_stil_dependencies_e137','physical_e137_role2_protocol')
        rows=[]
        for name in order:
            raw=(repo/'src/data'/(name+'.py')).read_bytes()
            rows.append(dict(name=name,sha256=m.sha(raw),body=base64.b64encode(raw).decode('ascii')))
        manifest=m.sha(m.canonical([{k:r[k] for k in ('name','sha256')} for r in rows]))
        original=sys.modules['src.data']
        with self.assertRaisesRegex(ValueError,'ROLE2_TRUSTED_BUNDLE_REVIEW_REQUIRED'):
            with m.inert_source_bundle(rows):pass
        with mock.patch('builtins.open') as opened:
            with m.inert_source_bundle(rows,manifest) as modules:
                self.assertEqual(set(modules),m.BUNDLE_NAMES)
                self.assertIsNone(modules['physical_f_replay_execution_e137'].AUTH_SHA)
                self.assertEqual(modules['physical_engine_selector_e137'].__source_sha256__,m.SELECTOR_SHA256)
        opened.assert_not_called();self.assertIs(sys.modules['src.data'],original)
        bad=list(rows);bad[-1]=dict(rows[-1],body=base64.b64encode(b'changed').decode('ascii'))
        with self.assertRaisesRegex(ValueError,'ROLE2_SOURCE_BYTES'):
            with m.inert_source_bundle(bad,manifest):pass
        self.assertIs(sys.modules['src.data'],original)

    def test_first_call_requires_external_context_before_parsing_or_io(self):
        with self.assertRaisesRegex(ValueError,'ROLE2_TRUSTED_FIRST_CALL_REVIEW_REQUIRED'):
            m.verify_first_call({}, {})
        context=dict(authorization_sha256='0'*64,proposal_sha256='1'*64,role1_stdout_sha256='2'*64,
            clock_sha256='3'*64,role2_payload_sha256='4'*64,nonce='5'*64)
        with self.assertRaisesRegex(ValueError,'ROLE2_EXACT_FIRST_CALL_CONTEXT'):
            m.verify_first_call({},context,m.sha(m.canonical(context)))
        context['authorization_sha256']='49f000fe45de6cfc029ad8a9c1ead5e09edd24321de6062039d638436cce4969'
        from src.data import physical_replay_capture_e137 as capture
        context['proposal_sha256']=capture.PROPOSAL_SHA
        with self.assertRaisesRegex(ValueError,'ROLE2_FIRST_CALL_RAW_HASHES'):
            m.verify_first_call(dict(role1_stdout=b'fake',package_clock=b'fake'),context,m.sha(m.canonical(context)))

    def test_forward_import_cannot_resolve_old_cached_child_and_restores(self):
        import types
        names=frozenset(('old_dependency','forward_user'))
        old=types.ModuleType('src.data.old_dependency');old.SENTINEL='OLD_CACHE'
        previous=sys.modules.get('src.data.old_dependency')
        sys.modules['src.data.old_dependency']=old
        parent=sys.modules['src.data']
        rows=[]
        for name,raw in [('forward_user',b'from .old_dependency import SENTINEL\n'),
                ('old_dependency',b'SENTINEL="NEW_PRIVATE"\n')]:
            rows.append(dict(name=name,sha256=m.sha(raw),body=base64.b64encode(raw).decode('ascii')))
        manifest=m.sha(m.canonical([{k:r[k] for k in ('name','sha256')} for r in rows]))
        try:
            with mock.patch.object(m,'BUNDLE_NAMES',names):
                with self.assertRaises(ModuleNotFoundError):
                    with m.inert_source_bundle(rows,manifest):self.fail('Forward import used cached source')
                self.assertIs(sys.modules['src.data.old_dependency'],old)
                self.assertIs(sys.modules['src.data'],parent)
                ordered=list(reversed(rows))
                digest=m.sha(m.canonical([{k:r[k] for k in ('name','sha256')} for r in ordered]))
                with m.inert_source_bundle(ordered,digest) as modules:
                    self.assertEqual(modules['forward_user'].SENTINEL,'NEW_PRIVATE')
                    self.assertIsNot(sys.modules['src.data.old_dependency'],old)
                self.assertIs(sys.modules['src.data.old_dependency'],old)
        finally:
            if previous is None:sys.modules.pop('src.data.old_dependency',None)
            else:sys.modules['src.data.old_dependency']=previous
