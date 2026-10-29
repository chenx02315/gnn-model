import ast
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from scripts import run_e137_role2_interactive as m


class Tests(unittest.TestCase):
    def fixture(self):
        metadata=b'{"redacted":true}'
        context=dict({k:str(i+1)*64 for i,k in enumerate(m.ack.HASH_KEYS)},nonce='a'*64,role='execution')
        context['metadata_sha256']=m.ack.sha(metadata)
        evidence=m.ack.make_evidence(context);stream=io.BytesIO()
        for raw in (evidence,metadata):m.protocol.write_frame(stream,raw,mock.Mock())
        return evidence,metadata,stream.getvalue()

    def test_default_denies_before_any_io(self):
        source,target=mock.Mock(),mock.Mock()
        with self.assertRaisesRegex(ValueError,'ROLE2_INTERACTIVE_PACKET_UNRELEASED'):
            m.review_exchange(source,target,Path('unused'),mock.Mock(),mock.Mock())
        source.read.assert_not_called();target.write.assert_not_called()

    def test_private_raw_persisted_before_review_and_ack_no_retry(self):
        evidence,metadata,wire=self.fixture()
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp)/'private'
            def reviewer(e,md):
                self.assertTrue((stage/'evidence.frame').exists());self.assertTrue((stage/'metadata.frame').exists())
                raw=m.ack.canonical(dict(schema='e137-engine-instance-review-v1',status='PASS',
                    reviewed=dict(m.ack.evidence_context(e),evidence_sha256=m.ack.sha(e))))
                return raw,m.ack.sha(raw) # synthetic trust provider, not real reviewer
            with mock.patch.object(m,'RELEASE_PACKET_SHA256','a'*64):
                result=m.review_exchange(io.BytesIO(wire),io.BytesIO(),stage,reviewer,mock.Mock())
                self.assertFalse(result['execution_ready']);self.assertTrue((stage/'ack_consumed.json').exists())
                with self.assertRaises(FileExistsError):m.review_exchange(io.BytesIO(wire),io.BytesIO(),stage,reviewer,mock.Mock())

    def test_untrusted_review_no_ack_sent(self):
        evidence,metadata,wire=self.fixture();target=io.BytesIO()
        with tempfile.TemporaryDirectory() as tmp,mock.patch.object(m,'RELEASE_PACKET_SHA256','a'*64):
            with self.assertRaises(ValueError):
                m.review_exchange(io.BytesIO(wire),target,Path(tmp)/'private',lambda e,md:(b'{}',None),mock.Mock())
        self.assertEqual(target.getvalue(),b'')

    def test_ast36(self):
        ast.parse(Path(m.__file__).read_text(encoding='utf-8'),feature_version=(3,6))
        ast.parse(Path(__file__).read_text(encoding='utf-8'),feature_version=(3,6))
        self.assertFalse(m.readiness()['execution_ready'])
