"""Pure synthetic ACK evidence only; no runtime or identity proof."""
import ast
import copy
from pathlib import Path
import unittest
from unittest import mock
from src.data import physical_engine_ack_e137 as m


class Tests(unittest.TestCase):
    def setUp(self):
        self.bindings = dict({k:str(i+1)*64 for i,k in enumerate(m.HASH_KEYS)},role='execution',nonce='a'*64)
        self.evidence = m.make_evidence(self.bindings)
        self.ack = m.make_ack(self.evidence)
        self.review = m.canonical(dict(schema='e137-engine-instance-review-v1',status='PASS',
            reviewed=dict(self.bindings,evidence_sha256=m.sha(self.evidence))))
        self.trusted = m.sha(self.review)  # Synthetic fixture, not reviewer authentication.

    def test_default_none_denies_even_self_declared_pass(self):
        self.assertIsNone(m.TRUSTED_REVIEW_SHA256)
        with self.assertRaisesRegex(ValueError,'ACK_TRUSTED_REVIEW_SHA_REQUIRED'):
            m.validate_ack(self.ack,self.evidence,self.review)
        with self.assertRaises(ValueError):m.validate_ack(self.ack,self.evidence,self.review,True)

    def test_exact_binding_and_limitations_not_execution_release(self):
        result = m.validate_ack(self.ack,self.evidence,self.review,self.trusted)
        self.assertTrue(result['bindings_matched'])
        for key,value in result.items():
            if key.endswith('_proven') or key in ('execution_ready','deadlines_enforced'):self.assertIs(value,False)
        self.assertEqual(m.make_evidence(dict(reversed(list(self.bindings.items())))),self.evidence)

    def test_every_original_binding_and_nonce_drift_rejected(self):
        for key in m.CONTEXT_KEYS:
            value = m.decode(self.ack)
            value[key] = 'capture' if key == 'role' else 'f'*64
            with self.assertRaises(ValueError):m.validate_ack(m.canonical(value),self.evidence,self.review,self.trusted)
        changed = dict(self.bindings,instance_sha256='f'*64)
        with self.assertRaises(ValueError):m.validate_ack(self.ack,m.make_evidence(changed),self.review,self.trusted)

    def test_no_code_path_commands_or_self_supplied_review_hash(self):
        for key in ('code','paths','commands','trusted_review_sha256'):
            ack = dict(m.decode(self.ack),**{key:self.trusted})
            with self.assertRaises(ValueError):m.validate_ack(m.canonical(ack),self.evidence,self.review,self.trusted)
        for bad in ('A'*64,'a'*63,123):
            with self.assertRaises(ValueError):m.make_evidence(dict(self.bindings,nonce=bad))

    def test_exact_trusted_review_bytes_and_mapping(self):
        with self.assertRaisesRegex(ValueError,'ACK_TRUSTED_REVIEW_BYTES'):
            m.validate_ack(self.ack,self.evidence,self.review,'0'*64)
        review = m.decode(self.review)
        review['reviewed']['original_clock_sha256'] = 'f'*64
        raw = m.canonical(review)
        with self.assertRaisesRegex(ValueError,'ACK_EXACT_REVIEW_MAPPING'):
            m.validate_ack(self.ack,self.evidence,raw,m.sha(raw))

    def test_duplicate_unknown_and_oversized_encoded_frames(self):
        duplicate = self.ack[:-1]+b',"decision":"ACK"}'
        with self.assertRaisesRegex(ValueError,'DUPLICATE_JSON_KEY'):
            m.validate_ack(duplicate,self.evidence,self.review,self.trusted)
        for which in range(3):
            values = [self.ack,self.evidence,self.review];values[which] = b' '*65537
            with self.assertRaises(ValueError):m.validate_ack(*values,self.trusted)
        with self.assertRaises(ValueError):m.make_evidence(dict(self.bindings,code='not allowed'))

    def test_inert_import_ast36_no_io(self):
        raw = Path(m.__file__).read_bytes()
        ast.parse(raw.decode('utf-8'),feature_version=(3,6))
        ast.parse(Path(__file__).read_text(encoding='utf-8'),feature_version=(3,6))
        with mock.patch('builtins.open') as opened:
            namespace = dict(__package__='src.data')
            exec(compile(raw,'<inert-pure-ack>','exec'),namespace)
        opened.assert_not_called()
        self.assertIsNone(namespace['TRUSTED_REVIEW_SHA256'])


if __name__ == '__main__':unittest.main()
