import ast
import hashlib
import json
from pathlib import Path
import unittest
from src.data import prospective_generation_context_e127 as m


class Tests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]
        self.raw = (self.root / 'contracts/prospective_pt_label_repair_authorization_e127_20261027.json').read_bytes()
        self.boot = '3ebeb9bb-410c-476c-a000-5c625f590473'

    def test_inert_local_import(self):
        self.assertIsNone(m.CONFIG)

    def test_exact_user_reply_codepoints_and_proposal_scope(self):
        authority = json.loads(self.raw)
        self.assertEqual(authority['user_reply'], '\u6279\u51c6 E127 \u65b0\u6574\u5305')
        self.assertNotIn('\ufffd', authority['user_reply'])
        proposal_raw = (self.root / authority['proposal_file']).read_bytes()
        self.assertEqual(hashlib.sha256(proposal_raw).hexdigest(), m.PROPOSAL_SHA256)
        self.assertEqual(authority['approved_scope'], json.loads(proposal_raw)['proposed_scope'])

    def test_exact_authority_and_immutable_new_clock(self):
        context = m.build_context(self.raw, self.boot, 123.0, 124.0)
        self.assertEqual(context['PACKAGE_END'], 50523.0)
        self.assertEqual(context['ROOT'], m.ROOT)
        with self.assertRaises(TypeError):
            context['PACKAGE_START'] = 0

    def test_any_authority_byte_change_rejected(self):
        for raw in (self.raw + b' ', b'{}', self.raw.decode('utf-8')):
            with self.assertRaises(ValueError):
                m.build_context(raw, self.boot, 123, 124)

    def test_invalid_or_renewed_bootstrap_rejected(self):
        for start, now in ((123, 122), (123, 154), (True, 1), (0, float('nan')),
                           (-1, 0), (float('inf'), float('inf'))):
            with self.assertRaises(ValueError):
                m.build_context(self.raw, self.boot, start, now)
        with self.assertRaises(ValueError):
            m.build_context(self.raw, 'bad-boot', 123, 124)

    def test_python36_syntax(self):
        ast.parse(Path(m.__file__).read_text(encoding='utf-8'), feature_version=(3, 6))

    def test_reviewed_bootstrap_injection_and_exact_shape(self):
        source = Path(m.__file__).read_bytes()
        context = dict(authority_bytes=self.raw, boot_id=self.boot,
                       start_monotonic=123.0, current_monotonic=124.0)
        namespace = {'__runtime_context__': context}
        exec(compile(source, '<context>', 'exec'), namespace)
        self.assertEqual(namespace['CONFIG']['PACKAGE_START'], 123.0)
        for wrong in (None, {}, dict(context, renewal=True)):
            with self.assertRaises(ValueError):
                exec(compile(source, '<context>', 'exec'), {'__runtime_context__': wrong})


if __name__ == '__main__':
    unittest.main()
