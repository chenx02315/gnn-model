"""Finite entry bytes and actual private native graph, synthetic tests only."""
import ast
import base64
from pathlib import Path
import unittest
from unittest import mock
from scripts import e140_entry_candidate as m
from scripts import e140_local_materials as materials
from scripts import e138_source_session as loader

REPO=Path(__file__).resolve().parents[1]


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original=(REPO/'scripts/run_physical_f_clean_replay_e138.py').read_bytes()
        cls.effective=m.build(cls.original).private_sources()[m.KEY]

    def test_exact_origin_effective_reverse_and_new_proposal(self):
        previous=m.previous.build(self.original).private_sources()[m.KEY]
        raw=self.effective
        for old,new,count in reversed(m.REPLACEMENTS):
            self.assertEqual(raw.count(new.encode()),count)
            raw=raw.replace(new.encode(),old.encode())
        self.assertEqual(raw,previous)
        self.assertEqual(materials.origin.sha(self.effective),m.EFFECTIVE_SHA256)
        self.assertEqual(materials.origin.sha((REPO/'contracts/physical_f_clean_replay_proposal_e140_v1.json').read_bytes()),m.PROPOSAL_SHA256)
        ast.parse(self.effective,feature_version=(3,6))

    def test_build_zero_io_compile_and_failclosed(self):
        with mock.patch('builtins.open') as opened,mock.patch('builtins.compile') as compiled:
            m.build(self.original)
            with self.assertRaises(ValueError):m.build(self.original+b' ')
        opened.assert_not_called();compiled.assert_not_called()

    def test_private_actual_e140_graph_default_auth_denies_before_io(self):
        material=materials.prepare().private_bytes()
        sources={n:raw for b in material['roles'].values() for n,raw in b['sources'].items()}
        pins={n:materials.origin.sha(raw) for n,raw in sources.items()}
        rows=[dict(name=n,sha256=pins[n],body_base64=base64.b64encode(sources[n]).decode()) for n in materials.native.SOURCE_ORDER]
        with mock.patch.object(loader,'FROZEN_SOURCE_SHA256',pins),mock.patch.object(loader,'FROZEN_SOURCE_ORDER',materials.native.SOURCE_ORDER),loader.source_session(rows) as loaded:
            facade=mock.Mock()
            namespace=dict(__name__='_TEST_ONLY_E140_entry',E140_MATERIALS=facade)
            exec(compile(self.effective,'<TEST_ONLY_E140>','exec'),namespace)
            self.assertIs(namespace['contract'],loaded['physical_e138_contract'])
            self.assertEqual(namespace['contract'].ROOT,materials.native.ROOT)
            self.assertIsNone(namespace['AUTH_SHA256'])
            self.assertIsNone(namespace['REVIEW_PINS'])
            with mock.patch('pathlib.Path.open') as opened,mock.patch('subprocess.Popen') as spawn:
                with self.assertRaisesRegex(ValueError,'ENTRY_AUTHORITY_PINS_REQUIRED'):namespace['prepare_capture']()
            opened.assert_not_called();spawn.assert_not_called();facade._read.assert_not_called()

    def test_review_schemas_providers_and_clock_lifetime_fix_retained(self):
        text=self.effective.decode()
        self.assertIn('materials=E140_MATERIALS',text)
        self.assertIn('e140-independent-exact-packet-review-request-v1',text)
        self.assertIn('e140-independent-exact-packet-review-v1',text)
        tree=ast.parse(self.effective)
        start=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='start')
        for node in ast.walk(start):
            if isinstance(node,ast.Attribute):self.assertNotEqual(node.attr,'run_role')
            if isinstance(node,ast.Name):self.assertNotEqual(node.id,'_private_capture_clock')
        self.assertIn('clock.capture.contract is contract',text)
        self.assertEqual(m.SOURCE_KEYS,m.previous.SOURCE_KEYS)


if __name__=='__main__':unittest.main()
