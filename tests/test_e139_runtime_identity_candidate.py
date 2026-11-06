"""Structural wire-identity evidence only; no ownership/readback integration."""
import ast
import hashlib
from pathlib import Path
import sys
import unittest
from unittest import mock

from scripts import e139_runtime_identity_candidate as m

REPO = Path(__file__).resolve().parents[1]


def sha(raw): return hashlib.sha256(raw).hexdigest()


class Tests(unittest.TestCase):
    def setUp(self):
        self.original = {name: (REPO / 'src/data' / (name + '.py')).read_bytes()
                         for name in m.MODULES}
        self.result = m.build(self.original)
        self.effective = self.result.private_sources()

    def test_effective_pins_and_exact_reverse_equivalence(self):
        for name, raw in self.effective.items():
            self.assertEqual(sha(raw), m.EFFECTIVE_PINS[name])
            self.assertEqual(sha(self.original[name]), m.ORIGIN_PINS[name])
            ast.parse(raw, feature_version=(3, 6))
            reverse = raw
            for old, new, count in m.REPLACEMENTS[name]:
                self.assertEqual(self.original[name].count(old.encode('ascii')), count)
                self.assertEqual(raw.count(new.encode('ascii')), count)
                reverse = reverse.replace(new.encode('ascii'), old.encode('ascii'))
            self.assertEqual(reverse, self.original[name])

    def test_schema_literal_producer_consumer_alignment_not_runtime_proof(self):
        def has(name, schema):
            values = {n.value for n in ast.walk(ast.parse(self.effective[name]))
                      if isinstance(n, ast.Constant) and type(n.value) is str}
            self.assertIn(schema, values)
        final = 'e139-final-registered-root-receipt-v1'
        context = 'e139-authenticated-role2-owned-root-context-v1'
        has(m.RECEIPT, final); has(m.JOIN, final)
        has(m.JOIN, context); has(m.EXPORT, context)
        has(m.RUNTIME, 'physical-f-clean-replay-package-clock-e139-v1')
        links = m.schema_inventory()
        self.assertTrue(any(any(x.startswith('OUTSIDE_SUBSET:') for x in row['producers'])
                            for row in links))
        self.assertEqual(len(links), 7)

    def test_fixed_source_pins_and_default_gates_unchanged(self):
        # Full AST equality after reverting only exact listed string constants
        # protects every numeric limit, legacy pin, None gate and algorithm.
        for name in m.MODULES:
            tree = ast.parse(self.effective[name])
            replacements = {new[1:-1]: old[1:-1]
                            for old, new, _ in m.REPLACEMENTS[name]}
            class Restore(ast.NodeTransformer):
                def visit_Constant(self, node):
                    if type(node.value) is str and node.value in replacements:
                        node.value = replacements[node.value]
                    return node
            restored = Restore().visit(tree)
            self.assertEqual(ast.dump(restored), ast.dump(ast.parse(self.original[name])))

    def test_no_io_compile_import_or_registry_mutation_during_build(self):
        before = dict(sys.modules)
        with mock.patch('builtins.open') as opened, mock.patch('builtins.compile') as compiled, \
             mock.patch('subprocess.Popen') as spawn:
            result = m.build(self.original)
        opened.assert_not_called(); compiled.assert_not_called(); spawn.assert_not_called()
        self.assertEqual(dict(sys.modules), before)
        self.assertEqual(result.private_sources(), self.effective)

    def test_candidate_explicitly_incomplete_and_defensive_metadata(self):
        manifest = self.result.public_manifest()
        scope = manifest['candidate_scope']
        self.assertFalse(scope['complete_private_graph']); self.assertFalse(scope['execution_ready'])
        self.assertIn('actual E139 authorization', scope['pending'])
        scope['pending'].clear(); manifest['rules'].clear()
        self.assertTrue(self.result.public_manifest()['rules'])
        self.assertTrue(self.result.public_manifest()['candidate_scope']['pending'])
        inventory = m.schema_inventory(); inventory.clear()
        self.assertEqual(len(m.schema_inventory()), 7)

    def test_drift_missing_and_extra_rejected_original_files_unchanged(self):
        bad = dict(self.original); bad[m.RUNTIME] += b' '
        with self.assertRaises(ValueError): m.build(bad)
        bad = dict(self.original); bad.pop(m.JOIN)
        with self.assertRaises(ValueError): m.build(bad)
        with self.assertRaises(ValueError): m.build(dict(self.original, extra=b'x'))
        for name, raw in self.original.items():
            self.assertEqual((REPO / 'src/data' / (name + '.py')).read_bytes(), raw)


if __name__ == '__main__': unittest.main()
