import ast
import tempfile
import unittest
from pathlib import Path
from scripts.build_v5_head_b_gate import program


class BGateTests(unittest.TestCase):
    def test_program_syntax_fixed_scope_and_no_training(self):
        source=program(); tree=ast.parse(source)
        self.assertLess(len(source.encode()),60000)
        called={getattr(n.func,'id',getattr(n.func,'attr','')) for n in ast.walk(tree) if isinstance(n,ast.Call)}
        self.assertFalse(called & {'open','mkdir','save','fit_neural','step','Popen'})
        self.assertIn('HEAD_FIXED_INTERPRETER',source)
        self.assertIn('HEAD_DEPENDENCY_DRIFT',source)
        self.assertIn('HEAD_RSS_OBSERVED_CAP',source)
        self.assertIn("'remote_artifact_writes':False",source)

    def test_wrong_sources_cannot_form_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/'src/models').mkdir(parents=True)
            (root/'src/models/ranking_v5_head_objective.py').write_text('bad')
            with self.assertRaises(ValueError): program(root)


if __name__=='__main__': unittest.main()
