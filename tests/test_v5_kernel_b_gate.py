import ast
from pathlib import Path
import tempfile
import unittest
from scripts.build_v5_kernel_b_gate import program


class GateTests(unittest.TestCase):
    def test_pinned_in_memory_program_and_fixed_caps(self):
        source=program(); tree=ast.parse(source)
        self.assertLess(len(source.encode()),60000)
        calls={getattr(n.func,'id',getattr(n.func,'attr','')) for n in ast.walk(tree) if isinstance(n,ast.Call)}
        self.assertFalse(calls & {'open','mkdir','save','Popen','execute','predict_neural'})
        self.assertIn('decoder.eof',source)
        self.assertIn('KERNEL_DEPENDENCY_DRIFT',source)
        self.assertIn('KERNEL_DETERMINISM',source)
        self.assertIn('real_fits=0,retries=0',source)
        self.assertIn('RLIMIT_AS,(8*1024**3,8*1024**3)',source)
        self.assertIn('signal.alarm(180)',source)
        self.assertLess(source.index("os.environ['CUDA_VISIBLE_DEVICES']=''"),source.index('import torch'))

    def test_missing_or_wrong_source_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/'src/models').mkdir(parents=True)
            (root/'src/models/runtime_ranking_v3.py').write_text('bad')
            with self.assertRaises(ValueError): program(root)
