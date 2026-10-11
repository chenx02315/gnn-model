"""Synthetic no-ML protocol tests, not installed Torch or resource proof."""
from contextlib import contextmanager
import hashlib
import importlib.machinery as machinery
import os
from pathlib import Path
import sys
import tempfile
from types import FunctionType, ModuleType
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def external(name, path):
    module = ModuleType(name)
    module.__file__ = str(ROOT / path)
    exec(compile((ROOT / path).read_bytes(), module.__file__, 'exec'), module.__dict__)
    return module


probe = external('synthetic_fx_probe', 'src/models/ranking_v5_fx2trt_probe_admission.py')
REAL_READ = probe._read
old = external('synthetic_fx_base', 'src/models/ranking_v5_locked_runtime_imports.py')
obs = external('synthetic_fx_obs', 'src/models/ranking_v5_locked_runtime_observations.py')


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.base = external('synthetic_fx_context', 'src/models/ranking_v5_locked_runtime_imports.py')
        self.original = self.base._optional_probe
        self.jit = ModuleType('synthetic_jit_delegate')
        self.receipt = {'jit_template_proven': False}
        self.tail = '/ssd/cjc/gnn_model_ranking_v5_optimizer_gate_20261011_r1/jit_tmp/tmpabcd1234'
        self.facade = ModuleType('synthetic_owned_path_facade')
        self.facade.SEARCH_PATHS = obs.SEARCH_PATHS
        def paths(value):
            if type(value) is not list or value not in (list(obs.SEARCH_PATHS), list(obs.SEARCH_PATHS)+[self.tail]):
                raise ValueError('SYNTHETIC_BAD_PATH')
        self.facade._search_paths = paths
        @contextmanager
        def controlled(*args, **kwargs):
            self.assertIs(kwargs['base_context'], self.base)
            code = next(c for c in self.base.controlled_imports.__wrapped__.__code__.co_consts
                        if hasattr(c, 'co_name') and c.co_name == 'optional_probe')
            cell = (lambda value: lambda: value)(self.facade).__closure__[0]
            self.bridge = FunctionType(code, self.base.__dict__, 'optional_probe', (None,), (cell,))
            yield self.receipt
            self.receipt['jit_template_proven'] = True
        self.jit.controlled_imports = controlled
        self.jit.verify_generated_template = lambda r: self.assertIs(r, self.receipt)
        self.origin = self.base.SITE_ROOT+'/torch/_dynamo/trace_rules.py'
        self.raw = (('\n'*3352)+'def add(name):\n'+'    pass\n'*5+'    return bridge(name)\n').encode()
        self.trace = ModuleType(probe.TRACE)
        loader = machinery.SourceFileLoader(probe.TRACE, self.origin)
        self.trace.__spec__ = machinery.ModuleSpec(probe.TRACE, loader, origin=self.origin)
        self.trace.__file__ = self.origin
        self.trace.__loader__ = loader
        exec(compile(self.raw, self.origin, 'exec'), self.trace.__dict__)
        self.patches = [patch.object(sys, 'path', list(obs.SEARCH_PATHS)),
            patch.dict(sys.modules, {probe.TRACE: self.trace}),
            patch.object(probe, '_read', return_value=self.raw)]
        for item in self.patches:
            item.start()
        self.addCleanup(lambda: [p.stop() for p in reversed(self.patches)])

    def context(self):
        return probe.controlled_imports({}, {}, frozen_helper=ModuleType('frozen'),
            observation_helper=obs, lock_raw=b'fixture', base_context=self.base,
            jit_root=self.tail.rsplit('/', 1)[0], generated_raw=b'fixture', jit_admission=self.jit)

    def call(self, name=probe.NAME):
        self.trace.bridge = self.bridge
        return self.trace.add(name)

    def call_all(self):
        for name in probe.NEGATIVE_NAMES:
            self.assertIsNone(self.call(name))

    def test_absent_exact_probe_five_paths_identity_and_restore(self):
        with patch.object(machinery.PathFinder, 'find_spec', return_value=None) as find:
            with self.context() as receipt:
                sys.path.append(self.tail)
                self.assertIs(receipt, self.receipt)
                self.call_all()
                probe.verify_generated_template(receipt)
                self.assertFalse(receipt['fx2trt_probe']['probe_verified'])
                self.assertEqual([c.args for c in find.call_args_list],
                                 [(n, list(obs.SEARCH_PATHS)) for n in probe.NEGATIVE_NAMES])
            self.assertTrue(receipt['jit_template_proven'])
            self.assertTrue(receipt['fx2trt_probe']['probe_verified'])
            self.assertEqual(receipt['fx2trt_probe']['probe_invocations'], 15)
            self.assertIs(self.base._optional_probe, self.original)
            self.assertFalse(probe._ACTIVE)

    def test_missing_invocation_exception_and_nested_entry_restore(self):
        with self.assertRaisesRegex(ValueError, 'PROBE_NOT_OBSERVED'):
            with self.context():
                pass
        self.assertIs(self.base._optional_probe, self.original)
        with self.assertRaisesRegex(RuntimeError, 'body'):
            with self.context() as receipt:
                with self.assertRaisesRegex(ValueError, 'CONTEXT'):
                    with self.context():
                        pass
                raise RuntimeError('body')
        self.assertFalse(receipt['fx2trt_probe']['probe_verified'])
        self.assertIs(self.base._optional_probe, self.original)
        with self.assertRaisesRegex(ValueError, 'VERIFY_CONTEXT'):
            probe.verify_generated_template(receipt)

    def test_cached_root_none_or_submodule_fails_before_lookup(self):
        for name, value in [(probe.NAME, None), (probe.NAME, ModuleType(probe.NAME)),
                            (probe.NAME+'.injected', ModuleType('injected'))]:
            with self.subTest(name=name), patch.dict(sys.modules, {name: value}), \
                 patch.object(machinery.PathFinder, 'find_spec', side_effect=AssertionError('lookup')):
                with self.assertRaisesRegex(ValueError, 'OPTIONAL_CACHE'):
                    with self.context():
                        self.call()
                self.assertIs(self.base._optional_probe, self.original)

    def test_present_or_namespace_spec_fails_closed(self):
        for spec in (object(), machinery.ModuleSpec(probe.NAME, None, is_package=True)):
            with patch.object(machinery.PathFinder, 'find_spec', return_value=spec):
                with self.assertRaisesRegex(ValueError, 'OPTIONAL_PRESENT'):
                    with self.context():
                        self.call()

    def test_other_probes_and_package_values_delegate_unchanged(self):
        delegate = lambda *a, **k: ('delegated', a, k)
        self.base._optional_probe = delegate
        # An externally authenticated production base always contains a function.
        with patch.object(machinery.PathFinder, 'find_spec', return_value=None):
            with self.context():
                for name, package in [('arbitrary_unknown', None), ('networkx', None),
                                      ('numpy', None), ('sklearn', None), ('fx2trt_oss.child', None),
                                      ('fx2trt_oss', 'some_package'), (object(), None)]:
                    result = self.base._optional_probe(name, package, observation_helper=self.facade)
                    self.assertEqual(result[0], 'delegated')
                    self.assertEqual(result[1], (name, package))
                self.call_all()
        self.assertIs(self.base._optional_probe, delegate)

    def test_direct_unknown_import_retains_rejection(self):
        frozen = ModuleType('synthetic_frozen'); frozen.NAMESPACES = frozenset()
        finder = old._RuntimeFinder({}, frozen, obs, frozenset())
        with patch.object(machinery.PathFinder, 'find_spec', side_effect=AssertionError('lookup')):
            with self.assertRaises(ModuleNotFoundError):
                finder.find_spec('fx2trt_oss')
            with self.assertRaises(ModuleNotFoundError):
                finder.find_spec('arbitrary_unknown')

    def test_wrong_path_direct_caller_and_wrong_provenance_refuse(self):
        with self.assertRaisesRegex(ValueError, 'PROBE_BRIDGE'):
            with self.context():
                self.base._optional_probe(probe.NAME, observation_helper=self.facade)
        with self.assertRaisesRegex(ValueError, 'SYNTHETIC_BAD_PATH'):
            with self.context():
                sys.path.append('/tmp/unowned')
                self.call()
        sys.path[:] = list(obs.SEARCH_PATHS)
        for change in ('origin', 'loader', 'function', 'globals', 'code'):
            original = dict(self.trace.__dict__)
            if change == 'origin': self.trace.__file__ = '/tmp/trace_rules.py'
            if change == 'loader': self.trace.__loader__ = object()
            if change == 'function': self.trace.add = lambda name: self.bridge(name)
            if change == 'globals':
                self.trace.add = FunctionType(self.trace.add.__code__, dict(self.trace.__dict__))
            if change == 'code':
                other = (('\n'*3352)+'def add(name):\n'+'    pass\n'*5+'    return bridge(name) or 1\n').encode()
                exec(compile(other, self.origin, 'exec'), self.trace.__dict__)
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'TRACE_ORIGIN|CALLER'):
                with self.context():
                    self.call()
            self.trace.__dict__.clear(); self.trace.__dict__.update(original)

    def test_source_hash_failure_restores_without_success(self):
        with patch.object(probe, '_read', side_effect=ValueError('V5_FX2TRT_SOURCE_HASH')):
            with self.assertRaisesRegex(ValueError, 'SOURCE_HASH'):
                with self.context() as receipt:
                    self.call()
        self.assertFalse(receipt['fx2trt_probe']['probe_verified'])
        self.assertIs(self.base._optional_probe, self.original)

    def test_all_fifteen_cache_present_and_submodule_forms(self):
        for name in probe.NEGATIVE_NAMES:
            for cached in (name, name+'.injected'):
                with self.subTest(name=name, cached=cached), patch.dict(sys.modules, {cached: None}), \
                     patch.object(machinery.PathFinder, 'find_spec') as lookup:
                    with self.assertRaisesRegex(ValueError, 'OPTIONAL_CACHE'):
                        with self.context(): self.call(name)
                    lookup.assert_not_called()
            with self.subTest(present=name), patch.object(machinery.PathFinder, 'find_spec', return_value=object()):
                with self.assertRaisesRegex(ValueError, 'OPTIONAL_PRESENT'):
                    with self.context(): self.call(name)
            with self.subTest(submodule=name), patch.object(self.base, '_ORIGINAL_FIND_SPEC', return_value='old'):
                with self.assertRaisesRegex(RuntimeError, 'end'):
                    with self.context():
                        self.assertEqual(self.base._optional_probe(name+'.child', observation_helper=self.facade), 'old')
                        self.assertEqual(self.base._optional_probe(name, 'package', observation_helper=self.facade), 'old')
                        raise RuntimeError('end')

    def test_public_count_forgery_cannot_satisfy_unobserved_probes(self):
        with patch.object(machinery.PathFinder, 'find_spec', return_value=None):
            with self.assertRaisesRegex(ValueError, 'PROBE_NOT_OBSERVED'):
                with self.context() as receipt:
                    self.call()
                    receipt['fx2trt_probe']['probe_counts'] = {n: 1 for n in probe.NEGATIVE_NAMES}
                    receipt['fx2trt_probe']['probe_invocations'] = 15
            self.assertFalse(receipt['fx2trt_probe']['probe_verified'])

    def test_jit_entry_and_exit_failures_restore_probe_and_invalidate_proof(self):
        for stage in ('entry', 'exit'):
            original_delegate = self.jit.controlled_imports
            @contextmanager
            def failure(*args, **kwargs):
                if stage == 'entry': raise RuntimeError('delegate entry')
                with original_delegate(*args, **kwargs) as receipt:
                    yield receipt
                raise RuntimeError('delegate exit')
            with self.subTest(stage=stage), patch.object(self.jit, 'controlled_imports', failure), \
                 patch.object(machinery.PathFinder, 'find_spec', return_value=None):
                with self.assertRaisesRegex(RuntimeError, 'delegate'):
                    with self.context():
                        self.call_all()
                self.assertIs(self.base._optional_probe, self.original)
                self.assertFalse(probe._ACTIVE)
                if stage == 'exit': self.assertFalse(self.receipt['fx2trt_probe']['probe_verified'])

    @unittest.skipUnless(sys.platform == 'linux', 'Linux no-follow/fstat proof is not simulated on Windows')
    def test_real_bounded_reader_hash_regular_hardlink_and_symlink(self):
        raw = b'synthetic pinned source\n'
        digest = hashlib.sha256(raw).hexdigest()
        with tempfile.TemporaryDirectory() as tmp, patch.object(probe, 'TRACE_BYTES', len(raw)), \
             patch.object(probe, 'TRACE_SHA256', digest):
            path = Path(tmp)/'source.py'
            path.write_bytes(raw)
            self.assertEqual(REAL_READ(path.resolve().as_posix()), raw)
            with patch.object(probe, 'TRACE_SHA256', '0'*64), self.assertRaisesRegex(ValueError, 'SOURCE_HASH'):
                REAL_READ(path.resolve().as_posix())
            path.write_bytes(raw+b'x')
            with self.assertRaisesRegex(ValueError, 'SOURCE_FILE'): REAL_READ(path.resolve().as_posix())
            path.write_bytes(raw)
            hard = Path(tmp)/'hard.py'
            os.link(path, hard)
            with self.assertRaisesRegex(ValueError, 'SOURCE_FILE'): REAL_READ(path.resolve().as_posix())
            hard.unlink()
            symbolic = Path(tmp)/'symbolic.py'
            try:
                symbolic.symlink_to(path)
            except OSError:
                if sys.platform == 'linux': raise
            else:
                with self.assertRaisesRegex(ValueError, 'SOURCE_SYMLINK'):
                    REAL_READ(symbolic.absolute().as_posix())


if __name__ == '__main__':
    unittest.main()
