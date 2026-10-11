"""Synthetic narrow-admission tests; never execute installed Torch or TRAIN."""
from contextlib import contextmanager
import hashlib
import importlib.machinery as machinery
import importlib.util
from pathlib import Path
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
def external(name, path):
    module = ModuleType(name)
    exec(compile((ROOT / path).read_bytes(), path, 'exec'), module.__dict__)
    return module

jit = external('synthetic_train_jit_v2_admission', 'src/models/ranking_v5_train_jit_admission_v2.py')
old = external('synthetic_old_context', 'src/models/ranking_v5_locked_runtime_imports.py')
obs = external('synthetic_observation', 'src/models/ranking_v5_locked_runtime_observations.py')


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.base = ModuleType('synthetic_base')
        self.base._RuntimeFinder = old._RuntimeFinder
        self.base.SITE_ROOT = old.SITE_ROOT
        self.finder = None
        self.seen = []
        @contextmanager
        def context(sources, pins, **kwargs):
            observation = kwargs['observation_helper']
            # Fixed entry gate, standing in for old metadata-only context. This
            # mock is not actual metadata provenance or installed-Torch proof.
            observation._search_paths(sys.path)
            self.seen.append(tuple(sys.path))
            self.finder = self.base._RuntimeFinder({}, ModuleType('frozen'), observation, frozenset())
            self.finder._frozen.NAMESPACES = frozenset()
            yield {'status': 'SYNTHETIC_CONTEXT_ONLY', 'formal_training_release': False}
        self.base.controlled_imports = context
        self.root = '/ssd/cjc/gnn_model_ranking_v5_train_20261011_r1/jit_tmp/iwls_aes_core_20260824'
        self.temp = self.root + '/tmpabcd1234'
        # A synthetic snapshot is patched explicitly; production rejects it.
        self.raw = b'answer = 42\n'
        self.digest = hashlib.sha256(self.raw).hexdigest()
        self.patches = [patch.object(sys, 'path', list(obs.SEARCH_PATHS)),
                        patch.dict(jit.os.environ, {'TMPDIR': self.root, 'TMP': self.root, 'TEMP': self.root}),
                        patch.object(tempfile, 'tempdir', self.root),
                        patch.object(jit, '_private'),
                        patch.object(jit, 'GENERATED_BYTES', len(self.raw)),
                        patch.object(jit, 'GENERATED_SHA256', self.digest),
                        patch.object(jit, '_ordinary'),
                        patch.object(jit, '_read', return_value=self.raw),
                        patch.object(jit, '_pinned_modules', side_effect=self.owner)]
        for item in self.patches:
            item.start()
        self.addCleanup(lambda: [item.stop() for item in reversed(self.patches)])
        self.addCleanup(lambda: sys.modules.pop(jit.GENERATED_NAME, None))

    def owner(self, base):
        module = ModuleType('synthetic_instantiator')
        # Construct a non-owning typed fixture; no arbitrary temp source is run.
        module._TEMP_DIR = object.__new__(tempfile.TemporaryDirectory)
        module._TEMP_DIR.name = self.temp
        module.INSTANTIATED_TEMPLATE_DIR_PATH = self.temp
        return module

    def context(self, **kwargs):
        return jit.controlled_imports({}, {}, frozen_helper=ModuleType('frozen'),
            observation_helper=obs, lock_raw=b'synthetic', base_context=self.base,
            jit_root=kwargs.get('jit_root', self.root), generated_raw=kwargs.get('generated_raw', self.raw))

    def load(self):
        spec = self.finder.find_spec(jit.GENERATED_NAME)
        module = importlib.util.module_from_spec(spec)
        sys.modules[jit.GENERATED_NAME] = module
        spec.loader.exec_module(module)
        return module

    def test_exact_snapshot_pass_and_restoration(self):
        original = self.base._RuntimeFinder
        with self.context() as receipt:
            sys.path.append(self.temp)
            module = self.load()
            self.assertEqual(module.answer, 42)
            self.assertFalse(receipt['jit_template_proven'])
            jit.validate_current(receipt)
            self.assertTrue(receipt['jit_template_proven'])
        self.assertTrue(receipt['jit_template_proven'])
        self.assertEqual(receipt['generated_source_sha256'], self.digest)
        self.assertEqual(self.seen, [obs.SEARCH_PATHS])
        self.assertIs(self.base._RuntimeFinder, original)
        self.assertEqual(sys.path, list(obs.SEARCH_PATHS))
        self.assertNotIn(jit.GENERATED_NAME, sys.modules)

    def test_exception_restores_path_and_finder_without_proof(self):
        original = self.base._RuntimeFinder
        with self.assertRaisesRegex(RuntimeError, 'body'):
            with self.context() as receipt:
                sys.path.append(self.temp)
                self.finder.find_spec(jit.GENERATED_NAME)
                raise RuntimeError('body')
        self.assertFalse(receipt['jit_template_proven'])
        self.assertIs(self.base._RuntimeFinder, original)
        self.assertEqual(sys.path, list(obs.SEARCH_PATHS))

    def test_bad_paths_rejected_before_io(self):
        bad = [list(obs.SEARCH_PATHS) + ['/tmp/unknown'],
               [self.temp] + list(obs.SEARCH_PATHS),
               list(obs.SEARCH_PATHS) + [self.temp, self.temp],
               list(obs.SEARCH_PATHS) + [self.root + '/tmpabcdefgh/../tmpabcd1234'],
               list(obs.SEARCH_PATHS) + [object()]]
        for paths in bad:
            with self.assertRaisesRegex(RuntimeError, 'end'):
                with self.context():
                    sys.path[:] = paths
                    with patch.object(jit, '_pinned_modules', side_effect=AssertionError('IO')), \
                         self.assertRaisesRegex(ValueError, 'V5_JIT_(SEARCH_PATHS|TEMP_PATH)'):
                        self.finder.find_spec(jit.GENERATED_NAME)
                    raise RuntimeError('end')
            sys.path[:] = list(obs.SEARCH_PATHS)  # Explicit test-fixture cleanup, not wrapper behavior.

    def test_unknown_module_has_no_temp_pathfinder_fallback(self):
        with self.assertRaisesRegex(RuntimeError, 'end'):
            with self.context():
                sys.path.append(self.temp)
                with patch.object(machinery.PathFinder, 'find_spec', side_effect=AssertionError('fallback')), \
                     self.assertRaises(ModuleNotFoundError):
                    self.finder.find_spec('_remote_module_typed')
                raise RuntimeError('end')
        sys.path[:] = list(obs.SEARCH_PATHS)

    def test_regular_dependency_lookup_only_five_paths(self):
        with self.assertRaisesRegex(RuntimeError, 'end'):
            with self.context():
                sys.path.append(self.temp)
                spec = machinery.ModuleSpec('torch', machinery.SourceFileLoader('torch', old.SITE_ROOT+'/torch/__init__.py'),
                    origin=old.SITE_ROOT+'/torch/__init__.py')
                with patch.object(machinery.PathFinder, 'find_spec', return_value=spec) as lookup, \
                     patch.object(old, '_ordinary'):
                    self.finder.find_spec('torch')
                    self.assertEqual(lookup.call_args.args[1], list(obs.SEARCH_PATHS))
                raise RuntimeError('end')

    def test_missing_execution_and_changed_bytes_fail_proof(self):
        with self.assertRaisesRegex(ValueError, 'GENERATED_PROOF'):
            with self.context():
                sys.path.append(self.temp)
                spec = self.finder.find_spec(jit.GENERATED_NAME)
                sys.modules[jit.GENERATED_NAME] = importlib.util.module_from_spec(spec)
        sys.modules.pop(jit.GENERATED_NAME)
        with self.assertRaisesRegex(ValueError, 'SOURCE_HASH'):
            with self.context():
                sys.path.append(self.temp)
                self.load()
                jit._read.side_effect = ValueError('V5_JIT_SOURCE_HASH')

    def test_bad_root_snapshot_zero_io(self):
        for value in ('/ssd/cjc/multimode_ate_gnn_v1/jit_tmp',
                      '/ssd/cjc/gnn_model_ranking_v5_train_20261010_r2/jit_tmp', self.root+'/..', 1):
            with patch.object(jit, '_ordinary', side_effect=AssertionError('IO')), \
                 self.assertRaisesRegex(ValueError, 'ROOT'):
                with self.context(jit_root=value):
                    pass
        with self.assertRaisesRegex(ValueError, 'SNAPSHOT'):
            with self.context(generated_raw=bytearray(self.raw)):
                pass

    def test_substitution_change_and_textually_similar_path_refused(self):
        with self.assertRaisesRegex(ValueError, 'SNAPSHOT'):
            with self.context(generated_raw=b'answer = 43\n'):
                pass
        with self.assertRaisesRegex(RuntimeError, 'end'):
            with self.context():
                sys.path.append(self.root.replace('/jit_tmp', '//jit_tmp')+'/tmpabcd1234')
                with patch.object(jit, '_pinned_modules', side_effect=AssertionError('IO')), \
                     self.assertRaisesRegex(ValueError, 'TEMP_PATH'):
                    self.finder.find_spec(jit.GENERATED_NAME)
                raise RuntimeError('end')

    def test_temp_owner_mismatch_and_missing_generated_dir(self):
        for wrong in (self.temp+'x', None):
            owner = self.owner(self.base)
            owner.INSTANTIATED_TEMPLATE_DIR_PATH = wrong
            with self.assertRaisesRegex(RuntimeError, 'end'):
                with self.context():
                    sys.path.append(self.temp)
                    with patch.object(jit, '_pinned_modules', return_value=owner), \
                         self.assertRaisesRegex(ValueError, 'TEMP_OWNER'):
                        self.finder.find_spec(jit.GENERATED_NAME)
                    raise RuntimeError('end')
            sys.path[:] = list(obs.SEARCH_PATHS)
        with self.assertRaisesRegex(ValueError, 'GENERATED_IMPORT'):
            with self.context():
                self.finder.find_spec(jit.GENERATED_NAME)

    def test_presave_identity_verifier_and_foreign_cache_preserved(self):
        foreign = ModuleType(jit.GENERATED_NAME)
        with self.assertRaisesRegex(ValueError, 'GENERATED_PROOF'):
            with self.context() as receipt:
                sys.path.append(self.temp)
                self.load()
                with self.assertRaisesRegex(ValueError, 'VERIFY_RECEIPT'):
                    jit.validate_current(dict(receipt))
                jit.validate_current(receipt)
                sys.modules[jit.GENERATED_NAME] = foreign
        self.assertFalse(receipt['jit_template_proven'])
        self.assertIs(sys.modules[jit.GENERATED_NAME], foreign)
        self.assertEqual(sys.path, list(obs.SEARCH_PATHS))
        with self.assertRaisesRegex(ValueError, 'VERIFY_CONTEXT'):
            jit.validate_current(receipt)

    def test_anomalous_paths_not_silently_reset_and_owned_cache_cleanup(self):
        with self.assertRaisesRegex(ValueError, 'SEARCH_PATHS'):
            with self.context() as receipt:
                sys.path.append(self.temp)
                self.load()
                sys.path.append('/unexpected/nonowned')
        self.assertEqual(sys.path[-1], '/unexpected/nonowned')
        self.assertNotIn(jit.GENERATED_NAME, sys.modules)
        self.assertFalse(receipt['jit_template_proven'])

    def test_early_temp_removal_refused(self):
        with self.assertRaisesRegex(ValueError, 'TEMP_REMOVED'):
            with self.context():
                sys.path.append(self.temp)
                self.load()
                sys.path.pop()

    def test_temp_environment_rejected_before_root_io(self):
        with patch.dict(jit.os.environ, {'TMPDIR': '/tmp/other'}), \
             patch.object(jit, '_private', side_effect=AssertionError('IO')), \
             self.assertRaisesRegex(ValueError, 'TEMP_ENVIRONMENT'):
            with self.context():
                pass

    def test_all_eighteen_exact_task_roots_execute_and_isolate_cleanup(self):
        initial_root, initial_temp = self.root, self.temp
        self.assertEqual(len(jit.TASK_ROOTS), 18)
        for root in sorted(jit.TASK_ROOTS):
            self.root, self.temp = root, root+'/tmpabcd1234'
            with self.subTest(task=root), patch.dict(jit.os.environ,
                    {'TMPDIR': root, 'TMP': root, 'TEMP': root}), patch.object(tempfile, 'tempdir', root):
                original_finder = self.base._RuntimeFinder
                with self.context() as receipt:
                    sys.path.append(self.temp)
                    self.assertEqual(self.load().answer, 42)
                    jit.verify_generated_template(receipt)
                    self.assertEqual(receipt['jit_root'], root)
                    self.assertEqual(receipt['jit_temp_dir'], self.temp)
                    self.assertFalse(receipt['formal_training_release'])
                self.assertTrue(receipt['jit_template_proven'])
                self.assertIs(self.base._RuntimeFinder, original_finder)
                self.assertEqual(sys.path, list(obs.SEARCH_PATHS))
                self.assertNotIn(jit.GENERATED_NAME, sys.modules)
                self.assertFalse(jit._ACTIVE)
        self.root, self.temp = initial_root, initial_temp

    def test_foreign_task_tails_all_eighteen_reject_before_source_io(self):
        initial_root, initial_temp = self.root, self.temp
        roots = sorted(jit.TASK_ROOTS)
        for index, root in enumerate(roots):
            self.root, self.temp = root, root+'/tmpabcd1234'
            foreign = roots[(index+1) % len(roots)]+'/tmpabcd1234'
            with self.subTest(task=root), patch.dict(jit.os.environ,
                    {'TMPDIR': root, 'TMP': root, 'TEMP': root}), patch.object(tempfile, 'tempdir', root):
                with self.assertRaisesRegex(RuntimeError, 'end'):
                    with self.context() as receipt:
                        sys.path.append(foreign)
                        with patch.object(jit, '_pinned_modules', side_effect=AssertionError('IO')), \
                             patch.object(jit, '_read', side_effect=AssertionError('IO')), \
                             self.assertRaisesRegex(ValueError, 'TEMP_PATH'):
                            self.finder.find_spec(jit.GENERATED_NAME)
                        raise RuntimeError('end')
                self.assertFalse(receipt['jit_template_proven'])
            # The context must not delete another task's unowned tail.
            self.assertEqual(sys.path[-1], foreign)
            sys.path[:] = list(obs.SEARCH_PATHS)
        self.root, self.temp = initial_root, initial_temp

    def test_nonexact_root_family_seed_and_protected_roots_zero_io(self):
        prefix = jit.SOURCE_ROOT+'/jit_tmp/'
        denied = [jit.SOURCE_ROOT, jit.SOURCE_ROOT+'/jit_tmp', self.root+'/', self.root+'/..',
            self.root+'/tmpabcd1234', self.root.replace('20261011', '20261010'),
            self.root.replace('_r1/', '_r2/'), self.root.replace('/jit_tmp/', '//jit_tmp/'),
            self.root.replace('/jit_tmp/', '/jit_tmp/../jit_tmp/'),
            '/ssd/cjc/gnn_model_ranking_v5_optimizer_gate_20261011_r1/jit_tmp',
            '/ssd/cjc/multimode_ate_gnn_v1/jit_tmp/iwls_aes_core_20260824',
            '/ssd/cjc/gnn_model_ranking_v5_serial_parent.lock', None, 1, object()]
        denied += [prefix+family+'_20260827' for family in jit.FAMILIES]
        denied += [prefix+family+'_20260823' for family in jit.FAMILIES]
        denied += [prefix+'iscas89_s5378_'+str(seed) for seed in jit.SEEDS]
        denied += [prefix+'iwls_aes_core_'+str(seed)+'.0' for seed in jit.SEEDS]
        with patch.object(jit, '_ordinary', side_effect=AssertionError('IO')), \
             patch.object(jit, '_private', side_effect=AssertionError('IO')), \
             patch.object(jit, '_read', side_effect=AssertionError('IO')), \
             patch.object(jit, '_pinned_modules', side_effect=AssertionError('IO')):
            for root in denied:
                with self.subTest(root=root), self.assertRaisesRegex(ValueError, 'ROOT'):
                    with self.context(jit_root=root):
                        pass

    def test_nested_context_rejects_without_disturbing_active_task(self):
        original = self.base._RuntimeFinder
        with self.context() as receipt:
            active_finder = self.base._RuntimeFinder
            with self.assertRaisesRegex(ValueError, 'CONTEXT'):
                with self.context(): pass
            self.assertIs(self.base._RuntimeFinder, active_finder)
            sys.path.append(self.temp)
            self.load()
            jit.verify_generated_template(receipt)
        self.assertIs(self.base._RuntimeFinder, original)
        self.assertTrue(receipt['jit_template_proven'])

    def test_entry_delegate_exception_restores_finder_and_active_flags(self):
        original = self.base._RuntimeFinder
        @contextmanager
        def fail(*args, **kwargs):
            raise RuntimeError('delegate entry')
            yield
        with patch.object(self.base, 'controlled_imports', fail), self.assertRaisesRegex(RuntimeError, 'delegate entry'):
            with self.context(): pass
        self.assertIs(self.base._RuntimeFinder, original)
        self.assertFalse(jit._ACTIVE)
        self.assertIsNone(jit._VERIFY)

    def test_preloaded_generated_cache_rejected_before_root_filesystem(self):
        with patch.dict(sys.modules, {jit.GENERATED_NAME: None}), \
             patch.object(jit, '_private', side_effect=AssertionError('IO')), \
             self.assertRaisesRegex(ValueError, 'PRELOADED_GENERATED'):
            with self.context(): pass


class ByteAndOriginTests(unittest.TestCase):
    def test_source_protocol_same_as_immutable_optimizer_except_root_policy(self):
        import ast
        before = ast.parse((ROOT/'src/models/ranking_v5_jit_template_admission.py').read_bytes())
        after = ast.parse((ROOT/'src/models/ranking_v5_train_jit_admission_v2.py').read_bytes())
        declarations = lambda tree: {n.name: ast.dump(n, include_attributes=False)
            for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
        old_declarations, new_declarations = declarations(before), declarations(after)
        self.assertEqual(set(old_declarations), set(new_declarations))
        for name in old_declarations:
            if name != '_root': self.assertEqual(old_declarations[name], new_declarations[name], name)
        self.assertEqual(jit.SOURCE_ROOT, '/ssd/cjc/gnn_model_ranking_v5_train_20261011_r1')
        self.assertEqual(jit.FAMILIES, ('iwls_aes_core', 'iscas89_s13207', 'iscas89_s15850',
            'iscas89_s35932', 'iscas89_s38417', 'iwls_spi'))
        self.assertEqual(jit.SEEDS, (20260824, 20260825, 20260826))

    @unittest.skipUnless(sys.platform == 'linux', 'Linux inode/fstat proof is not simulated on Windows')
    def test_bounded_read_real_file_hash_change_and_hardlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'source.py'
            path.write_bytes(b'x = 1\n')  # Test fixture only.
            value = path.resolve().as_posix()
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(jit._read(value, 6, digest), b'x = 1\n')
            with self.assertRaisesRegex(ValueError, 'SOURCE_HASH'):
                jit._read(value, 6, '0'*64)
            with self.assertRaisesRegex(ValueError, 'SOURCE_SIZE'):
                jit._read(value, 5, digest)
            link = Path(directory)/'hardlink.py'
            try:
                link.hardlink_to(path)
            except OSError:
                self.skipTest('Filesystem does not permit test hardlink')
            with self.assertRaisesRegex(ValueError, 'HARDLINK'):
                jit._read(value, 6, digest)

    def test_missing_or_forged_pinned_origin_before_read(self):
        base = ModuleType('base')
        base.SITE_ROOT = old.SITE_ROOT
        name = next(iter(jit.SOURCE_PINS))
        module = ModuleType(name)
        with patch.dict(sys.modules, {name: module}), \
             patch.object(jit, '_read', side_effect=AssertionError('IO')), \
             self.assertRaisesRegex(ValueError, 'PINNED_ORIGIN'):
            jit._pinned_modules(base)

    def test_real_pinned_source_specs_are_checked_and_changed_hash_refused(self):
        base = ModuleType('base')
        base.SITE_ROOT = old.SITE_ROOT
        modules = {}
        for name in jit.SOURCE_PINS:
            origin = base.SITE_ROOT+'/'+name.replace('.', '/')+'.py'
            loader = machinery.SourceFileLoader(name, origin)
            spec = machinery.ModuleSpec(name, loader, origin=origin)
            spec.has_location = True
            modules[name] = importlib.util.module_from_spec(spec)
        instantiator = modules['torch.distributed.nn.jit.instantiator']
        template = modules['torch.distributed.nn.jit.templates.remote_module_template']
        exec(compile('def get_remote_module_template(value): return ""',
                     base.SITE_ROOT+'/'+template.__name__.replace('.', '/')+'.py', 'exec'), template.__dict__)
        instantiator._FILE_PREFIX = '_remote_module_'
        instantiator.get_remote_module_template = template.get_remote_module_template
        with patch.dict(sys.modules, modules), patch.object(jit, '_read', return_value=b'') as reader:
            self.assertIs(jit._pinned_modules(base), modules['torch.distributed.nn.jit.instantiator'])
            self.assertEqual(reader.call_count, 2)
            reader.side_effect = ValueError('V5_JIT_SOURCE_HASH')
            with self.assertRaisesRegex(ValueError, 'SOURCE_HASH'):
                jit._pinned_modules(base)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux symlink checks are not simulated on Windows')
    def test_generated_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)/'source.py'
            source.write_bytes(b'x = 1\n')
            link = Path(directory)/'link.py'
            link.symlink_to(source)
            with self.assertRaisesRegex(ValueError, 'SYMLINK'):
                jit._read(link.as_posix(), 6, hashlib.sha256(b'x = 1\n').hexdigest())

    def test_snapshot_constants_are_exact(self):
        self.assertEqual(jit.GENERATED_BYTES, 2355)
        self.assertEqual(jit.GENERATED_SHA256, '8205b16956fb264841ecd8644784a0d157f87df79b17c16825dc1163433ce5d8')
        self.assertEqual(len(jit.SOURCE_PINS), 2)

    def test_approved_exact_generated_snapshot_compiles_without_execution(self):
        raw = (ROOT/'data/fixtures/ranking_v5_remote_module_non_scriptable_20261010.txt').read_bytes()
        self.assertEqual(len(raw), jit.GENERATED_BYTES)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), jit.GENERATED_SHA256)
        loader = jit._SnapshotLoader('/synthetic/'+jit.GENERATED_NAME+'.py', raw)
        self.assertIs(loader.get_data(loader.path), raw)
        self.assertIsNotNone(loader.get_code(jit.GENERATED_NAME))
        self.assertIsNone(loader._executed_module)  # No generated Torch imports.


if __name__ == '__main__':
    unittest.main()
