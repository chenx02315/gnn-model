"""No ML/SSH/package data: authenticated byte loading with fake namespaces."""
import hashlib
from contextlib import contextmanager
from importlib.machinery import ModuleSpec
import sys
from types import ModuleType
import unittest
from unittest.mock import patch

from src.models import ranking_v5_freeze_supplement_v2 as loader


class SupplementTests(unittest.TestCase):
    @contextmanager
    def isolated_namespace(self, package, extra=None):
        # Discovery imports the real v2 modules before running these tests.
        # Restore every original identity on exit; do not weaken runtime refusal.
        with patch.dict(sys.modules, {'src.models': package}):
            for path in loader.FILES:
                sys.modules.pop(path[:-3].replace('/', '.'), None)
            if extra:
                sys.modules.update(extra)
            yield

    def fixtures(self):
        sources = {p: b'value = 42\n' for p in loader.FILES}
        return sources, {p: hashlib.sha256(b).hexdigest() for p, b in sources.items()}

    def namespace(self):
        package = ModuleType('src.models')
        package.__path__ = []
        package.__spec__ = ModuleSpec('src.models', loader=None,
                                      origin='sealed://namespace/src.models', is_package=True)
        return package

    def test_authenticate_all_before_compile(self):
        sources, pins = self.fixtures()
        for path in loader.FILES:
            changed = dict(pins, **{path: '0' * 64})
            with self.subTest(path=path), patch('builtins.compile') as compiler:
                with self.assertRaisesRegex(ValueError, 'SOURCE_SHA'):
                    with loader.authenticated_supplements(sources, changed):
                        self.fail('entered')
                compiler.assert_not_called()

    def test_exact_set_and_resource_bounds(self):
        sources, pins = self.fixtures()
        for changed in ({}, dict(sources, arbitrary=b'pass'),
                        dict(sources, **{loader.FILES[0]: b'x' * (loader.SOURCE_MAX_BYTES + 1)})):
            with self.assertRaises(ValueError):
                loader.validate_sources(changed, pins)
        sources = {p: b'x' * loader.SOURCE_MAX_BYTES for p in loader.FILES}
        pins = {p: hashlib.sha256(b).hexdigest() for p, b in sources.items()}
        with self.assertRaisesRegex(ValueError, 'TOTAL_BOUND'):
            loader.validate_sources(sources, pins)

    def test_requires_sealed_core_context(self):
        sources, pins = self.fixtures()
        with self.assertRaisesRegex(ValueError, 'CORE_CONTEXT_REQUIRED'):
            with loader.authenticated_supplements(sources, pins):
                self.fail('entered')

    def test_success_and_exception_cleanup_preserve_old_identity(self):
        sources, pins = self.fixtures()
        for raises in (False, True):
            package = self.namespace()
            sentinel = object()
            package.ranking_v5_real_artifact_store = sentinel
            with self.isolated_namespace(package):
                try:
                    with loader.authenticated_supplements(sources, pins) as loaded:
                        self.assertEqual(set(loaded), set(loader.FILES))
                        self.assertTrue(all(m.value == 42 for m in loaded.values()))
                        self.assertIs(package.ranking_v5_real_artifact_store, sentinel)
                        if raises:
                            raise RuntimeError('synthetic')
                except RuntimeError:
                    self.assertTrue(raises)
                for path in loader.FILES:
                    name = path[:-3].replace('/', '.')
                    self.assertNotIn(name, sys.modules)
                    self.assertNotIn(name.rsplit('.', 1)[1], package.__dict__)
                self.assertIs(package.ranking_v5_real_artifact_store, sentinel)

    def test_compile_failure_cleans_partially_loaded_modules(self):
        sources, pins = self.fixtures()
        sources[loader.FILES[2]] = b'broken syntax!'
        pins[loader.FILES[2]] = hashlib.sha256(sources[loader.FILES[2]]).hexdigest()
        package = self.namespace()
        with self.isolated_namespace(package):
            with self.assertRaises(SyntaxError):
                with loader.authenticated_supplements(sources, pins):
                    self.fail('entered')
            for path in loader.FILES:
                self.assertNotIn(path[:-3].replace('/', '.'), sys.modules)

    def test_preloaded_new_name_refuses_without_replacement(self):
        sources, pins = self.fixtures()
        package = self.namespace()
        name = loader.FILES[0][:-3].replace('/', '.')
        sentinel = ModuleType(name)
        with self.isolated_namespace(package, {name: sentinel}):
            with self.assertRaisesRegex(ValueError, 'PRELOADED'):
                with loader.authenticated_supplements(sources, pins):
                    self.fail('entered')
            self.assertIs(sys.modules[name], sentinel)

    def test_discovery_preloads_are_isolated_and_restored(self):
        sources, pins = self.fixtures()
        sentinels = {p[:-3].replace('/', '.'): ModuleType(p) for p in loader.FILES}
        with patch.dict(sys.modules, sentinels):
            with self.isolated_namespace(self.namespace()):
                with loader.authenticated_supplements(sources, pins) as loaded:
                    self.assertEqual(len(loaded), 6)
            for name, sentinel in sentinels.items():
                self.assertIs(sys.modules[name], sentinel)
