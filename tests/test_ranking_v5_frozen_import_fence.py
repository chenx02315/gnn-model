"""Isolated synthetic import-protocol proofs; no Torch or training execution."""
from pathlib import Path
import subprocess
import sys
import textwrap
import unittest


HELPER = Path(__file__).resolve().parents[1] / 'src/models/ranking_v5_frozen_import_fence.py'
BOOTSTRAP = """
import hashlib, importlib, importlib.util, json, pathlib, sys, tempfile, types
from unittest.mock import patch
spec = importlib.util.spec_from_file_location('external_frozen_fence', HELPER)
fence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fence)
sources = {name: b'# synthetic fixture\\n' for name in fence.FILES}
def pins_for(values):
    return {name: hashlib.sha256(raw).hexdigest() for name, raw in values.items()}
pins = pins_for(sources)
before_modules = dict(sys.modules)
before_meta = list(sys.meta_path)
def unchanged():
    assert sys.meta_path == before_meta
    assert not any(fence._owned(name) for name in sys.modules)
def refuses(values, hashes, token):
    try:
        with fence.sealed_imports(values, hashes):
            raise AssertionError('unexpected entry')
    except ValueError as error:
        assert token in str(error), str(error)
    unchanged()
"""


class FrozenImportFenceTests(unittest.TestCase):
    def child(self, body):
        script = 'HELPER = ' + repr(str(HELPER)) + '\n' + BOOTSTRAP + textwrap.dedent(body)
        result = subprocess.run([sys.executable, '-I', '-c', script],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('SYNTHETIC_PROOF_OK', result.stdout)

    def test_frozen_source_ignores_disk_and_unknown_local_never_falls_through(self):
        self.child("""
            sources['src/models/ranking_v5_single_fit_worker.py'] = b'VALUE = "frozen"\\n'
            with tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                for package in ('src', 'src/models', 'scripts'):
                    (root / package).mkdir(exist_ok=True)
                    (root / package / '__init__.py').write_text('raise AssertionError("disk package")')
                (root / 'src/models/ranking_v5_single_fit_worker.py').write_text('raise AssertionError("disk module")')
                (root / 'src/models/unknown.py').write_text('raise AssertionError("disk unknown")')
                (root / 'scripts/unknown.py').write_text('raise AssertionError("disk unknown")')
                sys.path.insert(0, directory)
                with fence.sealed_imports(sources, pins_for(sources)) as receipt:
                    module = importlib.import_module('src.models.ranking_v5_single_fit_worker')
                    assert module.VALUE == 'frozen'
                    assert module.__file__ == 'sealed://src/models/ranking_v5_single_fit_worker.py'
                    assert module.__spec__.origin == module.__file__
                    assert module.__spec__.loader._code.co_filename == module.__file__
                    for name in fence.NAMESPACES:
                        package = importlib.import_module(name)
                        assert type(package.__path__) is list and package.__path__ == []
                    for name in ('src.models.unknown', 'scripts.unknown', 'src.other', 'scriptsx'):
                        try:
                            importlib.import_module(name)
                        except ModuleNotFoundError as error:
                            assert 'V5_FENCE_' in str(error)
                        else:
                            raise AssertionError(name)
                    assert receipt['status'] == 'SYNTHETIC_GATE_ONLY'
                    assert receipt['actual_ml_permitted'] is False
                sys.path.remove(directory)
            unchanged()
            print('SYNTHETIC_PROOF_OK')
        """)

    def test_all_hashes_checked_before_compile_or_namespace_writes(self):
        self.child("""
            sources['src/models/runtime_ranking_v3.py'] = b'not valid Python !!!'
            pins = pins_for(sources)
            pins['src/models/runtime_training_v2.py'] = '0' * 64
            with patch('builtins.compile', side_effect=AssertionError('compile forbidden')):
                refuses(sources, pins, 'SOURCE_DRIFT')
            print('SYNTHETIC_PROOF_OK')
        """)

    def test_compile_failure_before_namespace_writes(self):
        self.child("""
            sources['src/models/runtime_ranking_v3.py'] = b'not valid Python !!!'
            try:
                with fence.sealed_imports(sources, pins_for(sources)):
                    raise AssertionError('unexpected entry')
            except SyntaxError:
                pass
            unchanged()
            print('SYNTHETIC_PROOF_OK')
        """)

    def test_every_owned_preloaded_module_is_rejected_including_helper(self):
        self.child("""
            for name in ('src', 'src.models', 'src.data.other', 'scripts',
                         'scripts.unknown', 'src.models.ranking_v5_frozen_import_fence'):
                injected = types.ModuleType(name)
                sys.modules[name] = injected
                try:
                    with fence.sealed_imports(sources, pins):
                        raise AssertionError('unexpected entry')
                except ValueError as error:
                    assert 'PRELOADED_LOCAL' in str(error)
                assert sys.modules[name] is injected
                assert sys.meta_path == before_meta
                del sys.modules[name]
            unchanged()
            print('SYNTHETIC_PROOF_OK')
        """)

    def test_preloaded_heavy_roots_and_children_rejected(self):
        self.child("""
            for root in fence.HEAVY_ROOTS:
                for name in (root, root + '.synthetic'):
                    injected = types.ModuleType(name)
                    sys.modules[name] = injected
                    refuses(sources, pins, 'PRELOADED_HEAVY')
                    assert sys.modules[name] is injected
                    del sys.modules[name]
            print('SYNTHETIC_PROOF_OK')
        """)

    def test_heavy_and_other_third_party_imports_blocked_before_execution(self):
        self.child("""
            with tempfile.TemporaryDirectory() as directory:
                for name in tuple(fence.HEAVY_ROOTS) + ('synthetic_third_party',):
                    pathlib.Path(directory, name + '.py').write_text('raise AssertionError("disk execution")')
                sys.path.insert(0, directory)
                for root in fence.HEAVY_ROOTS:
                    sources['src/models/runtime_ranking_v3.py'] = ('import ' + root + '\\nraise AssertionError("after heavy import")').encode()
                    with fence.sealed_imports(sources, pins_for(sources)):
                        try:
                            importlib.import_module('src.models.runtime_ranking_v3')
                        except ModuleNotFoundError as error:
                            assert 'HEAVY_IMPORT' in str(error)
                        else:
                            raise AssertionError('heavy permitted')
                        assert root not in sys.modules
                        try:
                            importlib.import_module('synthetic_third_party')
                        except ModuleNotFoundError as error:
                            assert 'NON_STDLIB_IMPORT' in str(error)
                        else:
                            raise AssertionError('third party permitted')
                sys.path.remove(directory)
            unchanged()
            print('SYNTHETIC_PROOF_OK')
        """)

    def test_input_shape_exact_source_set_names_and_independent_pins(self):
        self.child("""
            refuses([], pins, 'DICTIONARY_REQUIRED')
            refuses(sources, types.MappingProxyType(pins), 'DICTIONARY_REQUIRED')
            for name in ('../bad.py', 'src/models/bad-name.py', 'src\\\\models\\\\bad.py',
                         '/src/models/bad.py', 'src/models/x/__init__.py', 1):
                changed = dict(sources); changed[name] = b'x = 1'
                refuses(changed, pins, 'SOURCE_NAME')
            missing = dict(sources); missing.pop(next(iter(missing)))
            refuses(missing, pins, 'SOURCE_SET')
            extra = dict(sources); extra['src/models/unknown.py'] = b'x = 1'
            refuses(extra, pins, 'SOURCE_SET')
            for pin in ('a' * 63, 'A' * 64, 123, '0' * 64):
                changed = dict(pins); changed[next(iter(changed))] = pin
                refuses(sources, changed, 'SOURCE_DRIFT')
            print('SYNTHETIC_PROOF_OK')
        """)

    def test_file_count_per_file_and_total_bounds(self):
        self.child("""
            for raw in (b'', bytearray(b'x = 1'), b'#' * (fence.MAX_FILE_BYTES + 1)):
                changed = dict(sources); changed[next(iter(changed))] = raw
                refuses(changed, pins, 'SOURCE_BOUND')
            oversized = {name: b'#' * fence.MAX_FILE_BYTES for name in sources}
            refuses(oversized, pins_for(oversized), 'TOTAL_BOUND')
            too_many = dict(sources)
            too_many.update({'src/models/extra_%d.py' % number: b'x = 1' for number in range(3)})
            refuses(too_many, pins, 'FILE_COUNT_BOUND')
            too_many_pins = dict(pins); too_many_pins.update({'x' + str(n): 'a' * 64 for n in range(3)})
            refuses(sources, too_many_pins, 'FILE_COUNT_BOUND')
            print('SYNTHETIC_PROOF_OK')
        """)

    def test_frozen_snapshots_and_cleanup_preserve_unrelated_state(self):
        self.child("""
            name = 'src/models/runtime_ranking_v3.py'
            sources[name] = b'VALUE = "before"\\n'
            pins = pins_for(sources)
            unrelated = types.ModuleType('unrelated_synthetic_marker')
            other_finder = object()
            try:
                with fence.sealed_imports(sources, pins) as receipt:
                    sources[name] = b'raise AssertionError("changed")'
                    pins[name] = '0' * 64
                    assert receipt['sources'][name] != pins[name]
                    for mapping in (receipt, receipt['sources']):
                        try:
                            mapping['x'] = 1
                        except TypeError:
                            pass
                        else:
                            raise AssertionError('mutable receipt')
                    assert importlib.import_module('src.models.runtime_ranking_v3').VALUE == 'before'
                    sys.modules[unrelated.__name__] = unrelated
                    sys.meta_path.append(other_finder)
                    raise RuntimeError('body failure')
            except RuntimeError as error:
                assert str(error) == 'body failure'
            assert sys.modules[unrelated.__name__] is unrelated
            assert sys.meta_path == before_meta + [other_finder]
            assert not any(fence._owned(name) for name in sys.modules)
            sys.meta_path.remove(other_finder)
            del sys.modules[unrelated.__name__]
            unchanged()
            print('SYNTHETIC_PROOF_OK')
        """)

    def test_stdlib_and_relative_local_imports_work(self):
        self.child("""
            sources['src/models/runtime_ranking_v3.py'] = b'from .runtime_training_v2 import VALUE\\nfrom fractions import Fraction\\nRESULT = Fraction(VALUE, 2)\\n'
            sources['src/models/runtime_training_v2.py'] = b'VALUE = 6\\n'
            with fence.sealed_imports(sources, pins_for(sources)):
                assert importlib.import_module('src.models.runtime_ranking_v3').RESULT == 3
            unchanged()
            print('SYNTHETIC_PROOF_OK')
        """)


if __name__ == '__main__':
    unittest.main()
