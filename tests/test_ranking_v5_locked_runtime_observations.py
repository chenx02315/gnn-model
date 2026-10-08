"""Pure/fabricated runtime checks, plus isolated zero-query refusal proofs."""
from copy import deepcopy
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys
import textwrap
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'src/models/ranking_v5_locked_runtime_observations.py'
SPEC = importlib.util.spec_from_file_location('external_runtime_observations', HELPER)
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


def lock_fixture():
    return ''.join(name + '==' + version + '\n' for name, version in runtime.LOCK_PINS).encode()


def observation_fixture():
    return dict(platform='linux', interpreter=runtime.INTERPRETER,
                python_version=(3, 11, 2), cwd=runtime.CWD,
                sys_path=list(runtime.SEARCH_PATHS),
                versions=dict(runtime.LOCK_PINS),
                distribution_roots={name: runtime.SITE_ROOT for name, _ in runtime.LOCK_PINS},
                top_level_origins={name: runtime.SITE_ROOT + '/' + name + '/__init__.py'
                                   for name in ('torch', 'numpy')}, heavy_ml_preloaded=False)


class RuntimeObservationTests(unittest.TestCase):
    def test_exact_local_lock_and_pure_receipt_no_trust_or_ml_claim(self):
        raw = (ROOT / 'requirements/runtime_v2.lock.txt').read_bytes()
        self.assertEqual(runtime.parse_lock_bytes(raw), dict(runtime.LOCK_PINS))
        with (patch.object(runtime.metadata, 'distribution', side_effect=AssertionError('no query')),
              patch.object(runtime.util, 'find_spec', side_effect=AssertionError('no query'))):
            result = runtime.validate_observations(raw, observation_fixture())
        self.assertEqual(result['distribution_count'], 31)
        self.assertEqual(result['dependency_lock_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result['status'], 'PASS_FIXED_RUNTIME_METADATA_ONLY')
        for key in ('observation_provenance_proven', 'dependency_contents_sealed',
                    'transitive_import_origins_verified', 'compiled_extensions_verified',
                    'ml_imported', 'actual_ml_permitted', 'actual_linux_resource_proof',
                    'formal_training_release', 'authentic_user_consent_proven'):
            self.assertIs(result[key], False)
        self.assertEqual(result['actual_fits'], 0)

    def test_lock_bounds_shape_duplicate_aliases_and_exact_pins(self):
        raw = lock_fixture()
        for invalid, token in ((b'', 'BOUND'), (bytearray(raw), 'BOUND'),
                               (b'x' * (runtime.MAX_LOCK_BYTES + 1), 'BOUND'),
                               (b'\xff', 'ENCODING'), (b'#\n' * 129, 'LINES'),
                               (b'#' * 1025, 'LINE_BOUND'),
                               (raw + b'numpy>=2\n', 'PIN_SYNTAX'),
                               (raw + b'NumPy==2.1.3\n', 'DUPLICATE'),
                               (raw + b'typing_extensions==4.16.0\n', 'DUPLICATE'),
                               (raw + b'unknown==1\n', 'EXACT_PINS'),
                               (raw.replace(b'numpy==2.1.3', b'numpy==2.1.4'), 'EXACT_PINS'),
                               (raw.replace(b'numpy==2.1.3\n', b''), 'EXACT_PINS')):
            with self.subTest(token=token), self.assertRaisesRegex(ValueError, token):
                runtime.parse_lock_bytes(invalid)

    def test_strict_observation_runtime_types_and_fields(self):
        for key, value, token in (
                ('platform', 'win32', 'PLATFORM'), ('platform', 1, 'PLATFORM'),
                ('interpreter', '/usr/bin/python', 'INTERPRETER'),
                ('python_version', [3, 11, 2], 'PYTHON'),
                ('python_version', (3, 11, True), 'PYTHON'),
                ('python_version', (3, 11, 3), 'PYTHON'),
                ('cwd', runtime.CWD + '/', 'CWD'),
                ('cwd', runtime.CWD + '/local', 'CWD'),
                ('heavy_ml_preloaded', 0, 'PRELOADED_HEAVY'),
                ('heavy_ml_preloaded', True, 'PRELOADED_HEAVY')):
            observations = observation_fixture(); observations[key] = value
            with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, token):
                runtime.validate_observations(lock_fixture(), observations)
        for observations in ([], {}, dict(observation_fixture(), extra=False)):
            with self.assertRaisesRegex(ValueError, 'OBSERVATION_FIELDS'):
                runtime.validate_observations(lock_fixture(), observations)

    def test_versions_roots_and_origins_exact_sets_and_strict_values(self):
        for key, token in (('versions', 'DISTRIBUTION_SET'),
                           ('distribution_roots', 'ROOT_SET'), ('top_level_origins', 'ORIGIN_SET')):
            for mutation in ('missing', 'extra', 'wrong_type'):
                observations = observation_fixture()
                if mutation == 'missing': observations[key].pop(next(iter(observations[key])))
                elif mutation == 'extra': observations[key]['unknown'] = 'x'
                else: observations[key] = []
                with self.subTest(key=key, mutation=mutation), self.assertRaisesRegex(ValueError, token):
                    runtime.validate_observations(lock_fixture(), observations)
        for value in ('2.1.4', 2, True, None):
            observations = observation_fixture(); observations['versions']['numpy'] = value
            with self.assertRaisesRegex(ValueError, 'VERSION_DRIFT'):
                runtime.validate_observations(lock_fixture(), observations)

    def test_all_distribution_roots_reject_escape_protected_local_and_unknown(self):
        values = (runtime.SITE_ROOT + '/', runtime.SITE_ROOT + '/..',
                  runtime.SITE_ROOT.replace('/venv/', '/venv/./'),
                  runtime.SITE_ROOT.replace('/venv/', '//venv/'),
                  runtime.SITE_ROOT + '-other', runtime.SITE_ROOT + '/torch',
                  '/ssd/cjc/multimode_ate_gnn_v1/x', '/tmp/site-packages',
                  'site-packages', runtime.SITE_ROOT.replace('/', '\\'),
                  runtime.SITE_ROOT + '\x00', ' ' + runtime.SITE_ROOT, None, 123)
        for name, _ in runtime.LOCK_PINS:
            for value in values:
                observations = observation_fixture(); observations['distribution_roots'][name] = value
                with self.subTest(name=name, value=value), self.assertRaisesRegex(ValueError, 'DISTRIBUTION_ROOT'):
                    runtime.validate_observations(lock_fixture(), observations)

    def test_top_level_origins_exact_ordinary_package_spelling(self):
        for name in ('torch', 'numpy'):
            expected = runtime.SITE_ROOT + '/' + name + '/__init__.py'
            for value in (expected + '/', expected.replace('/__init__.py', '/../__init__.py'),
                          expected.replace('/__init__.py', '/./__init__.py'),
                          expected.replace('/' + name + '/', '//' + name + '/'),
                          expected.replace('/__init__.py', '/_C.so'),
                          '/tmp/' + name + '/__init__.py',
                          '/ssd/cjc/multimode_ate_gnn_v1/' + name + '/__init__.py',
                          None, 'built-in', runtime.SITE_ROOT + '/other/__init__.py'):
                observations = observation_fixture(); observations['top_level_origins'][name] = value
                with self.subTest(name=name, value=value), self.assertRaisesRegex(ValueError, 'TOP_LEVEL_ORIGIN'):
                    runtime.validate_observations(lock_fixture(), observations)

    def test_receipt_copies_input_mappings(self):
        observations = observation_fixture()
        result = runtime.validate_observations(lock_fixture(), observations)
        original = deepcopy(result)
        observations['versions'].clear(); observations['distribution_roots'].clear()
        observations['top_level_origins'].clear()
        self.assertEqual(result, original)

    def child(self, body):
        bootstrap = '''
            import importlib.util, pathlib, sys, types
            from unittest.mock import patch
            runtime = types.ModuleType('isolated_observations')
            exec(compile(pathlib.Path(HELPER).read_bytes(), 'sealed://runtime-observations', 'exec'), runtime.__dict__)
            raw = ''.join(name+'=='+version+'\\n' for name,version in runtime.LOCK_PINS).encode()
            '''
        script = 'HELPER = ' + repr(str(HELPER)) + '\n' + textwrap.dedent(bootstrap) + textwrap.dedent(body)
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('METADATA_ONLY_PROOF_OK', result.stdout)

    def test_isolated_bad_runtime_and_preloaded_modules_before_any_queries(self):
        self.child("""
            with patch.object(runtime.metadata,'distribution',side_effect=AssertionError('metadata queried')), patch.object(runtime.util,'find_spec',side_effect=AssertionError('spec queried')):
                for platform,executable,version,cwd,token in (
                    ('win32',runtime.INTERPRETER,(3,11,2),runtime.CWD,'PLATFORM'),
                    ('linux','/usr/bin/python',(3,11,2),runtime.CWD,'INTERPRETER'),
                    ('linux',runtime.INTERPRETER,(3,11,3),runtime.CWD,'PYTHON'),
                    ('linux',runtime.INTERPRETER,(3,11,2),'/tmp','CWD')):
                    with patch.object(sys,'platform',platform),patch.object(sys,'executable',executable),patch.object(sys,'version_info',version),patch.object(runtime.os,'getcwd',return_value=cwd):
                        try: runtime.observe_runtime(raw)
                        except ValueError as error: assert token in str(error)
                        else: raise AssertionError('unexpected pass')
                with patch.object(sys,'platform','linux'),patch.object(sys,'executable',runtime.INTERPRETER),patch.object(sys,'version_info',(3,11,2)),patch.object(runtime.os,'getcwd',return_value=runtime.CWD),patch.object(sys,'path',list(runtime.SEARCH_PATHS)):
                    for root in runtime.HEAVY_ROOTS:
                        for name in (root,root+'.synthetic'):
                            marker = types.ModuleType(name); sys.modules[name] = marker
                            try:
                                try: runtime.observe_runtime(raw)
                                except ValueError as error: assert 'PRELOADED_HEAVY' in str(error)
                                else: raise AssertionError('unexpected pass')
                                assert sys.modules[name] is marker
                            finally: del sys.modules[name]
            print('METADATA_ONLY_PROOF_OK')
        """)

    def test_isolated_mocked_queries_exact_count_and_missing_spec_distribution(self):
        self.child("""
            queries, specs = [], []
            class Distribution:
                def __init__(self,name): self.version = dict(runtime.LOCK_PINS)[name]
                def locate_file(self,path):
                    assert path == ''
                    return pathlib.PurePosixPath(runtime.SITE_ROOT)
            def distribution(name): queries.append(name); return Distribution(name)
            def find_spec(name):
                specs.append(name)
                return types.SimpleNamespace(origin=runtime.SITE_ROOT+'/'+name+'/__init__.py')
            with patch.object(sys,'platform','linux'),patch.object(sys,'executable',runtime.INTERPRETER),patch.object(sys,'version_info',(3,11,2)),patch.object(runtime.os,'getcwd',return_value=runtime.CWD),patch.object(sys,'path',list(runtime.SEARCH_PATHS)),patch.object(runtime.metadata,'distribution',side_effect=distribution),patch.object(runtime.util,'find_spec',side_effect=find_spec):
                result = runtime.observe_runtime(raw)
                assert queries == sorted(dict(runtime.LOCK_PINS)) and specs == ['torch','numpy']
                assert result['ml_imported'] is False and result['actual_ml_permitted'] is False
                assert not runtime._preloaded_heavy()
                with patch.object(runtime.util,'find_spec',return_value=None):
                    try: runtime.observe_runtime(raw)
                    except ValueError as error: assert 'SPEC_MISSING' in str(error)
                    else: raise AssertionError('missing spec permitted')
                with patch.object(runtime.metadata,'distribution',side_effect=runtime.metadata.PackageNotFoundError('synthetic')):
                    try: runtime.observe_runtime(raw)
                    except ValueError as error: assert 'DISTRIBUTION_MISSING' in str(error)
                    else: raise AssertionError('missing distribution permitted')
            print('METADATA_ONLY_PROOF_OK')
        """)

    def test_isolated_search_path_precheck_forbids_queries_and_filesystem_resolution(self):
        self.child("""
            bad_paths = ['', '.', 'relative', '../escape', '/ssd/cjc',
                         '/ssd/cjc/multimode_ate_gnn_v1',
                         '/ssd/cjc/multimode_ate_gnn_v1/lib', '/tmp/site-packages',
                         runtime.SITE_ROOT+'/..', runtime.SITE_ROOT.replace('/venv/','/venv/./'),
                         runtime.SITE_ROOT.replace('/venv/','//venv/'),
                         runtime.SITE_ROOT.replace('/','\\\\'), None, 123]
            with patch.object(sys,'platform','linux'),patch.object(sys,'executable',runtime.INTERPRETER),patch.object(sys,'version_info',(3,11,2)),patch.object(runtime.os,'getcwd',return_value=runtime.CWD),patch.object(runtime.metadata,'distribution',side_effect=AssertionError('metadata queried')),patch.object(runtime.util,'find_spec',side_effect=AssertionError('spec queried')),patch.object(pathlib.Path,'resolve',side_effect=AssertionError('candidate resolved')),patch.object(pathlib.Path,'stat',side_effect=AssertionError('candidate stat')):
                for value in bad_paths:
                    paths = list(runtime.SEARCH_PATHS); paths[-1] = value
                    with patch.object(sys,'path',paths):
                        try: runtime.observe_runtime(raw)
                        except ValueError as error: assert 'SEARCH_PATHS' in str(error), str(error)
                        else: raise AssertionError('bad path allowed')
                for paths in (list(reversed(runtime.SEARCH_PATHS)),list(runtime.SEARCH_PATHS)+['/tmp'],list(runtime.SEARCH_PATHS[:-1]),tuple(runtime.SEARCH_PATHS)):
                    with patch.object(sys,'path',paths):
                        try: runtime.observe_runtime(raw)
                        except ValueError as error: assert 'SEARCH_PATHS' in str(error)
                        else: raise AssertionError('bad path list allowed')
            print('METADATA_ONLY_PROOF_OK')
        """)


if __name__ == '__main__':
    unittest.main()
