"""Isolated synthetic import protocol tests; no installed Torch is executed."""
from pathlib import Path
import subprocess
import sys
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = r'''
import hashlib, importlib, importlib.machinery as machinery, pathlib, sys, tempfile, types
from unittest.mock import patch
repo = pathlib.Path(REPO)
def external(name, filename):
    module = types.ModuleType(name)
    exec(compile((repo/filename).read_bytes(),'sealed://'+filename,'exec'),module.__dict__)
    return module
frozen = external('external_frozen','src/models/ranking_v5_frozen_import_fence.py')
observations = external('external_observations','src/models/ranking_v5_locked_runtime_observations.py')
runtime = external('external_runtime_imports','src/models/ranking_v5_locked_runtime_imports.py')
sources = {name:b'# synthetic source\n' for name in frozen.FILES}
def hashes(values): return {name:hashlib.sha256(raw).hexdigest() for name,raw in values.items()}
pins = hashes(sources)
lock_raw = ''.join(name+'=='+version+'\n' for name,version in observations.LOCK_PINS).encode()
query_calls = []
def fresh(raw):
    query_calls.append(raw)
    return observations.validate_observations(raw,dict(platform='linux',interpreter=observations.INTERPRETER,
        python_version=(3,11,2),cwd=observations.CWD,sys_path=list(observations.SEARCH_PATHS),
        versions=dict(observations.LOCK_PINS),
        distribution_roots={name:observations.SITE_ROOT for name,_ in observations.LOCK_PINS},
        top_level_origins={name:observations.SITE_ROOT+'/'+name+'/__init__.py' for name in ('torch','numpy')},
        heavy_ml_preloaded=False))
cached = set(sys.modules)
real_validate = runtime._validate_existing_module
def synthetic_cached(fullname,module,finder):
    # Windows cached stdlib is a mocked Linux baseline, never a production bypass.
    if fullname in cached: return
    return real_validate(fullname,module,finder)
checked_paths = []
def ordinary(value,*,directory=False):
    assert value.startswith(runtime.SITE_ROOT+'/') or value.startswith(runtime.STDLIB_ROOT+'/')
    checked_paths.append((value,directory))
patches = [patch.object(sys,'platform','linux'),patch.object(sys,'executable',observations.INTERPRETER),
           patch.object(sys,'version_info',(3,11,2)),patch.object(sys,'path',list(observations.SEARCH_PATHS)),
           patch.object(observations.os,'getcwd',return_value=observations.CWD),
           patch.object(observations,'observe_runtime',side_effect=fresh),
           patch.object(runtime,'_validate_existing_module',side_effect=synthetic_cached),
           patch.object(runtime,'_ordinary',side_effect=ordinary)]
for item in patches: item.start()
before_meta = list(sys.meta_path)
def context():
    return runtime.controlled_imports(sources,pins,frozen_helper=frozen,observation_helper=observations,lock_raw=lock_raw)
def unchanged():
    assert sys.meta_path == before_meta
    assert not any(runtime._owned(name) for name in sys.modules)
def refusal(token):
    try:
        with context(): raise AssertionError('unexpected entry')
    except (ValueError,ModuleNotFoundError) as error: assert token in str(error),str(error)
    else: raise AssertionError('unexpected pass')
    unchanged()
def spec_for(name,origin=None,namespace=False):
    if namespace:
        spec = machinery.ModuleSpec(name,None,is_package=True)
        spec.submodule_search_locations = [runtime.SITE_ROOT+'/'+name.replace('.','/')]
        return spec
    if origin is None: origin = runtime.SITE_ROOT+'/'+name.replace('.','/')+'/__init__.py'
    loader = machinery.SourceFileLoader(name,origin)
    spec = machinery.ModuleSpec(name,loader,origin=origin,is_package=True)
    spec.submodule_search_locations = [origin.rsplit('/',1)[0]]
    return spec
'''


class ControlledImportTests(unittest.TestCase):
    def child(self, body):
        script = 'REPO = ' + repr(str(ROOT)) + '\n' + BOOTSTRAP + textwrap.dedent(body)
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('SYNTHETIC_CONTROLLED_IMPORT_OK', result.stdout)

    def test_frozen_source_disk_poison_ignored_fresh_query_and_cleanup(self):
        self.child("""
            sources['src/models/runtime_ranking_v3.py'] = b'VALUE = "frozen"\\n'
            pins = hashes(sources)
            with tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory); path=root/'src/models/runtime_ranking_v3.py'
                path.parent.mkdir(parents=True); path.write_text('raise AssertionError("disk poison")')
                # Real PathFinder can see poison; the local finder never delegates.
                with context() as receipt:
                    assert len(query_calls) == 1
                    module = importlib.import_module('src.models.runtime_ranking_v3')
                    assert module.VALUE == 'frozen'
                    assert module.__file__ == module.__spec__.origin == 'sealed://src/models/runtime_ranking_v3.py'
                    for name in frozen.NAMESPACES:
                        assert importlib.import_module(name).__path__ == []
                    for name in ('src.models.unknown','scripts.unknown','src.other'):
                        try: importlib.import_module(name)
                        except ModuleNotFoundError as error: assert 'UNKNOWN_LOCAL' in str(error)
                        else: raise AssertionError(name)
                    assert receipt['runtime_imports_enabled'] is True
                    assert receipt['formal_training_release'] is False
                    assert receipt['actual_training_proven'] is False
                    try: receipt['sources']['x'] = 'x'
                    except TypeError: pass
                    else: raise AssertionError('mutable receipt')
            unchanged()
            print('SYNTHETIC_CONTROLLED_IMPORT_OK')
        """)

    def test_sha_drift_precedes_compile_runtime_query_and_namespace_writes(self):
        self.child("""
            sources['src/models/runtime_ranking_v3.py'] = b'bad syntax !!!'
            with patch('builtins.compile',side_effect=AssertionError('compile called')):
                refusal('SOURCE_DRIFT')
            assert query_calls == []
            print('SYNTHETIC_CONTROLLED_IMPORT_OK')
        """)

    def test_compile_failure_no_query_or_import_state_change(self):
        self.child("""
            sources['src/models/runtime_ranking_v3.py'] = b'bad syntax !!!'; pins = hashes(sources)
            try:
                with context(): raise AssertionError('unexpected entry')
            except SyntaxError: pass
            unchanged(); assert query_calls == []
            print('SYNTHETIC_CONTROLLED_IMPORT_OK')
        """)

    def test_preloaded_owned_and_heavy_roots_children_fail_before_fresh_queries(self):
        self.child("""
            for name in ('src','scripts','src.models.x','scripts.x'):
                marker = types.ModuleType(name); sys.modules[name]=marker
                try:
                    try:
                        with context(): raise AssertionError('unexpected entry')
                    except ValueError as error: assert 'PRELOADED_LOCAL' in str(error)
                    assert sys.modules[name] is marker and sys.meta_path == before_meta
                finally: del sys.modules[name]
            for root in frozen.HEAVY_ROOTS:
                for name in (root,root+'.synthetic'):
                    marker=types.ModuleType(name); sys.modules[name]=marker
                    refusal('PRELOADED_HEAVY'); assert sys.modules[name] is marker
                    del sys.modules[name]
            assert query_calls == []; unchanged()
            print('SYNTHETIC_CONTROLLED_IMPORT_OK')
        """)

    def test_bad_runtime_and_search_paths_no_fresh_queries(self):
        self.child("""
            with patch.object(sys,'platform','win32'): refusal('PLATFORM')
            with patch.object(sys,'path',list(observations.SEARCH_PATHS)+['/ssd/cjc/multimode_ate_gnn_v1']):
                refusal('SEARCH_PATHS')
            assert query_calls == []
            print('SYNTHETIC_CONTROLLED_IMPORT_OK')
        """)

    def test_unknown_third_party_cannot_fallthrough_pathfinder_or_other_finders(self):
        self.child("""
            with context(),patch.object(machinery.PathFinder,'find_spec',side_effect=AssertionError('disk resolution forbidden')):
                for name in ('unknown_third_party','packaging','scriptsx'):
                    try: importlib.import_module(name)
                    except ModuleNotFoundError as error: assert 'UNKNOWN_ROOT' in str(error)
                    else: raise AssertionError(name)
            unchanged()
            print('SYNTHETIC_CONTROLLED_IMPORT_OK')
        """)

    def test_fake_torch_namespace_and_builtin_specs_no_actual_installed_ml(self):
        self.child("""
            def source_code(loader,fullname):
                return compile(b'VALUE = "synthetic dependency"',loader.path,'exec')
            with context() as receipt,patch.object(machinery.PathFinder,'find_spec',side_effect=lambda name,path=None:spec_for(name,namespace=name=='nvidia')),patch.object(machinery.SourceFileLoader,'get_code',source_code):
                module = importlib.import_module('torch')
                assert module.VALUE == 'synthetic dependency'
                assert module.__spec__.origin == runtime.SITE_ROOT+'/torch/__init__.py'
                namespace = importlib.import_module('nvidia')
                assert list(namespace.__path__) == [runtime.SITE_ROOT+'/nvidia']
                assert sys.meta_path[0].find_spec('_string').origin == 'built-in'
                assert sys.meta_path[0].find_spec('abc').origin == 'frozen'
            assert sys.modules['torch'] is module
            del sys.modules['torch']; del sys.modules['nvidia']
            unchanged()
            print('SYNTHETIC_CONTROLLED_IMPORT_OK')
        """)

    def test_torchgen_exact_distribution_and_origin_no_generic_root_admission(self):
        self.child("""
            assert runtime.ROOT_DISTRIBUTIONS['torchgen'] == ('torch',)
            with context():
                finder=sys.meta_path[0]
                with patch.object(machinery.PathFinder,'find_spec',return_value=spec_for('torchgen')):
                    assert finder.find_spec('torchgen').origin == runtime.SITE_ROOT+'/torchgen/__init__.py'
                for origin in ('/tmp/torchgen/__init__.py',
                               '/ssd/cjc/multimode_ate_gnn_v1/torchgen/__init__.py',
                               runtime.SITE_ROOT+'/torch/__init__.py',
                               runtime.SITE_ROOT+'/torchgen/../__init__.py'):
                    before=len(checked_paths)
                    with patch.object(machinery.PathFinder,'find_spec',return_value=spec_for('torchgen',origin)):
                        try: finder.find_spec('torchgen')
                        except ValueError as error: assert 'DEPENDENCY_ORIGIN' in str(error)
                        else: raise AssertionError(origin)
                    assert len(checked_paths)==before
                with patch.object(machinery.PathFinder,'find_spec',side_effect=AssertionError('no lookup')):
                    for name in ('torchgenx','torch_other','packaging'):
                        try: finder.find_spec(name)
                        except ModuleNotFoundError as error: assert 'UNKNOWN_ROOT' in str(error)
                        else: raise AssertionError(name)
            unchanged()
            print('SYNTHETIC_CONTROLLED_IMPORT_OK')
        """)

    def test_dependency_origin_and_namespace_escapes_reject_before_filesystem_inspection(self):
        self.child("""
            with context():
                finder=sys.meta_path[0]
                for origin in ('/tmp/torch/__init__.py','/ssd/cjc/multimode_ate_gnn_v1/torch/__init__.py',
                               runtime.SITE_ROOT+'/torch/../__init__.py',runtime.SITE_ROOT+'/other/__init__.py',
                               runtime.SITE_ROOT+'/torch//__init__.py'):
                    before=len(checked_paths)
                    with patch.object(machinery.PathFinder,'find_spec',return_value=spec_for('torch',origin)):
                        try: finder.find_spec('torch')
                        except ValueError as error: assert 'DEPENDENCY_ORIGIN' in str(error)
                        else: raise AssertionError(origin)
                    assert len(checked_paths)==before
                spec=spec_for('nvidia',namespace=True); spec.submodule_search_locations=['/tmp/nvidia']
                with patch.object(machinery.PathFinder,'find_spec',return_value=spec):
                    try: finder.find_spec('nvidia')
                    except ValueError as error: assert 'PACKAGE_PATH' in str(error)
                    else: raise AssertionError('namespace escape')
                try: finder.find_spec('nvidia.unknown')
                except (ValueError,ModuleNotFoundError) as error: assert 'NVIDIA_PACKAGE' in str(error) or 'MISSING' in str(error)
                else: raise AssertionError('unknown NVIDIA subtree')
            unchanged()
            print('SYNTHETIC_CONTROLLED_IMPORT_OK')
        """)

    def test_subpackage_paths_rejected_before_any_finder_or_filesystem(self):
        self.child("""
            with context():
                finder = sys.meta_path[0]
                for path in (None, [], ['/ssd/cjc/multimode_ate_gnn_v1'], ['/tmp/numpy'],
                             [runtime.SITE_ROOT+'/numpy/../numpy'], [1], ['.'],
                             [runtime.SITE_ROOT+'/numpy']*2):
                    before = len(checked_paths)
                    with patch.object(machinery.PathFinder,'find_spec',side_effect=AssertionError('finder touched')):
                        try: finder.find_spec('numpy.linalg', path)
                        except ValueError as error: assert 'INPUT_PACKAGE_PATH' in str(error)
                        else: raise AssertionError(path)
                    assert len(checked_paths) == before
                with patch.object(machinery.PathFinder,'find_spec',return_value=spec_for('numpy.linalg')):
                    assert finder.find_spec('numpy.linalg',[runtime.SITE_ROOT+'/numpy']).name == 'numpy.linalg'
            unchanged()
            print('SYNTHETIC_CONTROLLED_IMPORT_OK')
        """)

    def test_cached_file_loader_consistency_and_fixed_frozen_aliases(self):
        self.child("""
            finder = runtime._RuntimeFinder({}, frozen, observations, frozenset())
            origin = runtime.STDLIB_ROOT+'/fractions.py'
            spec = spec_for('fractions',origin); spec.submodule_search_locations=None
            for file,loader in (('/ssd/cjc/multimode_ate_gnn_v1/poison.py',spec.loader),
                                (origin,object()), (None,spec.loader)):
                marker = types.ModuleType('fractions'); marker.__spec__=spec
                marker.__file__=file; marker.__loader__=loader
                before=len(checked_paths)
                try: real_validate('fractions',marker,finder)
                except ValueError as error: assert 'PRELOADED_FILE' in str(error) or 'PRELOADED_LOADER' in str(error)
                else: raise AssertionError('cache poison accepted')
                assert len(checked_paths)==before
            marker.__file__=origin; marker.__loader__=spec.loader
            real_validate('fractions',marker,finder)
            for fullname,name,file in (('os.path','posixpath','posixpath.py'),
                                       ('importlib._bootstrap','_frozen_importlib','importlib/_bootstrap.py'),
                                       ('importlib._bootstrap_external','_frozen_importlib_external','importlib/_bootstrap_external.py')):
                marker=types.ModuleType(fullname)
                marker.__spec__=machinery.ModuleSpec(name,machinery.FrozenImporter,origin='frozen')
                marker.__loader__=machinery.FrozenImporter
                marker.__file__=runtime.STDLIB_ROOT+'/'+file
                real_validate(fullname,marker,finder)
                marker.__file__='/ssd/cjc/multimode_ate_gnn_v1/poison.py'
                try: real_validate(fullname,marker,finder)
                except ValueError as error: assert 'PRELOADED_FILE' in str(error)
                else: raise AssertionError('frozen alias poison accepted')
            print('SYNTHETIC_CONTROLLED_IMPORT_OK')
        """)

    def test_stdlib_local_shadow_and_custom_loader_rejected(self):
        self.child("""
            with context():
                finder=sys.meta_path[0]
                spec=spec_for('fractions','/tmp/fractions.py'); spec.submodule_search_locations=None
                with patch.object(machinery.PathFinder,'find_spec',return_value=spec):
                    try: finder.find_spec('fractions')
                    except ValueError as error: assert 'STDLIB_ORIGIN' in str(error)
                    else: raise AssertionError('stdlib shadow')
                spec=spec_for('torch'); spec.loader=object()
                with patch.object(machinery.PathFinder,'find_spec',return_value=spec):
                    try: finder.find_spec('torch')
                    except ValueError as error: assert 'LOADER' in str(error)
                    else: raise AssertionError('custom loader')
            unchanged()
            print('SYNTHETIC_CONTROLLED_IMPORT_OK')
        """)

    def test_cached_unknown_and_misnamed_stdlib_modules_rejected(self):
        self.child("""
            marker=types.ModuleType('unknown_cached'); sys.modules[marker.__name__]=marker
            refusal('PRELOADED_UNKNOWN'); del sys.modules[marker.__name__]
            finder=runtime._RuntimeFinder({},frozen,observations,frozenset())
            marker=types.ModuleType('json'); marker.__spec__=machinery.ModuleSpec('sys',machinery.BuiltinImporter,origin='built-in')
            try: real_validate('json',marker,finder)
            except ValueError as error: assert 'PRELOADED_ALIAS' in str(error)
            else: raise AssertionError('cached alias poison')
            marker=types.ModuleType('fractions'); marker.__spec__=spec_for('fractions','/tmp/fractions.py')
            marker.__file__=marker.__spec__.origin; marker.__loader__=marker.__spec__.loader
            try: real_validate('fractions',marker,finder)
            except ValueError as error: assert 'STDLIB_ORIGIN' in str(error)
            else: raise AssertionError('cached stdlib poison')
            print('SYNTHETIC_CONTROLLED_IMPORT_OK')
        """)

    def test_input_snapshot_state_cleanup_and_no_synthetic_fence_toggle(self):
        self.child("""
            original_heavy = frozen.HEAVY_ROOTS
            sources['src/models/runtime_ranking_v3.py']=b'VALUE = 1'; pins=hashes(sources)
            unrelated=types.ModuleType('unrelated_marker'); other=object()
            try:
                with context() as receipt:
                    sources['src/models/runtime_ranking_v3.py']=b'raise AssertionError("drift")'
                    pins['src/models/runtime_ranking_v3.py']='0'*64
                    assert importlib.import_module('src.models.runtime_ranking_v3').VALUE==1
                    assert receipt['sources']['src/models/runtime_ranking_v3.py']!='0'*64
                    sys.modules['unrelated_marker']=unrelated; sys.meta_path.append(other)
                    assert frozen.HEAVY_ROOTS is original_heavy
                    raise RuntimeError('synthetic body error')
            except RuntimeError as error: assert str(error)=='synthetic body error'
            assert sys.modules['unrelated_marker'] is unrelated
            assert sys.meta_path==before_meta+[other]
            sys.meta_path.remove(other); del sys.modules['unrelated_marker']
            unchanged(); assert frozen.HEAVY_ROOTS is original_heavy
            print('SYNTHETIC_CONTROLLED_IMPORT_OK')
        """)

    def test_exact_typing_pseudo_namespaces_and_poison_rejection(self):
        self.child("""
            runtime._validate_existing_module=real_validate  # exercise recursive parent checks, not mocked baseline
            finder=runtime._RuntimeFinder({},frozen,observations,frozenset())
            parent=types.ModuleType('typing')
            parent.__spec__=machinery.ModuleSpec('typing',machinery.SourceFileLoader('typing',runtime.STDLIB_ROOT+'/typing.py'),origin=runtime.STDLIB_ROOT+'/typing.py')
            parent.__loader__=parent.__spec__.loader; parent.__file__=parent.__spec__.origin
            meta=type('_DeprecatedType',(type,),{'__module__':'typing'})
            parent._DeprecatedType=meta
            parent.IO=object();parent.TextIO=object();parent.BinaryIO=object();parent.Pattern=object();parent.Match=object()
            old=sys.modules['typing'];sys.modules['typing']=parent
            try:
                for suffix,exports in [('io',['IO','TextIO','BinaryIO']),('re',['Pattern','Match'])]:
                    attrs={'__module__':'typing','__all__':exports,**{n:parent.__dict__[n] for n in exports}}
                    namespace=meta('typing.'+suffix,(),attrs);setattr(parent,suffix,namespace)
                    real_validate('typing.'+suffix,namespace,finder)
                    forged=meta('typing.'+suffix,(),attrs)
                    try:real_validate('typing.'+suffix,forged,finder)
                    except ValueError as error:assert 'TYPING_NAMESPACE' in str(error)
                    else:raise AssertionError('substituted namespace accepted')
                    setattr(namespace,exports[0],object())
                    try:real_validate('typing.'+suffix,namespace,finder)
                    except ValueError as error:assert 'TYPING_NAMESPACE' in str(error)
                    else:raise AssertionError('poisoned export accepted')
                    setattr(namespace,exports[0],parent.__dict__[exports[0]])
                    namespace.__file__='/ssd/cjc/multimode_ate_gnn_v1/x'
                    try:real_validate('typing.'+suffix,namespace,finder)
                    except ValueError as error:assert 'TYPING_NAMESPACE' in str(error)
                    else:raise AssertionError('pseudo namespace file accepted')
                    del namespace.__file__
                    class EqualitySpoof:
                        def __eq__(self,other):return True
                        def __ne__(self,other):return False
                    class ListSubclass(list):pass
                    for poisoned_all in (EqualitySpoof(),ListSubclass(exports),tuple(exports),[EqualitySpoof()]*len(exports)):
                        namespace.__all__=poisoned_all
                        try:real_validate('typing.'+suffix,namespace,finder)
                        except ValueError as error:assert 'TYPING_NAMESPACE' in str(error)
                        else:raise AssertionError('untyped exports accepted')
                    namespace.__all__=exports
                    good_spec=parent.__spec__
                    for bad_spec in (machinery.ModuleSpec('typing',machinery.SourceFileLoader('typing',runtime.STDLIB_ROOT+'/fractions.py'),origin=runtime.STDLIB_ROOT+'/fractions.py'),
                                     machinery.ModuleSpec('typing',machinery.BuiltinImporter,origin='built-in'),
                                     machinery.ModuleSpec('typing',machinery.FrozenImporter,origin='frozen'),
                                     machinery.ModuleSpec('typing',good_spec.loader,origin=good_spec.origin,is_package=True)):
                        parent.__spec__=bad_spec;parent.__loader__=bad_spec.loader;parent.__file__=bad_spec.origin
                        with patch.object(runtime,'_ordinary') as stats:
                            try:real_validate('typing.'+suffix,namespace,finder)
                            except ValueError as error:assert 'TYPING_PARENT' in str(error)
                            else:raise AssertionError('wrong exact parent accepted')
                            stats.assert_not_called()
                    parent.__spec__=good_spec;parent.__loader__=good_spec.loader;parent.__file__=good_spec.origin
                parent.__file__='/tmp/typing.py'
                try:real_validate('typing.io',parent.io,finder)
                except ValueError as error:assert 'PRELOADED_FILE' in str(error)
                else:raise AssertionError('poisoned parent accepted')
                arbitrary=types.ModuleType('typing.other')
                try:real_validate('typing.other',arbitrary,finder)
                except ValueError as error:assert 'PRELOADED_SPEC' in str(error)
                else:raise AssertionError('arbitrary spec-less object accepted')
            finally:sys.modules['typing']=old
            print('SYNTHETIC_CONTROLLED_IMPORT_OK')
        """)


if __name__ == '__main__':
    unittest.main()
