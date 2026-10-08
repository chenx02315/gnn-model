"""Mocked Linux integration in isolated children; not actual Linux resource proof."""
from pathlib import Path
import subprocess
import sys
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = r'''
import hashlib, importlib.util, json, pathlib, sys, tempfile
from unittest.mock import patch
repo = pathlib.Path(REPO)
spec = importlib.util.spec_from_file_location('external_linux_launcher', repo / 'scripts/launch_v5_frozen_import_linux_gate.py')
launcher = importlib.util.module_from_spec(spec); spec.loader.exec_module(launcher)
def digest(raw): return hashlib.sha256(raw).hexdigest()
def external_helper():
    spec = importlib.util.spec_from_file_location('fixture_external_fence', repo / launcher.HELPER)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module
helper = external_helper()
temporary = tempfile.TemporaryDirectory()
root = pathlib.Path(temporary.name)
sources = {name: b'# synthetic source\n' for name in helper.FILES}
for name in ('src/models/ranking_v5_caller_source_binding.py',
             'src/models/ranking_v5_parent_guard_receipt.py',
             'src/models/ranking_v4_memory_guard.py'):
    sources[name] = (repo / name).read_bytes()
sources['src/models/ranking_v4_memory_guard.py'] += b'\nrun_bounded = __import__("__main__").fake_run\n'
sources['requirements/runtime_v2.lock.txt'] = b'numpy==2.1.3\ntorch==2.5.1\nscipy==1.14.1\nscikit-learn==1.5.2\nxgboost==2.1.2\n'
pins = {name:digest(raw) for name,raw in sources.items()}
manifest = dict(schema='v5-caller-source-bytes-v1', formal_training_release=False, sources=pins)
manifest_raw = json.dumps(manifest, sort_keys=True).encode()
helper_raw = (repo / launcher.HELPER).read_bytes()
verifier_raw = b'# synthetic verified supervisor, mocked guard only\n'
for name,raw in dict(sources, **{launcher.MANIFEST:manifest_raw, launcher.HELPER:helper_raw, launcher.VERIFIER:verifier_raw}).items():
    path = root / name; path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(raw)
anchors = [digest(manifest_raw), digest(helper_raw), digest(verifier_raw)]
calls = []
memory_change = None
worker_change = None
disk_change = None
duplicate_memory = False
def fake_run(argv, log_path, env):
    import src.models.ranking_v4_memory_guard as guard
    calls.append((argv,log_path,env))
    assert argv == [launcher.INTERPRETER,'-I','-B',str(root / launcher.VERIFIER),
                    '--manifest-sha256',anchors[0],'--helper-sha256',anchors[1]]
    assert env == launcher._environment()
    assert 'PYTHONPATH' not in env and 'VIRTUAL_ENV' not in env
    total = 32 * guard.GIB
    returned = dict(status='PASS_BOUNDED_WORKER',memory_policy=guard.policy(),
                    initial_available_bytes=24*guard.GIB,effective_total_bytes=total,
                    reserve_bytes=guard.check_available(total,24*guard.GIB),sample_count=2,
                    peak_group_rss_bytes=123456,peak_combined_rss_bytes=345678,
                    exit_code=0,process_group=123,elapsed_seconds=0.5)
    if memory_change: memory_change(returned)
    worker = dict(status='PASS_FROZEN_SOURCE_IMPORT_GATE_ONLY', loaded_python_modules=1,
                  origins=['sealed://src/models/ranking_v5_single_fit_worker.py'],
                  namespaces_empty=True,heavy_ml_imports_blocked=True,actual_torch_fits=0,
                  production_package_reads=0,actual_linux_resource_proof=False,
                  formal_training_release=False,manifest_sha256=anchors[0],helper_sha256=anchors[1],
                  child_exit_code=0,automatic_retries=0,isolated_python_child=True,worker_count=1,
                  claim_boundary='Actual local source-import experiment only; not Linux RSS, installed ML runtime, consent or training')
    if worker_change: worker_change(worker)
    log_path.write_text(json.dumps(worker))
    disk = dict(returned)
    if disk_change: disk_change(disk)
    text = json.dumps(disk)
    if duplicate_memory: text = text[:-1] + ',"sample_count":2}'
    pathlib.Path(str(log_path)+'.memory.json').write_text(text)
    return returned
def execute():
    # Test-only patch. Production API has no root/platform/guard bypass flag.
    with patch.object(launcher,'_preconditions',return_value=root):
        return launcher.execute(root,*anchors)
def refuses(token):
    try: execute()
    except (ValueError, RuntimeError) as error: assert token in str(error), str(error)
    else: raise AssertionError('unexpected pass')
    assert not (root / launcher.RECEIPT).exists()
def clean_outputs():
    for name in (launcher.LOG,launcher.LOG+'.memory.json',launcher.RECEIPT):
        path = root/name
        if path.exists(): path.unlink()
'''


class LinuxImportGateTests(unittest.TestCase):
    def child(self, body):
        result = subprocess.run([sys.executable, '-I', '-B', '-c',
                                 'REPO = ' + repr(str(ROOT)) + '\n' + BOOTSTRAP + textwrap.dedent(body)],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('MOCKED_GATE_OK', result.stdout)

    def test_platform_interpreter_root_cwd_refused_before_path_io(self):
        self.child("""
            with patch.object(launcher,'_fresh_artifacts',side_effect=AssertionError('path IO')), patch.object(launcher,'_ordinary_read',side_effect=AssertionError('read IO')):
                for platform,executable,value,cwd,token in (
                    ('win32',launcher.INTERPRETER,'/ssd/cjc/gnn_model_ranking_v5_import_gate_20261008_r1','x','PLATFORM'),
                    ('linux','/wrong/python','/ssd/cjc/gnn_model_ranking_v5_import_gate_20261008_r1','x','INTERPRETER'),
                    ('linux',launcher.INTERPRETER,'/ssd/cjc/gnn_model_ranking_v5_import_gate_20261008_r1/../other','x','ROOT'),
                    ('linux',launcher.INTERPRETER,'/ssd/cjc/gnn_model_ranking_v5_import_gate_20261008_r1','/wrong','CWD')):
                    with patch.object(sys,'platform',platform),patch.object(sys,'executable',executable),patch.object(launcher.os,'getcwd',return_value=cwd):
                        try: launcher.execute(value,*anchors)
                        except (ValueError,RuntimeError) as error: assert token in str(error)
                        else: raise AssertionError('unexpected entry')
            assert calls == []
            print('MOCKED_GATE_OK')
        """)

    def test_mocked_success_exact_resource_supervisor_and_persisted_receipt(self):
        self.child("""
            result = execute()
            assert result == json.loads((root/launcher.RECEIPT).read_bytes())
            assert result['status'] == 'PASS_LINUX_BOUNDED_FROZEN_SOURCE_IMPORT_GATE_ONLY'
            assert result['actual_ml_permitted'] is False and result['formal_training_release'] is False
            assert result['actual_torch_fits'] == result['production_package_reads'] == 0
            assert result['sources'] == pins
            assert len(calls) == 1
            assert not any(name=='src' or name.startswith('src.') for name in sys.modules)
            print('MOCKED_GATE_OK')
        """)

    def test_zero_rss_and_zero_samples_refuse_preserve_failed_files(self):
        self.child("""
            for key,token in [('peak_combined_rss_bytes','RECEIPT_RSS'),('peak_group_rss_bytes','ZERO_CHILD_RSS'),('sample_count','RECEIPT_SAMPLES')]:
                memory_change = lambda result,key=key: result.update({key:0})
                refuses(token)
                assert (root/launcher.LOG).exists() and (root/(launcher.LOG+'.memory.json')).exists()
                refuses('ARTIFACT_EXISTS')
                clean_outputs()
            assert len(calls) == 3
            print('MOCKED_GATE_OK')
        """)

    def test_returned_vs_independent_memory_reread_mismatch_and_duplicate(self):
        self.child("""
            disk_change = lambda result: result.update(sample_count=3)
            refuses('RECEIPT_MISMATCH')
            clean_outputs(); disk_change = None; duplicate_memory = True
            refuses('DUPLICATE_JSON')
            print('MOCKED_GATE_OK')
        """)

    def test_independent_manifest_helper_verifier_and_source_sha(self):
        self.child("""
            for name,token in [(launcher.MANIFEST,'MANIFEST_SHA'),(launcher.HELPER,'HELPER_SHA'),(launcher.VERIFIER,'VERIFIER_SHA'),('src/models/runtime_ranking_v3.py','SOURCE_SHA')]:
                path = root/name; original = path.read_bytes(); path.write_bytes(original+b'# drift')
                refuses(token); path.write_bytes(original)
                assert calls == []
            print('MOCKED_GATE_OK')
        """)

    def test_create_once_each_artifact_before_worker_and_preserves_contents(self):
        self.child("""
            for name in (launcher.LOG,launcher.LOG+'.memory.json',launcher.RECEIPT):
                path = root/name; path.write_bytes(b'preserve failed evidence')
                try: execute()
                except ValueError as error: assert 'ARTIFACT_EXISTS' in str(error)
                else: raise AssertionError('overwritten')
                assert path.read_bytes() == b'preserve failed evidence'
                path.unlink()
            assert calls == []
            print('MOCKED_GATE_OK')
        """)

    def test_worker_receipt_malformed_claims_pins_origins_counts_refused(self):
        self.child("""
            for key,value in [('status','PASS_TRAINING'),('helper_sha256','0'*64),('manifest_sha256','0'*64),
                              ('origins',['sealed://src/models/runtime_ranking_v3.py']),('actual_torch_fits',True),
                              ('production_package_reads',1),('heavy_ml_imports_blocked',False),
                              ('child_exit_code',1),('loaded_python_modules',2),('formal_training_release',True),
                              ('automatic_retries',1),('actual_linux_resource_proof',True)]:
                worker_change = lambda worker,key=key,value=value: worker.update({key:value})
                refuses('WORKER_RECEIPT'); clean_outputs()
            print('MOCKED_GATE_OK')
        """)

    def test_bounded_reads_total_and_json_limits(self):
        self.child("""
            with patch.object(launcher,'MAX_TOTAL',1): refuses('TOTAL_BOUND')
            (root/launcher.VERIFIER).write_bytes(b'#'*(launcher.MAX_SOURCE+1))
            refuses('BYTE_BOUND')
            (root/launcher.VERIFIER).write_bytes(verifier_raw)
            original_read = launcher._ordinary_read
            def oversized_memory(path,cap):
                if str(path).endswith('.memory.json'):
                    path.write_bytes(b' '*(cap+1))
                return original_read(path,cap)
            with patch.object(launcher,'_ordinary_read',side_effect=oversized_memory):
                refuses('BYTE_BOUND')
            assert (root/launcher.LOG).exists()
            assert len(calls) == 1
            clean_outputs(); calls.clear()
            assert calls == []
            print('MOCKED_GATE_OK')
        """)

    def test_ordinary_file_checks_refuse_symlink_and_directory(self):
        self.child("""
            path = root/'ordinary_probe'; path.write_bytes(b'probe')
            with patch.object(pathlib.Path,'is_symlink',return_value=True):
                try: launcher._ordinary_read(path,100)
                except ValueError as error: assert 'SYMLINK' in str(error)
                else: raise AssertionError('symlink allowed')
            try: launcher._ordinary_read(root,100)
            except ValueError as error: assert 'NOT_REGULAR' in str(error)
            else: raise AssertionError('directory allowed')
            assert calls == []
            print('MOCKED_GATE_OK')
        """)


if __name__ == '__main__':
    unittest.main()
