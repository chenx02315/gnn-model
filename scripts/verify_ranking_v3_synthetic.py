"""Run only generated-data ranking tests and retain bounded evidence."""
import hashlib
import json
import os
import platform
from pathlib import Path
import sys
import unittest

MODULES=['tests.test_runtime_ranking_v3','tests.test_runtime_ranking_v3_runner',
         'tests.test_ranking_v3_freeze_io','tests.test_ranking_v3_fold_package',
         'tests.test_ranking_v3_real_synthetic']

def main():
    root=Path.cwd().resolve()
    if not str(root).startswith('/ssd/cjc/gnn_model_ranking_v3_synthetic_'):
        raise SystemExit('SYNTHETIC_WORKSPACE_REQUIRED')
    from src.models.preflight_runtime_v2 import parse_lock,validate_installed_dependencies
    installed=validate_installed_dependencies(parse_lock(root/'requirements/runtime_v2.lock.txt'))
    evidence=root/'evidence'; evidence.mkdir(exist_ok=False)
    suite=unittest.defaultTestLoader.loadTestsFromNames(MODULES)
    with (evidence/'tests.log').open('x') as stream:
        result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    receipt={'scope':'GENERATED_SYNTHETIC_NO_EXTERNAL_DATA',
             'status':'PASS' if result.wasSuccessful() and result.testsRun>=30 and not result.skipped else 'FAIL',
             'testsRun':result.testsRun,'skipped':len(result.skipped),
             'failures':len(result.failures),'errors':len(result.errors),
             'python':sys.version,'platform':platform.platform(),'kernel':platform.release(),
             'installed_versions':installed,'cwd':str(root),
             'dependency_mode':'fresh_venv_readonly_shared_locked_site_packages',
             'legacy_dependency_write_prevention':os.environ.get('PYTHONDONTWRITEBYTECODE')=='1',
             'source_sha256':{str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()
                              for folder in ['src','tests','scripts','requirements','contracts']
                              for p in sorted((root/folder).rglob('*')) if p.is_file()},
             'log_sha256':hashlib.sha256((evidence/'tests.log').read_bytes()).hexdigest(),
             'real_circuit_rows_read':False,'blind_accessed':False,'formal_training':False}
    with (evidence/'receipt.json').open('x') as stream: json.dump(receipt,stream,indent=2)
    print(json.dumps({k:receipt[k] for k in ['status','testsRun','skipped','failures','errors','log_sha256']}))
    raise SystemExit(0 if receipt['status']=='PASS' else 1)

if __name__=='__main__': main()
