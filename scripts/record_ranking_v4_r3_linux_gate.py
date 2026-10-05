"""Create-once raw log and actual subprocess exit receipt for fixed Linux tests."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path('/ssd/cjc/gnn_model_ranking_v4_integrated_dec61b0_20261005_r2')
PYTHON = '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/venv/bin/python'
ARCHIVE = Path('/ssd/cjc/ranking_v4_integrated_dec61b0_overlay_r2.tar.gz')
ARCHIVE_SHA = 'a16d50b81fc844faca6dea143913161e9d360133b30f06fe822a9498c695d652'
PREP_SHA = '0a79da62d68c0a6cb6b362acbe8cb0abadbc1dcfde59bf4be64a7a005df4534b'


def main():
    if sys.platform != 'linux' or any(p.is_symlink() for p in (ROOT, *ROOT.parents)):
        raise ValueError('R3_LINUX_GATE_ROOT')
    log, receipt = ROOT / 'linux_gate_recorded.log', ROOT / 'linux_gate_exit.json'
    if log.exists() or receipt.exists():
        raise ValueError('R3_LINUX_GATE_CREATE_ONCE')
    argv = [PYTHON, '-m', 'unittest', 'tests.test_ranking_v4_memory_guard', 'tests.test_ranking_v4_real_execution', '-v']
    value = dict(scope='LINUX_FOCUSED_TESTS_NO_REAL_TRAINING', argv=argv, cwd=str(ROOT / 'code'),
                 exit_code=1, gate_pass=False, real_training_release=False, error=None)
    try:
        if any(p.is_symlink() for p in (ARCHIVE, *ARCHIVE.parents)) or hashlib.sha256(ARCHIVE.read_bytes()).hexdigest() != ARCHIVE_SHA:
            raise ValueError('R3_GATE_ARCHIVE_SHA')
        prep_raw = (ROOT / 'code_preparation.json').read_bytes()
        if hashlib.sha256(prep_raw).hexdigest() != PREP_SHA:
            raise ValueError('R3_GATE_PREPARATION_SHA')
        prep = json.loads(prep_raw)
        if prep['archive_sha256'] != ARCHIVE_SHA or len(prep['overlay']) != 7 or len(set(prep['overlay'])) != 7:
            raise ValueError('R3_GATE_OVERLAY')
        actual = list((ROOT / 'code').rglob('*'))
        if any(p.is_symlink() for p in actual):
            raise ValueError('R3_GATE_SOURCE_PATH')
        names = {p.relative_to(ROOT / 'code').as_posix() for p in actual if p.is_file()}
        if names != set(prep['code_sha256']):
            raise ValueError('R3_GATE_CODE_INVENTORY')
        for name, sha in prep['code_sha256'].items():
            path = ROOT / 'code' / name
            if Path(name).is_absolute() or '..' in Path(name).parts or any(p.is_symlink() for p in (path, *path.parents)):
                raise ValueError('R3_GATE_SOURCE_PATH')
            if hashlib.sha256(path.read_bytes()).hexdigest() != sha:
                raise ValueError('R3_GATE_CODE_SHA')
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
        env.pop('PYTHONPATH', None)
        with log.open('xb') as stream:
            result = subprocess.run(argv, cwd=ROOT / 'code', stdout=stream, stderr=subprocess.STDOUT,
                timeout=30, env=env)
        raw = log.read_bytes()
        text = raw.decode('utf-8')
        passed = (result.returncode == 0 and re.search(r'Ran 14 tests in ', text) is not None
                  and '\nOK\n' in text and 'skipped' not in text.lower())
        value.update(exit_code=result.returncode, testsRun=14 if passed else None,
                     skipped=0 if passed else None, gate_pass=passed, log_sha256=hashlib.sha256(raw).hexdigest(),
                     archive_sha256=ARCHIVE_SHA, preparation_sha256=PREP_SHA, checked_code_files=len(prep['code_sha256']))
    except Exception as error:
        value.update(error=f'{type(error).__name__}: {error}', exit_code=1, gate_pass=False)
    finally:
        with receipt.open('x') as stream:
            json.dump(value, stream, sort_keys=True)
    print(json.dumps(value, sort_keys=True))
    return 0 if value['gate_pass'] else 1


if __name__ == '__main__':
    sys.exit(main())
