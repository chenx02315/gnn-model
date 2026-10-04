"""Read-only local integrity audit; not an independent code review."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile

ARCHIVE_SHA = 'a928e34f7674378c7e8a41ddc95873e3f0cf76bcab0cec7e43a358ff370410cd'
PARENT_SHA = '43aca787fd8302e164a2b7a56e5620859054acc416efc54e0fd2b7277b954400'
GRID_SHA = '69c8943dfc2a37feb6f62e6398fc5fcf323528f9c1f8ee24a01ae6b1b2f55175'
LAUNCHER_SHA = '9434073a1e68ad6eecc1b3aae2ea45160457816b28f7e869acb706952f18c56c'
EXTENSION_SHA = 'f9e37d36a325e629c4df5bb0063feaefc7c25f4b0b669a6b919e29d68fa6c39f'

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def require(condition, message):
    if not condition:
        raise ValueError(message)

def audit(stage, extension):
    stage = Path(stage)
    require(digest(stage / 'source.tar.gz') == ARCHIVE_SHA, 'archive digest')
    require(digest(stage / 'receipt.json') == PARENT_SHA, 'parent receipt digest')
    require(digest(stage / 'followup/receipt.json') == GRID_SHA, 'grid receipt digest')
    require(digest(stage / 'followup/run_full_grid.py') == LAUNCHER_SHA, 'launcher digest')
    require(digest(stage / 'followup/full_grid_test.py') == EXTENSION_SHA, 'sealed extension digest')
    parent = json.loads((stage / 'receipt.json').read_text())
    child = json.loads((stage / 'followup/receipt.json').read_text())
    for receipt, count, log in ((parent, 30, stage / 'tests.log'),
                                (child, 3, stage / 'followup/tests.log')):
        require(receipt['scope'] == 'GENERATED_SYNTHETIC_NO_EXTERNAL_DATA', 'scope')
        require(receipt['status'] == 'PASS' and receipt['testsRun'] == count, 'test count/status')
        require(all(receipt[k] == 0 for k in ('skipped', 'failures', 'errors')), 'test failures/skips')
        require(all(receipt[k] is False for k in ('real_circuit_rows_read', 'blind_accessed', 'formal_training')), 'scope claims')
        require(digest(log) == receipt['log_sha256'], 'log digest')
    require(child['parent_receipt_sha256'] == PARENT_SHA, 'receipt lineage')
    require(digest(Path(extension)) == child['extension_sha256'], 'extension source digest')
    with tarfile.open(stage / 'source.tar.gz', 'r:gz') as archive:
        members = archive.getmembers()
        require(len(members) == 17 and len({m.name for m in members}) == 17, 'archive member count')
        require(all(m.isfile() and m.size <= 262144 for m in members), 'archive type/size')
        expected = {}
        for member in members:
            expected[member.name] = hashlib.sha256(archive.extractfile(member).read()).hexdigest()
    for name in ('src/__init__.py', 'src/models/__init__.py', 'src/data/__init__.py', 'tests/__init__.py'):
        expected[name] = hashlib.sha256(b'').hexdigest()
    require(expected == parent['source_sha256'], 'sealed source inventory')
    return {'status': 'PASS_SYNTHETIC_EVIDENCE_INTEGRITY',
            'parent_receipt_sha256': PARENT_SHA,
            'grid_receipt_sha256': digest(stage / 'followup/receipt.json'),
            'archive_sha256': ARCHIVE_SHA,
            'extension_sha256': child['extension_sha256'],
            'launcher_sha256': LAUNCHER_SHA,
            'audit_revision': 2,
            'audit_script_sha256': digest(Path(__file__)),
            'tests': [30, 3], 'skips': 0, 'failures': 0, 'errors': 0,
            'generated_data_grid_fits': 54,
            'independent_code_review': False, 'formal_release': False}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--stage', required=True)
    parser.add_argument('--extension', required=True)
    parser.add_argument('--output')
    args = parser.parse_args()
    result = audit(args.stage, args.extension)
    payload = json.dumps(result, indent=2) + '\n'
    if args.output:
        with Path(args.output).open('x', encoding='utf-8') as stream:
            stream.write(payload)
    print(payload)

if __name__ == '__main__':
    main()
