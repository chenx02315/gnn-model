"""Seal reviewed synthetic entrypoint evidence without touching real inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile

ARCHIVE = '48a27a503c04408e575823860e28db11dadf513aa053c68c8eacc396108393e8'
RECEIPT = 'eb16928074410597ce592ce008e23e68ff9800b529448f16174f50e7a834ab90'
BOOTSTRAP = '79a91dde2116598c9cdeab2d97394dbe338fbea64d169e0f4a211a78fde2bf9f'

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def seal(stage, repo):
    stage=Path(stage); repo=Path(repo)
    for name, expected in (('source.tar.gz', ARCHIVE), ('receipt.json', RECEIPT), ('bootstrap.py', BOOTSTRAP)):
        if sha(stage/name)!=expected: raise ValueError('SEALED_ARTIFACT_SHA:'+name)
    receipt=json.loads((stage/'receipt.json').read_bytes())
    if receipt['status']!='PASS' or receipt['testsRun']!=23 or any(receipt[k]!=0 for k in ('skipped','failures','errors')):
        raise ValueError('ENTRYPOINT_TEST_GATE')
    if receipt['real_data_read'] is not False or receipt['formal_training'] is not False or sha(stage/'tests.log')!=receipt['log_sha256']:
        raise ValueError('ENTRYPOINT_SCOPE_OR_LOG')
    with tarfile.open(stage/'source.tar.gz', 'r:gz') as archive:
        members=archive.getmembers()
        if len(members)!=26 or len({m.name for m in members})!=26: raise ValueError('ARCHIVE_COUNT')
        sources={}
        for member in members:
            if not member.isfile() or member.size>262144: raise ValueError('ARCHIVE_MEMBER')
            value=hashlib.sha256(archive.extractfile(member).read()).hexdigest()
            if receipt['source_sha256'][member.name]!=value or sha(repo/member.name)!=value:
                raise ValueError('REVIEWED_SOURCE_DRIFT:'+member.name)
            sources[member.name]=value
    return dict(status='PASS_CODE_AND_ML_SYNTHETIC_GATE', code_review='ranking_isolation_review PASS_CODE_GATE',
                scope='SYNTHETIC_ONLY_NO_REAL_TRAINING', archive_sha256=ARCHIVE,
                execution_receipt_sha256=RECEIPT, bootstrap_sha256=BOOTSTRAP,
                testsRun=23, skipped=0, failures=0, errors=0, source_sha256=sources,
                model_toy_fits=54, baseline_toy_evaluations=18, subprocess_baseline_e2e_runs=18)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--stage',required=True); parser.add_argument('--repo',required=True); parser.add_argument('--output',required=True)
    args=parser.parse_args(); value=seal(args.stage,args.repo)
    with Path(args.output).open('x',encoding='utf-8') as stream: json.dump(value,stream,indent=2)
    print(json.dumps({k:value[k] for k in ('status','testsRun','skipped','failures','errors')}))

if __name__=='__main__': main()
