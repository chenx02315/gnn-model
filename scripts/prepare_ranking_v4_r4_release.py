"""Create a fresh r4 release only after the bounded independent precondition review."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path('/ssd/cjc/gnn_model_ranking_v4_train_af05de0_20261005_r4')
CODE = Path('/ssd/cjc/gnn_model_ranking_v4_exit_boundary_ml_fe67d2d_20261005_r1/code')
SMOKE = CODE.parent / 'generated_smoke/receipt.json'


def prepare(review_path, review_sha):
    if Path.cwd().resolve() != CODE.resolve():
        raise ValueError('R4_PREPARATION_CWD')
    # Direct absolute-script invocation has /ssd/cjc as sys.path[0].
    # Import only the already-validated fixed, read-only code snapshot.
    sys.path.insert(0, str(CODE.resolve()))
    if any(path.is_symlink() for path in (ROOT, *ROOT.parents, CODE, *CODE.parents, SMOKE, *SMOKE.parents,
                                          Path(review_path), *Path(review_path).parents)):
        raise ValueError('R4_PREPARATION_SYMLINK')
    raw = Path(review_path).read_bytes()
    if len(raw) > 20000 or hashlib.sha256(raw).hexdigest() != review_sha:
        raise ValueError('R4_PREPARATION_REVIEW_SHA')
    review = json.loads(raw)
    if (review.get('status') != 'PASS_LOW_MEMORY_REAL_V4_CODE_GATE' or
            review.get('real_training_authorized') is not True or
            review.get('independent_audit') != 'PASS_R4_REAL_RELEASE_PRECONDITION' or
            review.get('execution_root') != str(ROOT) or
            review.get('code_root') != str(CODE) or review.get('fourth_run_explicitly_authorized') is not True):
        raise ValueError('R4_PREPARATION_REVIEW_SCOPE')
    from src.models.ranking_v4_real_worker import verify_reviewed_sources, check_release, SOURCE_SHA256, PACKAGE_SHA256
    from src.models.ranking_v4_memory_guard import available_memory, check_available
    verify_reviewed_sources(review)
    total, available = available_memory()
    check_available(total, available)
    smoke_raw = SMOKE.read_bytes()
    if len(smoke_raw) > 20000 or hashlib.sha256(smoke_raw).hexdigest() != review['guarded_smoke_sha256']:
        raise ValueError('R4_PREPARATION_SMOKE_SHA')
    smoke = json.loads(smoke_raw)
    if smoke.get('status') != 'PASS_GUARDED_SYNTHETIC_ML' or smoke.get('memory', {}).get('status') != 'PASS_BOUNDED_WORKER':
        raise ValueError('R4_PREPARATION_SMOKE_STATUS')
    release = dict(status='PASS_V4_TRAIN_ONLY_EXECUTION', source_sha256=SOURCE_SHA256,
                   package_receipt_sha256=PACKAGE_SHA256, roles=['TRAIN'],
                   seeds=[20260824, 20260825, 20260826], model='candidate_mlp',
                   training_release=True, reviewed_sources=review['reviewed_sources'],
                   independent_review_sha256=review_sha, guarded_smoke_sha256=review['guarded_smoke_sha256'],
                   resource_policy='serial1, sampled combined RSS1GiB, RLIMIT_AS8GiB, threads1, no retry',
                   user_authorization=review['authorization'])
    check_release(release, SOURCE_SHA256)
    ROOT.mkdir(exist_ok=False)
    with (ROOT / 'independent_review.json').open('xb') as stream:
        stream.write(raw)
    with (ROOT / 'execution_release.json').open('x') as stream:
        json.dump(release, stream, sort_keys=True, separators=(',', ':'))
        stream.write('\n')
    result = dict(status=release['status'], release_sha256=hashlib.sha256((ROOT / 'execution_release.json').read_bytes()).hexdigest())
    receipt = dict(result, root=str(ROOT), code_root=str(CODE), independent_review_sha256=review_sha,
                   effective_total_bytes=total, available_bytes=available, launch_started=False, retries=0)
    with (ROOT / 'release_preparation.json').open('x') as stream:
        json.dump(receipt, stream, sort_keys=True)
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--review', required=True)
    parser.add_argument('--review-sha256', required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.review, args.review_sha256), sort_keys=True))
