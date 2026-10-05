"""Create-once exact code/data/resource release after SHA-bound review."""
import argparse
import hashlib
import json
from pathlib import Path
from src.data.ranking_v3_real_fold_package import _read_json_once, _write_once
from src.models.ranking_v4_real_worker import REVIEWED_FILES, SOURCE_SHA256, PACKAGE_SHA256, check_release


def create(review_path, review_sha, smoke_path, output):
    review = _read_json_once(Path(review_path), review_sha, 'V4_INDEPENDENT_REVIEW_SHA')
    if review.get('status') != 'PASS_LOW_MEMORY_REAL_V4_CODE_GATE' or review.get('real_training_authorized') is not True:
        raise ValueError('V4_RELEASE_REVIEW')
    smoke = _read_json_once(Path(smoke_path), review['guarded_smoke_sha256'], 'V4_RELEASE_SMOKE_SHA')
    if smoke['status'] != 'PASS_GUARDED_SYNTHETIC_ML' or smoke['memory']['status'] != 'PASS_BOUNDED_WORKER':
        raise ValueError('V4_RELEASE_RESOURCE_SMOKE')
    sources = {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in REVIEWED_FILES}
    if sources != review['reviewed_sources']:
        raise ValueError('V4_RELEASE_CODE_DRIFT')
    release = dict(status='PASS_V4_TRAIN_ONLY_EXECUTION', source_sha256=SOURCE_SHA256,
                   package_receipt_sha256=PACKAGE_SHA256, roles=['TRAIN'],
                   seeds=[20260824, 20260825, 20260826], model='candidate_mlp',
                   training_release=True, reviewed_sources=sources, independent_review_sha256=review_sha,
                   guarded_smoke_sha256=review['guarded_smoke_sha256'],
                   resource_policy='serial1, sampled combined RSS1GiB, RLIMIT_AS8GiB, threads1, no retry',
                   user_authorization='2026-10-05 proceed continuously with memory control; TRAIN-only 18 fits after independent gates')
    check_release(release, SOURCE_SHA256)
    _write_once(Path(output), release)
    return dict(status=release['status'], release_sha256=hashlib.sha256(Path(output).read_bytes()).hexdigest())


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for name in ('review', 'review-sha256', 'smoke', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    print(json.dumps(create(args.review, args.review_sha256, args.smoke, args.output), sort_keys=True))
