"""Bounded local candidate collection after externally supplied guard success.

This NEW adapter fixes stdout naming to output + '.stdout.log'; it does not
claim this was an existing production convention. Guard receipt provenance,
authenticated package preflight, trusted context construction and actual parent
bootstrap/prelaunch/resource enforcement remain external obligations. No remote
access, training, checkpoint decode, authorization or numerical metric proof.

Four artifact reads reuse the existing readback private ordinary/bounded I/O
helpers. The stdout reader mirrors those change/ordinary-file checks but seeks
only a <=20 KiB tail, never scans earlier successful JSON. Private helpers are
current implementation dependencies, not stable public APIs or hostile-FS proof.
Measured file hashes establish observed candidate-byte integrity, not authority.
"""
import hashlib
import os
from pathlib import Path

from scripts import run_v5_train_single_fit as cli
from src.models import ranking_v5_independent_fit_context as fit_context
from src.models import ranking_v5_train_artifact_readback as reader
from src.models.ranking_v5_parent_guard_receipt import validate_parent_guard_receipt


STDOUT_TAIL_CAP = 20*1024


def _require(ok, code):
    if not ok:
        raise ValueError('V5_PARENT_CANDIDATE_' + code)


def _stdout_tail(path):
    """Read at most 20 KiB after ordinary/snapshot checks, without full-file read."""
    try:
        for ancestor in path.parents:
            reader._ordinary(ancestor.lstat(), directory=True)
        before = path.lstat()
        reader._ordinary(before)
        _require(before.st_size > 0, 'STDOUT_EMPTY')
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, 'rb') as stream:
            opened = os.fstat(stream.fileno())
            reader._ordinary(opened)
            _require((opened.st_dev, opened.st_ino, opened.st_size) ==
                     (before.st_dev, before.st_ino, before.st_size), 'STDOUT_CHANGED')
            offset = max(0, before.st_size-STDOUT_TAIL_CAP)
            stream.seek(offset)
            tail = stream.read(STDOUT_TAIL_CAP)
            after = os.fstat(stream.fileno())
        final = path.lstat()
        reader._ordinary(final)
        _require(len(tail) == min(before.st_size, STDOUT_TAIL_CAP)
                 and (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns) ==
                     (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                 and (after.st_size, after.st_mtime_ns) == (before.st_size, before.st_mtime_ns),
                 'STDOUT_CHANGED')
        _require(tail.endswith(b'\n'), 'STDOUT_UNTERMINATED')
        if offset:
            # The first line is potentially partial. Never treat it as a whole
            # receipt, even if its bytes happen to form independently valid JSON.
            boundary = tail.find(b'\n')
            _require(boundary >= 0, 'STDOUT_TAIL_INCOMPLETE')
            tail = tail[boundary+1:]
        lines = [line for line in tail.split(b'\n') if line.strip()]
        _require(bool(lines), 'STDOUT_TAIL_INCOMPLETE')
        last = lines[-1]+b'\n'
        _require(len(last) <= STDOUT_TAIL_CAP, 'STDOUT_LINE_BOUND')
        return reader._decode(last)
    except OSError as error:
        raise ValueError('V5_PARENT_CANDIDATE_STDOUT_IO') from error


def collect_parent_artifact_candidate(source_root, output, guard_log_path, *, context,
                                     guard_returned_receipt, guard_reread_receipt):
    """Collect/validate exactly one candidate; failed guard rejects before ALL I/O.

    Existing CLI lexical rules bind output to approved source-root/family/seed.
    External caller must independently approve that source root and authenticate
    both guard receipts/context; this function cannot establish their provenance.
    Candidate receipts are never promoted into independent complete expectations:
    context binding precedes final exact-byte reread, whose broader numerical
    predictions/metrics remain expressly unverified.
    """
    fit_context._validate_context(context)
    cli._lexical(source_root, output, cli.PACKAGE_ROOT, context.family, context.seed)
    _require(type(guard_log_path) is str and guard_log_path == output+'.stdout.log', 'STDOUT_PATH')
    root = reader._root(output)  # lexical only, prior to guard/file operations
    guard_check = validate_parent_guard_receipt(guard_returned_receipt, guard_reread_receipt)
    candidate = _stdout_tail(Path(guard_log_path))
    raw = {name: reader._read(root, name) for name in reader.LIMITS}
    measured = {name: hashlib.sha256(value).hexdigest() for name, value in raw.items()}
    receipt = reader._decode(raw['worker_receipt.json'])
    _require(type(candidate) is dict and type(receipt) is dict
             and reader._canonical(candidate) == reader._canonical(receipt), 'STDOUT_RECEIPT_MISMATCH')
    freeze = reader._decode(raw['freeze.json'])
    lines = raw['fitting.jsonl'].splitlines(keepends=True)
    _require(len(lines) == 122 and all(0 < len(line) <= reader.LOG_RECORD_MAX_BYTES
                                     for line in lines), 'LOG_RECORD_BOUND')
    records = [reader._decode(line) for line in lines]
    identity_check = fit_context.verify_candidate_fit_artifacts(context, receipt, freeze, records, measured)
    artifact_check = reader.validate_train_artifact_readback(output,
        expected_receipt=receipt, expected_freeze=freeze, trusted_file_sha256=measured)
    return dict(status='PASS_PARENT_ARTIFACT_CANDIDATE_BINDING_ONLY', family=context.family,
                seed=context.seed, output=output, guard_check=guard_check,
                fit_context_check=identity_check, artifact_check=artifact_check,
                candidate_worker_receipt=receipt, freeze_envelope=freeze,
                parent_measured_file_sha256=dict(measured),
                numerical_model_predictions_verified=False, numerical_held_metrics_verified=False,
                guard_receipt_provenance_authenticated=False, authentic_user_consent_proven=False,
                formal_training_authorized_by_this_function=False, new_formal_18_fit_release=False)
