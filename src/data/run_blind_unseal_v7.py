#!/usr/bin/env python3
"""Single-file operational one-shot executor for the sealed BLIND runtime audit.

This program intentionally uses only the Python standard library and is only
callable through its fixed command-line entry point.  It is an operational
control (not a same-account adversarial-irreversibility claim).
"""
from __future__ import print_function

import csv
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

FORMAL_STAGES = set(("02_hf_coarse", "03_hmf_coarse", "04_integer_refine"))
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class Refusal(Exception):
    pass


def _read_json(path):
    with open(path, "r", encoding="utf-8") as stream:
        return json.load(stream)


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sha256_lines(lines):
    return hashlib.sha256("".join(item + "\n" for item in sorted(set(lines))).encode("utf-8")).hexdigest()


def _resolve(root, relative):
    root = os.path.realpath(root)
    path = os.path.realpath(os.path.join(root, *relative.replace("\\", "/").split("/")))
    if os.path.commonpath((root, path)) != root:
        raise Refusal("BUNDLE_PATH_ESCAPE")
    return path


def _fsync_directory(path):
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _exclusive_write(path, payload):
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    _fsync_directory(os.path.dirname(os.path.abspath(path)))


def _atomic_write(path, payload):
    directory = os.path.dirname(os.path.abspath(path))
    descriptor, temporary = tempfile.mkstemp(prefix=".blind-unseal-v7-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(directory)
    except Exception:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def _git(root, *args):
    try:
        return subprocess.check_output(["git", "-C", root] + list(args), stderr=subprocess.STDOUT).decode("ascii").strip()
    except (OSError, subprocess.CalledProcessError):
        raise Refusal("GIT_VERIFICATION_FAILED")


def _require_lsf(job):
    job_id = os.environ.get("LSB_JOBID", "")
    index = os.environ.get("LSB_JOBINDEX", "")
    if not job_id or (index and index not in ("0", "-1")):
        raise Refusal("LSF_ENVIRONMENT_REQUIRED")
    if not job_id.isdigit() or job_id != str(job["registration"]["job_id"]):
        raise Refusal("LSF_JOB_ID_MISMATCH")


def _require_clean_git(root, review, artifacts):
    if _git(root, "status", "--porcelain"):
        raise Refusal("GIT_DIRTY")
    head = _git(root, "rev-parse", "HEAD")
    reviewed = review.get("reviewed_commit", "")
    if not re.match(r"^[0-9a-f]{40}$", reviewed) or _git(root, "rev-parse", reviewed) != reviewed:
        raise Refusal("REVIEWED_COMMIT_UNRESOLVED")
    if _git(root, "merge-base", "--is-ancestor", reviewed, head) != "":
        raise Refusal("REVIEWED_COMMIT_NOT_ANCESTOR")
    for relative, expected in artifacts.items():
        if not SHA256_RE.match(expected or ""):
            raise Refusal("ARTIFACT_DIGEST_FORMAT")
        blob = _git(root, "show", reviewed + ":" + relative)
        # git show decodes bytes poorly for arbitrary artifacts; reviewed files are UTF-8 JSON/Python.
        if hashlib.sha256(blob.encode("ascii")).hexdigest() != expected or _sha256_file(_resolve(root, relative)) != expected:
            raise Refusal("REVIEWED_BLOB_OR_WORKTREE_DRIFT")


def _verify_snapshot(root, contract):
    snapshot_path = _resolve(root, contract["gate_snapshot"]["path"])
    if _sha256_file(snapshot_path) != contract["gate_snapshot"]["sha256"]:
        raise Refusal("GATE_SNAPSHOT_DIGEST")
    snapshot = _read_json(snapshot_path)
    if snapshot.get("snapshot_status") != "SEALED_PENDING_BLIND_AUDIT" or snapshot.get("blind_data_accessed"):
        raise Refusal("GATE_SNAPSHOT_SEMANTICS")
    for relative, expected in snapshot.get("upstream_files", {}).items():
        if _sha256_file(_resolve(root, relative)) != expected:
            raise Refusal("GATE_SNAPSHOT_UPSTREAM_DRIFT")


def _verify_preconditions(root, contract, job):
    required = {
        contract["scope"]["split_contract"]: contract["scope"]["split_contract_sha256"],
        contract["scope"]["method_registry"]: contract["scope"]["method_registry_sha256"],
        contract["inputs"]["inventory_freeze_receipt"]: contract["inputs"]["inventory_freeze_receipt_sha256"],
        contract["protocol"]["path"]: contract["protocol"]["sha256"],
        contract["registry"]["path"]: contract["registry"]["sha256"],
    }
    for relative, expected in required.items():
        if _sha256_file(_resolve(root, relative)) != expected:
            raise Refusal("FROZEN_INPUT_DIGEST")
    if job.get("status") != "REGISTERED_HELD" or not job.get("registration", {}).get("job_id"):
        raise Refusal("JOB_NOT_REGISTERED_HELD")
    split = _read_json(_resolve(root, contract["scope"]["split_contract"]))
    expected_scope = [(x["circuit"], x["family"]) for x in split["formal_runtime_membership"]["BLIND_TEST"]]
    supplied = [(x.get("circuit"), x.get("family")) for x in job.get("circuits", [])]
    if supplied != expected_scope:
        raise Refusal("JOB_SCOPE_MISMATCH")
    _verify_snapshot(root, contract)


def _verify_review(root, contract, contract_sha, job, artifacts):
    path = _resolve(root, contract["review_gate"]["receipt"])
    review = _read_json(path)
    required = {"status": "PASS", "execution_allowed": True, "no_blind_parse": True, "no_blind_output": True,
                "contract_sha256": contract_sha, "job_id": job["registration"]["job_id"],
                "protocol_sha256": contract["protocol"]["sha256"], "gate_snapshot_sha256": contract["gate_snapshot"]["sha256"],
                "reviewed_artifacts": artifacts}
    if any(review.get(key) != value for key, value in required.items()):
        raise Refusal("INDEPENDENT_REVIEW_NOT_PASS")
    if review.get("blind_data_read") or review.get("real_unseal_executed"):
        raise Refusal("REVIEW_SCOPE_VIOLATION")
    return review


def _prepare_output(path):
    path = os.path.abspath(path)
    if os.path.lexists(path):
        if os.path.islink(path) or not os.path.isdir(path) or os.listdir(path):
            raise Refusal("OUTPUT_ROOT_NOT_EMPTY")
    else:
        parent = os.path.dirname(path)
        if not os.path.isdir(parent) or os.path.islink(parent):
            raise Refusal("OUTPUT_PARENT_INVALID")
        os.mkdir(path, 0o700)
        _fsync_directory(parent)
    if os.path.realpath(path) != path:
        raise Refusal("OUTPUT_ROOT_SYMLINKED")
    return path


def _inventory(root, relative_paths, prefix):
    lines = []
    for relative in relative_paths:
        path = os.path.join(root, *relative.split("/"))
        if not os.path.isfile(path) or os.path.islink(path):
            raise ValueError("INPUT_FILE_MISSING_OR_SYMLINK")
        lines.append(_sha256_file(path) + "  " + prefix + relative + "\n")
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def _driver_inventory(root):
    paths = []
    for parent, directories, files in os.walk(root):
        directories.sort()
        for name in sorted(files):
            if name.endswith(".driver.log"):
                paths.append(os.path.relpath(os.path.join(parent, name), root).replace(os.sep, "/"))
    return _inventory(root, sorted(paths), "./"), len(paths)


def _table_paths(root):
    names = (("01_single_boundaries", "measurements.tsv", "single"), ("02_hf_coarse", "measurements.tsv", "hf"),
             ("03_hmf_coarse", "measurements.tsv", "hmf"), ("04_integer_refine", "hf_measurements.tsv", "hf"),
             ("04_integer_refine", "hmf_measurements.tsv", "hmf"), ("05_repeatability", "measurements.tsv", "repeatability"))
    result = []
    for stage, filename, kind in names:
        path = os.path.join(root, stage, filename)
        if os.path.isfile(path) and not os.path.islink(path):
            result.append((stage, kind, path))
    return result


def _value(row, key):
    for candidate in (key, key.upper(), key.lower()):
        if row.get(candidate) is not None:
            return row[candidate].strip()
    return ""


def _source_rows(kind, row):
    modes = (("H", "h_result_path"),) if kind == "hf" else (("H", "h_result_path"), ("M", "m_result_path"), ("F", "f_result_path"))
    return [(mode, _value(row, field)) for mode, field in modes]


def _attempt_index(log_root):
    source, run = {}, {}
    for parent, directories, files in os.walk(log_root):
        directories.sort()
        for name in sorted(files):
            if not name.endswith(".driver.log"):
                continue
            path = os.path.join(parent, name)
            with open(path, "r", encoding="utf-8", errors="replace") as stream:
                text = stream.read()
            mode_match = re.search(r"(?:^|[ _-])([HMF])(?:[ _-]|$)", name)
            run_match = re.search(r"(?:run[_ -]?id|run_id)\s*[:=]\s*([^\s]+)", text, re.I)
            mode = mode_match.group(1) if mode_match else ""
            if mode:
                source.setdefault((mode, name), []).append(path)
                if run_match:
                    run.setdefault((mode, run_match.group(1)), []).append(path)
    return source, run


def _audit_circuit(entry, measurement_files):
    for field in ("measurements_root", "log_root", "evidence_root"):
        root = entry[field]
        if not os.path.isdir(root) or os.path.islink(root) or os.path.realpath(root) != os.path.abspath(root):
            raise ValueError("INPUT_ROOT_INVALID")
    if _inventory(entry["measurements_root"], measurement_files, "") != entry["measurement_file_set_sha256"]:
        raise ValueError("MEASUREMENT_SOURCE_SET_CHANGED")
    log_sha, log_count = _driver_inventory(entry["log_root"])
    if log_sha != entry["driver_log_file_set_sha256"] or log_count != entry["expected_driver_log_count"]:
        raise ValueError("DRIVER_SOURCE_SET_CHANGED")
    source, run = _attempt_index(entry["log_root"])
    selected, actions, artifacts = [], [], []
    for stage, kind, path in _table_paths(entry["measurements_root"]):
        artifacts.append(stage + ":" + _sha256_file(path))
        with open(path, "r", encoding="utf-8", newline="") as stream:
            for row in csv.DictReader(stream, delimiter="\t"):
                if kind in ("hf", "hmf"):
                    h, m = _value(row, "h_patterns"), _value(row, "m_patterns") if kind == "hmf" else ""
                    if not h or (kind == "hmf" and not m):
                        raise ValueError("INVALID_ACTION_KEY")
                    actions.append("|".join((entry["circuit"], "HF" if kind == "hf" else "HMF", h, m)))
                for mode, result_path in _source_rows(kind, row):
                    if stage not in FORMAL_STAGES:
                        continue
                    marker = os.path.basename(result_path)
                    if not marker:
                        selected.append("MISSING")
                    else:
                        matches = source.get((mode, marker), []) or run.get((mode, marker), [])
                        selected.append("UNIQUE" if len(matches) == 1 else ("MISSING" if not matches else "AMBIGUOUS"))
    if not actions:
        raise ValueError("EMPTY_ACTION_SPACE")
    unique, missing, ambiguous = (selected.count("UNIQUE"), selected.count("MISSING"), selected.count("AMBIGUOUS"))
    if missing or ambiguous or unique != len(selected):
        raise ValueError("R06_R07_FAILED")
    return {"circuit": entry["circuit"], "executed_stage_reference_count": len(selected), "unique_runtime_join_count": unique,
            "missing_runtime_join_count": missing, "ambiguous_runtime_join_count": ambiguous, "coverage_rate": 1.0,
            "frozen_runtime_eligible_action_space_sha256": _sha256_lines(actions),
            "source_artifact_set_sha256": _sha256_lines(artifacts)}


def _release_marker(contract_sha, receipt_sha):
    return _json_bytes({"schema_version": "blind-runtime-unseal-release-v7", "status": "RELEASED", "contract_sha256": contract_sha, "receipt_sha256": receipt_sha})


def _write_release(root, contract, contract_sha, tool_sha, output_root, receipt):
    receipt_path = os.path.join(output_root, "receipt.json")
    payload = _json_bytes(receipt)
    receipt_sha = hashlib.sha256(payload).hexdigest()
    _atomic_write(receipt_path, payload)
    _atomic_write(os.path.join(output_root, "receipt.json.sha256"), (receipt_sha + "  receipt.json\n").encode("ascii"))
    _exclusive_write(os.path.join(output_root, "RELEASED"), _release_marker(contract_sha, receipt_sha))
    if not _verify_release(root, contract, contract_sha, tool_sha, output_root):
        raise RuntimeError("RELEASE_VERIFY_FAILED")


def _verify_release(root, contract, contract_sha, tool_sha, output_root):
    paths = {name: os.path.join(output_root, name) for name in ("CONSUMED", "receipt.json", "receipt.json.sha256", "RELEASED")}
    if not all(os.path.isfile(path) and not os.path.islink(path) for path in paths.values()):
        return False
    try:
        consumed, receipt, released = (_read_json(paths["CONSUMED"]), _read_json(paths["receipt.json"]), _read_json(paths["RELEASED"]))
        with open(paths["receipt.json.sha256"], "r", encoding="ascii") as stream:
            fields = stream.read().strip().split()
    except (OSError, ValueError):
        return False
    receipt_sha = _sha256_file(paths["receipt.json"])
    if fields != [receipt_sha, "receipt.json"]:
        return False
    if consumed != {"schema_version": "blind-runtime-unseal-consumed-v7", "status": "CONSUMED", "contract_sha256": contract_sha, "tool_set_sha256": tool_sha}:
        return False
    if released != {"schema_version": "blind-runtime-unseal-release-v7", "status": "RELEASED", "contract_sha256": contract_sha, "receipt_sha256": receipt_sha}:
        return False
    required = {"schema_version", "status", "formal_runtime_membership_sha256", "method_registry_sha256", "tool_set_sha256", "contract_sha256", "circuits"}
    allowed = set(contract["allowed_receipt"]["envelope_fields"])
    if not required.issubset(receipt) or not set(receipt).issubset(allowed):
        return False
    if receipt.get("schema_version") != "blind-runtime-unseal-receipt-v7" or receipt.get("contract_sha256") != contract_sha or receipt.get("tool_set_sha256") != tool_sha:
        return False
    rows = receipt.get("circuits")
    if receipt.get("status") == "PASS":
        allowed_row = set(contract["allowed_receipt"]["circuit_row_fields"])
        return isinstance(rows, list) and [x.get("circuit") for x in rows] == contract["scope"]["blind_circuits"] and all(set(x) == allowed_row for x in rows)
    return receipt.get("status") == "FAIL" and rows == [] and receipt.get("failure_code") == "SEALED_AUDIT_FAILED"


def _main(bundle_root):
    contract_path = _resolve(bundle_root, "contracts/blind_runtime_unseal_v7.json")
    contract_sha, contract = _sha256_file(contract_path), _read_json(contract_path)
    if contract.get("status") != "SEALED_PENDING_REGISTRATION_AND_REVIEW":
        raise Refusal("CONTRACT_NOT_SEALED")
    job_path = _resolve(bundle_root, contract["inputs"]["job_spec"])
    if _sha256_file(job_path) != contract["inputs"]["job_spec_sha256"]:
        raise Refusal("JOB_DIGEST")
    job = _read_json(job_path)
    _require_lsf(job)
    artifacts = contract["implementation"]["artifact_sha256"]
    if _sha256_file(os.path.abspath(__file__)) != artifacts.get("src/data/run_blind_unseal_v7.py"):
        raise Refusal("RUNNER_DIGEST")
    _verify_preconditions(bundle_root, contract, job)
    review = _verify_review(bundle_root, contract, contract_sha, job, artifacts)
    _require_clean_git(bundle_root, review, artifacts)
    output_root = _prepare_output(job["output_root"])
    tool_sha = _sha256_lines(path + ":" + digest for path, digest in artifacts.items())
    _exclusive_write(os.path.join(output_root, "CONSUMED"), _json_bytes({"schema_version": "blind-runtime-unseal-consumed-v7", "status": "CONSUMED", "contract_sha256": contract_sha, "tool_set_sha256": tool_sha}))
    try:
        rows = [_audit_circuit(entry, job["measurement_files"]) for entry in job["circuits"]]
        receipt = {"schema_version": "blind-runtime-unseal-receipt-v7", "status": "PASS", "formal_runtime_membership_sha256": contract["scope"]["formal_runtime_membership_sha256"], "method_registry_sha256": contract["scope"]["method_registry_sha256"], "tool_set_sha256": tool_sha, "contract_sha256": contract_sha, "circuits": rows}
        _write_release(bundle_root, contract, contract_sha, tool_sha, output_root, receipt)
        return 0
    except Exception:
        receipt = {"schema_version": "blind-runtime-unseal-receipt-v7", "status": "FAIL", "formal_runtime_membership_sha256": contract["scope"]["formal_runtime_membership_sha256"], "method_registry_sha256": contract["scope"]["method_registry_sha256"], "tool_set_sha256": tool_sha, "contract_sha256": contract_sha, "failure_code": "SEALED_AUDIT_FAILED", "circuits": []}
        try:
            _write_release(bundle_root, contract, contract_sha, tool_sha, output_root, receipt)
        except Exception:
            pass
        return 1


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2 or argv[0] != "--bundle-root":
        print("BLIND_UNSEAL=REFUSED_FIXED_ARGV")
        return 2
    try:
        code = _main(os.path.abspath(argv[1]))
    except Refusal as error:
        print("BLIND_UNSEAL=REFUSED_%s" % error)
        return 2
    print("BLIND_UNSEAL=%s" % ("PASS" if code == 0 else "INCOMPLETE_CONSUMED"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
