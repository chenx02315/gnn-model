#!/usr/bin/env python3
"""Audit explicitly bound common-fault denominators (Python 3.6+)."""
from __future__ import print_function

import argparse
import csv
import hashlib
import io
import json
import math
import os
import re
import stat
import sys
import tempfile


HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONTRACT = os.path.normpath(os.path.join(
    HERE, "..", "..", "contracts", "common_fault_denominator_v2.json"))
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GLOB_RE = re.compile(r"[*?\[\]]")
BASIC_RE = re.compile(r"^\s*([01])\s+(\S+)\s+(.+?)\s*$")
MTFI_RE = re.compile(r'^\s*([01]),\s+([^,]+),\s+"([^"]+)";\s*$')
FLAT_INSTANCE_RE = re.compile(r"(?<=/)U(\d+)(?=/)")
MODES = ("H", "M", "F")
TOP_FIELDS = frozenset(("schema_version", "evidence_root", "circuits"))
CIRCUIT_FIELDS = frozenset((
    "circuit", "family", "role", "manifest", "mapping", "readback", "modes",
    "native_universes"))
ARTIFACT_FIELDS = frozenset(("path", "sha256"))
MANIFEST_FIELDS = frozenset((
    "schema", "fault_model", "common_fault_count", "files", "mapping",
    "f_flat_instance_offset", "native_fault_counts", "minimum_fraction"))
MAPPING_MANIFEST_FIELDS = frozenset(("path", "sha256", "row_count_excluding_header"))
MODE_MANIFEST_FIELDS = frozenset(("path", "sha256", "fault_count"))


class AuditError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise AuditError(code)


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def canonical_json_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("utf-8")


def read_regular_bytes(path, label):
    require(os.path.exists(path), label + "_MISSING")
    require(not os.path.islink(path), label + "_SYMLINK")
    info = os.stat(path, follow_symlinks=False)
    require(stat.S_ISREG(info.st_mode), label + "_NOT_REGULAR")
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AuditError(label + "_OPEN_FAILED: " + str(exc))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode), label + "_NOT_REGULAR")
        return stream.read()


def load_json_bytes(data, label):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuditError(label + "_INVALID_UTF8: " + str(exc))
    try:
        value = json.loads(text)
    except (TypeError, ValueError) as exc:
        raise AuditError(label + "_INVALID_JSON: " + str(exc))
    require(isinstance(value, dict), label + "_NOT_OBJECT")
    return value


def load_json_file(path, label):
    data = read_regular_bytes(path, label)
    return load_json_bytes(data, label), data


def validate_contract(contract):
    require(contract.get("schema_version") == "common-fault-denominator-v2",
            "CONTRACT_SCHEMA")
    require(contract.get("status") == "DESIGN_FROZEN_LOCAL_AUDIT_ONLY",
            "CONTRACT_STATUS")
    binding = contract.get("binding_schema", {})
    require(binding.get("schema_version") == "common-fault-denominator-bindings-v2",
            "CONTRACT_BINDING_SCHEMA")
    require(binding.get("glob_paths_allowed") is False and
            binding.get("symlinks_allowed") is False and
            binding.get("path_escape_allowed") is False and
            binding.get("ambiguous_or_reused_artifact_paths_allowed") is False,
            "CONTRACT_PATH_POLICY")
    manifest = contract.get("manifest_contract", {})
    require(manifest.get("schema") == "multimode_common_fault_universe_v1" and
            manifest.get("fault_model") == "stuck-at", "CONTRACT_MANIFEST")
    require(manifest.get("recompute_intersection_from_native_mtfi") is True,
            "CONTRACT_NATIVE_INTERSECTION")
    readback = contract.get("readback_contract", {})
    require(readback.get("status") == "PASS" and
            readback.get("errors") == [] and
            readback.get("all_counts_equal_common_fault_count") is True,
            "CONTRACT_READBACK")
    identity = contract.get("identity_rules", {})
    require(identity.get("stuck_values") == ["0", "1"] and
            identity.get("basic_class_is_ignored") is True and
            identity.get("duplicate_identities_allowed") is False,
            "CONTRACT_IDENTITY")
    denominator = contract.get("denominator_rules", {})
    require(denominator.get("d95") == "ceil(0.95 * common_fault_count)" and
            denominator.get("fault_model") == "stuck-at", "CONTRACT_DENOMINATOR")
    receipt = contract.get("receipt_policy", {})
    require(receipt.get("aggregate_only") is True and
            receipt.get("fault_identities_allowed") is False and
            receipt.get("candidate_or_outcome_fields_allowed") is False and
            receipt.get("raw_source_paths_allowed") is False,
            "CONTRACT_RECEIPT")
    execution = contract.get("execution_boundary", {})
    require(execution.get("remote_access_allowed") is False and
            execution.get("training_allowed") is False and
            execution.get("lsf_or_tessent_allowed") is False and
            execution.get("input_discovery_allowed") is False,
            "CONTRACT_EXECUTION")
    roster = contract.get("required_roster")
    require(isinstance(roster, list) and roster, "CONTRACT_ROSTER")
    require(all(isinstance(item, dict) and
                set(item) == set(("circuit", "family", "role"))
                for item in roster), "CONTRACT_ROSTER_FIELDS")


def validate_root(root):
    require(isinstance(root, str) and root, "EVIDENCE_ROOT")
    require(os.path.isabs(root), "EVIDENCE_ROOT_NOT_ABSOLUTE")
    require(not GLOB_RE.search(root), "EVIDENCE_ROOT_GLOB")
    absolute = os.path.abspath(root)
    real = os.path.realpath(root)
    require(os.path.normcase(absolute) == os.path.normcase(real),
            "EVIDENCE_ROOT_SYMLINK")
    require(os.path.isdir(real), "EVIDENCE_ROOT_NOT_DIRECTORY")
    return real


def path_components(root, path):
    relative = os.path.relpath(path, root)
    current = root
    yield current
    for component in relative.split(os.sep):
        current = os.path.join(current, component)
        yield current


def resolve_artifact(root, artifact, label):
    require(isinstance(artifact, dict) and set(artifact) == ARTIFACT_FIELDS,
            label + "_FIELDS")
    relative = artifact.get("path")
    expected_sha = artifact.get("sha256")
    require(isinstance(relative, str) and relative, label + "_PATH")
    require(not GLOB_RE.search(relative), label + "_GLOB")
    drive, _tail = os.path.splitdrive(relative)
    require(not drive and not os.path.isabs(relative), label + "_ABSOLUTE")
    normalized = os.path.normpath(relative)
    require(normalized not in ("", ".", "..") and
            not normalized.startswith(".." + os.sep), label + "_ESCAPE")
    require(SHA256_RE.match(expected_sha or "") is not None, label + "_SHA_FORMAT")
    joined = os.path.abspath(os.path.join(root, normalized))
    real = os.path.realpath(joined)
    try:
        inside = os.path.commonpath((root, real)) == root
    except ValueError:
        inside = False
    require(inside, label + "_ESCAPE")
    for component in path_components(root, joined):
        require(not os.path.islink(component), label + "_SYMLINK")
    require(os.path.exists(joined), label + "_MISSING")
    info = os.stat(joined, follow_symlinks=False)
    require(stat.S_ISREG(info.st_mode), label + "_NOT_REGULAR")
    data = read_regular_bytes(joined, label)
    observed_sha = sha256_bytes(data)
    require(observed_sha == expected_sha, label + "_SHA_MISMATCH")
    return {
        "path": joined,
        "relative": normalized.replace(os.sep, "/"),
        "sha256": observed_sha,
        "data": data,
    }


def normalize_manifest_reference(manifest_relative, reference, label):
    require(isinstance(reference, str) and reference, label + "_MANIFEST_PATH")
    require(not GLOB_RE.search(reference), label + "_MANIFEST_GLOB")
    drive, _tail = os.path.splitdrive(reference)
    require(not drive and not os.path.isabs(reference), label + "_MANIFEST_ABSOLUTE")
    normalized = os.path.normpath(os.path.join(
        os.path.dirname(manifest_relative), reference))
    require(normalized != ".." and not normalized.startswith(".." + os.sep),
            label + "_MANIFEST_ESCAPE")
    return normalized.replace(os.sep, "/")


def parse_mapping(data, accepted_headers):
    try:
        stream = io.StringIO(data.decode("utf-8"), newline="")
    except UnicodeDecodeError as exc:
        raise AuditError("MAPPING_INVALID_UTF8: " + str(exc))
    with stream:
        reader = csv.DictReader(stream, delimiter="\t")
        header = tuple(reader.fieldnames or ())
        require(header in accepted_headers, "MAPPING_HEADER")
        if header[1] == "canonical_core_path":
            canonical_column = "canonical_core_path"
            mode_columns = dict((mode, mode + "_native_path") for mode in MODES)
        else:
            canonical_column = "canonical_path"
            mode_columns = dict((mode, mode + "_path") for mode in MODES)
        canonical = set()
        mode_sets = dict((mode, set()) for mode in MODES)
        row_count = 0
        for row_count, row in enumerate(reader, 1):
            require(row.get(None) is None, "MAPPING_EXTRA_COLUMNS")
            stuck = (row.get("stuck_value") or "").strip()
            require(stuck in ("0", "1"), "MAPPING_STUCK_VALUE")
            canonical_path = (row.get(canonical_column) or "").strip()
            require(canonical_path, "MAPPING_CANONICAL_PATH")
            canonical_key = (stuck, canonical_path)
            require(canonical_key not in canonical, "MAPPING_DUPLICATE_CANONICAL")
            canonical.add(canonical_key)
            for mode in MODES:
                native_path = (row.get(mode_columns[mode]) or "").strip()
                require(native_path, "MAPPING_%s_PATH" % mode)
                key = (stuck, native_path)
                require(key not in mode_sets[mode], "MAPPING_DUPLICATE_%s" % mode)
                mode_sets[mode].add(key)
    require(row_count > 0, "MAPPING_EMPTY")
    return canonical, mode_sets


def parse_basic(data, mode):
    identities = set()
    try:
        stream = io.StringIO(data.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise AuditError("BASIC_%s_INVALID_UTF8: %s" % (mode, exc))
    with stream:
        for line_number, raw in enumerate(stream, 1):
            line = raw.rstrip("\r\n")
            if not line.strip():
                continue
            match = BASIC_RE.match(line)
            require(match is not None, "BASIC_%s_MALFORMED_LINE_%d" %
                    (mode, line_number))
            stuck, _fault_class, location = match.groups()
            location = location.strip()
            if location.startswith('"') or location.endswith('"'):
                require(len(location) >= 2 and location.startswith('"') and
                        location.endswith('"'), "BASIC_%s_QUOTE_%d" %
                        (mode, line_number))
                location = location[1:-1]
            require(location, "BASIC_%s_EMPTY_PATH_%d" % (mode, line_number))
            key = (stuck, location)
            require(key not in identities, "BASIC_DUPLICATE_%s" % mode)
            identities.add(key)
    require(identities, "BASIC_EMPTY_%s" % mode)
    return identities


def parse_mtfi(data, mode):
    try:
        stream = io.StringIO(data.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise AuditError("MTFI_%s_INVALID_UTF8: %s" % (mode, exc))
    identities = set()
    matched = 0
    with stream:
        for line_number, raw in enumerate(stream, 1):
            line = raw.rstrip("\r\n")
            match = MTFI_RE.match(line)
            if match is None:
                if re.match(r"^\s*[01]\s*,", line):
                    raise AuditError("MTFI_%s_MALFORMED_LINE_%d" %
                                     (mode, line_number))
                continue
            matched += 1
            key = (match.group(1), match.group(3))
            require(key not in identities, "MTFI_DUPLICATE_%s" % mode)
            identities.add(key)
    require(matched > 0, "MTFI_EMPTY_%s" % mode)
    return identities


def shift_key(key, offset):
    value, location = key
    return (value, FLAT_INSTANCE_RE.sub(
        lambda match: "U%d" % (int(match.group(1)) + offset), location))


def int_field(value, label):
    require(isinstance(value, int) and not isinstance(value, bool) and value > 0,
            label)
    return value


def audit_circuit(root, entry, accepted_headers, seen_paths):
    require(isinstance(entry, dict) and set(entry) == CIRCUIT_FIELDS,
            "CIRCUIT_FIELDS")
    circuit = entry.get("circuit")
    require(isinstance(circuit, str) and circuit.strip() == circuit and circuit,
            "CIRCUIT_NAME")
    family = entry.get("family")
    role = entry.get("role")
    require(isinstance(family, str) and family.strip() == family and family,
            "CIRCUIT_FAMILY")
    require(role in ("TRAIN", "VALIDATION"), "CIRCUIT_ROLE")
    require(isinstance(entry.get("modes"), dict) and
            set(entry["modes"]) == set(MODES), "CIRCUIT_MODES")
    require(isinstance(entry.get("native_universes"), dict) and
            set(entry["native_universes"]) == set(MODES),
            "CIRCUIT_NATIVE_UNIVERSES")
    artifacts = {
        "manifest": resolve_artifact(root, entry["manifest"],
                                     circuit + "_MANIFEST"),
        "mapping": resolve_artifact(root, entry["mapping"],
                                    circuit + "_MAPPING"),
        "readback": resolve_artifact(root, entry["readback"],
                                     circuit + "_READBACK"),
    }
    for mode in MODES:
        artifacts[mode] = resolve_artifact(
            root, entry["modes"][mode], circuit + "_" + mode)
        artifacts["native_" + mode] = resolve_artifact(
            root, entry["native_universes"][mode],
            circuit + "_NATIVE_" + mode)
    for artifact in artifacts.values():
        key = os.path.normcase(os.path.realpath(artifact["path"]))
        require(key not in seen_paths, "REUSED_ARTIFACT_PATH")
        seen_paths.add(key)

    manifest = load_json_bytes(artifacts["manifest"]["data"],
                               circuit + "_MANIFEST")
    require(MANIFEST_FIELDS.issubset(set(manifest)), "MANIFEST_FIELDS")
    require(manifest.get("schema") == "multimode_common_fault_universe_v1",
            "MANIFEST_SCHEMA")
    require(manifest.get("fault_model") == "stuck-at", "MANIFEST_FAULT_MODEL")
    count = int_field(manifest.get("common_fault_count"), "MANIFEST_COUNT")
    readback = load_json_bytes(artifacts["readback"]["data"],
                               circuit + "_READBACK")
    require(set(("status", "errors", "expected", "readback_counts")).issubset(
        set(readback)), "READBACK_FIELDS")
    require(readback.get("status") == "PASS" and readback.get("errors") == [],
            "READBACK_STATUS")
    require(readback.get("expected") == count, "READBACK_EXPECTED")
    require(isinstance(readback.get("readback_counts"), dict) and
            set(readback["readback_counts"]) == set(MODES),
            "READBACK_MODE_KEYS")
    require(all(readback["readback_counts"][mode] == count for mode in MODES),
            "READBACK_COUNT_MISMATCH")
    mapping_meta = manifest.get("mapping")
    require(isinstance(mapping_meta, dict) and
            MAPPING_MANIFEST_FIELDS.issubset(set(mapping_meta)),
            "MANIFEST_MAPPING_FIELDS")
    require(normalize_manifest_reference(
        artifacts["manifest"]["relative"], mapping_meta.get("path"),
        circuit + "_MAPPING") == artifacts["mapping"]["relative"],
        "MANIFEST_MAPPING_PATH")
    require(mapping_meta.get("sha256") == artifacts["mapping"]["sha256"],
            "MANIFEST_MAPPING_SHA")
    require(int_field(mapping_meta.get("row_count_excluding_header"),
                      "MANIFEST_MAPPING_COUNT") == count,
            "MANIFEST_MAPPING_COUNT_MISMATCH")

    files_meta = manifest.get("files")
    require(isinstance(files_meta, dict) and set(files_meta) == set(MODES),
            "MANIFEST_MODE_KEYS")
    for mode in MODES:
        meta = files_meta[mode]
        require(isinstance(meta, dict) and
                MODE_MANIFEST_FIELDS.issubset(set(meta)),
                "MANIFEST_%s_FIELDS" % mode)
        require(normalize_manifest_reference(
            artifacts["manifest"]["relative"], meta.get("path"),
            circuit + "_" + mode) == artifacts[mode]["relative"],
            "MANIFEST_%s_PATH" % mode)
        require(meta.get("sha256") == artifacts[mode]["sha256"],
                "MANIFEST_%s_SHA" % mode)
        require(int_field(meta.get("fault_count"), "MANIFEST_%s_COUNT" % mode)
                == count, "MANIFEST_%s_COUNT_MISMATCH" % mode)

    canonical, mapping_modes = parse_mapping(
        artifacts["mapping"]["data"], accepted_headers)
    require(len(canonical) == count, "MAPPING_COUNT_MISMATCH")
    offset = manifest.get("f_flat_instance_offset")
    require(isinstance(offset, int) and not isinstance(offset, bool),
            "MANIFEST_F_OFFSET")
    native_counts = manifest.get("native_fault_counts")
    require(isinstance(native_counts, dict) and
            set(native_counts) == set(MODES), "MANIFEST_NATIVE_COUNTS")
    native_counts = dict((mode, int_field(
        native_counts[mode], "MANIFEST_NATIVE_COUNT_%s" % mode))
                         for mode in MODES)
    minimum_fraction = manifest.get("minimum_fraction")
    require(isinstance(minimum_fraction, (int, float)) and
            not isinstance(minimum_fraction, bool) and
            0.0 < minimum_fraction <= 1.0, "MANIFEST_MINIMUM_FRACTION")
    native_sets = dict((mode, parse_mtfi(
        artifacts["native_" + mode]["data"], mode)) for mode in MODES)
    for mode in MODES:
        require(len(native_sets[mode]) == native_counts[mode],
                "NATIVE_COUNT_MISMATCH_%s" % mode)
    recomputed = (set(shift_key(key, offset) for key in native_sets["F"]) &
                  native_sets["M"] & native_sets["H"])
    require(recomputed == canonical, "RECOMPUTED_INTERSECTION_MISMATCH")
    require(len(recomputed) >= minimum_fraction * min(
        len(native_sets[mode]) for mode in MODES),
        "COMMON_FRACTION_BELOW_MINIMUM")
    shifted_mapping_f = set(shift_key(key, offset)
                            for key in mapping_modes["F"])
    require(shifted_mapping_f == canonical,
            "MAPPING_F_OFFSET_MISMATCH")
    require(mapping_modes["M"] == canonical and
            mapping_modes["H"] == canonical, "MAPPING_MH_CANONICAL_MISMATCH")
    mode_counts = {}
    for mode in MODES:
        basic = parse_basic(artifacts[mode]["data"], mode)
        require(basic == mapping_modes[mode], "MODE_SET_MISMATCH_%s" % mode)
        require(len(basic) == count, "MODE_COUNT_MISMATCH_%s" % mode)
        mode_counts[mode] = len(basic)

    return circuit, {
        "family": family,
        "role": role,
        "common_fault_count": count,
        "d95": int(math.ceil(0.95 * count)),
        "fault_model": "stuck-at",
        "mapping_count": len(canonical),
        "mode_counts": mode_counts,
        "manifest_sha256": artifacts["manifest"]["sha256"],
        "mapping_sha256": artifacts["mapping"]["sha256"],
        "readback_sha256": artifacts["readback"]["sha256"],
        "mode_sha256": dict((mode, artifacts[mode]["sha256"])
                            for mode in MODES),
        "native_fault_counts": dict((mode, len(native_sets[mode]))
                                    for mode in MODES),
        "native_universe_sha256": dict(
            (mode, artifacts["native_" + mode]["sha256"])
            for mode in MODES),
        "f_flat_instance_offset": offset,
        "intersection_recomputed_from_native_universes": True,
        "all_mode_sets_equal_mapping": True,
        "readback_pass": True,
        "d95_rule_pass": True,
    }


def build_receipt(contract_path, bindings_path):
    contract, contract_bytes = load_json_file(contract_path, "CONTRACT")
    validate_contract(contract)
    bindings, bindings_bytes = load_json_file(bindings_path, "BINDINGS")
    require(set(bindings) == TOP_FIELDS, "BINDINGS_FIELDS")
    require(bindings.get("schema_version") ==
            "common-fault-denominator-bindings-v2", "BINDINGS_SCHEMA")
    root = validate_root(bindings.get("evidence_root"))
    entries = bindings.get("circuits")
    require(isinstance(entries, list) and entries, "BINDINGS_CIRCUITS")
    require(all(isinstance(item, dict) for item in entries),
            "BINDINGS_CIRCUIT_OBJECT")
    observed_roster = sorted((item.get("circuit"), item.get("family"),
                              item.get("role")) for item in entries)
    required_roster = sorted((item["circuit"], item["family"], item["role"])
                             for item in contract["required_roster"])
    require(observed_roster == required_roster, "BINDINGS_ROSTER_MISMATCH")
    accepted_headers = tuple(tuple(item) for item in
                             contract.get("accepted_mapping_headers", []))
    require(len(accepted_headers) == 2, "CONTRACT_MAPPING_HEADERS")
    circuits = {}
    seen_paths = set()
    total_faults = 0
    for entry in entries:
        circuit, record = audit_circuit(
            root, entry, accepted_headers, seen_paths)
        require(circuit not in circuits, "DUPLICATE_CIRCUIT")
        circuits[circuit] = record
        total_faults += record["common_fault_count"]
    ordered = dict((name, circuits[name]) for name in sorted(circuits))
    return {
        "schema_version": "common-fault-denominator-audit-receipt-v2",
        "status": "PASS",
        "contract_sha256": sha256_bytes(contract_bytes),
        "bindings_sha256": sha256_bytes(bindings_bytes),
        "circuit_count": len(ordered),
        "aggregate_common_fault_count": total_faults,
        "circuits": ordered,
        "all_manifest_hashes_match": True,
        "all_mapping_counts_match": True,
        "all_mode_sets_equal_mapping": True,
        "all_readback_receipts_pass": True,
        "all_d95_rules_pass": True,
        "all_intersections_recomputed_from_native_universes": True,
        "fault_identities_persisted": False,
        "candidate_or_outcome_data_read": False,
        "remote_access_performed": False,
        "training_performed": False,
        "lsf_or_tessent_submitted": False,
    }


def atomic_write_json(path, value):
    require(not os.path.exists(path), "OUTPUT_ALREADY_EXISTS")
    parent = os.path.dirname(os.path.abspath(path)) or os.curdir
    require(os.path.isdir(parent), "OUTPUT_PARENT")
    descriptor, temporary = tempfile.mkstemp(
        prefix=".common-fault-denominator-v2-", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_json_bytes(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", default=DEFAULT_CONTRACT)
    parser.add_argument("--bindings", required=True)
    parser.add_argument("output_json")
    args = parser.parse_args(argv)
    try:
        receipt = build_receipt(args.contract, args.bindings)
        atomic_write_json(args.output_json, receipt)
    except (AuditError, OSError) as exc:
        parser.error(str(exc))
    print("status=PASS circuits=%d total_faults=%d" %
          (receipt["circuit_count"], receipt["aggregate_common_fault_count"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
