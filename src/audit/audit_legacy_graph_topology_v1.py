#!/usr/bin/env python3
"""Digest legacy PyTorch edge tensors without torch or pickle execution."""
from __future__ import print_function

import argparse
import hashlib
import io
import json
import os
import re
import stat
import struct
import tempfile
import zipfile


HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONTRACT = os.path.normpath(os.path.join(
    HERE, "..", "..", "contracts", "legacy_graph_topology_audit_v1.json"))
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GLOB_RE = re.compile(r"[*?\[\]]")


class TopologyAuditError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise TopologyAuditError(code)


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def read_regular_bytes(path, label):
    require(os.path.exists(path), label + "_MISSING")
    require(not os.path.islink(path), label + "_SYMLINK")
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise TopologyAuditError(label + "_OPEN_FAILED: " + str(exc))
    with os.fdopen(descriptor, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode),
                label + "_NOT_REGULAR")
        return stream.read()


def json_object(data, label):
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, TypeError, ValueError) as exc:
        raise TopologyAuditError(label + "_INVALID_JSON: " + str(exc))
    require(isinstance(value, dict), label + "_NOT_OBJECT")
    return value


def validate_root(path):
    require(isinstance(path, str) and os.path.isabs(path), "EVIDENCE_ROOT")
    absolute, real = os.path.abspath(path), os.path.realpath(path)
    require(os.path.normcase(absolute) == os.path.normcase(real),
            "EVIDENCE_ROOT_SYMLINK")
    require(os.path.isdir(real), "EVIDENCE_ROOT_NOT_DIRECTORY")
    return real


def resolve(root, relative, label):
    require(isinstance(relative, str) and relative and
            not os.path.isabs(relative), label + "_PATH")
    require(not GLOB_RE.search(relative), label + "_GLOB")
    normalized = os.path.normpath(relative)
    require(normalized not in ("", ".", "..") and
            not normalized.startswith(".." + os.sep), label + "_ESCAPE")
    candidate = os.path.abspath(os.path.join(root, normalized))
    real = os.path.realpath(candidate)
    try:
        inside = os.path.commonpath((root, real)) == root
    except ValueError:
        inside = False
    require(inside, label + "_ESCAPE")
    current = root
    for component in os.path.relpath(candidate, root).split(os.sep):
        current = os.path.join(current, component)
        require(not os.path.islink(current), label + "_SYMLINK")
    return candidate


def positive_int(value, label):
    require(isinstance(value, int) and not isinstance(value, bool) and value > 0,
            label)
    return value


def edge_digest(artifact_bytes, circuit, nodes, edges):
    try:
        archive = zipfile.ZipFile(io.BytesIO(artifact_bytes), "r")
    except (OSError, zipfile.BadZipFile) as exc:
        raise TopologyAuditError("GRAPH_ZIP_INVALID_%s: %s" % (circuit, exc))
    with archive:
        edge_member = circuit + "/data/1"
        byteorder_member = circuit + "/byteorder"
        names = archive.namelist()
        require(names.count(edge_member) == 1 and
                names.count(byteorder_member) == 1,
                "GRAPH_MEMBERS_%s" % circuit)
        require(archive.getinfo(edge_member).file_size == edges * 2 * 8,
                "GRAPH_EDGE_MEMBER_SIZE_%s" % circuit)
        byteorder = archive.read(byteorder_member).decode("ascii").strip()
        require(byteorder in ("little", "big"),
                "GRAPH_BYTEORDER_%s" % circuit)
        raw = archive.read(edge_member)
    require(len(raw) == edges * 2 * 8, "GRAPH_EDGE_BYTES_%s" % circuit)
    prefix = "<" if byteorder == "little" else ">"
    values = struct.unpack(prefix + "%dq" % (edges * 2), raw)
    pairs = sorted((values[index], values[edges + index])
                   for index in range(edges))
    require(len(set(pairs)) == edges, "GRAPH_DUPLICATE_EDGE_%s" % circuit)
    require(all(0 <= source < nodes and 0 <= destination < nodes
                for source, destination in pairs),
            "GRAPH_EDGE_RANGE_%s" % circuit)
    encoded = (json.dumps([list(pair) for pair in pairs],
                          separators=(",", ":")) + "\n").encode("utf-8")
    return sha256_bytes(encoded)


def build_receipt(contract_path, bindings_path):
    contract_bytes = read_regular_bytes(contract_path, "CONTRACT")
    contract = json_object(contract_bytes, "CONTRACT")
    require(contract.get("schema_version") ==
            "legacy-graph-topology-audit-v1-contract", "CONTRACT_SCHEMA")
    require(contract.get("status") == "FROZEN_DIGEST_ONLY",
            "CONTRACT_STATUS")
    expected_circuits = ["aes_core", "s13207", "s15850", "s35932",
                         "s38417", "s5378", "spi", "tv80"]
    expected_fields = ["circuit", "path", "sha256", "nodes", "edges"]
    contract_input = contract.get("input", {})
    contract_format = contract.get("format", {})
    contract_output = contract.get("output", {})
    require(contract_input.get("bindings_schema_version") ==
            "legacy-graph-topology-bindings-v1" and
            contract_input.get("required_graph_count") == 8 and
            contract_input.get("required_circuits") == expected_circuits and
            contract_input.get("artifact_fields") == expected_fields and
            contract_input.get("symlinks_allowed") is False and
            contract_input.get("glob_allowed") is False and
            contract_input.get("path_escape_allowed") is False,
            "CONTRACT_INPUT")
    require(contract_format.get("container") == "pytorch-zip" and
            contract_format.get("pickle_execution_allowed") is False and
            contract_format.get("edge_storage_member") ==
            "<circuit>/data/1" and
            contract_format.get("byteorder_member") ==
            "<circuit>/byteorder" and
            contract_format.get("edge_dtype") == "signed-int64" and
            contract_format.get("edge_shape") == "2 x edges" and
            contract_format.get("canonicalization") ==
            "sorted unique [source,destination] pairs serialized as compact JSON plus LF",
            "CONTRACT_FORMAT")
    require(contract_output.get("schema_version") ==
            "legacy-graph-topology-receipt-v1" and
            contract_output.get("aggregate_only") is True and
            contract_output.get("raw_nodes_or_edges_allowed") is False and
            contract_output.get("training_execution_allowed") is False,
            "CONTRACT_OUTPUT")
    bindings_bytes = read_regular_bytes(bindings_path, "BINDINGS")
    bindings = json_object(bindings_bytes, "BINDINGS")
    require(set(bindings) == set(("schema_version", "evidence_root", "graphs")),
            "BINDINGS_FIELDS")
    require(bindings.get("schema_version") ==
            "legacy-graph-topology-bindings-v1", "BINDINGS_SCHEMA")
    root = validate_root(bindings.get("evidence_root"))
    graphs = bindings.get("graphs")
    expected_fields = set(contract_input["artifact_fields"])
    require(isinstance(graphs, list) and len(graphs) ==
            contract["input"]["required_graph_count"], "GRAPH_COUNT")
    require(sorted(item.get("circuit") for item in graphs) ==
            sorted(contract["input"]["required_circuits"]), "GRAPH_ROSTER")
    records = {}
    seen_paths = set()
    for item in graphs:
        require(isinstance(item, dict) and set(item) == expected_fields,
                "GRAPH_BINDING_FIELDS")
        circuit = item["circuit"]
        require(SHA256_RE.match(str(item["sha256"])),
                "GRAPH_SHA_FORMAT_%s" % circuit)
        path = resolve(root, item["path"], "GRAPH_%s" % circuit)
        key = os.path.normcase(os.path.realpath(path))
        require(key not in seen_paths, "GRAPH_REUSED_PATH")
        seen_paths.add(key)
        artifact = read_regular_bytes(path, "GRAPH_%s" % circuit)
        require(sha256_bytes(artifact) == item["sha256"],
                "GRAPH_SHA_MISMATCH_%s" % circuit)
        nodes = positive_int(item["nodes"], "GRAPH_NODES_%s" % circuit)
        edges = positive_int(item["edges"], "GRAPH_EDGES_%s" % circuit)
        records[circuit] = {
            "artifact_sha256": item["sha256"],
            "nodes": nodes,
            "edges": edges,
            "canonical_edge_index_sha256": edge_digest(
                artifact, circuit, nodes, edges),
        }
    return {
        "schema_version": "legacy-graph-topology-receipt-v1",
        "status": "PASS_DIGEST_ONLY",
        "contract_sha256": sha256_bytes(contract_bytes),
        "bindings_sha256": sha256_bytes(bindings_bytes),
        "graph_count": len(records),
        "graphs": dict((name, records[name]) for name in sorted(records)),
        "raw_nodes_or_edges_persisted": False,
        "pickle_executed": False,
        "torch_imported": False,
        "training_execution_allowed": False,
    }


def atomic_write(path, value):
    require(not os.path.exists(path), "OUTPUT_EXISTS")
    parent = os.path.dirname(os.path.abspath(path)) or os.curdir
    descriptor, temporary = tempfile.mkstemp(
        prefix=".legacy-topology-v1-", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
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
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", default=DEFAULT_CONTRACT)
    parser.add_argument("--bindings", required=True)
    parser.add_argument("output")
    args = parser.parse_args(argv)
    receipt = build_receipt(args.contract, args.bindings)
    atomic_write(args.output, receipt)
    print("LEGACY_GRAPH_TOPOLOGY=PASS_DIGEST_ONLY graphs=%d" %
          receipt["graph_count"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
