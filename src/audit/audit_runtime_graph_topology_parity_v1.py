#!/usr/bin/env python3
"""Fail-closed aggregate digest comparison for legacy and runtime graph receipts."""
from __future__ import print_function

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile


HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONTRACT = os.path.normpath(os.path.join(
    HERE, "..", "..", "contracts", "runtime_graph_topology_parity_v1.json"))
SHA256_RE = re.compile(r"[0-9a-f]{64}")
GLOB_RE = re.compile(r"[*?\[\]]")
ROSTER = ["aes_core", "s13207", "s15850", "s35932", "s38417", "s5378", "spi", "tv80"]
REMOTE_AUDITOR_CONTRACT_SHA256 = "f3f969bd5a9cc4036f78cd983116ed6de419d22582567e4c894074a33c0f5bda"
LOCAL_RUNTIME_GRAPH_CONTRACT_SHA256 = "c1fb2934147d4a28b291dff0417a3805b0a921e07b2f8b0a05beaf5b6af2ef24"
LOCAL_RECEIPT_SHA256 = "dbe2c6701b2bafa249bc69f888c20a2b0e350d5a9e18d904b539846ec1036d0c"
HISTORICAL_ARTIFACT_SHA256 = {
    "aes_core": "6a80adf31462ec3c8f59ff81ff824e41f48dfe04ee5d8bf326cd984179be7d37",
    "s13207": "c0dd02034937a92bd68358fe738bf352d615702444950350527f942497d5f0a8",
    "s15850": "9a03e8985e7f72f72e96e2a989ef8b305fd9de46502bbbbcebb784b56c54b3e0",
    "s35932": "18db55ac1a96406213bc5350abf2bad8da495b8c0d5f9a98f148b36816ee2c3a",
    "s38417": "8a9564a545ad26ca44e1aba321256b09921b9ed32e06afff1f9a31bf54a0eb2e",
    "s5378": "cba75e68e46fc12c409fa523135bf02372f94c56d4d947f520a0c6415718a31b",
    "spi": "a9d4b5f11a684746ff1eebc2b05acca77e59b06194ecebee87a4c451ea85653d",
    "tv80": "35fb8bd99d8bdbe481e8342fd39140cbc587f8532b680ae4fd8a2ed560defe40",
}


class TopologyParityError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise TopologyParityError(code)


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def read_regular_bytes(path, label):
    require(os.path.exists(path), label + "_MISSING")
    require(not os.path.islink(path), label + "_SYMLINK")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise TopologyParityError(label + "_OPEN_FAILED: " + str(exc))
    with os.fdopen(descriptor, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), label + "_NOT_REGULAR")
        return stream.read()


def json_object(data, label):
    try:
        result = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise TopologyParityError(label + "_INVALID_JSON: " + str(exc))
    require(isinstance(result, dict), label + "_NOT_OBJECT")
    return result


def validate_root(path):
    require(isinstance(path, str) and os.path.isabs(path), "EVIDENCE_ROOT")
    absolute, real = os.path.abspath(path), os.path.realpath(path)
    require(os.path.normcase(absolute) == os.path.normcase(real), "EVIDENCE_ROOT_SYMLINK")
    require(os.path.isdir(real), "EVIDENCE_ROOT_NOT_DIRECTORY")
    return real


def resolve(root, relative, label):
    require(isinstance(relative, str) and relative and not os.path.isabs(relative), label + "_PATH")
    require(not GLOB_RE.search(relative), label + "_GLOB")
    normalized = os.path.normpath(relative)
    require(normalized not in ("", ".", "..") and not normalized.startswith(".." + os.sep), label + "_ESCAPE")
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


def valid_sha(value, label):
    require(isinstance(value, str) and len(value) == 64 and
            SHA256_RE.fullmatch(value) is not None, label)
    return value


def validate_contract(contract):
    require(contract.get("schema_version") == "runtime-graph-topology-parity-v1-contract", "CONTRACT_SCHEMA")
    inp = contract.get("input")
    remote, local, output = contract.get("remote_receipt"), contract.get("local_receipt"), contract.get("output")
    require(isinstance(inp, dict) and inp.get("bindings_schema_version") == "runtime-graph-topology-parity-bindings-v1" and inp.get("required_circuits") == ROSTER and inp.get("evidence_root_absolute") is True and inp.get("symlinks_allowed") is False and inp.get("glob_allowed") is False and inp.get("path_escape_allowed") is False and inp.get("receipt_binding_fields") == ["path", "sha256"], "CONTRACT_INPUT")
    require(remote == {"schema_version": "legacy-graph-topology-receipt-v1", "status": "PASS_DIGEST_ONLY", "comparison_key": "canonical_edge_index_sha256", "auditor_contract_sha256": REMOTE_AUDITOR_CONTRACT_SHA256, "historical_artifact_sha256": HISTORICAL_ARTIFACT_SHA256}, "CONTRACT_REMOTE")
    require(local == {"schema_version": "runtime-graphs-aggregate-receipt-v1", "status": "BLOCKED_HISTORICAL_TOPOLOGY_DIGEST", "comparison_key": "edge_index_sha256", "runtime_graph_contract_sha256": LOCAL_RUNTIME_GRAPH_CONTRACT_SHA256, "training_execution_allowed": False}, "CONTRACT_LOCAL")
    anchors = contract.get("trust_anchors")
    require(isinstance(anchors, dict) and set(anchors) == set(("remote_receipt_sha256", "local_receipt_sha256")), "CONTRACT_TRUST_ANCHORS")
    require(anchors["local_receipt_sha256"] == LOCAL_RECEIPT_SHA256, "CONTRACT_LOCAL_TRUST_ANCHOR")
    remote_anchor = anchors["remote_receipt_sha256"]
    if remote_anchor is None:
        require(contract.get("status") == "DESIGN_FROZEN_REMOTE_RECEIPT_SHA_PENDING", "CONTRACT_STATUS")
    else:
        valid_sha(remote_anchor, "CONTRACT_REMOTE_TRUST_ANCHOR")
        require(contract.get("status") == "ACTIVE_VERIFIED_REMOTE_RECEIPT_SHA", "CONTRACT_STATUS")
    require(output == {"schema_version": "runtime-graph-topology-parity-receipt-v1", "status": "PASS_TOPOLOGY_PARITY_DIGEST_ONLY", "aggregate_only": True, "raw_nodes_or_edges_allowed": False, "training_execution_allowed": False}, "CONTRACT_OUTPUT")


def receipt_binding(root, value, label):
    require(isinstance(value, dict) and set(value) == set(("path", "sha256")), label + "_BINDING_FIELDS")
    expected = valid_sha(value["sha256"], label + "_SHA_FORMAT")
    path = resolve(root, value["path"], label)
    data = read_regular_bytes(path, label)
    require(sha256_bytes(data) == expected, label + "_SHA_MISMATCH")
    return data, expected


def validate_remote(receipt):
    expected = set(("schema_version", "status", "contract_sha256", "bindings_sha256", "graph_count", "graphs", "raw_nodes_or_edges_persisted", "pickle_executed", "torch_imported", "training_execution_allowed"))
    require(set(receipt) == expected, "REMOTE_RECEIPT_FIELDS")
    require(receipt["schema_version"] == "legacy-graph-topology-receipt-v1" and receipt["status"] == "PASS_DIGEST_ONLY" and receipt["graph_count"] == 8 and receipt["raw_nodes_or_edges_persisted"] is False and receipt["pickle_executed"] is False and receipt["torch_imported"] is False and receipt["training_execution_allowed"] is False, "REMOTE_RECEIPT_STATUS")
    require(receipt["contract_sha256"] == REMOTE_AUDITOR_CONTRACT_SHA256, "REMOTE_CONTRACT_SHA")
    valid_sha(receipt["bindings_sha256"], "REMOTE_BINDINGS_SHA")
    graphs = receipt["graphs"]
    require(isinstance(graphs, dict) and sorted(graphs) == ROSTER, "REMOTE_ROSTER")
    result = {}
    for circuit in ROSTER:
        item = graphs[circuit]
        require(isinstance(item, dict) and set(item) == set(("artifact_sha256", "nodes", "edges", "canonical_edge_index_sha256")), "REMOTE_GRAPH_FIELDS_" + circuit)
        require(item["artifact_sha256"] == HISTORICAL_ARTIFACT_SHA256[circuit], "REMOTE_ARTIFACT_SHA_" + circuit)
        require(isinstance(item["nodes"], int) and not isinstance(item["nodes"], bool) and item["nodes"] > 0 and isinstance(item["edges"], int) and not isinstance(item["edges"], bool) and item["edges"] > 0, "REMOTE_GRAPH_COUNTS_" + circuit)
        result[circuit] = valid_sha(item["canonical_edge_index_sha256"], "REMOTE_EDGE_SHA_" + circuit)
    return result


def validate_local(receipt):
    expected = set(("schema_version", "status", "bindings_sha256", "contract_sha256", "historical_graph_manifest_sha256", "historical_node_edge_count_parity_pass", "historical_topology_parity_pass", "historical_topology_blocker", "source_hashes", "graph_manifest_sha256", "graph_count", "training_execution_allowed"))
    require(set(receipt) == expected, "LOCAL_RECEIPT_FIELDS")
    require(receipt["schema_version"] == "runtime-graphs-aggregate-receipt-v1" and receipt["status"] == "BLOCKED_HISTORICAL_TOPOLOGY_DIGEST" and receipt["graph_count"] == 8 and receipt["training_execution_allowed"] is False and receipt["historical_node_edge_count_parity_pass"] is True and receipt["historical_topology_parity_pass"] is False and receipt["historical_topology_blocker"] == "HISTORICAL_CANONICAL_EDGE_INDEX_SHA256_NOT_BOUND", "LOCAL_RECEIPT_STATUS")
    require(receipt["contract_sha256"] == LOCAL_RUNTIME_GRAPH_CONTRACT_SHA256, "LOCAL_CONTRACT_SHA")
    for name in ("bindings_sha256", "historical_graph_manifest_sha256", "graph_manifest_sha256"):
        valid_sha(receipt[name], "LOCAL_" + name.upper())
    hashes = receipt["source_hashes"]
    require(isinstance(hashes, dict) and sorted(hashes) == ROSTER, "LOCAL_ROSTER")
    result = {}
    for circuit in ROSTER:
        item = hashes[circuit]
        require(isinstance(item, dict) and set(item) == set(("role", "family", "netlist_path", "netlist_sha256", "nodes", "edges", "historical_nodes", "historical_edges", "historical_feature_dim", "historical_graph_sha256", "topology_sha256", "edge_index_sha256")), "LOCAL_SOURCE_FIELDS_" + circuit)
        result[circuit] = valid_sha(item["edge_index_sha256"], "LOCAL_EDGE_SHA_" + circuit)
    return result


def build_receipt(contract_path, bindings_path):
    contract_bytes = read_regular_bytes(contract_path, "CONTRACT")
    contract = json_object(contract_bytes, "CONTRACT")
    validate_contract(contract)
    require(contract["trust_anchors"]["remote_receipt_sha256"] is not None,
            "REMOTE_RECEIPT_TRUST_ANCHOR_PENDING")
    bindings_bytes = read_regular_bytes(bindings_path, "BINDINGS")
    bindings = json_object(bindings_bytes, "BINDINGS")
    require(set(bindings) == set(("schema_version", "evidence_root", "remote_receipt", "local_receipt")), "BINDINGS_FIELDS")
    require(bindings.get("schema_version") == "runtime-graph-topology-parity-bindings-v1", "BINDINGS_SCHEMA")
    root = validate_root(bindings.get("evidence_root"))
    remote_bytes, remote_sha = receipt_binding(root, bindings["remote_receipt"], "REMOTE_RECEIPT")
    local_bytes, local_sha = receipt_binding(root, bindings["local_receipt"], "LOCAL_RECEIPT")
    require(remote_sha == contract["trust_anchors"]["remote_receipt_sha256"],
            "REMOTE_RECEIPT_TRUST_ANCHOR_MISMATCH")
    require(local_sha == contract["trust_anchors"]["local_receipt_sha256"],
            "LOCAL_RECEIPT_TRUST_ANCHOR_MISMATCH")
    remote = validate_remote(json_object(remote_bytes, "REMOTE_RECEIPT"))
    local = validate_local(json_object(local_bytes, "LOCAL_RECEIPT"))
    parity = dict((circuit, {"match": remote[circuit] == local[circuit], "remote_canonical_edge_index_sha256": remote[circuit], "local_edge_index_sha256": local[circuit]}) for circuit in ROSTER)
    require(all(item["match"] for item in parity.values()), "TOPOLOGY_DIGEST_MISMATCH")
    return {"schema_version": "runtime-graph-topology-parity-receipt-v1", "status": "PASS_TOPOLOGY_PARITY_DIGEST_ONLY", "contract_sha256": sha256_bytes(contract_bytes), "bindings_sha256": sha256_bytes(bindings_bytes), "remote_receipt_sha256": remote_sha, "local_receipt_sha256": local_sha, "graph_count": 8, "circuit_parity": parity, "raw_nodes_or_edges_persisted": False, "training_execution_allowed": False}


def atomic_write(path, value):
    require(not os.path.exists(path), "OUTPUT_EXISTS")
    parent = os.path.dirname(os.path.abspath(path)) or os.curdir
    descriptor, temporary = tempfile.mkstemp(prefix=".topology-parity-v1-", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, sort_keys=True, indent=2); stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try: os.unlink(temporary)
        except OSError: pass
        raise


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", default=DEFAULT_CONTRACT)
    parser.add_argument("--bindings", required=True)
    parser.add_argument("output")
    args = parser.parse_args(argv)
    receipt = build_receipt(args.contract, args.bindings)
    atomic_write(args.output, receipt)
    print("RUNTIME_GRAPH_TOPOLOGY_PARITY=PASS_TOPOLOGY_PARITY_DIGEST_ONLY graphs=8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
