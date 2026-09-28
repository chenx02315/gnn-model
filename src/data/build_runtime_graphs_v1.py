#!/usr/bin/env python3
"""Build deterministic, outcome-free runtime graphs from mapped Verilog.

The input is a small explicit bindings JSON.  There is intentionally no
directory walk, glob expansion, remote access, or training entry point.
"""
from __future__ import print_function

import argparse
import csv
import hashlib
import io
import json
import os
import re
import shutil
import stat
import tempfile


HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
CONTRACT_PATH = os.path.join(REPO_ROOT, "contracts", "runtime_graph_v1.json")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
INSTANCE_RE = re.compile(
    r"(?ms)^\s*([A-Za-z_][A-Za-z0-9_$]*)\s+(\\?[^\s(]+)\s*\((.*?)\)\s*;"
)
PIN_RE = re.compile(r"\.\s*([A-Za-z_][A-Za-z0-9_$]*)\s*\(\s*([^()]+?)\s*\)")
ASSIGN_RE = re.compile(r"\bassign\s+([^=;\s]+)\s*=\s*([^;\s]+)\s*;")


class GraphBuildError(ValueError):
    pass


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def _fail(code):
    raise GraphBuildError(code)


def _read_regular_bytes(path):
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        _fail("BINDING_OPEN_FAILED")
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            _fail("BINDING_NOT_REGULAR_FILE")
        return stream.read()


def _json_bytes(value, code="INVALID_JSON"):
    try:
        document = json.loads(value.decode("utf-8"))
    except (UnicodeDecodeError, TypeError, ValueError):
        _fail(code)
    if not isinstance(document, dict):
        _fail(code)
    return document


def _json(path):
    return _json_bytes(_read_regular_bytes(path))


def _same_path(first, second):
    return os.path.normcase(os.path.abspath(first)) == os.path.normcase(
        os.path.abspath(second))


def _check_nonsymlink_chain(path):
    absolute = os.path.abspath(path)
    drive, tail = os.path.splitdrive(absolute)
    current = drive + os.sep if drive else os.sep
    for component in [item for item in tail.split(os.sep) if item]:
        current = os.path.join(current, component)
        if os.path.lexists(current):
            info = os.lstat(current)
            if stat.S_ISLNK(info.st_mode):
                _fail("BINDING_SYMLINK_FORBIDDEN")


def _under(root, relative):
    if not isinstance(relative, str) or not relative or os.path.isabs(relative):
        _fail("BINDING_PATH_INVALID")
    normalized = relative.replace("\\", "/")
    if any(token in normalized for token in ("*", "?", "[", "]")):
        _fail("BINDING_GLOB_FORBIDDEN")
    candidate = os.path.abspath(os.path.join(root, *normalized.split("/")))
    real_root, real_candidate = os.path.realpath(root), os.path.realpath(candidate)
    if (not _same_path(os.path.commonpath((root, candidate)), root) or
            not _same_path(os.path.commonpath((real_root, real_candidate)),
                           real_root)):
        _fail("BINDING_PATH_ESCAPE")
    _check_nonsymlink_chain(root)
    _check_nonsymlink_chain(candidate)
    if not os.path.exists(candidate):
        _fail("BINDING_NOT_REGULAR_FILE")
    info = os.stat(candidate, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode):
        _fail("BINDING_NOT_REGULAR_FILE")
    return candidate


class _UnionFind(object):
    def __init__(self):
        self.parent = {}

    def find(self, value):
        if value not in self.parent:
            self.parent[value] = value
        if self.parent[value] != value:
            self.parent[value] = self.find(self.parent[value])
        return self.parent[value]

    def union(self, first, second):
        first, second = self.find(first), self.find(second)
        if first != second:
            if first < second:
                self.parent[second] = first
            else:
                self.parent[first] = second


def _strip_comments(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//.*?$", " ", text, flags=re.M)


def _clean_net(token):
    token = token.strip()
    if not token or token in ("1'b0", "1'b1", "1'h0", "1'h1"):
        return None
    if token.startswith("{") or any(op in token for op in ("&", "|", "^", "?")):
        return None
    return token


def _is_sequential(cell_type, contract):
    return bool(re.match(contract["parser"]["sequential_cell_name_regex"],
                         cell_type.upper()))


def _is_output_pin(cell_type, pin, contract):
    if pin.upper() in set(contract["parser"]["output_pin_names"]):
        return True
    return (pin.upper() == "S" and re.match(
        contract["parser"]["sum_pin_output_cell_regex"],
        cell_type.upper()) is not None)


def _parse_mapped_verilog(text, contract):
    text = _strip_comments(text)
    unions = _UnionFind()
    for lhs, rhs in ASSIGN_RE.findall(text):
        lhs, rhs = _clean_net(lhs), _clean_net(rhs)
        if lhs and rhs:
            unions.union(lhs, rhs)
    nodes = []
    skipped = set(("module", "endmodule", "assign", "wire", "input", "output", "inout"))
    for cell_type, instance, body in INSTANCE_RE.findall(text):
        if cell_type.lower() in skipped:
            continue
        pins = PIN_RE.findall(body)
        if not pins:
            _fail("NON_NAMED_PIN_CONNECTION")
        node = {"instance": instance, "cell_type": cell_type, "pins": []}
        for pin, expression in pins:
            net = _clean_net(expression)
            if net:
                node["pins"].append((pin.upper(), unions.find(net)))
        nodes.append(node)
    if not nodes:
        _fail("NO_STANDARD_CELL_INSTANCES")
    index_by_instance = {node["instance"]: index for index, node in enumerate(nodes)}
    drivers, consumers = {}, {}
    for node in nodes:
        index = index_by_instance[node["instance"]]
        for pin, net in node["pins"]:
            if _is_output_pin(node["cell_type"], pin, contract):
                drivers.setdefault(net, set()).add(index)
            else:
                consumers.setdefault(net, set()).add(index)
    edges = set()
    for net in sorted(set(drivers).intersection(consumers)):
        for source in drivers[net]:
            for destination in consumers[net]:
                if source != destination:
                    edges.add((source, destination))
    payload_nodes = []
    for node in nodes:
        payload_nodes.append({
            "node_type": "standard_cell_instance",
            "cell_type": node["cell_type"],
            "sequential_flag": _is_sequential(node["cell_type"], contract),
        })
    return payload_nodes, [list(edge) for edge in sorted(edges)]


def _topology_sha256(nodes, edge_index):
    return sha256_bytes((json.dumps(
        {"nodes": nodes, "edge_index": edge_index}, sort_keys=True,
        separators=(",", ":")) + "\n").encode("utf-8"))


def _load_bindings(path, bindings_bytes, bindings_root, contract):
    document = _json_bytes(bindings_bytes, "BINDINGS_JSON_INVALID")
    if (set(document) != set(contract["input"]["top_level_fields"]) or
            document.get("schema_version") !=
            contract["input"]["bindings_schema_version"]):
        _fail("BINDINGS_SCHEMA_INVALID")
    parity_binding = document.get("parity_manifest")
    if (not isinstance(parity_binding, dict) or
            set(parity_binding) != set(
                contract["input"]["parity_manifest_fields"])):
        _fail("PARITY_MANIFEST_BINDING_INVALID")
    parity_path = _under(bindings_root, parity_binding.get("path"))
    if not SHA256_RE.match(str(parity_binding.get("sha256"))):
        _fail("PARITY_MANIFEST_SHA256_INVALID")
    parity_bytes = _read_regular_bytes(parity_path)
    parity_sha = sha256_bytes(parity_bytes)
    if parity_sha != parity_binding["sha256"]:
        _fail("PARITY_MANIFEST_SHA256_MISMATCH")
    parity = {}
    try:
        parity_text = parity_bytes.decode("utf-8")
    except UnicodeDecodeError:
        _fail("PARITY_MANIFEST_UTF8")
    with io.StringIO(parity_text, newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        required_columns = set(
            contract["input"]["parity_manifest_required_columns"])
        if not required_columns.issubset(set(reader.fieldnames or ())):
            _fail("PARITY_MANIFEST_COLUMNS")
        for row in reader:
            circuit = row.get("circuit")
            if not circuit or circuit in parity:
                _fail("PARITY_MANIFEST_DUPLICATE_CIRCUIT")
            try:
                nodes, edges, feature_dim = (
                    int(row["nodes"]), int(row["edges"]),
                    int(row["feature_dim"]))
            except (TypeError, ValueError):
                _fail("PARITY_MANIFEST_NUMERIC")
            if nodes <= 0 or edges <= 0 or feature_dim <= 0:
                _fail("PARITY_MANIFEST_NUMERIC")
            parity[circuit] = {
                "nodes": nodes, "edges": edges,
                "feature_dim": feature_dim,
                "graph_sha256": row.get("graph_sha256"),
            }
            if not SHA256_RE.match(str(parity[circuit]["graph_sha256"])):
                _fail("PARITY_MANIFEST_GRAPH_SHA256")
    bindings = document.get("bindings")
    required = set(contract["input"]["binding_fields"])
    if not isinstance(bindings, list) or not bindings:
        _fail("BINDINGS_EMPTY")
    seen = set()
    output = []
    for binding in bindings:
        if not isinstance(binding, dict) or set(binding) != required:
            _fail("BINDING_FIELDS_INVALID")
        circuit = binding["circuit"]
        if not isinstance(circuit, str) or not circuit or circuit in seen:
            _fail("BINDING_CIRCUIT_DUPLICATE")
        if binding["role"] not in contract["input"]["allowed_roles"] or not binding["family"]:
            _fail("BINDING_ROLE_INVALID")
        if not SHA256_RE.match(str(binding["sha256"])):
            _fail("BINDING_SHA256_INVALID")
        netlist = _under(bindings_root, binding["path"])
        netlist_bytes = _read_regular_bytes(netlist)
        if sha256_bytes(netlist_bytes) != binding["sha256"]:
            _fail("BINDING_SHA256_MISMATCH")
        if circuit not in parity:
            _fail("PARITY_CIRCUIT_MISSING")
        seen.add(circuit)
        item = dict(binding)
        item["_netlist"] = netlist
        item["_netlist_bytes"] = netlist_bytes
        output.append(item)
    return (sorted(output, key=lambda item: item["circuit"]),
            sha256_bytes(bindings_bytes), parity_sha, parity)


def build(bindings_json, bindings_root, output_root, contract_path=CONTRACT_PATH):
    """Build a new graph package from explicit local bindings."""
    contract_bytes = _read_regular_bytes(contract_path)
    contract = _json_bytes(contract_bytes, "CONTRACT_JSON_INVALID")
    if (contract.get("schema_version") != "runtime-graph-v1-contract" or
            contract.get("status") != "FROZEN_IMPLEMENTATION_ONLY" or
            contract.get("output", {}).get("graph_schema_version") != "runtime-graph-v1" or
            contract.get("boundary", {}).get("no_lsf_or_tessent") is not True or
            contract.get("boundary", {}).get("no_outcome_or_runtime_fields") is not True or
            contract.get("boundary", {}).get("no_torch_dependency") is not True or
            contract.get("boundary", {}).get("no_blind_rows") is not True):
        _fail("CONTRACT_INVALID")
    bindings_root = os.path.abspath(bindings_root)
    _check_nonsymlink_chain(bindings_root)
    if not os.path.isdir(bindings_root) or os.path.islink(bindings_root):
        _fail("BINDINGS_ROOT_INVALID")
    bindings_path = _under(bindings_root, bindings_json)
    bindings_bytes = _read_regular_bytes(bindings_path)
    bindings, bindings_sha, parity_sha, parity = _load_bindings(
        bindings_path, bindings_bytes, bindings_root, contract)
    roster = sorted((item["circuit"], item["family"], item["role"])
                    for item in bindings)
    required_roster = sorted((item["circuit"], item["family"], item["role"])
                             for item in contract.get("required_roster", []))
    if not required_roster or roster != required_roster:
        _fail("BINDINGS_ROSTER_MISMATCH")
    output_root = os.path.abspath(output_root)
    if os.path.exists(output_root):
        raise FileExistsError("OUTPUT_ROOT_ALREADY_EXISTS")
    parent = os.path.dirname(output_root)
    if not os.path.isdir(parent):
        _fail("OUTPUT_PARENT_MISSING")
    temporary = tempfile.mkdtemp(prefix=".runtime-graphs-v1-", dir=parent)
    try:
        graphs_dir = os.path.join(temporary, "graphs")
        os.makedirs(graphs_dir)
        manifest_rows, source_hashes = [], {}
        for binding in bindings:
            try:
                netlist_text = binding["_netlist_bytes"].decode("utf-8")
            except UnicodeDecodeError:
                _fail("NETLIST_UTF8_%s" % binding["circuit"])
            nodes, edge_index = _parse_mapped_verilog(netlist_text, contract)
            if not edge_index:
                _fail("GRAPH_HAS_NO_EDGES")
            expected = parity[binding["circuit"]]
            if (len(nodes) != expected["nodes"] or
                    len(edge_index) != expected["edges"]):
                _fail("HISTORICAL_GRAPH_PARITY_MISMATCH_%s" %
                      binding["circuit"])
            graph = {
                "schema_version": "runtime-graph-v1",
                "circuit": binding["circuit"],
                "nodes": nodes,
                "edge_index": edge_index,
            }
            topology_sha = _topology_sha256(nodes, edge_index)
            relative = "graphs/%s.json" % binding["circuit"]
            graph_path = os.path.join(temporary, *relative.split("/"))
            with open(graph_path, "x", encoding="utf-8", newline="\n") as stream:
                json.dump(graph, stream, sort_keys=True, separators=(",", ":"))
                stream.write("\n")
            graph_sha = sha256_file(graph_path)
            manifest_rows.append({
                "graph_key": binding["circuit"],
                "circuit": binding["circuit"],
                "graph_path": relative,
                "graph_sha256": graph_sha,
            })
            source_hashes[binding["circuit"]] = {
                "role": binding["role"],
                "family": binding["family"],
                "netlist_path": binding["path"],
                "netlist_sha256": binding["sha256"],
                "nodes": len(nodes),
                "edges": len(edge_index),
                "historical_nodes": expected["nodes"],
                "historical_edges": expected["edges"],
                "historical_feature_dim": expected["feature_dim"],
                "historical_graph_sha256": expected["graph_sha256"],
                "topology_sha256": topology_sha,
            }
        manifest_path = os.path.join(temporary, "graph_manifest.tsv")
        with open(manifest_path, "x", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(
                stream,
                fieldnames=contract["output"]["graph_manifest_fields"],
                delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerows(manifest_rows)
        receipt = {
            "schema_version": "runtime-graphs-aggregate-receipt-v1",
            "status": "BLOCKED_HISTORICAL_TOPOLOGY_DIGEST",
            "bindings_sha256": bindings_sha,
            "contract_sha256": sha256_bytes(contract_bytes),
            "historical_graph_manifest_sha256": parity_sha,
            "historical_node_edge_count_parity_pass": True,
            "historical_topology_parity_pass": False,
            "historical_topology_blocker":
                "HISTORICAL_CANONICAL_EDGE_INDEX_SHA256_NOT_BOUND",
            "source_hashes": source_hashes,
            "graph_manifest_sha256": sha256_file(manifest_path),
            "graph_count": len(manifest_rows),
            "training_execution_allowed": False,
        }
        with open(os.path.join(
                temporary, contract["output"]["aggregate_receipt"]),
                "x", encoding="utf-8", newline="\n") as stream:
            json.dump(receipt, stream, sort_keys=True, indent=2)
            stream.write("\n")
        os.replace(temporary, output_root)
        temporary = None
        return receipt
    finally:
        if temporary is not None and os.path.isdir(temporary):
            shutil.rmtree(temporary)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("bindings_json", help="relative path below bindings_root")
    parser.add_argument("bindings_root")
    parser.add_argument("output_root")
    parser.add_argument("--contract", default=CONTRACT_PATH)
    args = parser.parse_args(argv)
    build(args.bindings_json, args.bindings_root, args.output_root, args.contract)
    print("RUNTIME_GRAPHS=BLOCKED_HISTORICAL_TOPOLOGY_DIGEST")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
