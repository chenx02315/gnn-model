#!/usr/bin/env python3
"""Build the normalized, non-disclosing runtime training package."""
from __future__ import print_function

import argparse
import csv
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import validate_runtime_training_package_v1 as validator


def _write_tsv(path, fields, rows):
    with open(path, "x", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def build(package_root, output_root, contract_root=None):
    """Validate ``package_root`` and write a fresh normalized package once."""
    result = validator.validate_source_package(package_root, contract_root)
    destination = os.path.abspath(output_root)
    if os.path.exists(destination):
        raise FileExistsError("OUTPUT_ROOT_ALREADY_EXISTS")
    os.makedirs(destination)
    try:
        source_root = os.path.abspath(package_root)
        for name in ("package_manifest.json",) + validator.REQUIRED_FILES:
            shutil.copyfile(os.path.join(source_root, name), os.path.join(destination, name))
        for graph in result["graphs"]:
            relative = graph["graph_path"].replace("\\", "/")
            source_graph = validator._under(source_root, relative)
            destination_graph = validator._under(destination, relative)
            os.makedirs(os.path.dirname(destination_graph), exist_ok=True)
            shutil.copyfile(source_graph, destination_graph)
        feature_rows, outcome_rows = [], []
        for uid in sorted(result["actions"]):
            action = result["actions"][uid]
            derived = result["derived"][uid]
            feature_rows.append({field: action[field] for field in validator.FEATURE_FIELDS})
            outcome_rows.append({
                "action_uid": uid,
                "execution_status": action["execution_status"],
                "is_d95_feasible": "1" if validator._boolean(action["is_d95_feasible"], "D95_BOOLEAN_INVALID") else "0",
                "total_cycles": action["total_cycles"],
                "policy_charged_runtime_s": "%.9f" % derived["policy_charged_runtime_s"],
                "epsilon_hit": "1" if derived["epsilon_hit"] else "0",
            })
        features_path = os.path.join(destination, "features.tsv")
        outcomes_path = os.path.join(destination, "outcomes.tsv")
        _write_tsv(features_path, validator.FEATURE_FIELDS, feature_rows)
        _write_tsv(outcomes_path, validator.OUTCOME_FIELDS, outcome_rows)
        circuit_oracles = {}
        for uid, action in result["actions"].items():
            circuit_oracles[action["circuit"]] = result["derived"][uid]["oracle_cycles"]
        manifest = {
            "schema_version": "runtime-training-package-v1",
            "status": "PASS",
            "files": {
                name: validator.sha256_file(os.path.join(destination, name))
                for name in ("features.tsv", "outcomes.tsv", "package_manifest.json") + validator.REQUIRED_FILES
            },
            "counts": {
                "action_count": result["action_count"], "attempt_count": result["attempt_count"],
                "edge_count": result["edge_count"], "graph_count": result["graph_count"],
                "circuit_count": result["circuit_count"],
            },
            "circuit_oracles": dict(sorted(circuit_oracles.items())),
            "input_manifest_sha256": result["input_manifest_sha256"],
            "authority": result["input_manifest"]["authority"],
            "training_execution_allowed": False,
        }
        with open(os.path.join(destination, "runtime_training_package_manifest_v1.json"), "x", encoding="utf-8", newline="\n") as stream:
            json.dump(manifest, stream, sort_keys=True, indent=2)
            stream.write("\n")
        validator.validate_output_package(destination)
        return manifest
    except Exception:
        # Do not remove a partially written audit artifact automatically.
        raise


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("package_root")
    parser.add_argument("output_root")
    parser.add_argument("--contract-root")
    args = parser.parse_args(argv)
    build(args.package_root, args.output_root, args.contract_root)
    print("RUNTIME_TRAINING_PACKAGE=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
