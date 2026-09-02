#!/usr/bin/env python3
"""Produce a blind-safe aggregate inventory of GNU-time driver logs.

The output intentionally contains no paths, run IDs, timing values, candidates,
patterns, cycles, or outcomes. Python 3.6+; standard library only.
"""
from __future__ import print_function

import argparse
import hashlib
import json
import os
import re


PATTERNS = {
    "elapsed": re.compile(r"^\s*Elapsed \(wall clock\) time .*:\s*\S+", re.M),
    "user": re.compile(r"^\s*User time \(seconds\):\s*\S+", re.M),
    "system": re.compile(r"^\s*System time \(seconds\):\s*\S+", re.M),
    "exit": re.compile(r"^\s*Exit status:\s*(\S+)", re.M),
}


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        data = stream.read()
    digest.update(data)
    return digest.hexdigest(), data.decode("utf-8", "replace")


def audit(root, circuit, cohort):
    paths = []
    for parent, _directories, files in os.walk(root):
        for name in files:
            if name.endswith(".driver.log"):
                paths.append(os.path.join(parent, name))
    paths.sort()
    counts = dict((key, 0) for key in PATTERNS)
    nonzero_exit = 0
    inventory = hashlib.sha256()
    for path in paths:
        digest, text = file_sha256(path)
        relative = os.path.relpath(path, root).replace(os.sep, "/")
        inventory.update((relative + "\t" + digest + "\n").encode("utf-8"))
        for key, pattern in PATTERNS.items():
            match = pattern.search(text)
            if match:
                counts[key] += 1
                if key == "exit" and match.group(1) != "0":
                    nonzero_exit += 1
    total = len(paths)
    result = {
        "schema_version": "runtime_log_inventory_aggregate_v1",
        "circuit": circuit,
        "cohort": cohort,
        "driver_log_count": total,
        "elapsed_footer_count": counts["elapsed"],
        "user_footer_count": counts["user"],
        "system_footer_count": counts["system"],
        "exit_footer_count": counts["exit"],
        "nonzero_exit_count": nonzero_exit,
        "missing_elapsed_count": total - counts["elapsed"],
        "missing_exit_count": total - counts["exit"],
        "inventory_manifest_sha256": inventory.hexdigest(),
        "field_policy": "aggregate-only; no path, run_id, elapsed value, candidate, pattern, cycle, or outcome fields",
    }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--circuit", required=True)
    parser.add_argument("--cohort", required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.input, args.circuit, args.cohort), sort_keys=True))


if __name__ == "__main__":
    main()
