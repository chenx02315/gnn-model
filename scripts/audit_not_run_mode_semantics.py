#!/usr/bin/env python3
"""Aggregate non-blind measurement states by stage, mode, and path presence."""
from __future__ import print_function

import argparse
import csv
import json
import os


LAYOUTS = (
    ("01_single_boundaries", "measurements.tsv", "single"),
    ("02_hf_coarse", "measurements.tsv", "hf"),
    ("03_hmf_coarse", "measurements.tsv", "hmf"),
    ("04_integer_refine", "hf_measurements.tsv", "hf"),
    ("04_integer_refine", "hmf_measurements.tsv", "hmf"),
)


def value(row, key):
    return (row.get(key) or "").strip()


def modes(kind, row):
    if kind == "single":
        return ((value(row, "mode"), value(row, "result_directory") or value(row, "result")),)
    names = ("H", "F") if kind == "hf" else ("H", "M", "F")
    return tuple((mode, value(row, mode.lower() + "_result")) for mode in names)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--circuit", required=True)
    args = parser.parse_args()
    counts = {}
    examples = {}
    for stage, filename, kind in LAYOUTS:
        path = os.path.join(args.root, stage, filename)
        if not os.path.isfile(path):
            continue
        with open(path, "r", encoding="utf-8", newline="") as stream:
            for row_number, row in enumerate(csv.DictReader(stream, delimiter="\t"), 2):
                state = value(row, "result_status") or value(row, "status") or "EMPTY_STATE"
                for mode, result_path in modes(kind, row):
                    key = "%s|%s|%s|%s" % (stage, state, mode, "PATH" if result_path else "NO_PATH")
                    counts[key] = counts.get(key, 0) + 1
                    if key not in examples:
                        examples[key] = {"file": "%s/%s" % (stage, filename), "row": row_number}
    print(json.dumps({"circuit": args.circuit, "counts": counts, "examples": examples},
                     indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
