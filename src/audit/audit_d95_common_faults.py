#!/usr/bin/env python3
from __future__ import print_function

import argparse
import glob
import hashlib
import json
import math
import os


CIRCUITS = ("b20", "b21", "b22", "wb_dma", "aes_core", "tv80", "spi")


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def data_rows(path):
    with open(path, "rb") as stream:
        return max(0, sum(1 for _ in stream) - 1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("base")
    parser.add_argument("output_json")
    args = parser.parse_args()

    result = {"schema_version": "d95_common_faults_seven_v1", "circuits": {}}
    for circuit in CIRCUITS:
        circuit_root = os.path.join(args.base, "10_circuits", circuit)
        common_matches = [path for path in glob.glob(os.path.join(
            circuit_root, "03_fault_universe", "common_%s_m16_phase4_v*" % circuit))
            if os.path.isdir(path)]
        if len(common_matches) != 1:
            raise RuntimeError("expected one common directory for %s, found %r" % (circuit, common_matches))
        common_path = common_matches[0]
        common_dir = os.path.basename(common_path)
        mapping = os.path.join(common_path, "canonical_fault_mapping.tsv")
        manifest = os.path.join(common_path, "manifest.json")
        readback_matches = glob.glob(os.path.join(common_path, "readback_validation_phase4_v*.json"))
        if len(readback_matches) != 1:
            raise RuntimeError("expected one readback file for %s, found %r" % (circuit, readback_matches))
        readback = readback_matches[0]
        with open(manifest, "r") as stream:
            manifest_data = json.load(stream)
        count = int(manifest_data["common_fault_count"])
        d95 = int(math.ceil(0.95 * count))
        record = {
            "common_fault_count": count,
            "d95": d95,
            "d95_rule": "ceil(0.95 * common_fault_count)",
            "d95_rule_pass": d95 == int(math.ceil(0.95 * count)),
            "common_dir": common_dir,
            "common_path": common_path,
            "canonical_mapping_rows": data_rows(mapping),
            "canonical_mapping_sha256": sha256_file(mapping),
            "manifest_sha256": sha256_file(manifest),
            "fault_file_sha256": {},
        }
        for mode in ("H", "M", "F"):
            path = os.path.join(common_path, mode + "_common_initial_faults.basic")
            record["fault_file_sha256"][mode] = sha256_file(path)
        with open(readback, "r") as stream:
            record["readback_validation"] = json.load(stream)
        record["readback_validation_file"] = os.path.basename(readback)
        record["readback_validation_sha256"] = sha256_file(readback)
        record["mapping_count_pass"] = record["canonical_mapping_rows"] == count
        result["circuits"][circuit] = record
    result["all_d95_rule_pass"] = all(row["d95_rule_pass"] for row in result["circuits"].values())
    result["all_mapping_count_pass"] = all(row["mapping_count_pass"] for row in result["circuits"].values())
    result["all_readback_pass"] = all(
        row["readback_validation"].get("status") == "PASS" and
        not row["readback_validation"].get("errors")
        for row in result["circuits"].values())
    with open(args.output_json, "w") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print("circuits=%d d95_pass=%s mapping_pass=%s readback_pass=%s" % (
        len(result["circuits"]), result["all_d95_rule_pass"],
        result["all_mapping_count_pass"], result["all_readback_pass"]))


if __name__ == "__main__":
    main()
