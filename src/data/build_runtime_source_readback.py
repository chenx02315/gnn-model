#!/usr/bin/env python3
"""Create an A-side runtime-source SHA readback receipt without source paths."""
from __future__ import print_function

import argparse
import hashlib
import json
import os
import re


LOGICAL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_artifact(specification):
    if specification.count("=") != 1:
        raise ValueError("artifact must use LOGICAL_ID=PATH")
    logical_id, source_path = specification.split("=", 1)
    if not LOGICAL_ID_RE.match(logical_id):
        raise ValueError("unsafe logical artifact ID")
    if not source_path or not os.path.isfile(source_path):
        raise ValueError("artifact source is not a regular file")
    return logical_id, source_path


def build_receipt(specifications):
    if not specifications:
        raise ValueError("at least one --artifact is required")
    artifacts = {}
    for specification in specifications:
        logical_id, source_path = parse_artifact(specification)
        if logical_id in artifacts:
            raise ValueError("duplicate logical artifact ID: %s" % logical_id)
        artifacts[logical_id] = sha256_file(source_path)
    return {
        "schema_version": "runtime-source-readback-v1",
        "artifacts": dict((key, artifacts[key]) for key in sorted(artifacts)),
        "path_policy": "logical IDs and SHA-256 only; no source paths are emitted",
    }


def write_json(path, value):
    with open(path, "w") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", action="append", default=[])
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    receipt = build_receipt(args.artifact)
    write_json(args.output, receipt)
    print("RUNTIME_SOURCE_READBACK=PASS artifacts=%d" % len(receipt["artifacts"]))


if __name__ == "__main__":
    main()
