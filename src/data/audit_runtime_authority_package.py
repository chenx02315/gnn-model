#!/usr/bin/env python3
"""Audit a small versioned runtime-authority tarball and extracted payload."""
from __future__ import print_function

import argparse
import hashlib
import json
import os
import posixpath
import re
import tarfile


SHA_RE = re.compile(r"^[0-9a-f]{64}$")


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def audit(archive, extracted_root, manifest_name, payload_names, max_entries, max_bytes):
    allowed = set(payload_names + [manifest_name])
    if len(allowed) != len(payload_names) + 1:
        raise ValueError("duplicate payload or manifest name")
    regular = []
    total_bytes = 0
    archive_data = {}
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        if len(members) > max_entries:
            raise ValueError("archive entry limit exceeded")
        for member in members:
            normalized = posixpath.normpath(member.name)
            if member.name.startswith("/") or normalized == ".." or normalized.startswith("../"):
                raise ValueError("unsafe archive path")
            if member.isdir() and normalized == ".":
                continue
            if not member.isfile():
                raise ValueError("archive contains non-regular payload")
            name = normalized[2:] if normalized.startswith("./") else normalized
            if "/" in name or name not in allowed or name in regular:
                raise ValueError("unexpected archive member")
            regular.append(name)
            total_bytes += member.size
            extracted = bundle.extractfile(member)
            if extracted is None:
                raise ValueError("archive member cannot be read")
            archive_data[name] = extracted.read()
    if set(regular) != allowed or total_bytes > max_bytes:
        raise ValueError("archive payload set or size mismatch")
    manifest = {}
    try:
        manifest_text = archive_data[manifest_name].decode("ascii")
    except (KeyError, UnicodeDecodeError):
        raise ValueError("archive manifest is not ASCII")
    for line in manifest_text.splitlines():
        value, name = line.split("  ", 1)
        if not SHA_RE.match(value) or name in manifest:
            raise ValueError("invalid manifest entry")
        manifest[name] = value
    if set(manifest) != set(payload_names):
        raise ValueError("manifest payload set mismatch")
    for name in payload_names:
        if hashlib.sha256(archive_data[name]).hexdigest() != manifest[name]:
            raise ValueError("archive payload hash mismatch")
        path = os.path.join(extracted_root, name)
        if not os.path.isfile(path) or sha256_file(path) != manifest[name]:
            raise ValueError("extracted payload hash mismatch")
    return {
        "schema_version": "runtime-authority-package-audit-v1",
        "archive_sha256": sha256_file(archive),
        "archive_entry_count": len(members),
        "payload_file_count": len(payload_names),
        "payload_sha256": dict((name, manifest[name]) for name in sorted(manifest)),
        "manifest_sha256": hashlib.sha256(archive_data[manifest_name]).hexdigest(),
        "bounded_extract_status": "PASS",
        "audit_tool_sha256": sha256_file(os.path.abspath(__file__)),
        "path_policy": "basenames and SHA-256 only; no source roots or runtime values",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True)
    parser.add_argument("--extracted-root", required=True)
    parser.add_argument("--manifest", default="MANIFEST.sha256")
    parser.add_argument("--payload", action="append", required=True)
    parser.add_argument("--max-entries", type=int, default=8)
    parser.add_argument("--max-bytes", type=int, default=1048576)
    args = parser.parse_args()
    result = audit(args.archive, args.extracted_root, args.manifest,
                   args.payload, args.max_entries, args.max_bytes)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
