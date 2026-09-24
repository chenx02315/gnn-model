#!/usr/bin/env python3
"""Design-only v12 dual-order inventory gate.

This module deliberately contains no BLIND join, release path, scheduler entry
point, or execution authority. Source reads require an in-process capability
and an exact v12 CONSUMED marker. The future reviewed runner may import this
module only after its external control bundle has been verified and CONSUMED
has been created durably.
"""

from __future__ import print_function

import hashlib
import json
import os
import subprocess
import sys


SORT_VERSION = "sort (GNU coreutils) 8.22"
HISTORICAL_LANG = "en_US.UTF-8"
_ACTIVE_SOURCE_CAPABILITY = None


class Refusal(Exception):
    pass


def _require_source_guard(guard):
    if not isinstance(guard, tuple) or len(guard) != 4:
        raise Refusal("SOURCE_ACCESS_BEFORE_CONSUMED")
    path, contract_sha256, tool_set_sha256, capability = guard
    if capability is not _ACTIVE_SOURCE_CAPABILITY:
        raise Refusal("SOURCE_ACCESS_BEFORE_CONSUMED")
    if not os.path.isfile(path) or os.path.islink(path):
        raise Refusal("SOURCE_ACCESS_BEFORE_CONSUMED")
    try:
        with open(path, encoding="utf-8") as stream:
            marker = json.load(stream)
    except (OSError, ValueError):
        raise Refusal("SOURCE_ACCESS_BEFORE_CONSUMED")
    expected = {
        "schema_version": "blind-runtime-unseal-consumed-v12",
        "status": "CONSUMED",
        "contract_sha256": contract_sha256,
        "tool_set_sha256": tool_set_sha256,
    }
    if marker != expected:
        raise Refusal("SOURCE_ACCESS_BEFORE_CONSUMED")


def _sha256_file(path, guard):
    _require_source_guard(guard)
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _collect_driver_logs(root, guard):
    _require_source_guard(guard)
    root_absolute = os.path.abspath(root)
    root_real = os.path.realpath(root)
    if root_absolute != root_real or not os.path.isdir(root_real) or os.path.islink(root):
        raise ValueError("LOG_ROOT_INVALID")
    relative_paths = []
    for parent, directories, files in os.walk(root_real, followlinks=False):
        _require_source_guard(guard)
        if os.path.islink(parent):
            raise ValueError("LOG_DIRECTORY_SYMLINK")
        symlink_directories = [name for name in directories if os.path.islink(os.path.join(parent, name))]
        if symlink_directories:
            raise ValueError("LOG_DIRECTORY_SYMLINK")
        directories.sort()
        for filename in sorted(files):
            if not filename.endswith(".driver.log"):
                continue
            path = os.path.join(parent, filename)
            if os.path.islink(path) or not os.path.isfile(path):
                raise ValueError("LOG_FILE_MISSING_OR_SYMLINK")
            resolved = os.path.realpath(path)
            if os.path.commonpath((root_real, resolved)) != root_real:
                raise ValueError("LOG_FILE_ESCAPE")
            relative = os.path.relpath(resolved, root_real).replace(os.sep, "/")
            # GNU sha256sum escapes backslash/newline-containing filenames.
            # The frozen roots use portable ASCII names; reject anything whose
            # line representation would not be byte-identical to the original
            # `sha256sum` pipeline instead of silently hashing a new grammar.
            try:
                relative.encode("ascii", "strict")
            except UnicodeEncodeError:
                raise ValueError("LOG_PATH_ENCODING")
            if any(character in relative for character in ("\\", "\r", "\n")):
                raise ValueError("LOG_PATH_ENCODING")
            relative_paths.append(relative)
    if len(relative_paths) != len(set(relative_paths)):
        raise ValueError("DUPLICATE_LOG_PATH")
    return root_real, relative_paths


def _gnu_sort_version():
    try:
        result = subprocess.run(
            ["sort", "--version"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_historical_sort_environment(),
        )
    except (OSError, subprocess.CalledProcessError):
        raise Refusal("HISTORICAL_SORT_UNAVAILABLE")
    first_line = result.stdout.decode("utf-8", "strict").splitlines()[0] if result.stdout else ""
    if first_line != SORT_VERSION:
        raise Refusal("HISTORICAL_SORT_VERSION")
    return first_line


def _historical_sort_environment():
    environment = dict(os.environ)
    environment["LANG"] = HISTORICAL_LANG
    environment.pop("LC_ALL", None)
    environment.pop("LC_COLLATE", None)
    return environment


def _historical_locale_order(relative_paths):
    _gnu_sort_version()
    items = [("./" + relative).encode("utf-8") for relative in relative_paths]
    payload = b"\0".join(items) + (b"\0" if items else b"")
    try:
        result = subprocess.run(
            ["sort", "-z"],
            input=payload,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_historical_sort_environment(),
        )
    except (OSError, subprocess.CalledProcessError):
        raise Refusal("HISTORICAL_SORT_FAILED")
    ordered_raw = result.stdout.split(b"\0")
    if ordered_raw and ordered_raw[-1] == b"":
        ordered_raw.pop()
    try:
        ordered = [item.decode("utf-8", "strict") for item in ordered_raw]
    except UnicodeDecodeError:
        raise Refusal("HISTORICAL_SORT_ENCODING")
    expected = ["./" + relative for relative in relative_paths]
    if len(ordered) != len(expected) or set(ordered) != set(expected):
        raise Refusal("HISTORICAL_SORT_PERMUTATION")
    return [item[2:] for item in ordered]


def _digest_lines(ordered_paths, digests):
    lines = []
    for relative in ordered_paths:
        lines.append(digests[relative] + "  ./" + relative + "\n")
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def dual_log_inventory(root, guard):
    """Return both frozen order digests from one guarded file-hash snapshot."""
    _require_source_guard(guard)
    root_real, relative_paths = _collect_driver_logs(root, guard)
    digests = {}
    for relative in relative_paths:
        path = os.path.join(root_real, *relative.split("/"))
        digests[relative] = _sha256_file(path, guard)
    bytewise_order = sorted(relative_paths, key=lambda item: ("./" + item).encode("utf-8"))
    historical_order = _historical_locale_order(list(relative_paths))
    if len(historical_order) != len(relative_paths) or set(historical_order) != set(relative_paths):
        raise Refusal("HISTORICAL_SORT_PERMUTATION")
    return {
        "driver_log_count": len(relative_paths),
        "historical_locale_ordered_sha256": _digest_lines(historical_order, digests),
        "bytewise_ordered_sha256": _digest_lines(bytewise_order, digests),
    }


def verify_dual_log_inventory(root, expected, guard):
    _require_source_guard(guard)
    required = {
        "driver_log_count",
        "historical_locale_ordered_sha256",
        "bytewise_ordered_sha256",
    }
    if not isinstance(expected, dict) or set(expected) != required:
        raise Refusal("FROZEN_DUAL_INVENTORY_SCHEMA")
    observed = dual_log_inventory(root, guard)
    if observed != expected:
        raise Refusal("DUAL_INPUT_INVENTORY_DRIFT")
    return observed


def main(argv=None):
    del argv
    print("BLIND_UNSEAL_V12=DESIGN_ONLY_NO_EXECUTION")
    return 2


if __name__ == "__main__":
    sys.exit(main())
