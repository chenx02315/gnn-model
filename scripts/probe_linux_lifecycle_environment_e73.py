"""E73 fixed read-only B metadata probe. Import performs no I/O."""
import json
import os
import re
import selectors
import socket
import subprocess
import sys
import time


SCHEMA = 'e73-environment-probe-v1'
EXPECTED_HOST = 'bupt-gpus1'
MAX_BYTES = 32768
MAX_RETURN_BYTES = 8192
MAX_ROWS = 32
COMMAND_TIMEOUT_S = 8.0
COMMANDS = {
    'info': ('docker', 'info', '--format',
             '{"CgroupVersion":{{json .CgroupVersion}},"OSType":{{json .OSType}},'
             '"ServerVersion":{{json .ServerVersion}}}'),
    'images': ('docker', 'image', 'ls', '--no-trunc', '--format', '{{json .}}'),
    'create_help': ('docker', 'create', '--help'),
}


class ProbeBlocked(Exception):
    pass


def _stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=0.5)
    else:
        process.wait(timeout=0.5)


def _capture(kind, budget):
    if kind not in COMMANDS:
        raise ProbeBlocked('UNSUPPORTED_INTERNAL_COMMAND')
    process = None
    selector = None
    output = bytearray()
    lines = 0
    truncated = False
    deadline = time.monotonic() + COMMAND_TIMEOUT_S
    try:
        process = subprocess.Popen(COMMANDS[kind], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   shell=False, close_fds=True)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
        selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProbeBlocked('DOCKER_COMMAND_TIMEOUT')
            ready = selector.select(remaining)
            if not ready:
                raise ProbeBlocked('DOCKER_COMMAND_TIMEOUT')
            for key, _ in ready:
                if budget['bytes'] >= MAX_BYTES:
                    raise ProbeBlocked('METADATA_BYTE_CAP')
                # Never consume row 33.
                chunk = os.read(key.fileobj.fileno(), 1)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                budget['bytes'] += len(chunk)
                if key.data == 'stdout':
                    output.extend(chunk)
                    if kind == 'images' and chunk == b'\n':
                        lines += 1
                        if lines == MAX_ROWS:
                            truncated = True
                            break
            if truncated:
                break
        if truncated:
            _stop(process)
        else:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProbeBlocked('DOCKER_COMMAND_TIMEOUT')
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                raise ProbeBlocked('DOCKER_COMMAND_TIMEOUT')
            if process.returncode != 0:
                raise ProbeBlocked('DOCKER_COMMAND_FAILED')
        return output.decode('utf-8', errors='strict'), truncated, process.returncode
    except FileNotFoundError:
        raise ProbeBlocked('DOCKER_MISSING')
    except (OSError, UnicodeError):
        raise ProbeBlocked('DOCKER_METADATA_IO_OR_ENCODING')
    finally:
        if selector is not None:
            selector.close()
        if process is not None:
            try:
                _stop(process)
            finally:
                process.stdout.close()
                process.stderr.close()


def _parse_info(raw):
    value = json.loads(raw)
    fields = ('CgroupVersion', 'OSType', 'ServerVersion')
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ProbeBlocked('DOCKER_INFO_FIELDS')
    if any(not isinstance(value[key], str) or not value[key] or
           len(value[key]) > 128 for key in fields):
        raise ProbeBlocked('DOCKER_INFO_VALUES')
    if value['OSType'] != 'linux':
        raise ProbeBlocked('LINUX_DOCKER_REQUIRED')
    return value


def _parse_images(raw):
    rows = raw.splitlines()
    if len(rows) > MAX_ROWS:
        raise ProbeBlocked('IMAGE_ROW_CAP')
    result = []
    for line in rows:
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ProbeBlocked('IMAGE_ROW_OBJECT')
        name, tag, immutable_id = row.get('Repository'), row.get('Tag'), row.get('ID')
        if any(not isinstance(value, str) or not value or len(value) > 128
               for value in (name, tag)):
            raise ProbeBlocked('IMAGE_NAME_TAG_CAP')
        if not isinstance(immutable_id, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', immutable_id):
            raise ProbeBlocked('IMAGE_IMMUTABLE_ID')
        result.append(dict(name=name, tag=tag, immutable_id=immutable_id))
    return result


def probe(include_capabilities=False):
    result = dict(schema=SCHEMA, status='blocked', host=socket.gethostname(),
                  platform=sys.platform, python=sys.version.split()[0], docker=None,
                  images=[], inventory_truncated=False, full_inventory_claimed=False,
                  metadata_bytes=0, lifecycle_gate_pass=False,
                  python_image_capability_verified=False)
    budget = {'bytes': 0}
    try:
        if result['platform'] != 'linux':
            raise ProbeBlocked('LINUX_REQUIRED')
        if result['host'] != EXPECTED_HOST:
            raise ProbeBlocked('B_HOST_IDENTITY_REQUIRED')
        info_raw, _, _ = _capture('info', budget)
        info = _parse_info(info_raw)
        image_raw, truncated, returncode = _capture('images', budget)
        images = _parse_images(image_raw)
        result.update(status='metadata_collected', docker=info, images=images,
                      inventory_truncated=truncated,
                      image_cli_returncode=returncode,
                      image_cli_stopped_at_row_cap=truncated)
        if include_capabilities:
            help_text, unused, unused_code = _capture('create_help', budget)
            flags = set(re.findall(r'(?<!\S)(--[a-z0-9-]+)(?=[\s,=]|$)', help_text))
            required = ('--cgroup-conf', '--cgroupns', '--memory', '--memory-swap',
                        '--pids-limit', '--pull', '--read-only', '--tmpfs', '--cap-drop')
            result['docker_create_capabilities'] = {flag: flag in flags for flag in required}
    except ProbeBlocked as exc:
        result.update(status='blocked', docker=None, images=[])
        result['reason'] = str(exc)
    except (ValueError, TypeError):
        result.update(status='blocked', docker=None, images=[])
        result['reason'] = 'MALFORMED_DOCKER_METADATA'
    finally:
        result['metadata_bytes'] = budget['bytes']
    return result


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args:
        result = dict(schema=SCHEMA, status='blocked', reason='NO_ARGUMENTS_ACCEPTED')
    else:
        result = probe(include_capabilities=True)
    encoded = json.dumps(result, ensure_ascii=True, separators=(',', ':'))
    if len(encoded.encode('utf-8')) + 1 > MAX_RETURN_BYTES:
        result = dict(schema=SCHEMA, status='blocked', reason='RETURN_BYTE_CAP')
        encoded = json.dumps(result, separators=(',', ':'))
    print(encoded)
    return 0 if result['status'] == 'metadata_collected' else 2


if __name__ == '__main__':
    sys.exit(main())
