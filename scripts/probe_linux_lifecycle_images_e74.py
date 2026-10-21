"""Only enrich two exact already-observed image records; never run an image."""
import hashlib
import json
import os
import selectors
import socket
import subprocess
import sys
import time

IDS = ('sha256:c1702cf77b0857dd202ba298986ffc7942a4847c1b049bdc1f78567d0824df10',
       'sha256:75456a4ee6ffd0ae32272076d6164622bd4025304053ddab995399d10a9c7743')
FORMAT = '\n'.join('{{json .%s}}' % field for field in
    ('Id', 'Os', 'Architecture', 'Config.Cmd', 'Config.Entrypoint', 'Config.Volumes'))


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def capture(args, budget):
    proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, shell=False)
    raw = bytearray()
    deadline = time.monotonic()+5
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while selector.get_map():
                require(time.monotonic() < deadline, 'METADATA_TIMEOUT')
                for key, unused in selector.select(0.1):
                    remaining = 4096-budget[0]
                    require(remaining > 0, 'METADATA_BYTES')
                    chunk = os.read(key.fileobj.fileno(), min(512, remaining))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    budget[0] += len(chunk)
                    require(budget[0] <= 4096, 'METADATA_BYTES')
                    raw.extend(chunk)
        require(proc.wait(timeout=max(0.01, deadline-time.monotonic())) == 0, 'METADATA_COMMAND')
        return bytes(raw)
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=1)
        proc.stdout.close()


def probe():
    require(sys.platform == 'linux' and socket.gethostname() == 'bupt-gpus1', 'B_HOST_ONLY')
    budget = [0]
    info = capture(['docker', 'info', '--format',
        '{{json .CgroupVersion}}\n{{json .OSType}}\n{{if index .Runtimes "runc"}}true{{else}}false{{end}}'], budget)
    require(info.decode().splitlines() == ['"2"','"linux"','true'], 'LINUX_CGROUP2_RUNC_REQUIRED')
    raw = capture(['docker','image','inspect','--format',FORMAT]+list(IDS), budget)
    lines = raw.decode('utf-8').splitlines()
    require(len(lines) == 12, 'IMAGE_PROJECTION_ROWS')
    rows = []
    for index, image_id in enumerate(IDS):
        fields = [json.loads(value) for value in lines[index*6:index*6+6]]
        require(fields[0] == image_id and fields[1] == 'linux' and fields[2] == 'amd64', 'IMAGE_ID_OS_ARCH')
        for command in fields[3:5]:
            require(command is None or (type(command) is list and len(command) <= 32 and
                all(type(part) is str and len(part) <= 512 for part in command)), 'COMMAND_METADATA')
        require(fields[5] is None or type(fields[5]) is dict, 'VOLUME_METADATA')
        first = [command[0] for command in fields[3:5] if command]
        hint = any(os.path.basename(part).startswith('python') for part in first)
        rows.append(dict(image_id=image_id, volumes_empty=not fields[5],
            declared_python_command=hint, python_execution_verified=False,
            projection_sha256=hashlib.sha256(json.dumps(fields,sort_keys=True,separators=(',',':')).encode()).hexdigest()))
    return dict(schema='e74-fixed-image-metadata-v1', status='PASS_FIXED_IMAGE_METADATA',
        host='bupt-gpus1', metadata_bytes=budget[0], records=rows,
        new_inventory_scan=False, actual_containers_created=0)


def main():
    try:
        require(len(sys.argv)==1,'NO_ARGUMENTS')
        result=probe()
        code=0
    except Exception as exc:
        result=dict(schema='e74-fixed-image-metadata-v1',host=socket.gethostname(),
            status='BLOCKED_METADATA',reason=str(exc)[:120],actual_containers_created=0)
        code=2
    print(json.dumps(result,sort_keys=True))
    return code


if __name__=='__main__':
    raise SystemExit(main())
