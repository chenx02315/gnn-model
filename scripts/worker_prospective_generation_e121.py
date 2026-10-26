"""One physical fixed-plan worker; runtime environment values never leave RAM."""
import base64
import json
import os
import platform
import shlex
import sys
import time

from src.data import direct_tessent_acceptance_e104 as direct
from src.data import prospective_generation_controller_e116 as controller
from src.data import prospective_generation_artifacts_e117 as artifacts
from src.data import prospective_generation_storage_e118 as storage
from src.data import prospective_runtime_adapter_e114 as adapter
from src.data import prospective_runtime_profile_e112 as profile

SCHEMA = 'prospective-generation-worker-e121-v1'
NONCE = 'E121_PRIVATE_RUNTIME_V1'
require, sha, canonical = controller.require, controller.sha, controller.canonical


def host_gate():
    require(sys.platform.startswith('linux') and platform.node() == 'bupt-vncs2' and
            os.getuid() == 1047, 'FIXED_HOST_UID_PLATFORM')
    require(controller.process._boot_id() == controller.BOOT_ID, 'ORIGINAL_BOOT_REQUIRED')
    require(controller.PACKAGE_START <= time.monotonic() < controller.PACKAGE_END,
            'ORIGINAL_PACKAGE_DEADLINE')


def capture_runtime(package, domain, evidence=None):
    """Exactly one fixed module child; raw output must never be persisted."""
    source = base64.b64decode(package['runtime_profile_source'], validate=True)
    require(sha(source) == package['runtime_profile_source_sha256'] and
            sha(source) == package['source_sha256']['prospective_runtime_profile_e112'], 'PROFILE_SOURCE_BINDING')
    code = (source.decode('utf-8') + '\nimport os\nvalues={k:os.environ[k] for k in KEYS if k in os.environ}\n'
            'print(json.dumps(dict(nonce='+repr(NONCE)+',values=values,profile=snapshot(values,False)),sort_keys=True))\n')
    command = 'module load mentor/tessent2021 >/dev/null && /usr/bin/python3 -I -S -B -c '+shlex.quote(code)
    observed = direct.base.supervise(['/bin/bash', '-lc', command], '/',
        min(controller.PACKAGE_END, time.monotonic()+30), domain, [65536])
    output = observed.pop('output')
    metadata = dict(bytes=len(output), sha256=sha(output),
                    cleaned=observed.get('cleaned'), returncode=observed.get('returncode'),
                    launch_attempted=observed.get('launch_attempted'), values_disclosed=False)
    if evidence is not None:
        evidence.update(metadata)
    require(metadata['cleaned'] is True and metadata['returncode'] == 0 and
            observed.get('failure') is None, 'BOOTSTRAP_FAILED')
    require(type(output) is bytes and 0 < len(output) <= 65536, 'BOOTSTRAP_BOUND')
    try:
        value = json.loads(output.decode('ascii'), object_pairs_hook=controller.material.pins._pairs)
        require(type(value) is dict and set(value) == {'nonce', 'values', 'profile'} and
                value['nonce'] == NONCE and type(value['values']) is dict and
                set(value['values']) <= set(profile.KEYS), 'BOOTSTRAP_PRIVATE_SCHEMA')
        preparation = json.loads(base64.b64decode(package['inputs']['e112'], validate=True).decode('ascii'))
        adapter.prepare_runtime(value['values'], preparation['runtime_profile'],
                                controller.material.pins.LAUNCHER_SHA256)
        require(value['profile'] == preparation['runtime_profile'], 'BOOTSTRAP_PROFILE_DRIFT')
    except Exception:
        raise ValueError('BOOTSTRAP_PRIVATE_VALIDATION_FAILED') from None
    return value['values'], metadata


def run_selftests(ctx, domain):
    cases = (
        ('success', 'print("DIRECT_SYNTHETIC_OK")', 15),
        ('timeout', 'import time;time.sleep(5)', 10.5),
        ('setsid_child', 'import os,time\np=os.fork()\nif p==0:\n os.setsid();print("DIRECT_SETSID_READY %d"%os.getpid(),flush=True);time.sleep(30)\nelse:\n time.sleep(30)', 13))
    receipts = []
    for name, code, seconds in cases:
        ctx['sample']()
        end = min(ctx['end'], time.monotonic()+seconds)
        require(time.monotonic() < end-10, 'SELFTEST_CLEANUP_RESERVE')
        ctx['persist'](name+'_intent.json', canonical(dict(case=name, deadline=end,
            cleanup_reserve_seconds=10, actual_tessent_launch=False))+b'\n')
        try:
            observed = direct.base.supervise(['/usr/bin/python3', '-I', '-S', '-B', '-c', code],
                ctx['root']+'/journal', end, domain, [65536], scratch=SimpleMonitor(ctx['sample']),
                ready_check=direct.base._setsid_readiness if name == 'setsid_child' else None)
        except BaseException as exc:
            ctx['persist'](name+'_observation.json', canonical(dict(error_type=type(exc).__name__,
                status='SUPERVISION_RAISED_NO_RETRY'))+b'\n')
            raise
        raw = observed.pop('output')
        ctx['persist'](name+'_observation.json', canonical(dict(observed,
            output_bytes=len(raw), output_sha256=sha(raw),
            output_name=name+'_output.log', output_publication_ack=False))+b'\n')
        ctx['persist'](name+'_output.log', raw)
        passed = (observed.get('cleaned') is True and observed.get('launch_attempted') is True and
                  ((observed.get('returncode') == 0 and observed.get('failure') is None and
                    raw.strip() == b'DIRECT_SYNTHETIC_OK') if name == 'success' else
                   observed.get('failure') == 'CASE_TIMEOUT') and
                  (name != 'setsid_child' or observed.get('readiness') is not None))
        require(passed, 'ACTUAL_SELFTEST_FAILED')
        receipt = dict(case=name, passed=True, cleaned=True, authenticated_claim=True,
                       actual_linux_process=True, readiness=observed.get('readiness'), actual_tessent_launch=False)
        ctx['persist'](name+'_receipt.json', canonical(receipt)+b'\n')
        receipts.append(receipt)
        ctx['sample']()
    return receipts


class SimpleMonitor(object):
    def __init__(self, sample):
        self.sample = sample


def execute(package):
    """No retry or resume; returns only bounded metadata, never runtime values."""
    bootstrap = None
    try:
        host_gate()
        from src.data import prospective_generation_diagnostics_e120 as diagnostics
        raw = {k:base64.b64decode(v, validate=True) for k, v in package['inputs'].items()}
        gate = diagnostics.build_gate(raw['diagnostic_policy'])
        domain = direct.Descendants()
        bootstrap = {}
        values, unused_metadata = capture_runtime(package, domain, bootstrap)
        holder = {}
        def read(*args):
            return holder['artifacts'].read_artifacts(*args)
        def translate(*args):
            return holder['artifacts'].run_translation(*args)
        def selftests(ctx):
            ctx['persist']('bootstrap_metadata.json', canonical(bootstrap)+b'\n')
            return run_selftests(ctx, holder['controller'].domain)
        value = controller.Controller(raw['authority'], raw['e112'], raw['e85'], raw['e88'], raw['e93'],
            raw['common_tcl'], raw['incremental_tcl'], values, storage.persist_initial_intent,
            selftests, storage.DirectoryMonitor(), read, translate, package['review_gates'])
        holder['controller'] = value
        holder['artifacts'] = artifacts.Artifacts(value.maker, gate)
        summary = value.run()
        return dict(schema=SCHEMA, status=summary['status'], summary=summary, bootstrap=bootstrap,
                    execution_ready=False, training_release=False, runtime_values_disclosed=False)
    except BaseException as exc:
        # Neither arbitrary exception text nor private child output crosses this boundary.
        return dict(schema=SCHEMA, status='STOPPED_FIRST_FAILURE', error_type=type(exc).__name__,
                    error_code='WORKER_OPERATION_FAILED', bootstrap=bootstrap,
                    execution_ready=False, training_release=False, runtime_values_disclosed=False)
