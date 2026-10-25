"""E102 local composition; no CLI, deployment, or new user consent is supplied.

Authorization fields are caller assertions, not authenticated consent. A future
controller must bind the actual new reply, frozen bytes and unique run budget.
Known warnings remain rejected; this module is not execution readiness evidence.
Historical E100/E101 modules, roots and failed results are never rewritten.
"""
import hashlib
import json
import os
import platform
import shlex
import sys
import time

from . import direct_tessent_acceptance_e100 as base
from . import direct_memory_sample_e101 as sampler
from . import direct_scratch_monitor_e102 as monitor
from . import direct_observation_journal_e102 as journal
from . import direct_runtime_compatibility_e102 as compatibility
from . import direct_diagnostic_policy_e102 as diagnostics

ROOT = '/temp/jiangchuanc/multimode_ate_direct_e102_20261025_r1'
SOURCE_PINS = (
    (base, '92f9915bc431483ba73cc38829356ca315a16ae39713b021b2025d0ce744fb58'),
    (sampler, '8a4e81fb3ef50cb3ad7fcd720d7f205ba7df6228b2af34dd87c0986968a22009'),
    (monitor, '8ef6652bcf18867f3a5db44aad103f3734ff7b886a3d04912274c5ed150b4174'),
    (journal, 'e53e1d3b32f237519adf52b8d1005f7c592b428150e8b8e91bbe46878437c027'),
    (compatibility, '2ec8387acec97e38604141ea5e108149dbc310823c23684da1d7fb194f8d71c1'),
    (diagnostics, '67dbbd601cdcd667c06bc8b0c238016da2c6689a9549f0601b5f6a0fc7010ff0'))
PREDECESSOR_LOG_SHA = '2b6e78f2267934f8a859aaf8872956b9fed6050df59aa13d5c22c68748f3c54d'
require = base.require
material, recipe = base.material, base.recipe
OUTPUT_CAP = base.OUTPUT_CAP
supervise, synthetic_gate, accepts_log = base.supervise, base.synthetic_gate, base.accepts_log
ScratchMonitor = monitor.ScratchMonitor


def validate_authority(raw):
    require(type(raw) is bytes and len(raw) <= 65536, 'E102_AUTHORITY_BYTES')
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=recipe._pairs)
    require(type(value) is dict and
            value.get('schema') == 'direct-tessent-repair-authorization-e102-v1' and
            value.get('user_authorization_received') is True and
            value.get('approval_source') == 'explicit_user_reply' and
            type(value.get('user_reply')) is str and 0 < len(value['user_reply']) <= 4096 and
            value.get('root') == ROOT and
            value.get('predecessor_log_sha256') == PREDECESSOR_LOG_SHA,
            'E102_NEW_EXPLICIT_AUTHORITY_REQUIRED')
    for key, expected in (
            ('additional_launch_attempts_max', 4), ('workers', 1), ('automatic_retries', 0),
            ('sampled_rss_plus_swap_stop_bytes', 536870912),
            ('per_case_seconds_including_cleanup', 600), ('session_seconds', 2700),
            ('combined_output_bytes', 16777216), ('process_count_stop_threshold', 64),
            ('scratch_stop_threshold_bytes', 134217728)):
        require(type(value.get(key)) is int and value[key] == expected, 'E102_FIXED_BUDGET')
    for key, expected in (('package_repair_versions_max', 2),
                          ('package_additional_launch_attempts_total_max', 8),
                          ('package_version_index', 1)):
        require(type(value.get(key)) is int and value[key] == expected, 'E102_PACKAGE_BUDGET')
    require(value.get('stop_on_first_failure') is True and
            value.get('unchanged_code_retries_allowed') is False and
            value.get('warnings_require_individual_review') is True and
            value.get('blanket_warning_ignore_allowed') is False,
            'E102_REPAIR_POLICY')
    for key in ('lsf_allowed', 'kernel_memory_cap_required', 'atpg_generation_allowed',
                'training_allowed', 'blind_allowed'):
        require(value.get(key) is False, 'E102_SCOPE_NOT_EXPANDED')
    return value


class Descendants(base.Descendants):
    def sample(self):
        return sampler.sample_descendants(self, base._identity, base._small)


class DirectMaterializer(base.DirectMaterializer):
    def initialize_bundle(self):
        plan = super(DirectMaterializer, self).initialize_bundle()
        material._publish(self.root_fd, 'repair_binding.json', recipe.canonical(dict(
            execution_version='E102', root=ROOT, authorization=self.authorization,
            source_sha256=[pin for module, pin in SOURCE_PINS],
            predecessor_log_sha256=PREDECESSOR_LOG_SHA,
            warning_acceptance_policy_changed=True,
            acceptance_scope='FIXED_IMPORT_EXECUTION_ONLY_NOT_D95_OR_FAULT_SEMANTICS',
            kernel_memory_cap_enforced=False, lsf_used=False)) + b'\n')
        return plan


def execute(raw85, raw93, authority):
    validate_authority(authority)
    require(all(getattr(module, '__source_sha256__', None) == pin
                for module, pin in SOURCE_PINS), 'E102_SOURCE_BINDING')
    previous = (base.ROOT, base.validate_authority, recipe.ROOT, material.RECIPE_SHA256)
    try:
        base.ROOT = ROOT
        base.validate_authority = validate_authority
        recipe.ROOT = ROOT
        return _execute(raw85, raw93, authority)
    finally:
        (base.ROOT, base.validate_authority, recipe.ROOT, material.RECIPE_SHA256) = previous


def _execute(raw85,raw93,authority):
    require(sys.platform.startswith('linux') and platform.node()=='bupt-vncs2','FIXED_LINUX_HOST')
    end=time.monotonic()+2700
    maker=DirectMaterializer(raw85,raw93,authority)
    plan=maker.initialize_bundle()  # Exclusive new root; consumes this invocation.
    results=[]
    try:
        domain=Descendants()
        gate=synthetic_gate(domain)
        material._publish(maker.root_fd,'synthetic_gate.json',recipe.canonical(dict(passed=True,cases=gate))+b'\n')
        shared=[OUTPUT_CAP]
        for row in plan['items']:
            case_started=time.monotonic()
            case_end=min(end,case_started+600)
            item=maker.materialize_item(row['circuit'],row['transition'])
            scratch=ScratchMonitor(case_end)
            command='module load mentor/tessent2021 && export HOME=%s TMPDIR=%s && exec %s' % (
                shlex.quote(item['cwd']),shlex.quote(item['cwd']),
                ' '.join(shlex.quote(x) for x in item['argv']))
            material._publish(maker.root_fd,'started_%s_%s.json'%(row['circuit'],row['target_mode']),
                recipe.canonical(dict(circuit=row['circuit'],transition=row['transition'],
                    consumed=True,automatic_retries=0,kernel_memory_cap_enforced=False))+b'\n')
            observed=supervise(['/bin/bash','-lc',command],item['cwd'],case_end,domain,shared,scratch)
            def publish_log(name,raw):
                log_fd=material._directory(item['cwd'])
                try: material._publish(log_fd,name,raw)
                finally: os.close(log_fd)
            journal.seal_observation(observed,row['circuit'],row['transition'],
                time.monotonic()-case_started,
                lambda name,raw: material._publish(maker.root_fd,name,raw),
                publish_log,scratch.sample)
            log=observed.pop('output')
            require(time.monotonic()<=case_end,'CASE_DEADLINE_AFTER_LOGS')
            marker=('E94_TRANSLATED_STATUS_ACCEPTANCE=PASS %s %s'%(row['circuit'],row['transition'])).encode('ascii')
            diagnostic=diagnostics.evaluate(log,marker,row['circuit'],row['transition'],item['tcl_bytes'])
            passed=(observed['returncode']==0 and observed['failure'] is None and
                diagnostic['passed'])
            receipt=dict(observed,circuit=row['circuit'],transition=row['transition'],passed=passed,
                diagnostic_acceptance=diagnostic,d95_verified=False,fault_semantics_verified=False,
                log_sha256=hashlib.sha256(log).hexdigest(),log_bytes=len(log),
                kernel_memory_cap_enforced=False,atpg_calls=0,training_runs=0,
                elapsed_before_receipt_seconds=time.monotonic()-case_started)
            results.append(receipt)
            material._publish(maker.root_fd,'result_%s_%s.json'%(row['circuit'],row['target_mode']),recipe.canonical(receipt)+b'\n')
            scratch.sample()
            require(time.monotonic()<=case_end,'CASE_DEADLINE_AFTER_RECEIPT')
            if not passed: break
        summary=dict(schema='direct-tessent-acceptance-e102-v1',root=ROOT,
            cases=results,passed=len(results)==4 and all(r['passed'] for r in results),
            kernel_memory_cap_enforced=False,lsf_used=False,automatic_retries=0,
            tessent_launch_attempts=sum(bool(r['launch_attempted']) for r in results),
            accepted_cases=sum(bool(r['passed']) for r in results),
            acceptance_scope='FIXED_IMPORT_EXECUTION_ONLY_NOT_D95_OR_FAULT_SEMANTICS',
            d95_verified=False,fault_semantics_verified=False,
            atpg_calls=0,training_runs=0,blind_release=False)
        material._publish(maker.root_fd,'summary.json',recipe.canonical(summary)+b'\n')
        require(time.monotonic()<=end,'SESSION_DEADLINE_AFTER_SUMMARY')
        return summary
    except Exception as exc:
        material._publish(maker.root_fd,'failure.json',recipe.canonical(dict(
            error_type=type(exc).__name__,code=str(exc) if isinstance(exc,ValueError) else 'DIRECT_STAGE_FAILED',
            cases_completed=len(results),no_retry=True))+b'\n')
        raise
    finally:
        maker.close()
