"""Bounded anchored artifact readback and in-worker translation callbacks.

No launch, authority inference, retry or label release. Controller must admit
and debit before these callbacks. Translation runs in the same worker; samples
are cooperative, never a hard memory/CPU guarantee. Raw artifacts stay on A.
"""
import copy
import hashlib
import json
import os
import re
import stat

from . import prospective_generation_recipe_e108 as recipe
from . import prospective_acceptance_materializer_v1 as io
from . import prospective_fault_translation_v2 as faults
from . import prospective_report_dialect_e115 as reports
from . import prospective_generation_diagnostics_e120 as diagnostics

require, sha, canonical = faults.require, faults.sha, faults.canonical
SCHEMA = 'prospective-generation-artifact-reference-e117-v1'


def read_file(path, cap, tick, keep=True, expected=None):
    """Stable named inode read to EOF, bounded chunks; source never modified."""
    require(type(path) is str and path.startswith(recipe.ROOT + '/') and
            type(cap) is int and 0 < cap <= 64*1024*1024 and callable(tick), 'OWNED_READ_BOUND')
    tick()
    parent, name = path.rsplit('/', 1)
    parent_fd = io._directory(parent)
    fd = None
    try:
        directory_identity = io._identity(os.fstat(parent_fd))
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        require(stat.S_ISREG(named.st_mode) and named.st_nlink == 1 and
                0 < named.st_size <= cap, 'BOUNDED_SINGLE_LINK_FILE')
        if expected is not None:
            require(named.st_size == expected['bytes'], 'ARTIFACT_SIZE_CHANGED')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        require(io._identity(os.fstat(fd)) == io._identity(named), 'ARTIFACT_INODE_CHANGED')
        digest, parts, total = hashlib.sha256(), [], 0
        while total < named.st_size:
            tick()
            raw = os.read(fd, min(65536, named.st_size-total))
            require(bool(raw), 'ARTIFACT_SHORT_READ')
            total += len(raw)
            digest.update(raw)
            if keep:
                parts.append(raw)
        require(not os.read(fd, 1), 'ARTIFACT_GREW')
        tick()
        require(io._identity(named) == io._identity(os.fstat(fd)) ==
                io._identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)), 'ARTIFACT_CHANGED')
        fresh = io._directory(parent)
        try:
            require(io._identity(os.fstat(fresh)) == directory_identity, 'ARTIFACT_PARENT_REPLACED')
        finally:
            os.close(fresh)
        receipt = dict(path=path, bytes=total, sha256=digest.hexdigest())
        require(expected is None or receipt == expected, 'ARTIFACT_SHA_CHANGED')
        return (b''.join(parts) if keep else None), receipt
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent_fd)


def validate_driver(raw, binding, envelope, effective_tcl=None):
    require(type(raw) is bytes and 0 < len(raw) <= 16777216, 'DRIVER_BYTES')
    filtered = raw
    if effective_tcl is not None:
        require(sha(effective_tcl) == envelope['effective_tcl_sha256'], 'DRIVER_FROZEN_TCL_PIN')
        filtered, _ = diagnostics.strip_frozen_echo(raw, effective_tcl)
    require(diagnostics.ERROR.search(filtered) is None and
            diagnostics.INVALID_PATH.search(filtered) is None, 'DRIVER_ERROR')
    mode = envelope['stage']
    kind = 'MAPPED_COMMON_ATPG' if mode == 'H' else 'MAPPED_INCREMENTAL'
    expected = {kind + ('_STATUS' if mode == 'H' else '_ATPG_STATUS'): 'PASS',
                kind + '_MODE': mode, kind + '_RUN_ID': binding['task_uid']}
    control = binding['request']['control']
    expected['ATPG_TEST_COVERAGE_LIMIT' if control['kind'] == 'COVERAGE_PERCENT' else 'ATPG_PATTERN_LIMIT'] = (
        control['value'] if control['kind'] == 'COVERAGE_PERCENT' else
        str(control['value']) if control['kind'] == 'PATTERN_LIMIT' else 'FULL')
    if mode != 'H':
        expected[kind + '_TRANSLATED_STATUS_FILE'] = envelope['env']['STATUS_FILE']
        expected[kind + '_TRANSLATION_MANIFEST'] = envelope['env']['STATUS_TRANSLATION_MANIFEST']
    found = {}
    for line in raw.decode('utf-8', errors='strict').splitlines():
        if line.startswith(('MAPPED_', 'ATPG_')):
            require('=' in line, 'DRIVER_MARKER')
            key, value = line.split('=', 1)
            require(key in expected and key not in found and value == expected[key], 'DRIVER_MARKER')
            found[key] = value
        elif line.lstrip().startswith(('MAPPED_', 'ATPG_')):
            raise ValueError('INDENTED_DRIVER_MARKER')
    require(found == expected, 'MISSING_DRIVER_MARKER')
    return dict(bytes=len(raw), sha256=sha(raw), markers=found)


def scan_stil_file(receipt, tick):
    """Second bounded streaming pass; no complete STIL body retained in RAM."""
    path = receipt['path']
    require(path.startswith(recipe.ROOT+'/'), 'OWNED_STIL_PATH')
    parent, name = path.rsplit('/', 1)
    parent_fd, fd = io._directory(parent), None
    try:
        parent_identity = io._identity(os.fstat(parent_fd))
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                before.st_size == receipt['bytes'], 'STIL_SOURCE_CHANGED')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        require(io._identity(before) == io._identity(os.fstat(fd)), 'STIL_SOURCE_CHANGED')
        def chunks():
            remaining = before.st_size
            while remaining:
                tick()
                raw = os.read(fd, min(65536, remaining))
                require(bool(raw), 'STIL_SHORT_READ')
                remaining -= len(raw)
                yield raw
            require(not os.read(fd, 1), 'STIL_GREW')
        result = reports.scan_stil(chunks(), receipt['bytes'], receipt['sha256'], tick)
        require(io._identity(before) == io._identity(os.fstat(fd)) ==
                io._identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)), 'STIL_SOURCE_CHANGED')
        fresh = io._directory(parent)
        try:
            require(io._identity(os.fstat(fresh)) == parent_identity, 'STIL_PARENT_REPLACED')
        finally:
            os.close(fresh)
        return result
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent_fd)


class Artifacts(object):
    def __init__(self, materializer, diagnostic_gate):
        require(callable(diagnostic_gate), 'REVIEWED_DIAGNOSTIC_GATE_REQUIRED')
        self.maker, self.diagnostic_gate = materializer, diagnostic_gate
        self.references, self.translations = {}, {}
        self.action, self.detected_union = None, set()

    def _tick(self, ctx):
        ctx['sample']()
        fd = self.maker._owned(recipe.ROOT)
        os.close(fd)

    def _read(self, path, cap, ctx, keep=True, expected=None):
        return read_file(path, cap, lambda: self._tick(ctx), keep, expected)

    def _common(self, binding, freeze, ctx):
        circuit = binding['circuit']
        require(circuit == freeze['circuit'] and circuit in self.maker.common, 'CIRCUIT')
        common = recipe.ROOT+'/'+circuit+'/03_fault_universe/common_frozen/'
        pins = self.maker.common[circuit]
        raw_manifest, _ = self._read(common+'manifest.json', 65536, ctx, expected=dict(
            path=common+'manifest.json', **pins['manifest.json']))
        manifest = json.loads(raw_manifest.decode('utf-8'))
        require(manifest.get('schema') == 'multimode_common_fault_universe_v1' and
                manifest.get('fault_model') == 'stuck-at' and
                manifest.get('common_fault_count') == freeze['common_fault_count'] and
                pins['manifest.json']['sha256'] == freeze['authenticated_input_manifest_sha256'],
                'FROZEN_COMMON_MANIFEST')
        offset = manifest.get('f_flat_instance_offset')
        require(type(offset) is int and -2048 <= offset <= 2048, 'F_OFFSET')
        require(manifest.get('mapping', {}).get('sha256') == pins['canonical_fault_mapping.tsv']['sha256'],
                'MANIFEST_MAPPING_SHA')
        mapping, mapping_receipt = self._read(common+'canonical_fault_mapping.tsv', faults.MAX_FILE, ctx,
            expected=dict(path=common+'canonical_fault_mapping.tsv', **pins['canonical_fault_mapping.tsv']))
        return common, pins, offset, mapping, mapping_receipt

    def _reference(self, uid, expected_sha):
        require(uid in self.references and sha(self.references[uid]) == expected_sha, 'EXACT_PARENT_REFERENCE')
        return json.loads(self.references[uid].decode('ascii'))

    def _finish(self, binding, body):
        body.update(schema=SCHEMA, task_uid=binding['task_uid'], circuit=binding['circuit'],
                    action_uid=binding['action_uid'], binding_sha256=binding['binding_sha256'],
                    parent_reference_sha256=binding['parent_result_sha256'],
                    actual_atpg_runtime_ns=None, training_release=False, execution_ready=False)
        raw = canonical(body)+b'\n'
        require(len(raw) <= 65536, 'SMALL_REFERENCE_BOUND')
        self.references[binding['task_uid']] = raw
        return raw, dict(binding_sha256=binding['binding_sha256'], validation_passed=True,
                         output_authenticated_claim=True, reference_sha256=sha(raw),
                         d95_verified=False, actual_atpg_runtime_ns=None, training_release=False)

    def run_translation(self, binding, freeze, prep, parent_reference, ctx):
        require(binding['kind'] == 'TRANSLATION' and type(parent_reference) is bytes and
                sha(parent_reference) == binding['parent_result_sha256'] and
                self.references.get(binding['parent_task_uid']) == parent_reference, 'TRANSLATION_PARENT')
        common, pins, offset, mapping, mapping_pin = self._common(binding, freeze, ctx)
        parent = self._reference(binding['parent_task_uid'], binding['parent_result_sha256'])
        source, source_pin = self._read(parent['artifacts']['mtfi']['path'], faults.MAX_FILE, ctx,
                                       expected=parent['artifacts']['mtfi'])
        basic_name = binding['target_mode']+'_common_initial_faults.basic'
        require(prep['mapping'] == mapping_pin['path'] and prep['target_native_common_faults'] == common+basic_name,
                'TRANSLATION_PREPARATION_PATHS')
        basic, basic_pin = self._read(common+basic_name, faults.MAX_FILE, ctx,
                                    expected=dict(path=common+basic_name, **pins[basic_name]))
        self._tick(ctx)
        translated = faults.translate(mapping, source, basic, parent['mode'], binding['target_mode'],
            freeze['common_fault_count'], offset,
            dict(mapping=mapping_pin['sha256'], source_mtfi=source_pin['sha256'], target_basic=basic_pin['sha256']))
        self._tick(ctx)
        outputs = {}
        for role, path, raw in (('status', prep['output_status_file'], translated['output_mtfi_bytes']),
                                ('manifest', prep['output_manifest'], translated['manifest_bytes'])):
            self._tick(ctx)
            self.maker._publish(path, raw)
            _, outputs[role] = self._read(path, faults.MAX_FILE, ctx, keep=False,
                expected=dict(path=path, bytes=len(raw), sha256=sha(raw)))
        self.translations[binding['task_uid']] = dict(outputs=outputs,
            minimum=translated['expected_minimum_pre_detected'])
        return self._finish(binding, dict(kind='TRANSLATION', mode=binding['target_mode'],
            parent_native_mtfi=source_pin, mapping=mapping_pin, target_basic=basic_pin,
            artifacts=outputs, expected_minimum_pre_detected=translated['expected_minimum_pre_detected'],
            execution_scope='IN_PROCESS_WORKER_TRANSLATION_NOT_CHILD_PID', tessent_acceptance_verified=False))

    def read_artifacts(self, binding, freeze, envelope, observed, ctx):
        require(binding['kind'] == 'TESSENT' and envelope['task_uid'] == binding['task_uid'] and
                observed['cleaned'] is True and observed['returncode'] == 0 and observed['failure'] is None,
                'SUCCESSFUL_OBSERVATION_REQUIRED')
        name = 'common' if envelope['stage'] == 'H' else 'incremental'
        driver = validate_driver(observed['output'], binding, envelope, self.maker.sources[name]['tcl_bytes'])
        diagnostics = self.diagnostic_gate(observed['output'], binding, envelope)
        require(type(diagnostics) is dict and diagnostics.get('passed') is True, 'UNREVIEWED_DIAGNOSTIC')
        common, pins, offset, mapping, mapping_pin = self._common(binding, freeze, ctx)
        raw, artifacts, retained = None, {}, {}
        for role, path in sorted(envelope['output_paths'].items()):
            cap = faults.MAX_FILE if role == 'mtfi' else 65536 if role == 'statistics' else 64*1024*1024
            keep = role in ('statistics', 'mtfi')
            raw, artifacts[role] = self._read(path, cap, ctx, keep=keep)
            if keep:
                retained[role] = raw
        stats = reports.parse_statistics(retained['statistics'], freeze['common_fault_count'])
        annotation = scan_stil_file(artifacts['stil'], lambda: self._tick(ctx))
        lookup, _ = faults.mapping_lookup(mapping, freeze['common_fault_count'], offset, envelope['stage'], 'H')
        rows = faults.parse_source_mtfi(retained['mtfi'], freeze['common_fault_count'], set(lookup))
        detected = {lookup[key] for key, fault_class in rows}
        require(len(detected) <= stats['detected_common_faults'],
                'EXPLICIT_DETECTED_SUBSET_EXCEEDS_REPORTED_DETECTION')
        before, translated_pins = None, None
        if envelope['stage'] != 'H':
            parent = self._reference(binding['parent_task_uid'], binding['parent_result_sha256'])
            translation = self._reference(binding['translation_task_uid'], binding['translation_result_sha256'])
            require(translation['parent_reference_sha256'] == binding['parent_result_sha256'],
                    'TRANSLATION_EXACT_PARENT_JOIN')
            translated_pins = translation['artifacts']
            require(translated_pins['status']['path'] == envelope['env']['STATUS_FILE'] and
                    translated_pins['manifest']['path'] == envelope['env']['STATUS_TRANSLATION_MANIFEST'],
                    'EXACT_DEPLOYED_TRANSLATION_PATHS')
            for pin in translated_pins.values():
                self._read(pin['path'], faults.MAX_FILE, ctx, keep=False, expected=pin)
            raw_before, artifacts['pre_statistics'] = self._read(envelope['pre_statistics_path'], 65536, ctx)
            before = reports.parse_statistics(raw_before, freeze['common_fault_count'], patterns_required=False)
            require(before['detected_common_faults'] >= translation['expected_minimum_pre_detected'],
                    'INHERITED_DETECTION_MINIMUM_NOT_READ_BACK')
        if envelope['stage'] == 'H':
            require(self.action is None, 'PREVIOUS_ACTION_NOT_FINISHED')
            self.action, self.detected_union = binding['action_uid'], set()
        require(self.action == binding['action_uid'], 'ACTION_ORDER')
        self.detected_union.update(detected)
        union = dict(explicit_conservative_ds_di_union_count=len(self.detected_union),
            denominator=freeze['common_fault_count'], mathematical_d95=(
                100*len(self.detected_union) >= 95*freeze['common_fault_count']),
            eq_adjacency_detection_inferred=False, d95_verified=False)
        result = self._finish(binding, dict(kind='TESSENT', mode=envelope['stage'],
            effective_envelope_sha256=envelope['envelope_sha256'], artifacts=artifacts,
            requested_control=copy.deepcopy(binding['request']['control']),
            requested_vs_realized_equivalence_verified=False,
            statistics=stats, pre_statistics=before, stil_annotations=annotation,
            driver=driver, diagnostic_review=diagnostics, mapping=mapping_pin,
            translation_artifacts=translated_pins, action_union=union,
            final_action=envelope['stage'] == 'F', combined_pattern_cycles_qualified=False))
        if envelope['stage'] == 'F':
            self.action, self.detected_union = None, set()
        return result
