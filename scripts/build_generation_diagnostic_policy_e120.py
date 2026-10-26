"""Build a small registry from exact existing local readbacks; never fetch or write."""
import base64
import json
from pathlib import Path
import re

from scripts import acceptance_transport_e98 as control
from src.data import prospective_generation_diagnostics_e120 as diagnostic
from src.data import prospective_tessent_acceptance_v1 as pins

ROOT = Path(__file__).resolve().parents[1]
STAGING = control.STAGING
READBACKS = {
    'e119': ('v6_e119_warning_metadata_20261026_r1', 'd3df00f39060030cb77d2f5462a725c8d96eeda155c682a8b614b28271b4a69b'),
    'e104': ('v6_e104_result_readback_20261025_r1', 'd1fab60b05890aa3e7d4cffb031dd360a2672fc08ec9e2f500138c9ed7310ae4'),
    'e103': ('v6_e103_result_readback_20261025_r1', 'a451a0409aee9e470a65ebd2ce15313ef8b5c06976a0f45451d62850e01bf513')}
NATIVE_PINS = {
    'aes_core:M': ('e103', '5fe275ab8cf80f3001f42b9b0a4154e8310030b8e2072de9d22a7c0e70aff7c0'),
    'aes_core:F': ('e104', '19b016c53a93344d3400edb7c8d610b667ecab73b76e79d68a4ebc2fe7d1b667'),
    'spi:M': ('e104', 'c8a3c3d90d4716cf1478b437edeea34171c1b05985ee5d96b39acf6cac5a2af4'),
    'spi:F': ('e104', '927fc681267e1f5f135f640ca6a3b9cfa66ddb657a1df53f4946c61428b310dc')}
OLD_LIBRARY = '/home/jiangchuanc/Desktop/multimode_ate_20260725_A_staging/00_inputs_readonly/scc28nhk_hsc31_lvt_scan.tcelllib'
FIELDS = ('category', 'block_lines', 'normalized_block_sha256', 'reported_number')
GENERATION_KINDS = frozenset(('SPLIT_CAPTURE_COST_NOTICE', 'CLOCK_OFF_COST_NOTICE',
                              'UNSUCCESSFUL_SEARCH_PHASE', 'AU_INCREASE_RISK'))


def _readbacks():
    values = {}
    for name, (phase, pin) in READBACKS.items():
        raw = (STAGING/phase/'stdout.json').read_bytes()
        diagnostic.require(control.sha(raw) == pin and len(raw) <= 2*1048576, 'EXACT_LOCAL_READBACK_'+name)
        value = json.loads(raw.decode('ascii'), object_pairs_hook=pins._pairs)
        transport = json.loads((STAGING/phase/'transport.json').read_bytes().decode('ascii'))
        diagnostic.require(type(transport.get('exit_code')) is int and transport['exit_code'] == 0 and
            all(transport.get(k) is False for k in ('timeout','overflow','write_failed','threads_incomplete')),
            'LOCAL_READBACK_TRANSPORT_'+name)
        values[name] = value
    return values


def _body(row, key, expected_sha=None):
    raw = base64.b64decode(row[key], validate=True)
    diagnostic.require(type(row['bytes']) is int and row['bytes'] == len(raw) and
                       control.sha(raw) == row['sha256'] and (expected_sha is None or row['sha256'] == expected_sha),
                       'COMPLETE_RECEIVED_FILE_BYTES_SHA')
    return raw


def load_sources():
    """Six exact already-received logs; historical inputs remain untouched."""
    readbacks = _readbacks()
    sources, metadata = {}, {}
    for circuit in ('aes_core', 'spi'):
        path = '/temp/jiangchuanc/multimode_ate_phase4_20260825_A/10_circuits/'+circuit+'/logs/H_'+circuit+'_H_full_phase4_v2.driver.log'
        rows = [r for r in readbacks['e119']['reports'] if r['path'] == path]
        diagnostic.require(len(rows) == 1, 'EXACT_HISTORICAL_H_LOG')
        key = circuit+':H'
        sources[key] = _body(rows[0], 'body_base64')
        metadata[key] = dict(readback='e119', path=path, bytes=len(sources[key]), sha256=control.sha(sources[key]))
    for key, (readback, pin) in NATIVE_PINS.items():
        circuit, mode = key.split(':')
        name = 'scratch/'+circuit+'_'+mode+'/direct_tessent.log'
        rows = [r for r in readbacks[readback]['files'] if r['name'] == name]
        diagnostic.require(len(rows) == 1, 'EXACT_HISTORICAL_NATIVE_LOG')
        sources[key] = _body(rows[0], 'body_b64', pin)
        metadata[key] = dict(readback=readback, path=name, bytes=len(sources[key]), sha256=pin)
    return sources, metadata


def build():
    sources, source_pins = load_sources()
    startup, generation, au_width = {}, {}, None
    for key in sorted(sources):
        circuit, mode = key.split(':')
        rows, imports, creates = diagnostic.extract(sources[key], OLD_LIBRARY if mode == 'H' else pins.LIBRARY)
        startup[key] = [{field:row[field] for field in FIELDS} for row in rows if row['phase'] == 'STARTUP']
        diagnostic.require(bool(startup[key]), 'MISSING_STARTUP_PROFILE')
        for row in rows:
            if row['phase'] == 'STARTUP':
                continue
            diagnostic.require(mode == 'H' and row['phase'] == 'GENERATION' and row['category'] in GENERATION_KINDS,
                               'UNREVIEWED_SOURCE_DIAGNOSTIC')
            block = base64.b64decode(row['block_base64'], validate=True)
            if row['category'] == 'AU_INCREASE_RISK':
                width = len(block.splitlines()[1])
                diagnostic.require(au_width is None or au_width == width, 'AU_SOURCE_TABLE_WIDTH_CHANGED')
                au_width = width
                matches = list(re.finditer(rb'([0-9]{1,3}\.[0-9]{2})% since the start of this ATPG run\.', block))
                diagnostic.require(len(matches) == 1, 'EXACT_AU_SOURCE_PERCENT')
                match = matches[0]
                block = block[:match.start(1)]+b'EXACT_BOUNDED_PERCENT'+block[match.end(1):]
            normalized = base64.b64encode(block).decode('ascii')
            previous = generation.setdefault(row['category'], normalized)
            diagnostic.require(previous == normalized, 'DUPLICATE_GENERATION_BLOCK_CHANGED')
    diagnostic.require(set(generation) == GENERATION_KINDS, 'EXACT_FOUR_GENERATION_PROFILES')
    templates = ROOT/'src/data/templates'
    frozen = diagnostic.recipe.freeze_sources((templates/'e108_common_base.tcl').read_bytes(),
                                              (templates/'e108_incremental_base.tcl').read_bytes())
    result = dict(schema=diagnostic.SCHEMA, library_sha256=pins.LIBRARY_SHA256, startup=startup,
        generation=generation, au_table_line_bytes=au_width, effective_tcl_base64={mode:base64.b64encode(
            frozen['common' if mode == 'H' else 'incremental']['tcl_bytes']).decode('ascii') for mode in ('H','M','F')},
        source_pins=source_pins, readback_sha256={name:pin for name, (_, pin) in READBACKS.items()},
        normalization=dict(library='ONE_EXACT_FULL_ALL_MODEL_ATTRIBUTES_SOURCE_LINE_ONLY',
                           library_token=diagnostic.LIBRARY_TOKEN.decode('ascii'),
                           historical_H_library=OLD_LIBRARY,
                           native_MF_library=pins.LIBRARY,
                           au='TYPED_DECIMAL_AND_EXACT_FIXED_WIDTH_RIGHT_PADDING_ONLY'),
        known_post_messages_applied_MF_by_limited_policy_inference_not_observed_MF_generation=True,
        warnings_risk_not_quality_harmlessness=True, d95_verified=False, training_release=False)
    raw = control.encode(result)
    diagnostic.require(len(raw) <= 65536, 'SMALL_POLICY_BOUND')
    diagnostic.build_gate(raw)
    return result


if __name__ == '__main__':
    print(json.dumps(build(), sort_keys=True, ensure_ascii=True, allow_nan=False, indent=2))
