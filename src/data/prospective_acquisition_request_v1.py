"""Graphless E84 acquisition request freeze, independent of model features.

Pins are caller assertions; this pure module never reads or authenticates the
named input manifest or establishes execution authority.
"""
import hashlib
import json
import re

from src.data import prospective_acquisition_pilot_v1 as pilot

SCHEMA = 'prospective-acquisition-request-freeze-v1'
SHA = re.compile(r'[0-9a-f]{64}\Z')


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def freeze_acquisition(plan, circuit, common_fault_count,
                       authenticated_input_manifest_sha256):
    """Bind the exact E84 plan and one circuit; no graph/checkpoint fields."""
    pilot.validate_plan(plan)
    require(type(circuit) is str and circuit in pilot.CIRCUITS, 'CIRCUIT')
    require(type(common_fault_count) is int and 1 <= common_fault_count <= 2**31 - 1,
            'COMMON_FAULT_COUNT')
    require(type(authenticated_input_manifest_sha256) is str and
            SHA.fullmatch(authenticated_input_manifest_sha256) is not None,
            'INPUT_MANIFEST_SHA256')
    phase = next(row for row in plan['phases'] if row['circuit'] == circuit)
    body = dict(schema=SCHEMA, plan_sha256=plan['plan_sha256'],
                circuit=circuit,
                requested_roster=json.loads(canonical(phase['requested_roster']).decode('ascii')),
                roster_sha256=phase['roster_sha256'],
                requested_max_h=phase['requested_max_h'],
                requested_max_m=phase['requested_max_m'],
                common_fault_count=common_fault_count,
                authenticated_input_manifest_sha256=authenticated_input_manifest_sha256,
                input_manifest_bytes_authenticated=False,
                graph_required_for_acquisition=False,
                graph_or_checkpoint_present=False,
                model_features_generated=False,
                execution_ready=False, training_release=False)
    return dict(body, freeze_sha256=digest(body))


def validate_freeze(freeze, plan=None):
    """Exact schema/rebuild check; return a detached canonical snapshot."""
    require(type(freeze) is dict and set(freeze) ==
            {'schema', 'plan_sha256', 'circuit', 'requested_roster',
             'roster_sha256', 'requested_max_h', 'requested_max_m',
             'common_fault_count', 'authenticated_input_manifest_sha256',
             'input_manifest_bytes_authenticated',
             'graph_required_for_acquisition', 'graph_or_checkpoint_present',
             'model_features_generated', 'execution_ready', 'training_release',
             'freeze_sha256'}, 'ACQUISITION_FREEZE_SCHEMA')
    require(freeze['schema'] == SCHEMA, 'ACQUISITION_FREEZE_SCHEMA')
    expected = freeze_acquisition(pilot.build_plan() if plan is None else plan,
                                  freeze['circuit'], freeze['common_fault_count'],
                                  freeze['authenticated_input_manifest_sha256'])
    try:
        same = canonical(freeze) == canonical(expected)
    except (TypeError, ValueError, UnicodeError):
        same = False
    require(same, 'ACQUISITION_FREEZE_CHANGED')
    return json.loads(canonical(expected).decode('ascii'))
