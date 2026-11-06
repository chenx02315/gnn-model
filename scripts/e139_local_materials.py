"""Fixed read-only E139 local material adapter, not authority or an entry release.

prepare() reads only the existing bounded fixed E138 caches. rebind() is a
separate RAM-only transformation; origin metadata is never effective proof.
No derived module is imported, executed, registered, or granted permission.
"""
import ast
import copy
import hashlib
import json

from scripts import e138_deployment_materials as origin
from scripts import e139_native_graph_candidate as graph

READY = 'READY_LOCAL_MATERIALS_ONLY'
ROLE_COUNTS = dict(capture=35, execution=53, readback=36)
ROLE_ORDER_PINS = dict(
    capture='71cc455bc91d9b7c15dca9eea011703c033c541c488e9424536fddc3bcf3e563',
    execution='591a315ee0405e104f49707135a07118ef4645b322510d35d44a083c6a90a6ba',
    readback='4f587066a09174761daa97f91cf45b9cfb167efafe8be0b61115c02f43601371')
INPUT_SOURCES = dict(runtime_source='physical_f_replay_execution_e135',
    worker_source='physical_e138_runtime_primitives', bootstrap_source='physical_runtime_bootstrap_e138',
    collector_source='physical_engine_evidence_e138', root_receipt_source='physical_e138_root_receipt')
STATIC_INPUT_PINS = dict(
    functions='00dd479b93c31ddee02231887f417e4636dd7abbe765965eba1779da1df5181f',
    shell='75933bcaa3831bf3635bb305d3e721f011ba9abf4c226045aa6d1d1863e4ca6d',
    e112='fd09999da5355c8b66fb0bbae0e6f495544bbf578df8894b01ac5fc8685864ae',
    parent_worker_source='360dd42f9c0a950858dad085d9c0a3ebda551991cd9ab525ea71fa97216abe10',
    profile_source='b7f096782faefe9abcd9e3e748176ffcf3c2944c72cb1d39b32b0d196d1a2e3a',
    incremental='50982a3c1b9b93b452313ef503bbfe6d17a44f7f3a018334041244807587dafe',
    parent_helper='4593364ffe5c01533e7a47e976585e506ed3677daa6c91289bc799f7ea2d79b0',
    policy='632c0c30252ffc01f73df912ceb0e7783083b82a59de0e56053bebe32d070cc9')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def require(ok, code):
    if not ok:
        raise ValueError(code)


class Materials:
    __slots__ = ('_private', '_summary')

    def __init__(self, private, summary):
        self._private = copy.deepcopy(private)
        self._summary = copy.deepcopy(summary)

    def __repr__(self):
        return '<E139 LOCAL MATERIALS PRIVATE_RAM_ONLY; use public_summary()>'

    def __reduce_ex__(self, protocol):
        raise TypeError('E139_MATERIALS_NOT_SERIALIZABLE')

    def private_bytes(self):
        require(self._summary['status'] == READY, 'E139_FIXED_MATERIALS_NOT_READY')
        return copy.deepcopy(self._private)

    def public_summary(self):
        return copy.deepcopy(self._summary)


def rebind(origin_summary, private_material):
    """Verify exact original bytes/orders, then derive and crossjoin in RAM.

    Raises on invalid inputs. Neither summary status nor caller manifests can
    substitute for independently frozen origin/effective byte identities.
    """
    require(type(origin_summary) is dict and origin_summary.get('status') == READY,
            'E139_ORIGIN_NOT_READY')
    require(type(private_material) is dict and set(private_material) == {'roles', 'execution_inputs'},
            'E139_ORIGIN_SHAPE')
    roles = private_material['roles']
    inputs = private_material['execution_inputs']
    spec = graph.specification()
    pins = {r['name']: r['sha256'] for r in spec['origins']}
    effective_pins = {r['name']: r['effective_sha256'] for r in spec['origins']}
    require(type(roles) is dict and set(roles) == set(ROLE_COUNTS), 'E139_ROLE_ROSTER')
    union = {}
    for role, bundle in roles.items():
        require(type(bundle) is dict and set(bundle) ==
                {'sources', 'source_order', 'source_sha256', 'dependency_checks'}, 'E139_ROLE_SHAPE')
        order, sources, manifest = bundle['source_order'], bundle['sources'], bundle['source_sha256']
        require(type(order) is tuple and len(order) == ROLE_COUNTS[role] and
                sha(canonical(list(order))) == ROLE_ORDER_PINS[role], 'E139_ROLE_ORDER')
        require(type(sources) is dict and type(manifest) is dict and
                set(sources) == set(order) == set(manifest), 'E139_ROLE_SOURCE_ROSTER')
        require(type(bundle['dependency_checks']) is int and bundle['dependency_checks'] >= 0,
                'E139_ORIGIN_DEPENDENCY_COUNT')
        for name in order:
            raw = sources[name]
            require(name in pins and type(raw) is bytes and
                    sha(raw) == manifest[name] == pins[name], 'E139_ORIGIN_SOURCE_PIN')
            require(name not in union or union[name] == raw, 'E139_ORIGIN_SOURCE_CONFLICT')
            union[name] = raw
    require(set(union) == set(graph.SOURCE_ORDER), 'E139_EXACT_UNION')
    expected_inputs = dict(STATIC_INPUT_PINS, **{k: pins[n] for k, n in INPUT_SOURCES.items()})
    require(type(inputs) is dict and set(inputs) == set(expected_inputs), 'E139_INPUT_ROSTER')
    for key, pin in expected_inputs.items():
        require(type(inputs[key]) is bytes and sha(inputs[key]) == pin, 'E139_ORIGIN_INPUT_PIN')
    result = graph.build(union)
    effective = result.private_sources()
    require(set(effective) == set(pins) and all(type(raw) is bytes and sha(raw) == effective_pins[n]
            for n, raw in effective.items()), 'E139_EFFECTIVE_SOURCE_PIN')
    # Static declaration evaluation only, on exact independently pinned bytes.
    declarations = origin._declarations(ast.parse(effective['physical_e138_contract'],
                                                  feature_version=(3, 6)))
    policy = declarations['POLICY']
    require(policy['package'] == 'E139' and policy['schema'] == 'e139-fixed-f-replay-policy-v1'
            and policy['new_remote_root'] == graph.pair.ROOT_NEW
            and policy['new_local_phase'] == graph.pair.PHASE_NEW, 'E139_POLICY_IDENTITY')
    rebound_inputs = dict(inputs)
    rebound_inputs.update({key: effective[name] for key, name in INPUT_SOURCES.items()})
    rebound_inputs['policy'] = canonical(policy)
    rebound_roles = {}
    rows = []
    for role, bundle in roles.items():
        order = bundle['source_order']
        rebound_roles[role] = dict(sources={n: effective[n] for n in order}, source_order=order,
            source_sha256={n: effective_pins[n] for n in order},
            dependency_checks=None, origin_dependency_checks=bundle['dependency_checks'],
            effective_source_pin_checks=len(order))
        for name in order:
            rows.append(dict(role=role, path='src/data/' + name + '.py', bytes=len(effective[name]),
                origin_sha256=pins[name], sha256=effective_pins[name], check='EFFECTIVE_PIN_VERIFIED'))
    for key, raw in rebound_inputs.items():
        rows.append(dict(role=key, path='private-ram-input:' + key, bytes=len(raw),
                         sha256=sha(raw), check='EFFECTIVE_INPUT_PIN_VERIFIED'))
    summary = dict(schema='e139-fixed-local-materials-v1', package='E139',
        evidence_scope='EFFECTIVE_LOCAL_BYTE_PIN_CONSISTENCY_ONLY',
        status=READY, artifacts=rows, role_source_counts=dict(ROLE_COUNTS),
        origin_dependency_checks={r: roles[r]['dependency_checks'] for r in roles},
        effective_source_pin_checks=dict(ROLE_COUNTS), effective_dependency_checks=None,
        unique_source_count=len(effective), execution_ready=False, authority_supplied=False,
        remote_execution_observed=False, source_session_released=False)
    return Materials(dict(execution_inputs=rebound_inputs, roles=rebound_roles), summary)


def prepare():
    """Read fixed local inputs only, returning sanitized fail-closed status."""
    try:
        prepared = origin.prepare()
        summary = prepared.public_summary()
        require(summary.get('status') == READY, 'E139_ORIGIN_NOT_READY')
        return rebind(summary, prepared.private_bytes())
    except (ValueError, KeyError, TypeError, AttributeError, SyntaxError):
        return Materials({}, dict(schema='e139-fixed-local-materials-v1', package='E139',
            evidence_scope='NO_EFFECTIVE_MATERIALS_PROOF',
            status='MISSING_OR_INVALID_FIXED_MATERIALS', artifacts=[],
            execution_ready=False, authority_supplied=False, remote_execution_observed=False,
            source_session_released=False))
