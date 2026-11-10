"""LOCAL fixed-cache E140 adapter; finite reuse, no historical global mutation.

Old material source and original source origins are distinct from effective
adapter/native identities. Nothing here supplies authority or opens a session.
"""
from pathlib import Path
import types

from scripts import e138_deployment_materials as origin
from scripts import e140_native_graph_candidate as native
from scripts.e139_source_derivation import derive

KEY = 'scripts.e139_local_materials'
ORIGIN_SHA256 = 'd71176afd458e6941ff875e5eb7037fc39f7718a9ce30633e907a02f0f071d91'
EFFECTIVE_SHA256 = '8394fdea7abf1e39af4bfaf388eef182c11b6a8635904825d14e667417982a76'
READY = 'READY_LOCAL_MATERIALS_ONLY'
REPLACEMENTS = (
    ('from scripts import e138_deployment_materials as origin', 'origin=E140_ORIGIN', 1),
    ('from scripts import e139_native_graph_candidate as graph', 'graph=E140_GRAPH', 1),
    ("policy['package'] == 'E139'", "policy['package'] == 'E140'", 1),
    ("policy['schema'] == 'e139-fixed-f-replay-policy-v1'", "policy['schema'] == 'e140-fixed-f-replay-policy-v1'", 1),
    ('graph.pair.ROOT_NEW', 'graph.ROOT', 1),
    ('graph.pair.PHASE_NEW', 'graph.PHASE', 1),
    ("schema='e139-fixed-local-materials-v1', package='E139'", "schema='e140-fixed-local-materials-v1', package='E140'", 2),
    ('<E139 LOCAL MATERIALS PRIVATE_RAM_ONLY;', '<E140 LOCAL MATERIALS PRIVATE_RAM_ONLY;', 1),
)


def specification():
    return dict(schema='e139-source-derivation-v1',
        origins=[dict(name=KEY, sha256=ORIGIN_SHA256, effective_sha256=EFFECTIVE_SHA256)],
        rules=[dict(source=KEY, old_hex=a.encode('ascii').hex(), new_hex=b.encode('ascii').hex(), count=c)
               for a, b, c in REPLACEMENTS])


def build(origin_raw):
    return derive({KEY: origin_raw}, specification())


def _specification():
    # E140's own specification starts at E139 intermediate bytes. The material
    # adapter instead admits ORIGINAL fixed-cache bytes, never intermediate pins.
    old = native.previous.specification()
    effective = {r['name']: r['effective_sha256'] for r in native.specification()['origins']}
    return dict(origins=[dict(r, effective_sha256=effective[r['name']]) for r in old['origins']])


def load_adapter(origin_raw):
    raw = build(origin_raw).private_sources()[KEY]
    module = types.ModuleType('_e140_fixed_materials_private')
    module.E140_ORIGIN = origin
    module.E140_GRAPH = types.SimpleNamespace(specification=_specification, build=native.build,
        SOURCE_ORDER=native.SOURCE_ORDER, ROOT=native.ROOT, PHASE=native.PHASE)
    exec(compile(raw, '<e140-effective-materials>', 'exec'), module.__dict__)
    return module


def _adapter():
    path = Path(__file__).resolve().parent / 'e139_local_materials.py'
    return load_adapter(origin._read(path, 65536, ORIGIN_SHA256))


def prepare():
    """Only the pinned adapter source and existing fixed bounded caches read."""
    return _adapter().prepare()


def rebind(origin_summary, private_material, adapter_origin_raw):
    """No filesystem access; caller supplies exact pinned adapter origin bytes."""
    return load_adapter(adapter_origin_raw).rebind(origin_summary, private_material)
