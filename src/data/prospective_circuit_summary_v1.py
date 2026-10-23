"""Pre-execution static descriptors from supplied standard-cell topology.

No graph file, labels, model, or process is opened. Sequential cells are explicit
boundaries for combinational depth. A remaining combinational cycle produces a
missing depth, never a fabricated feature value or a silently clipped graph.
"""
from collections import deque
import hashlib
import json
import math


SCHEMA = 'STATIC_CIRCUIT_SUMMARY_V1'
FEATURE_COLUMNS = ('log1p_node_count', 'log1p_edge_count',
                   'sequential_cell_fraction', 'mean_fanout',
                   'p95_fanout', 'logic_depth')
MAX_NODES = 50000
MAX_EDGES = 250000


def require(value, reason):
    if not value:
        raise ValueError(reason)


def summarize(nodes, edge_index):
    """Accept the node/edge schema of build_runtime_graphs_v1's topology.

    Edges are directed source-cell to consumer-cell, duplicate-free. Fanout
    includes all unique cell edges, with zero-fanout cells in the distribution.
    p95 is nearest-rank x[ceil(.95*N)-1]. Depth counts combinational cells on the
    longest directed path after cutting every edge entering a sequential cell.
    An isolated combinational cell has depth 1; sequential-only depth is 0.
    """
    require(type(nodes) is list and 1 <= len(nodes) <= MAX_NODES, 'NODE_BOUND')
    require(type(edge_index) is list and len(edge_index) <= MAX_EDGES, 'EDGE_BOUND')
    for node in nodes:
        require(type(node) is dict and set(node) == {
            'node_type', 'cell_type', 'sequential_flag'}, 'NODE_SCHEMA')
        require(node['node_type'] == 'standard_cell_instance' and
                type(node['cell_type']) is str and 1 <= len(node['cell_type']) <= 128 and
                type(node['sequential_flag']) is bool, 'CELL_TOPOLOGY_SCHEMA')
    n = len(nodes)
    seq = [node['sequential_flag'] for node in nodes]
    unique = set()
    fanout = [0] * n
    indegree = [0] * n
    outgoing = [[] for _ in nodes]
    for edge in edge_index:
        require(type(edge) is list and len(edge) == 2 and
                all(type(v) is int and 0 <= v < n for v in edge), 'EDGE_SCHEMA')
        source, target = edge
        require((source, target) not in unique, 'DUPLICATE_EDGE')
        unique.add((source, target))
        fanout[source] += 1
        if not seq[target]:
            outgoing[source].append(target)
            indegree[target] += 1
    depth = [0 if s else 1 for s in seq]
    queue = deque(i for i, count in enumerate(indegree) if count == 0)
    processed = 0
    while queue:
        source = queue.popleft()
        processed += 1
        for target in outgoing[source]:
            depth[target] = max(depth[target], depth[source] + 1)
            indegree[target] -= 1
            if indegree[target] == 0:
                queue.append(target)
    logic_depth = max(depth) if processed == n else None
    sorted_fanout = sorted(fanout)
    # Exact integer nearest-rank index, avoiding floating ceil near an integer.
    p95 = sorted_fanout[(95 * n + 99) // 100 - 1]
    values = [math.log1p(n), math.log1p(len(unique)), sum(seq) / n,
              sum(fanout) / n, p95, logic_depth]
    topology = dict(nodes=nodes, edge_index=[list(e) for e in sorted(unique)])
    raw = json.dumps(topology, sort_keys=True, separators=(',', ':'),
                     ensure_ascii=True, allow_nan=False).encode('ascii')
    return dict(schema=SCHEMA, feature_columns=list(FEATURE_COLUMNS), values=values,
        node_count=n, edge_count=len(unique), sequential_cell_count=sum(seq),
        logic_depth=logic_depth,
        depth_status='COMPLETE' if logic_depth is not None else 'COMBINATIONAL_CYCLE_UNSUPPORTED',
        feature_vector_complete=logic_depth is not None,
        descriptor_topology_sha256=hashlib.sha256(raw).hexdigest(),
        supplied_graph_bytes_authenticated=False, design_mode_mapping_authenticated=False,
        outcome_fields_used=False, model_inference_performed=False,
        execution_ready=False, training_release=False)
