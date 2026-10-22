"""Pure REQUESTED_COUNT_V1 features; never legacy-model or safety release.

Requests are controls known before execution. Realized pattern counts, F
results, D95, cycles, and runtimes are deliberately not accepted as inputs.
No graph/checkpoint bytes are opened and no model weights are inspected.
"""
import hashlib
import json
import math
import re

from src.data import prospective_input_binding_v1 as request_binding

FEATURE_SCHEMA_ID = 'REQUESTED_COUNT_V1'
FEATURE_COLUMNS = ('scheme_hf', 'scheme_hmf', 'log1p_h_request',
                   'log1p_m_request',
                   'h_request_fraction_of_frozen_roster_max',
                   'm_request_fraction_of_frozen_roster_max',
                   'log1p_common_fault_count')
FREEZE_SCHEMA = 'prospective-request-features-freeze-v1'
SHA256 = re.compile(r'[0-9a-f]{64}\Z')


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),
                                   ensure_ascii=True,allow_nan=False).encode('ascii')).hexdigest()


def freeze_requests(circuit, rows, common_fault_count, graph_sha256):
    """Bind the *caller-supplied* full roster, not prove external completeness.

    The E71 validator rejects aliases and any outcome/realized fields. The
    graph pin names caller-supplied bytes but authenticates no graph itself.
    A later preregistered roster SHA is required before this can govern runs.
    """
    require(type(common_fault_count) is int and 1<=common_fault_count<=2**31-1,
            'COMMON_FAULT_COUNT')
    require(type(graph_sha256) is str and SHA256.fullmatch(graph_sha256) is not None,
            'GRAPH_SHA256')
    identities={name:None for name in request_binding.IDENTITIES}
    bound=request_binding.bind_requests(circuit,rows,identities)
    body=dict(schema=FREEZE_SCHEMA,feature_schema_id=FEATURE_SCHEMA_ID,
              circuit=circuit,requested_roster=bound['payload']['requested_roster'],
              roster_sha256=bound['roster_sha256'],
              requested_max_h=bound['payload']['requested_max_h'],
              requested_max_m=bound['payload']['requested_max_m'],
              requested_controls=bound['controls'],
              common_fault_count=common_fault_count,graph_sha256=graph_sha256,
              normalization_scope='ENTIRE_CALLER_SUPPLIED_ROSTER_BEFORE_SUBSET_SELECTION',
              legacy_model_compatible=False,
              future_unknown_actions_d95_preverified=False,
              supplied_roster_external_completeness_verified=False,
              graph_bytes_authenticated=False,
              execution_ready=False,training_release=False,inference_release=False)
    return dict(body,freeze_sha256=digest(body))


def _checked_freeze(freeze):
    require(type(freeze) is dict and type(freeze.get('freeze_sha256')) is str,
            'FREEZE_SCHEMA')
    rebuilt=freeze_requests(freeze.get('circuit'),freeze.get('requested_roster'),
                            freeze.get('common_fault_count'),freeze.get('graph_sha256'))
    require(freeze==rebuilt and digest(freeze)==digest(rebuilt),
            'FREEZE_CHANGED_OR_SCHEMA_MISMATCH')
    return rebuilt


def build_features(freeze, action_uids=None):
    """Use immutable full-roster maxima even when selecting a small subset.

    Output vectors belong only to REQUESTED_COUNT_V1; they cannot be passed
    to a legacy checkpoint by implication. No D95 safety is established.
    """
    frozen=_checked_freeze(freeze)
    rows={row['action_uid']:row for row in frozen['requested_roster']}
    if action_uids is None:
        selected=sorted(rows)
    else:
        require(type(action_uids) is list and 1<=len(action_uids)<=len(rows),
                'ACTION_SELECTION')
        require(all(type(uid) is str and uid in rows for uid in action_uids) and
                len(set(action_uids))==len(action_uids),'UNKNOWN_OR_DUPLICATE_ACTION')
        selected=sorted(action_uids)
    max_h=frozen['requested_max_h']
    max_m=frozen['requested_max_m']
    common=frozen['common_fault_count']
    vectors=[]
    for uid in selected:
        row=rows[uid]
        h=row['h_request']
        m=row['m_request'] if row['scheme']=='HMF' else 0
        values=[1.0 if row['scheme']=='HF' else 0.0,
                1.0 if row['scheme']=='HMF' else 0.0,
                math.log1p(h),math.log1p(m),h/max_h,
                m/max_m if max_m else 0.0,math.log1p(common)]
        require(len(values)==7 and all(math.isfinite(value) for value in values),
                'NONFINITE_FEATURE')
        vectors.append(dict(action_uid=uid,values=values))
    return dict(schema='prospective-request-feature-bundle-v1',
                status='REQUESTED_COUNT_V1_ONLY_NOT_LEGACY',
                feature_schema_id=FEATURE_SCHEMA_ID,feature_columns=list(FEATURE_COLUMNS),
                freeze_sha256=frozen['freeze_sha256'],
                roster_sha256=frozen['roster_sha256'],
                selected_action_uids=selected,
                selected_action_uids_sha256=digest(selected),vectors=vectors,
                normalization_scope=frozen['normalization_scope'],
                legacy_model_compatible=False,
                future_unknown_actions_d95_preverified=False,
                checkpoint_authenticated=False,graph_bytes_authenticated=False,
                execution_ready=False,training_release=False,inference_release=False)


def assess_checkpoint_schema(feature_schema_id):
    """Metadata-only schema-ID comparison, never checkpoint authentication."""
    require(type(feature_schema_id) is str and feature_schema_id==FEATURE_SCHEMA_ID,
            'CHECKPOINT_FEATURE_SCHEMA_MISMATCH')
    return dict(feature_schema_id=FEATURE_SCHEMA_ID,
                status='SCHEMA_ID_MATCH_ONLY_NO_CHECKPOINT_AUTH',
                schema_id_compatible=True,checkpoint_authenticated=False,
                weights_authenticated=False,model_inference_performed=False,
                future_unknown_actions_d95_preverified=False,
                execution_ready=False,training_release=False,inference_release=False)
