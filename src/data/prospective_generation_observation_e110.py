"""Bounded generation-observation sealing, no execution or acceptance policy.

Publishers must be trusted exclusive/anchored/fsync implementations supplied by
the future controller. Callback return is not OS authentication or an independent
durability attestation. Partial publications remain on error; no retries/repair.
"""
import copy
import math
from . import prospective_generation_supervision_e109 as supervisor

SCHEMA='prospective-generation-observation-seal-e110-v1'
OBS_KEYS=frozenset(('schema','launch_spec_sha256','effective_envelope_sha256',
    'environment_sha256','environment_keys','launch_attempted','known_process_handle',
    'returncode','cleaned','failure','cleanup_error','output','observed_wrapper_interval_seconds',
    'interval_scope','clock_api','sampled_peak_rss_swap_bytes','readiness','streams_combined',
    'stderr_separately_validated','physical_process_identity_authenticated',
    'full_session_cost_qualified','actual_atpg_runtime_ns','execution_ready','training_release'))
require=supervisor.require
canonical=supervisor.canonical
sha=supervisor.sha


def _signed(value,field,code):
    require(type(value) is dict and type(value.get(field)) is str and
            sha(canonical({k:v for k,v in value.items() if k!=field}))==value[field],code)


def seal_observation(observed,envelope,launch,publish_receipt,publish_log,final_sample):
    """Seal H/M/F observations, including failed spawn/unknown cleanup.

    Operational failures are evidence, not report-acceptance failures to drop.
    Invalid caller schemas/bindings fail before publication. This function owns
    neither attempt debit nor namespace ownership; it never grants next launch.
    """
    observed=copy.deepcopy(observed);envelope=copy.deepcopy(envelope);launch=copy.deepcopy(launch)
    _signed(envelope,'envelope_sha256','ENVELOPE_CHANGED')
    _signed(launch,'launch_spec_sha256','LAUNCH_CHANGED')
    require(envelope.get('schema')==supervisor.recipe.SCHEMA and
            launch.get('schema')==supervisor.SCHEMA and set(launch)==supervisor.LAUNCH_KEYS and
            envelope.get('circuit') in ('aes_core','spi') and envelope.get('stage') in ('H','M','F') and
            supervisor.recipe.stage.safe_uid(envelope.get('task_uid')),'CONTEXT_SCHEMA')
    require(all(envelope.get(k) is False for k in ('execution_authorized','execution_ready','training_release')) and
            all(launch.get(k) is False for k in ('environment_profile_authenticated','execution_authorized','execution_ready')),
            'CONTEXT_NOT_AUTHORITY')
    supervisor._environment(launch['env'],launch['cwd'])
    require(launch['effective_envelope_sha256']==envelope['envelope_sha256'] and
            launch['environment_sha256']==sha(canonical(launch['env'])) and
            canonical(launch['argv'])==canonical(envelope['argv']) and
            all(launch['env'].get(k)==v for k,v in envelope['env'].items()),'CONTEXT_JOIN')
    require(type(observed) is dict and set(observed)==OBS_KEYS and
            observed['schema']=='generation-process-observation-e109-v1' and
            observed['launch_spec_sha256']==launch['launch_spec_sha256'] and
            observed['effective_envelope_sha256']==envelope['envelope_sha256'] and
            observed['environment_sha256']==launch['environment_sha256'] and
            observed['environment_keys']==sorted(launch['env']),'OBSERVATION_JOIN')
    require(all(type(observed[k]) is bool for k in ('launch_attempted','known_process_handle','cleaned')) and
            observed['streams_combined'] is True and observed['stderr_separately_validated'] is False and
            all(observed[k] is False for k in ('physical_process_identity_authenticated',
                'full_session_cost_qualified','execution_ready','training_release')) and
            observed['actual_atpg_runtime_ns'] is None,'OBSERVATION_FLAGS')
    attempted=observed['launch_attempted'];known=observed['known_process_handle'];rc=observed['returncode']
    require((rc is None or (type(rc) is int and -(2**31)<=rc<2**31)) and
            (not known or attempted) and (known or rc is None),'PROCESS_OBSERVATION_STATE')
    interval=observed['observed_wrapper_interval_seconds']
    require((interval is None or (type(interval) in (int,float) and math.isfinite(interval) and interval>=0)) and
            (attempted or interval is None) and observed['clock_api']=='time.monotonic_seconds' and
            observed['interval_scope']=='PRE_POPEN_THROUGH_CLEANUP_RETURN_EXCLUDES_PREPARATION_AND_RECEIPT_IO',
            'INTERVAL_SCHEMA')
    log=observed.pop('output')
    require(type(log) is bytes and len(log)<=16777216 and (attempted or not log),'OUTPUT_BYTES')
    require(type(observed['sampled_peak_rss_swap_bytes']) is int and
            0<=observed['sampled_peak_rss_swap_bytes']<2**63,'SAMPLED_PEAK')
    readiness=observed['readiness']
    require(readiness is None or (type(readiness) is dict and len(canonical(readiness))<=4096),'READINESS_BOUND')
    omissions={}
    original_failure=observed['failure']
    for name in ('failure','cleanup_error'):
        value=observed[name]
        require(value is None or type(value) is str,'FAILURE_TEXT_TYPE')
        if value is not None and len(value.encode('utf-8'))>512:
            raw=value.encode('utf-8')
            omissions[name]=dict(bytes=len(raw),sha256=sha(raw))
            observed[name]='OMITTED_OVERSIZED_TEXT'
    if not observed['cleaned']:disposition='UNRESOLVED'
    elif not attempted:disposition='NOT_ATTEMPTED'
    elif not known or rc is None or interval is None:disposition='UNRESOLVED'
    elif rc!=0 or original_failure is not None or observed['cleanup_error'] is not None:disposition='OBSERVED_FAILED'
    else:disposition='OBSERVED_RETURNED_NOT_ACCEPTED'
    token=sha(canonical(dict(task_uid=envelope['task_uid'],launch_spec_sha256=launch['launch_spec_sha256'])))
    observation_name='observation_'+token+'.json';log_name='process_'+token+'.log';ack_name='seal_'+token+'.json'
    receipt=dict(schema=SCHEMA,task_uid=envelope['task_uid'],circuit=envelope['circuit'],stage=envelope['stage'],
        envelope_sha256=envelope['envelope_sha256'],semantic_binding_sha256=envelope['semantic_binding_sha256'],
        request_sha256=envelope['request_sha256'],effective_tcl_sha256=envelope['effective_tcl_sha256'],
        observation=observed,omitted_text=omissions,disposition=disposition,
        log_name=log_name,log_bytes=len(log),log_sha256=sha(log),
        report_acceptance_evaluated=False,final_sample_evaluated=False,
        actual_atpg_runtime_ns=None,physical_provenance_authenticated=False,training_release=False)
    raw=canonical(receipt)+b'\n'
    require(len(raw)<=65536 and all(callable(fn) for fn in (publish_receipt,publish_log,final_sample)),
            'PUBLICATION_BOUND_OR_CALLBACK')
    # Keep the observation even if log publication or final sampling fails.
    publish_receipt(observation_name,raw)
    publish_log(log_name,log)
    final_sample()
    ack=dict(schema=SCHEMA,task_uid=envelope['task_uid'],disposition=disposition,
        observation_name=observation_name,observation_sha256=sha(raw),log_name=log_name,log_sha256=sha(log),
        publication_callbacks_returned=True,final_sample_callback_returned=True,
        callback_returns_are_fsync_or_os_proof=False,allows_next_launch=False,
        observation_requires_failure_stop=disposition!='OBSERVED_RETURNED_NOT_ACCEPTED',
        physical_provenance_authenticated=False,actual_atpg_runtime_ns=None,training_release=False)
    ack_raw=canonical(ack)+b'\n'
    require(len(ack_raw)<=65536,'ACK_BOUND')
    publish_receipt(ack_name,ack_raw)
    return dict(receipt=receipt,ack=ack,observation_name=observation_name,ack_name=ack_name)
