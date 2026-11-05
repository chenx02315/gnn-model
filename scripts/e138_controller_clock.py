"""Pure local/remote original-clock join for the future E138 controller.

Raw capture/start origin and supplied current clock/domain must be established
by the reviewed local phase creator, not supplied by a remote response.
No IO, wall-clock sampling, source pin learning or execution release here.
"""
import datetime
import math
import types
from src.data import physical_e138_contract as contract
from src.data import physical_replay_capture_e138 as capture
from src.data import physical_e138_runtime_primitives as runtime

require,decode,canonical,sha=contract.require,contract.decode,contract.canonical,contract.sha


def _number(value):return type(value) in (int,float) and math.isfinite(value) and value>=0


def build(role1_raw,start_raw,payload_sha,authority,proposal,auth_pin,proposal_pin,now,utc_now,domain):
    contract.check_authority(authority,proposal,auth_pin,proposal_pin)
    require(contract._hex(payload_sha) and type(role1_raw) is bytes and len(role1_raw)<=6291456 and
        type(start_raw) is bytes and len(start_raw)<=4096 and _number(now) and _number(utc_now),
        'E138_CONTROLLER_CLOCK_INPUTS')
    first,value=decode(start_raw),decode(role1_raw)
    require(type(first) is dict and set(first)=={'schema','authorization_sha256','proposal_sha256',
        'start','end','utc_start','utc_end','domain'} and first['schema']=='e138-local-original-clock-v1' and
        first['authorization_sha256']==auth_pin and first['proposal_sha256']==proposal_pin and
        _number(first['start']) and _number(first['end']) and first['end']==first['start']+3600 and
        first['start']<=now<first['end'] and first['domain']==domain and
        type(domain) is dict and set(domain)=={'host','clock'} and
        all(type(v) is str and 0<len(v)<=512 for v in domain.values()),'E138_CONTROLLER_LOCAL_CLOCK')
    require(type(value) is dict and set(value)=={'role','capture','boot_id','remote_start_monotonic',
        'remote_sample_monotonic','remote_utc_sample','execution_ready'} and value['role']=='capture' and
        value['execution_ready'] is False,'E138_CONTROLLER_CAPTURE_FRAME')
    # Clone only this pure validator's namespace; do not reconfigure imported
    # historical/current module globals as a side effect of a clock join.
    namespace=dict(vars(capture),AUTH_SHA=auth_pin,PROPOSAL_SHA=proposal_pin)
    validate=types.FunctionType(capture.validate_receipt.__code__,namespace)
    validate(canonical(value['capture']))
    clock=dict(schema=runtime.CLOCK_SCHEMA,authorization_sha256=auth_pin,proposal_sha256=proposal_pin,
        root=contract.ROOT,phase=contract.PHASE,reader_payload_sha256=payload_sha,
        initial_response_sha256=sha(canonical(value['capture'])),start_file_sha256=sha(start_raw),
        boot_id=value['boot_id'],remote_start_monotonic=value['remote_start_monotonic'],
        remote_deadline_monotonic=value['remote_start_monotonic']+3600 if _number(value['remote_start_monotonic']) else None,
        remote_utc_sample=value['remote_utc_sample'],remote_clock_sample_monotonic=value['remote_sample_monotonic'],
        local_utc_start=first['utc_start'],local_utc_deadline=first['utc_end'],local_monotonic_start=first['start'],
        local_monotonic_deadline=first['end'],local_clock_domain=domain)
    raw=canonical(clock);checked=runtime.package_clock(raw,auth_pin,proposal_pin,sha(raw))
    began=datetime.datetime.strptime(first['utc_start'],'%Y-%m-%dT%H:%M:%S.%f%z').timestamp()
    remote=datetime.datetime.strptime(value['remote_utc_sample'],'%Y-%m-%dT%H:%M:%S.%f%z').timestamp()
    remote_began=remote-(value['remote_sample_monotonic']-value['remote_start_monotonic'])
    require(abs((utc_now-began)-(now-first['start']))<=5 and began-5<=remote_began<=remote<=utc_now+5 and
        min(first['end']-now,checked['utc_end']-utc_now)>10,'E138_CONTROLLER_CLOCK_SKEW_OR_EXPIRED')
    return raw
