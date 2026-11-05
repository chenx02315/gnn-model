"""Native E138 fixed-readback binding; no transport, writes or authority origin.

FROZEN comes from the reviewed phase producer and pinned host channel. Source
tags/hash equality do not establish that trust. Private join/exporter modules
are compiled only from previously verified bytes. Sampling is not a kernel cap.
"""
import copy
import math
import os
import platform
import sys
import time
import types
from . import physical_e138_contract as contract
from . import physical_e138_runtime_primitives as runtime
from . import physical_e138_role2_join as join_origin
from . import physical_e138_role3_export as export_origin

FROZEN=None
_USED=False
require,sha,canonical=contract.require,contract.sha,contract.canonical
SELF='physical_e138_readback_runtime'
REQUIRED=frozenset((SELF,'physical_e138_contract','physical_e138_runtime_primitives',
    'physical_e138_role2_join','physical_e138_role3_export',
    'prospective_acceptance_materializer_v1','physical_replay_source_reader_e135'))
WRAPPER_CODES=frozenset(('E138_READBACK_CONNECTION_DEADLINE','E138_READBACK_AUTHENTICATOR_INPUT',
    'E138_READBACK_RESULT_BOUND'))


def _error_frame(code,partial=None):
    return dict(schema='e138-readback-partial-failure-v1',status='STOPPED_FIRST_FAILURE',
        error_code=code,partial_result=partial,durable_publication_verified=False,
        execution_ready=False,physical_d95_verified=False,training_release=False)


def _private(raw,name):
    module=types.ModuleType('src.data._e138_readback_'+name);module.__package__='src.data'
    exec(compile(raw,'<e138-readback-'+name+'>','exec'),module.__dict__)
    module.__source_sha256__=sha(raw)
    return module


def _admit(package,sources,connection_start):
    f=FROZEN
    require(not _USED and type(f) is dict and set(f)=={'source_sha256','source_order','join_freeze'} and
        type(f['source_sha256']) is dict and REQUIRED<=set(f['source_sha256']) and len(f['source_sha256'])<=96 and
        all(type(name) is str and contract._hex(pin) for name,pin in f['source_sha256'].items()) and
        type(f['source_order']) is tuple and all(type(name) is str for name in f['source_order']) and
        len(f['source_order'])==len(set(f['source_order']))==len(f['source_sha256']) and
        set(f['source_order'])==set(f['source_sha256']) and contract.LOADED_SOURCE_ORDER==f['source_order'] and
        type(f['join_freeze']) is dict,'E138_READBACK_EXTERNAL_FREEZE_REQUIRED')
    require(type(sources) is dict and set(sources)==set(f['source_sha256']) and
        all(type(raw) is bytes and 0<len(raw)<=262144 and sha(raw)==f['source_sha256'][name] for name,raw in sources.items()) and
        sum(map(len,sources.values()))<=4194304 and globals().get('__source_sha256__')==f['source_sha256'][SELF],
        'E138_READBACK_SOURCE_BYTES')
    require(all(type(sys.modules.get('src.data.'+name)) is types.ModuleType and
        vars(sys.modules['src.data.'+name]).get('__source_sha256__')==pin for name,pin in f['source_sha256'].items()),
        'E138_READBACK_SOURCE_TAGS')
    require(type(connection_start) in (int,float) and math.isfinite(connection_start) and connection_start>=0,
        'E138_READBACK_CONNECTION_START')
    return copy.deepcopy(f)


def collect(package,sources,connection_start):
    """Return success or bounded partial-error data, for one outer raw frame.

    Admission/join failures raise before IO. Only genuine private exporter
    failures can supply a partial prefix; wrapper timing failure may retain an
    already completed, validated result. Caller must persist the returned bytes.
    """
    global _USED
    f=_admit(package,sources,connection_start);_USED=True
    joiner=_private(sources['physical_e138_role2_join'],'join')
    exporter=_private(sources['physical_e138_role3_export'],'export')
    joiner.FREEZE=f['join_freeze']
    context=joiner.join(package)  # Pure full raw/receipt join before host/clock/FS.
    require(platform.node()=='bupt-vncs2' and platform.system()=='Linux' and os.getuid()==1047,
        'E138_READBACK_FIXED_A_LINUX')
    rawpins=f['join_freeze']['raw_sha256']
    clock=runtime.package_clock(package['original_clock'],rawpins['authority'],rawpins['proposal'],rawpins['original_clock'])
    end=min(connection_start+60,clock['monotonic_end'])
    last=[connection_start]
    def monotonic():
        now=time.monotonic()
        require(type(now) in (int,float) and math.isfinite(now) and last[0]<=now<end,
            'E138_READBACK_CONNECTION_DEADLINE')
        last[0]=now
        return now
    monotonic()  # Source loading and pure join consume the original role3 budget.
    domain=runtime.legacy.direct.Descendants()
    def authenticate(raw):
        require(type(raw) is dict and set(raw)==set(package) and
            all(type(value) is bytes and value==package[name] for name,value in raw.items()),
            'E138_READBACK_AUTHENTICATOR_INPUT')
        value=joiner.join(raw)
        require(value==context,'E138_READBACK_AUTHENTICATOR_INPUT')
        return value
    def boot():return runtime.legacy.process._boot_id()
    def utc():return time.time()
    def sample():
        children=domain.sample()
        return dict(rss_swap_bytes=domain.peak,children=len(children))
    callbacks=dict(authenticate=authenticate,boot=boot,monotonic=monotonic,utc=utc,sample=sample)
    for fn in callbacks.values():fn.__source_sha256__=f['source_sha256'][SELF]
    exporter.AUTH_SHA256=rawpins['authority'];exporter.PROPOSAL_SHA=rawpins['proposal']
    for attr,key in (('ORIGINAL_CLOCK_SHA256','original_clock'),('ROLE2_STDOUT_SHA256','role2_stdout'),
            ('ROLE2_STDERR_SHA256','role2_stderr'),('ROLE2_TRANSPORT_SHA256','role2_transport'),
            ('ROLE2_INTENT_SHA256','role2_intent'),('ROLE3_INTENT_SHA256','role3_intent')):
        setattr(exporter,attr,rawpins[key])
    exporter.ROLE2_PAYLOAD_SHA256=f['join_freeze']['role2_payload_sha256']
    exporter.ROLE3_PAYLOAD_SHA256=f['join_freeze']['role3_payload_sha256']
    exporter.SOURCE_PINS={key:f['source_sha256'][name] for key,name in dict(self='physical_e138_role3_export',
        contract='physical_e138_contract',runtime='physical_e138_runtime_primitives',
        anchored='prospective_acceptance_materializer_v1',reader='physical_replay_source_reader_e135').items()}
    exporter.CAPABILITY_PINS={key:f['source_sha256'][SELF] for key in callbacks}
    for attr,key in (('ROLE2_AUTHENTICATOR','authenticate'),('BOOT_READER','boot'),('MONOTONIC_READER','monotonic'),
            ('UTC_READER','utc'),('RESOURCE_GUARD','sample')):setattr(exporter,attr,callbacks[key])
    value=None;partial=None;code=None
    try:
        value=exporter.collect(package)
        exporter.validate_result(value,complete=True)
        monotonic()
        require(len(canonical(value))<=exporter.MAX_RESPONSE,'E138_READBACK_RESULT_BOUND')
        monotonic()  # Serialization does not open another 60-second window.
    except BaseException as exc:
        try:
            if type(exc) is exporter.ExportFailure:
                code=exc.code if type(exc.code) is str and exc.code in exporter.PUBLIC_CODES else 'E138_READBACK_REDACTED_FAILURE'
                if exc.partial_result is not None:
                    partial=exporter.validate_result(exc.partial_result,complete=False)
            else:
                args=exc.args if type(exc) is ValueError else ()
                code=args[0] if type(args) is tuple and len(args)==1 and type(args[0]) is str and args[0] in WRAPPER_CODES else 'E138_READBACK_REDACTED_FAILURE'
                if value is not None:partial=exporter.validate_result(value,complete=False)
        except BaseException:
            code='E138_READBACK_REDACTED_FAILURE';partial=None
    if code is None:return value
    frame=_error_frame(code,partial);fallback=None
    try:
        monotonic()
        require(len(canonical(frame))<=exporter.MAX_RESPONSE,'E138_READBACK_RESULT_BOUND')
        monotonic()
    except BaseException as exc:
        args=exc.args if type(exc) is ValueError else ()
        deadline=(type(args) is tuple and len(args)==1 and type(args[0]) is str and
            args[0]=='E138_READBACK_CONNECTION_DEADLINE')
        fallback='E138_READBACK_CONNECTION_DEADLINE' if deadline else 'E138_READBACK_ERROR_FRAME_FAILED'
    # Never retry failed serialization. If deadline/bound/encoding fails, drop
    # all body data and return only a fixed tiny object for the outer wrapper;
    # no further IO or clock window is granted by this fallback.
    if fallback is not None:return _error_frame(fallback)
    return frame
