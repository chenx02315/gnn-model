"""Explicit-environment preparation and private process observation primitive.

No CLI or execution controller. _observe is NOT an admission/consent boundary:
an authorized future controller must first bind resources, own the namespace,
persist the debit/launch intent and authenticate deployed inputs. This module
does not turn E105's synthetic backend into a production backend.
"""
import copy
import math
import os
import posixpath
import selectors
import subprocess
import time
from . import prospective_generation_recipe_e108 as recipe

SCHEMA='prospective-generation-launch-spec-e109-v1'
RUNTIME_KEYS=frozenset(('PATH','LD_LIBRARY_PATH','MGC_HOME','MGC_ROOT',
                        'LM_LICENSE_FILE','MGLS_LICENSE_FILE'))
STAGE_ENV_KEYS=frozenset(('CIRCUIT_ROOT','CIRCUIT','TOP_MODULE','CELL_LIBRARY',
    'COMMON_FAULT_DIR','MODE','RUN_ID','TSDB_INPUT_DIR','PHASE','PATTERN_LIMIT',
    'TEST_COVERAGE_LIMIT','STATUS_FILE','STATUS_TRANSLATION_MANIFEST'))
LAUNCH_KEYS=frozenset(('schema','argv','env','cwd','effective_envelope_sha256',
    'environment_sha256','environment_profile_authenticated','execution_authorized',
    'execution_ready','launch_spec_sha256'))
require=recipe.require
canonical=recipe.canonical
sha=recipe.sha


def _absolute(value):
    return (type(value) is str and 0<len(value)<=4096 and value.startswith('/') and
            posixpath.normpath(value)==value and not any(c.isspace() or c=='\x00' for c in value))


def _runtime_values(runtime):
    require(type(runtime) is dict and 'PATH' in runtime and set(runtime)<=RUNTIME_KEYS,'RUNTIME_ENV_KEYS')
    for key,value in runtime.items():
        require(type(value) is str and 0<len(value)<=4096 and
                all(ord(c)>=32 and not c.isspace() for c in value) and '\x7f' not in value,'RUNTIME_ENV_VALUE')
        if key in ('PATH','LD_LIBRARY_PATH'):
            require(all(_absolute(part) for part in value.split(':')),'ABSOLUTE_SEARCH_PATHS_ONLY')
        elif key in ('MGC_HOME','MGC_ROOT'):require(_absolute(value),'ABSOLUTE_MGC_PATH')


def _environment(env,cwd):
    require(type(env) is dict and set(env)<=RUNTIME_KEYS|STAGE_ENV_KEYS|{'HOME','TMPDIR','LANG','LC_ALL'} and
            all(type(k) is str and type(v) is str and 0<len(v)<=4096 and
                not any(c in v for c in '\x00\r\n') for k,v in env.items()),'EXPLICIT_ENV_REQUIRED')
    require(env.get('HOME')==cwd and env.get('TMPDIR')==cwd and
            env.get('LANG')=='C' and env.get('LC_ALL')=='C','FIXED_HOME_TMP_LOCALE')
    _runtime_values({k:v for k,v in env.items() if k in RUNTIME_KEYS})
    require(sum(len(k.encode('utf-8'))+len(v.encode('utf-8'))+2 for k,v in env.items())<=32768,'ENV_TOTAL_BOUND')


def prepare_launch(freeze,binding,sources,runtime_environment,cwd):
    """Runtime values are caller-supplied, not read from os.environ or vetted."""
    runtime=copy.deepcopy(runtime_environment)
    effective=recipe.compile_execution(freeze,binding,sources)
    _runtime_values(runtime)
    require(_absolute(cwd) and cwd.startswith(recipe.ROOT+'/') and
            not (cwd==effective['result_dir'] or cwd.startswith(effective['result_dir']+'/')),
            'OWNED_WORKING_DIRECTORY_CLAIM')
    env=dict(runtime,HOME=cwd,TMPDIR=cwd,LANG='C',LC_ALL='C')
    env.update(effective['env'])
    _environment(env,cwd)
    body=dict(schema=SCHEMA,argv=effective['argv'],env=env,cwd=cwd,
        effective_envelope_sha256=effective['envelope_sha256'],environment_sha256=sha(canonical(env)),
        environment_profile_authenticated=False,execution_authorized=False,execution_ready=False)
    return dict(body,launch_spec_sha256=sha(canonical(body)))


def _observe(launch,end,domain,output_budget,scratch=None,ready_check=None):
    """Private Linux-style observer; caller owns all admission and journaling.

    Follows E100's select/read/sample/known-handle cleanup protocol with an
    explicit Popen env. Exceptions are returned after cleanup so the future
    controller can persist the observation BEFORE rejecting an uncertain run.
    Timing covers the wrapper call through cleanup, not an exact Tessent PID or
    create_patterns kernel interval. Monotonic seconds are not native ns ticks.
    """
    launch=copy.deepcopy(launch)
    require(type(launch) is dict and set(launch)==LAUNCH_KEYS and launch.get('schema')==SCHEMA and
            all(launch[k] is False for k in ('environment_profile_authenticated','execution_authorized','execution_ready')) and
            sha(canonical({k:v for k,v in launch.items() if k!='launch_spec_sha256'}))==launch.get('launch_spec_sha256') and
            launch.get('environment_sha256')==sha(canonical(launch.get('env'))),'LAUNCH_SPEC_CHANGED')
    _environment(launch['env'],launch['cwd'])
    argv=launch['argv']
    require(type(argv) is list and len(argv)==8 and
            argv[:5]==[recipe.identities.LAUNCHER,'-shell','-license_wait','5','-log'] and
            _absolute(argv[5]) and argv[5].startswith(recipe.ROOT+'/') and argv[6]=='-dofile' and
            argv[7] in (recipe.ROOT+'/code/common.tcl',recipe.ROOT+'/code/incremental.tcl') and
            _absolute(launch['cwd']) and launch['cwd'].startswith(recipe.ROOT+'/'),'FIXED_LAUNCH_ARGV_CWD')
    require(type(end) in (int,float) and math.isfinite(end) and type(output_budget) is list and
            len(output_budget)==1 and type(output_budget[0]) is int and 0<=output_budget[0]<=16777216,
            'OBSERVATION_BOUNDS')
    proc=None;output=bytearray();failure=None;cleanup_error=None;cleaned=False
    attempted=False;readiness=None;started=None;ended=None
    try:
        require(time.monotonic()<end-10,'PRELAUNCH_TIMEOUT')
        require(output_budget[0]>0,'OUTPUT_STOP')
        domain.sample()
        if scratch is not None:scratch.sample()
        require(time.monotonic()<end-10,'PRELAUNCH_TIMEOUT')
        started=time.monotonic();attempted=True
        proc=subprocess.Popen(launch['argv'],cwd=launch['cwd'],env=launch['env'],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
            close_fds=True,start_new_session=True)
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout,selectors.EVENT_READ);next_scratch=0
            while selector.get_map() or proc.poll() is None:
                require(time.monotonic()<end-10,'CASE_TIMEOUT')
                domain.sample()
                if scratch is not None and time.monotonic()>=next_scratch:
                    scratch.sample();next_scratch=time.monotonic()+1
                for key,_ in selector.select(.05):
                    require(output_budget[0]>0,'OUTPUT_STOP')
                    raw=os.read(key.fileobj.fileno(),min(65536,output_budget[0]))
                    if raw:
                        output_budget[0]-=len(raw);output.extend(raw)
                        if ready_check is not None and readiness is None:
                            readiness=ready_check(bytes(output),domain)
                    else:selector.unregister(key.fileobj)
            proc.wait(timeout=max(.001,end-10-time.monotonic()))
    except BaseException as exc:
        failure=str(exc) if isinstance(exc,ValueError) else type(exc).__name__
    finally:
        if proc is not None:
            try:cleaned=domain.cleanup(proc,end) is True
            except BaseException as exc:cleanup_error=type(exc).__name__
            if proc.stdout is not None:
                try:proc.stdout.close()
                except BaseException as exc:
                    cleanup_error=type(exc).__name__;cleaned=False
        else:
            try:
                remaining,more=domain._direct_batch();cleaned=not remaining and not more
            except BaseException as exc:cleanup_error=type(exc).__name__
        try:ended=time.monotonic()
        except BaseException as exc:
            failure=failure or type(exc).__name__
    if not cleaned:failure=failure or 'CLEANUP_UNCONFIRMED'
    interval=(ended-started if type(ended) in (int,float) and type(started) in (int,float) and
              math.isfinite(ended) and math.isfinite(started) and ended>=started else None)
    if attempted and interval is None:failure=failure or 'CLOCK_INTERVAL_UNAVAILABLE'
    return dict(schema='generation-process-observation-e109-v1',
        launch_spec_sha256=launch['launch_spec_sha256'],effective_envelope_sha256=launch['effective_envelope_sha256'],
        environment_sha256=launch['environment_sha256'],environment_keys=sorted(launch['env']),
        launch_attempted=attempted,known_process_handle=proc is not None,
        returncode=(None if proc is None else proc.returncode),cleaned=cleaned,
        failure=failure,cleanup_error=cleanup_error,output=bytes(output),
        observed_wrapper_interval_seconds=interval,
        interval_scope='PRE_POPEN_THROUGH_CLEANUP_RETURN_EXCLUDES_PREPARATION_AND_RECEIPT_IO',
        clock_api='time.monotonic_seconds',sampled_peak_rss_swap_bytes=domain.peak,
        readiness=readiness,streams_combined=True,stderr_separately_validated=False,
        physical_process_identity_authenticated=False,full_session_cost_qualified=False,
        actual_atpg_runtime_ns=None,execution_ready=False,training_release=False)
