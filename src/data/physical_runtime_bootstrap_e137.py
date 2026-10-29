"""One private E127-compatible environment bootstrap; no execution release.

The fixed shell child inherits the supervisor's environment as in E127; this
does not authenticate shell startup files. Only the pinned six-key profile is
read by its Python child, and only normalized allowlisted values are returned
in a deliberately nonserializable RAM object. Never persist environment().
"""
import base64
import copy
import json
import math
import os
import platform
import shlex
import time
from types import SimpleNamespace,CodeType,FunctionType
from . import direct_tessent_acceptance_e104 as direct
from . import prospective_generation_process_e113 as process
from . import prospective_runtime_profile_e112 as profile
from . import prospective_runtime_adapter_e114 as adapter
from . import prospective_tessent_acceptance_v1 as pins
from .physical_replay_source_reader_e135 import require,sha,canonical,decode

AUTH_SHA256 = CONTEXT_SHA256 = EXPECTED_BOOT_ID = None
ACTUAL_AUTH_SHA256 = '49f000fe45de6cfc029ad8a9c1ead5e09edd24321de6062039d638436cce4969'
WORKER_SHA256 = '360dd42f9c0a950858dad085d9c0a3ebda551991cd9ab525ea71fa97216abe10'
E112_SHA256 = 'fd09999da5355c8b66fb0bbae0e6f495544bbf578df8894b01ac5fc8685864ae'
PROFILE_SHA256 = 'b7f096782faefe9abcd9e3e748176ffcf3c2944c72cb1d39b32b0d196d1a2e3a'
LAUNCHER_SHA256 = 'd92e81eaacf0727fd18d4cafa67d7c9a066069c6d8f7fc05caaf1252c3e44905'
SOURCE_PINS = {
    'direct_tessent_acceptance_e104':'6b7961e8238b2676a9c90a69a1c554be7238daa789de2e41a1e820044e17b190',
    'direct_tessent_acceptance_e100':'92f9915bc431483ba73cc38829356ca315a16ae39713b021b2025d0ce744fb58',
    'prospective_generation_process_e113':'6b1922de253550b3d4091f11186d9447867662c445e46fdc47801f3c340411f6',
    'prospective_runtime_profile_e112':PROFILE_SHA256,
    'prospective_runtime_adapter_e114':'57ad390828e2ce33e2bebd0830c787473e98a7ba1c31843e12b03759ef6a77f1',
    'prospective_tessent_acceptance_v1':'6d4b45d303a4be34f03914b8f9cb4aad2d9fe73c41c666a6c12058c43ef5aac2'}
_USED = False


class PrivateRuntime(object):
    __slots__ = ('_values','_receipt')
    def __init__(self,values,receipt):
        self._values,self._receipt=copy.deepcopy(values),copy.deepcopy(receipt)
    def __repr__(self):
        return '<E137Runtime PRIVATE_RAM_ONLY; redacted_receipt() is exportable>'
    def environment(self):
        """Intentional RAM-only getter, never log, stringify or persist values."""
        return copy.deepcopy(self._values)
    def redacted_receipt(self):
        return copy.deepcopy(self._receipt)


def bootstrap(package,domain,tick,evidence=None):
    global _USED
    require(AUTH_SHA256 == ACTUAL_AUTH_SHA256 and type(CONTEXT_SHA256) is str and type(EXPECTED_BOOT_ID) is str,
        'E137_BOOTSTRAP_AUTH_CONTEXT_BOOT_NOT_FROZEN')
    require(type(package) is dict and set(package) == {'authority','context','e112','worker_source','profile_source'} and
        all(type(raw) is bytes for raw in package.values()),'E137_BOOTSTRAP_EXACT_PACKAGE')
    require(len(package['authority']) <= 65536 and sha(package['authority']) == AUTH_SHA256 and
        len(package['context']) <= 4096 and sha(package['context']) == CONTEXT_SHA256 and
        len(package['e112']) <= 262144 and sha(package['e112']) == E112_SHA256 and
        len(package['worker_source']) <= 131072 and sha(package['worker_source']) == WORKER_SHA256 and
        len(package['profile_source']) <= 65536 and sha(package['profile_source']) == PROFILE_SHA256,'E137_BOOTSTRAP_FROZEN_BYTES')
    auth,context=decode(package['authority']),decode(package['context'])
    require(auth.get('user_reply') == '\u90a3\u5c31\u6279\u51c6' and auth.get('approved_package') == 'E137' and
        auth.get('user_authorization_received') is True,'E137_BOOTSTRAP_ACTUAL_REPLY')
    require(set(context) == {'role','authorization_sha256','boot_id','package_start','package_end','connection_start','utc_end'} and
        context['role'] == 'execution' and context['authorization_sha256'] == AUTH_SHA256 and context['boot_id'] == EXPECTED_BOOT_ID and
        all(type(context[k]) in (int,float) and math.isfinite(context[k]) and context[k] >= 0 for k in
            ('package_start','package_end','connection_start','utc_end')) and
        context['package_end'] == context['package_start']+3600,'E137_BOOTSTRAP_ORIGINAL_CLOCK')
    for module in (direct,direct.base,process,profile,adapter,pins):
        require(getattr(module,'__source_sha256__',None) == SOURCE_PINS[module.__name__.rsplit('.',1)[1]],'E137_BOOTSTRAP_SOURCE_LOADER')
    require(callable(tick) and type(domain) is direct.Descendants and (evidence is None or type(evidence) is dict),
        'E137_BOOTSTRAP_OBSERVER_ARGUMENTS')
    require(not _USED,'E137_ONE_BOOTSTRAP_NO_RETRY')
    _USED=True
    metadata={}
    try:
        require(platform.node() == 'bupt-vncs2' and os.getuid() == 1047 and os.sys.platform.startswith('linux'),'E137_BOOTSTRAP_HOST')
        require(process._boot_id() == EXPECTED_BOOT_ID,'E137_BOOTSTRAP_CURRENT_BOOT')
        process._check_worker(domain)
        started=time.monotonic()
        outer_end=min(context['package_end'],context['connection_start']+2400)
        end=min(outer_end,started+30,started+max(0,context['utc_end']-time.time()))
        def guard():
            now=time.monotonic()
            require(context['package_start'] <= context['connection_start'] <= started <= now < end and
                time.time() < context['utc_end'],'E137_BOOTSTRAP_DEADLINE')
            tick();domain.sample()
            require(domain.peak <= 536870912,'E137_BOOTSTRAP_SAMPLED_MEMORY')
        guard()
        text=package['worker_source'].decode('utf-8')
        compiled=compile(text,'<pinned-E127-worker-not-executed>','exec')
        functions=[value for value in compiled.co_consts if isinstance(value,CodeType) and value.co_name == 'capture_runtime']
        require(len(functions) == 1,'E137_BOOTSTRAP_EXACT_ORIGINAL_FUNCTION')
        calls=[0]
        def supervise(argv,cwd,deadline,passed_domain,budget):
            require(calls[0] == 0 and passed_domain is domain and cwd == '/' and budget == [65536] and
                type(argv) is list and len(argv) == 3 and argv[:2] == ['/bin/bash','-lc'] and
                argv[2].startswith('module load mentor/tessent2021 >/dev/null && /usr/bin/python3 -I -S -B -c '),
                'E137_BOOTSTRAP_FIXED_COMMAND')
            calls[0]+=1;guard()
            metadata['command_sha256']=sha(canonical(argv))
            observed=direct.base.supervise(argv,cwd,min(deadline,end),domain,budget,scratch=SimpleNamespace(sample=guard))
            raw=observed.get('output')
            require(type(raw) is bytes and len(raw) <= 65536,'E137_BOOTSTRAP_OUTPUT_BOUND')
            metadata.update(bytes=len(raw),sha256=sha(raw),cleaned=observed.get('cleaned') is True,
                returncode=observed.get('returncode') if type(observed.get('returncode')) is int else None)
            require(observed.get('launch_attempted') is True and observed.get('cleaned') is True and
                type(observed.get('returncode')) is int and observed['returncode'] == 0 and observed.get('failure') is None,
                'E137_BOOTSTRAP_OBSERVATION_REJECTED')
            return observed
        namespace=dict(base64=base64,json=json,shlex=shlex,time=time,require=require,sha=sha,profile=profile,adapter=adapter,
            NONCE='E127_PRIVATE_RUNTIME_V1',direct=SimpleNamespace(base=SimpleNamespace(supervise=supervise)),
            controller=SimpleNamespace(PACKAGE_END=end,material=SimpleNamespace(pins=pins)))
        namespace['capture_runtime']=FunctionType(functions[0],namespace,'capture_runtime')
        original_package=dict(runtime_profile_source=base64.b64encode(package['profile_source']).decode('ascii'),
            runtime_profile_source_sha256=PROFILE_SHA256,source_sha256={'prospective_runtime_profile_e112':PROFILE_SHA256},
            inputs={'e112':base64.b64encode(package['e112']).decode('ascii')})
        values,_=namespace['capture_runtime'](original_package,domain,metadata)
        normalized,compatibility=adapter.prepare_runtime(values,decode(package['e112'])['runtime_profile'],LAUNCHER_SHA256)
        require(set(normalized) <= set(profile.KEYS) and not set(normalized)&{'DEBUG','MGC_DFT_EXTRA_ARG','TESSENT_PATH'},
            'E137_BOOTSTRAP_NO_TOOL_INJECTION_KEYS')
        guard()
        receipt=dict(schema='e137-private-runtime-bootstrap-v1',status='COMPATIBLE_PROFILE_ONLY',output_bytes=metadata['bytes'],
            output_sha256=metadata['sha256'],cleaned=metadata['cleaned'],returncode=metadata['returncode'],
            command_sha256=metadata['command_sha256'],
            bootstrap_children=calls[0],values_disclosed=False,compatibility=compatibility,
            environment_authenticated=False,full_executable_tree_authenticated=False,parent_shell_environment_sanitized=False,
            sampled_peak_rss_swap_bytes=domain.peak,bootstrap_counts_as_selftest=False,tessent_launches=0,execution_ready=False)
        if evidence is not None:evidence.update(receipt)
        return PrivateRuntime(normalized,receipt)
    except BaseException:
        if evidence is not None:
            evidence.update(dict(schema='e137-private-runtime-bootstrap-v1',status='FAILED',values_disclosed=False,
                output_bytes=metadata.get('bytes',0),output_sha256=metadata.get('sha256',sha(b'')),
                output_metadata_measured='bytes' in metadata,
                error_code='E137_BOOTSTRAP_FAILED_NO_RETRY',execution_ready=False))
        # Do not attach a supervisor/JSON exception (which could contain private
        # stdout) as __context__. Drop RAM mappings before the new traceback.
        values=normalized=namespace=original_package=None
    raise ValueError('E137_BOOTSTRAP_FAILED_NO_RETRY') from None
