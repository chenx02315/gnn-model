"""Actual E138 local preparation and independently reviewed staged entrypoint.

prepare_capture() is inert: no phase, clocks, host queries, SSH or child process.
start()/ReviewedRun.execute() CAN use the approved A transport, but only with an
exact independently installed REVIEW_PINS record. No CLI or automatic run exists.
Review records are internal packet-review gates, not another user grant request.
Private packet/vendor bytes stay in RAM; public_review_request() contains hashes.
"""
import copy
import base64
from contextlib import contextmanager
from pathlib import Path
import threading
import types

from scripts import e138_controller as controller
from scripts import e138_deployment_materials as materials
from scripts import e138_packet as packet
from scripts import e138_pinned_transport as transport
from scripts import e138_reviewed_envelope as envelope
from src.data import physical_e138_batch_assembler as assembler
from src.data import physical_e138_contract as contract
from src.data import physical_e138_role2_join as joiner

AUTH_SHA256='bcaa8da7adc2e61daa35ccd50ce42dfd4131de180c7f3ca3adbbc86e8403dd74'
PROPOSAL_SHA256='6e4d52d540aa3c776f7d443a1a14f0764ab90fa11657585d8d6c1b6c8acd0b4b'
# Installed by the trusted parent only AFTER independent exact packet review.
# Map role -> SHA256 of the complete canonical independent review record bytes.
# Never populate this from a candidate request, response, or alleged PASS flag.
REVIEW_PINS=None
_CONFIG_LOCK=threading.Lock()
canonical,sha=contract.canonical,contract.sha
require=contract.require


def _repo():return Path(__file__).resolve().parents[1]
def _staging():return _repo().parent/'runtime_training_staging_20260928'


def _grant():
    repo=_repo()
    authority=materials._read(repo/'contracts/physical_f_clean_replay_authorization_e138.json',65536,AUTH_SHA256)
    proposal=materials._read(repo/'contracts/physical_f_clean_replay_proposal_e138_v1.json',65536,PROPOSAL_SHA256)
    contract.check_authority(authority,proposal,AUTH_SHA256,PROPOSAL_SHA256)
    return authority,proposal


def _entry_sources():
    # Controller closure covers its transport/helper/static native validators;
    # preparation and this entrypoint are separately committed by exact request.
    names=('scripts/run_physical_f_clean_replay_e138.py','scripts/e138_deployment_materials.py',
           'scripts/worker_e138_batch.py','scripts/e138_source_session.py')
    return {name:sha(materials._read(_repo()/name,262144)) for name in names}


def _release():
    closure=controller.local_source_closure()
    return dict(authorization_sha256=AUTH_SHA256,proposal_sha256=PROPOSAL_SHA256,
        adapter_source_sha256=closure['scripts.e138_pinned_transport'],host=transport.HOST,
        host_key=transport.HOST_KEY,helper_sha256=transport.HELPER_SHA256,scope=transport.PinnedTransport.scope,
        local_source_sha256=closure,roles={role:None for role in controller.ROLES})


class Prepared:
    __slots__=('_role','_material','_plan','_descriptor','_release','_review','_request',
               '_authority','_proposal','_local','_owner','_entry_sources')
    def __repr__(self):return '<E138 EXACT PACKET PRIVATE_RAM_ONLY; independent review still required>'
    def __reduce_ex__(self,protocol):raise TypeError('E138_PRIVATE_PACKET_NOT_SERIALIZABLE')
    def public_review_request(self):return copy.deepcopy(self._request)
    def private_review_material(self):
        """Trusted reviewer RAM access; MUST NOT print/persist vendor payloads."""
        return copy.deepcopy(dict(material=self._material,plan=self._plan,controller_review=self._review,
                                  controller_release=self._release,packet_descriptor=self._descriptor))


def _prepare(role,inputs,local,authority,proposal,release,owner=None,previous_sha=None,readback_join=None):
    bundle=local['roles'][role]
    worker=materials._read(_repo()/'scripts/worker_e138_batch.py',65536)
    loader=materials._read(_repo()/'scripts/e138_source_session.py',65536)
    env=materials._read(_repo()/'scripts/e138_reviewed_envelope.py',65536)
    template=dict(role=role,loader_sha256=sha(loader),source_sha256=dict(bundle['source_sha256']),
        source_order=bundle['source_order'],input_sha256={key:sha(raw) for key,raw in inputs.items()},
        authorization_sha256=AUTH_SHA256,proposal_sha256=PROPOSAL_SHA256)
    if role=='capture':template['assembly']=None
    elif role=='execution':
        template['assembly']={key:copy.deepcopy(template[key]) for key in envelope.ASSEMBLY_KEYS-{'policy_sha256'}}
        template['assembly']['policy_sha256']=sha(inputs['policy'])
    else:
        template['readback']=dict(source_sha256=dict(bundle['source_sha256']),source_order=bundle['source_order'],
            join_freeze=dict(readback_join,raw_sha256=dict(template['input_sha256'])))
    pins=dict(compiler_sha256=sha(materials._read(Path(packet.__file__),65536)),
        worker_sha256=sha(worker),loader_sha256=sha(loader),envelope_sha256=sha(env),
        template_sha256=sha(canonical(template)),source_sha256=dict(bundle['source_sha256']),
        source_order=bundle['source_order'],input_sha256=dict(template['input_sha256']))
    material=dict(template=template,inputs=inputs,sources=bundle['sources'],
                  worker_raw=worker,loader_raw=loader,envelope_raw=env)
    plan=controller._private_function(packet.prepare,EXPECTED=pins)(**material)
    if role=='readback':
        frozen,package=envelope.derive(template,inputs,envelope.intent(role,sha(plan['payload'])),sha(plan['payload']))
        controller._private_function(joiner.join,FREEZE=frozen['readback']['join_freeze'])(package)
    review=canonical(dict(projection=plan['projection'],projection_sha256=plan['projection_sha256'],
        payload_sha256=sha(plan['payload']),remote_command=plan['remote_command'],host=release['host'],
        scope=release['scope'],host_key=release['host_key'],helper_sha256=release['helper_sha256'],
        adapter_source_sha256=release['adapter_source_sha256'],local_source_sha256=release['local_source_sha256']))
    prepared=Prepared()
    prepared._role=role;prepared._material=material;prepared._plan=plan
    prepared._descriptor=dict(packet=pins,review_sha256=sha(review));prepared._release=copy.deepcopy(release)
    prepared._review=review;prepared._authority=authority;prepared._proposal=proposal
    prepared._local=local;prepared._owner=owner;prepared._entry_sources=_entry_sources()
    request=dict(schema='e138-independent-exact-packet-review-request-v1',role=role,
        authorization_sha256=AUTH_SHA256,proposal_sha256=PROPOSAL_SHA256,
        payload_bytes=len(plan['payload']),payload_sha256=sha(plan['payload']),
        command_bytes=len(plan['remote_command'].encode('utf-8')),
        command_sha256=sha(plan['remote_command'].encode('utf-8')),
        projection=plan['projection'],projection_sha256=plan['projection_sha256'],
        controller_review_sha256=sha(review),controller_release_sha256=sha(canonical(release)),
        packet_descriptor_sha256=sha(canonical(prepared._descriptor)),
        entry_source_sha256=prepared._entry_sources,previous_role_accepted_sha256=previous_sha,
        root=contract.ROOT,phase=contract.PHASE,host=release['host'],host_key=release['host_key'],
        adapter_scope=release['scope'],local_staging=str(_staging()),
        review_scope='EXACT_PAYLOAD_COMMAND_SOURCE_POLICY',execution_ready=False,
        remote_instance_digest_scope=('PINNED_REMOTE_ASSEMBLER_RESPONSE_NOT_LOCALLY_RECONSTRUCTED'
            if role=='readback' else None))
    require(len(canonical(request))<=65536,'E138_REVIEW_REQUEST_BOUND')
    prepared._request=request
    return prepared


def prepare_capture():
    """Real fixed grant/materials, no phase creation and no remote operations."""
    authority,proposal=_grant()
    local=materials.prepare().private_bytes()
    return _prepare('capture',dict(authority=authority,proposal=proposal),local,authority,proposal,_release())


def _check_review(prepared,record_raw):
    # Independent record pin is checked BEFORE reads, clocks, configuration or IO.
    require(type(REVIEW_PINS) is dict and type(prepared) is Prepared and
        contract._hex(REVIEW_PINS.get(prepared._role)),'E138_INDEPENDENT_REVIEW_PIN_REQUIRED')
    require(type(record_raw) is bytes and 0<len(record_raw)<=4096 and
        sha(record_raw)==REVIEW_PINS[prepared._role],'E138_INDEPENDENT_REVIEW_RECORD_PIN')
    record=contract.decode(record_raw)
    expected=dict(schema='e138-independent-exact-packet-review-v1',role=prepared._role,
        request_sha256=sha(canonical(prepared._request)),review_scope='EXACT_PAYLOAD_COMMAND_SOURCE_POLICY')
    require(record_raw==canonical(expected),'E138_INDEPENDENT_REVIEW_RECORD_BINDING')
    authority,proposal=_grant()
    require(authority==prepared._authority and proposal==prepared._proposal and
        _entry_sources()==prepared._entry_sources and _release()==prepared._release,
        'E138_REVIEWED_LOCAL_SOURCE_OR_GRANT_DRIFT')
    plan=controller._private_function(packet.prepare,EXPECTED=prepared._descriptor['packet'])(**prepared._material)
    require(plan==prepared._plan and sha(prepared._review)==prepared._descriptor['review_sha256'],
        'E138_REVIEWED_PACKET_DRIFT')


def _private_capture_clock(prepared):
    """Actual reviewed source loader, isolated tagged native validation graph.

    Imported historical modules do not receive __source_sha256__ attributes.
    Scoped registry replacement is restored by the unchanged reviewed loader;
    returned private refs remain usable for pure receipt validation only.
    """
    material=prepared._material;pins=prepared._descriptor['packet']
    raw=material['loader_raw']
    require(sha(raw)==pins['loader_sha256'],'E138_LOCAL_VALIDATOR_LOADER_PIN')
    namespace=dict(__name__='_e138_local_receipt_validation',
        FROZEN_SOURCE_SHA256=None,FROZEN_SOURCE_ORDER=None)
    exec(compile(raw,'<e138-reviewed-local-receipt-loader>','exec'),namespace)
    namespace['FROZEN_SOURCE_SHA256']=pins['source_sha256']
    namespace['FROZEN_SOURCE_ORDER']=pins['source_order']
    rows=[dict(name=name,sha256=pins['source_sha256'][name],
        body_base64=base64.b64encode(material['sources'][name]).decode('ascii')) for name in pins['source_order']]
    with namespace['source_session'](rows) as loaded:
        private=types.ModuleType('_e138_local_original_clock')
        private.build=controller._private_function(controller.clock.build,
            capture=loaded['physical_replay_capture_e138'],runtime=loaded['physical_e138_runtime_primitives'])
    return private


@contextmanager
def _configuration(release):
    """Trusted single-process E138 config only; restore even after failures.

    Historical modules and files are never reconfigured. No concurrent E138
    construction/configuration is supported in this process.
    """
    require(_CONFIG_LOCK.acquire(blocking=False),'E138_ENTRYPOINT_CONFIGURATION_BUSY')
    changes=((controller,'AUTHORIZATION_SHA256',AUTH_SHA256),(controller,'PROPOSAL_SHA256',PROPOSAL_SHA256),
        (controller,'PINNED_RELEASE',release),(transport,'AUTHORIZATION_SHA256',AUTH_SHA256),
        (transport,'PROPOSAL_SHA256',PROPOSAL_SHA256),
        (transport,'FROZEN',dict(authorization_sha256=AUTH_SHA256,proposal_sha256=PROPOSAL_SHA256)))
    previous=[]
    try:
        for module,name,value in changes:
            previous.append((module,name,getattr(module,name)));setattr(module,name,value)
        yield
    finally:
        for module,name,value in reversed(previous):setattr(module,name,value)
        _CONFIG_LOCK.release()


class ReviewedRun:
    __slots__=('_controller','_capture','_execution','_accepted')
    def __repr__(self):return '<E138 ORIGINAL PHASE; no auto-retry or automatic next role>'
    def _stop(self):
        try:self._controller._stop('CONTROLLER_STOP')
        except BaseException:self._controller.terminal=True
    def execute(self,prepared,record_raw):
        failed=False
        try:
            c=self._controller
            require(type(prepared) is Prepared and prepared._owner in (None,self) and
                not c.terminal and prepared._role==controller.ROLES[c.index], 'E138_CURRENT_REVIEWED_ROLE')
            _check_review(prepared,record_raw)
            c.store.remaining()
            c.install_review(prepared._role,prepared._descriptor)
            receipt=c.run_role(prepared._material,prepared._review)
            accepted=materials._read(c.store.phase/prepared._role/'accepted.json',65536)
            native=materials._read(c.store.phase/prepared._role/'native_transport.json',65536)
            self._accepted[prepared._role]=(sha(accepted),contract.decode(accepted),sha(native))
            if prepared._role=='execution':self._execution=prepared
            return receipt
        except BaseException:failed=True
        if failed:
            self._stop()
            raise ValueError('E138_REVIEWED_ROLE_STOPPED_FIRST_FAILURE') from None
    def _saved(self,role,name,cap):
        c=self._controller
        accepted_pin,accepted,native_pin=self._accepted[role]
        materials._read(c.store.phase/role/'accepted.json',65536,accepted_pin)
        materials._read(c.store.phase/role/'native_transport.json',65536,native_pin)
        key={'stdout.raw':'stdout_sha256','stderr.raw':'stderr_sha256',
             'transport.json':'transport_sha256','intent.json':'intent_sha256'}[name]
        pin=accepted[key];path=c.store.phase/role/name
        if name=='stderr.raw' and pin==sha(b''):
            require(path.is_file() and not path.is_symlink() and path.stat().st_size==0,
                'E138_ACCEPTED_EMPTY_STDERR_CHANGED')
            return b''
        return materials._read(path,cap,pin)
    def _stage(self,method):
        failed=False
        try:return method()
        except BaseException:failed=True
        if failed:
            self._stop()
            raise ValueError('E138_STAGED_PREPARATION_STOPPED_FIRST_FAILURE') from None
    def prepare_execution(self):return self._stage(self._prepare_execution)
    def _prepare_execution(self):
        c=self._controller
        require(not c.terminal and c.index==1,'E138_CAPTURE_ACCEPTED_REQUIRED')
        c.store.remaining()
        inputs=dict(self._capture._local['execution_inputs'],authority=c.authority,proposal=c.proposal,
            original_clock=c.original_clock,
            role1_response=self._saved('capture','stdout.raw',6291456))
        materials._read(c.store.phase/'original_clock.json',4096,sha(c.original_clock))
        previous=materials._read(c.store.phase/'capture/accepted.json',65536,self._accepted['capture'][0])
        result=_prepare('execution',inputs,self._capture._local,c.authority,c.proposal,self._capture._release,
            owner=self,previous_sha=sha(previous))
        c.store.remaining();return result
    def prepare_readback(self):return self._stage(self._prepare_readback)
    def _prepare_readback(self):
        c=self._controller
        require(not c.terminal and c.index==2 and self._execution is not None,'E138_EXECUTION_ACCEPTED_REQUIRED')
        c.store.remaining();root=c.store.phase/'execution'
        inputs=dict(authority=c.authority,proposal=c.proposal,original_clock=c.original_clock)
        for key,name,cap in (('role2_stdout','stdout.raw',6291456),('role2_stderr','stderr.raw',65536),
            ('role2_transport','transport.json',65536),('role2_intent','intent.json',4096)):
            inputs[key]=self._saved('execution',name,cap)
        materials._read(c.store.phase/'original_clock.json',4096,sha(c.original_clock))
        outer=contract.decode(inputs['role2_stdout']);response=outer['worker_response'];receipt=outer['owned_root']
        require(type(receipt) is dict and type(response) is dict,'E138_NATIVE_OWNED_ROOT_REQUIRED')
        execution=self._execution
        payload=sha(execution._plan['payload']);sources=execution._material['sources']
        bindings=dict(authorization_sha256=AUTH_SHA256,proposal_sha256=PROPOSAL_SHA256,
            clock_sha256=sha(c.original_clock),role2_intent_sha256=sha(inputs['role2_intent']),
            role2_payload_sha256=payload,worker_spec_sha256=response.get('instance_sha256'),
            runtime_source_sha256=sha(execution._material['inputs']['runtime_source']),
            worker_source_sha256=sha(execution._material['inputs']['worker_source']),
            storage_source_sha256=sha(sources[assembler.ORIGINS['storage']]),
            emitter_source_sha256=sha(execution._material['inputs']['root_receipt_source']))
        require(all(contract._hex(v) for v in bindings.values()) and receipt.get('input_bindings')==bindings and
            response.get('policy_sha256')==sha(execution._material['inputs']['policy']) and
            response.get('payload_sha256')==payload and
            response.get('source_manifest_sha256')==sha(canonical(execution._material['template']['source_sha256'])),
            'E138_REVIEWED_EXECUTOR_SOURCE_POLICY_JOIN')
        join=dict(role2_payload_sha256=payload,input_bindings=bindings,
            cleanup_observer_source_sha256=sha(sources['physical_e138_batch_assembler']))
        previous=materials._read(root/'accepted.json',65536,self._accepted['execution'][0])
        result=_prepare('readback',inputs,self._capture._local,c.authority,c.proposal,self._capture._release,
            owner=self,previous_sha=sha(previous),readback_join=join)
        c.store.remaining();return result


def start(prepared,independent_record_raw):
    """Root-only actual first capture after independent exact packet review.

    This is the first phase/clock creation point. It is intentionally not called
    by module import, preparation, a CLI, or any automatic continuation.
    """
    require(type(prepared) is Prepared and prepared._role=='capture' and prepared._owner is None,
        'E138_FIRST_CAPTURE_PREPARATION_REQUIRED')
    _check_review(prepared,independent_record_raw)
    with _configuration(prepared._release):
        c=controller.Controller.create_pinned(_staging(),prepared._authority,prepared._proposal)
    failed=False
    try:
        private_clock=_private_capture_clock(prepared)
        run_role=controller._private_function(controller.Controller.run_role,clock=private_clock)
        c.run_role=types.MethodType(run_role,c)
        c.store.remaining()
    except BaseException:failed=True
    if failed:
        try:c._stop('CONTROLLER_STOP')
        except BaseException:c.terminal=True
        raise ValueError('E138_LOCAL_VALIDATOR_BINDING_FAILED') from None
    run=ReviewedRun();run._controller=c;run._capture=prepared;run._execution=None;run._accepted={}
    run.execute(prepared,independent_record_raw)
    return run
