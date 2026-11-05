"""Native local orchestration over scoped virtual FS, never a remote execution."""
import copy
import datetime
from pathlib import Path
import unittest
from unittest import mock

from scripts import e138_controller as m
from tests import test_e138_controller as boundary


class NativeTests(unittest.TestCase):
    def setUp(self):
        self.base=boundary.Tests();self.base.setUp();self.addCleanup(self.base.doCleanups)
        self.adapter=self.base.adapter
        self.controller=self.base.controller()
        self.controller.freeze['roles']={r:None for r in m.ROLES}
        self.status='OBSERVED_PENDING_SCIENTIFIC_AUDIT'
        self.no_root=False
        self.forged_root=False
        self.changed_capture=False
        self.adapter.effect=self.send

    def patch(self, obj, key, value):
        p=mock.patch.object(obj,key,value,create=True);p.start();self.addCleanup(p.stop)

    def prepare(self, role, inputs):
        material=copy.deepcopy(self.base.material)
        template=material['template'];template['role']=role
        template['input_sha256']={k:m.sha(v) for k,v in inputs.items()}
        material['inputs']=inputs
        if role=='execution':
            template['assembly']={k:copy.deepcopy(template[k]) for k in m.envelope.ASSEMBLY_KEYS-{'policy_sha256'}}
            template['assembly']['policy_sha256']=m.sha(inputs['policy'])
        if role=='readback':
            template.pop('assembly')
            template['readback']=dict(source_sha256=template['source_sha256'],source_order=template['source_order'],
                join_freeze=dict(raw_sha256=dict(template['input_sha256']),
                    role2_payload_sha256=self.role2_payload,
                    input_bindings=self.receipt['input_bindings'],
                    cleanup_observer_source_sha256=self.receipt['cleanup_observer_source_sha256']))
        pins=copy.deepcopy(self.base.release['roles']['capture']['packet'])
        pins.update(template_sha256=m.sha(m.canonical(template)),input_sha256=template['input_sha256'])
        plan=m._private_function(m.packet.prepare,EXPECTED=pins)(**material)
        review=m.canonical(dict(projection=plan['projection'],projection_sha256=plan['projection_sha256'],
            payload_sha256=m.sha(plan['payload']),remote_command=plan['remote_command'],
            host='bupt-vncs2',scope='LOCAL_SIMULATION_ONLY'))
        self.controller.install_review(role,dict(packet=pins,review_sha256=m.sha(review)))
        self.current_material=material;self.current_plan=plan
        return material,review

    def send(self, **call):
        self.assertEqual(call['payload'],self.current_plan['payload'])
        self.assertEqual(call['remote_command'],self.current_plan['remote_command'])
        role=call['role'];c=self.controller
        self.assertTrue((c.store.phase/role/'intent.json').exists())
        if role=='capture':raw=self.capture()
        elif role=='execution':raw=self.execute()
        else:raw=self.readback()
        return dict(stdout=raw,stderr=b'',exit_code=0,timeout=False,overflow=False,
                    write_failed=False,threads_incomplete=False)

    def capture(self):
        from tests.test_physical_replay_capture_e138 import CaptureTests
        cap=m.clock.capture
        case=CaptureTests();case.setUp()
        try:
            case.authority=self.base.authority;case.proposal=self.base.proposal
            with mock.patch.object(cap,'AUTH_SHA',self.base.auth),mock.patch.object(cap,'PROPOSAL_SHA',self.base.prop):
                value=case.capture()
            constants={k:copy.deepcopy(getattr(cap,k)) for k in ('PATTERN','INPUT_PINS','TREE_PIN')}
        finally:case.doCleanups()
        # Retain only the synthetic fixed source-policy and tags, not FS hooks.
        for k,v in constants.items():self.patch(cap,k,v)
        modules=dict(physical_e138_contract=cap.contract,prospective_acceptance_materializer_v1=cap.anchored,
            physical_replay_source_reader_e135=cap.source,physical_replay_source_inventory_e135=cap.inventory)
        for name,module in modules.items():self.patch(module,'__source_sha256__',cap.DEPENDENCY_SHA256[name])
        self.remote_utc=datetime.datetime.now(datetime.timezone.utc)
        return m.canonical(dict(role='capture',capture=value,boot_id='3ebeb9bb-410c-476c-a000-5c625f590473',
            remote_start_monotonic=1000.,remote_sample_monotonic=1000.,
            remote_utc_sample=self.remote_utc.strftime('%Y-%m-%dT%H:%M:%S.%f%z'),execution_ready=False))

    def execute(self):
        from tests.test_physical_e138_root_receipt import ReceiptTests
        from src.data import physical_e138_root_receipt as emitter
        c=self.controller
        self.role2_payload=m.sha(self.current_plan['payload'])
        case=ReceiptTests();case.setUp()
        try:
            package=case.package
            package.update(authority=self.base.authority,proposal=self.base.proposal,
                original_clock=c.original_clock,
                role2_intent=(c.store.phase/'execution/intent.json').read_bytes())
            case.utc=self.remote_utc.timestamp()+100
            bindings=dict(AUTH_SHA256=m.sha(package['authority']),PROPOSAL_SHA=m.sha(package['proposal']),
                CLOCK_SHA256=m.sha(package['original_clock']),ROLE2_INTENT_SHA256=m.sha(package['role2_intent']),
                ROLE2_PAYLOAD_SHA256=self.role2_payload)
            with mock.patch.multiple(emitter,**bindings),mock.patch.object(emitter.worker,'FACTORY_FREEZE',dict(
                    authorization_sha256=self.base.auth,proposal_sha256=self.base.prop,
                    origin_source_sha256=m.sha(package['runtime_source']),
                    adapter_source_sha256=m.sha(package['worker_source']),effective_root=emitter.ROOT)):
                session,files=case.create()
                response=m.canonical(dict(schema=emitter.worker.SCHEMA,launch_debit=1,status=self.status))
                self.receipt=session.emit(files,response,case.observation)
                outer=dict(role='execution',worker_response=m.contract.decode(response),
                    owned_root=None if self.no_root else ({'owned':True} if self.forged_root else self.receipt),
                    cleanup_observation=m.contract.decode(case.observation),execution_ready=False)
        finally:case.doCleanups()
        return m.canonical(outer)

    def readback(self):
        from tests.test_physical_e138_role3_export import ExportTests
        export=m.exporter
        case=ExportTests();case.setUp()
        try:
            frozen,package=m.envelope.derive(self.current_material['template'],self.current_material['inputs'],
                m.envelope.intent('readback',m.sha(self.current_plan['payload'])),m.sha(self.current_plan['payload']))
            join=m._private_function(m.joiner.join,FREEZE=frozen['readback']['join_freeze'])
            context=join(package)
            for key,value in context['identity'].items():setattr(case.fs.info[export.ROOT],key,value)
            case.now=1100.;case.utc=self.remote_utc.timestamp()+100
            case.authenticator.side_effect=join  # Actual native raw join, not supplied PASS/context.
            pins=dict(AUTH_SHA256=self.base.auth,PROPOSAL_SHA=self.base.prop,
                ORIGINAL_CLOCK_SHA256=m.sha(package['original_clock']),
                ROLE2_STDOUT_SHA256=m.sha(package['role2_stdout']),ROLE2_STDERR_SHA256=m.sha(package['role2_stderr']),
                ROLE2_TRANSPORT_SHA256=m.sha(package['role2_transport']),ROLE2_INTENT_SHA256=m.sha(package['role2_intent']),
                ROLE3_INTENT_SHA256=m.sha(package['role3_intent']),ROLE2_PAYLOAD_SHA256=self.role2_payload,
                ROLE3_PAYLOAD_SHA256=m.sha(self.current_plan['payload']))
            with mock.patch.multiple(export,**pins):
                value=export.collect(package)
                export.validate_result(value,complete=True)
                self.assertEqual(case.fs.opened,list(export.OUTPUTS))
        finally:case.doCleanups()
        return m.canonical(value)

    def run_chain(self):
        c=self.controller
        inputs=dict(authority=self.base.authority,proposal=self.base.proposal)
        c.run_role(*self.prepare('capture',inputs))
        execution=dict(inputs,original_clock=c.original_clock,
            role1_response=(c.store.phase/'capture/stdout.raw').read_bytes(),policy=b'{}')
        if self.changed_capture:execution['role1_response']+=b' '
        c.run_role(*self.prepare('execution',execution))
        root=c.store.phase/'execution'
        readback=dict(inputs,original_clock=c.original_clock,**{key:(root/name).read_bytes() for key,name in
            [('role2_stdout','stdout.raw'),('role2_stderr','stderr.raw'),('role2_transport','transport.json'),
             ('role2_intent','intent.json')]})
        c.run_role(*self.prepare('readback',readback))
        self.assertEqual([v['role'] for v in self.adapter.calls],list(m.ROLES))
        self.assertTrue(c.terminal)

    def test_native_three_role_sequence(self):self.run_chain()

    def test_owned_clean_scientific_failure_still_reads_evidence(self):
        self.status='STOPPED_FIRST_FAILURE';self.run_chain()

    def test_no_native_owned_root_stops_after_two(self):
        self.no_root=True
        with self.assertRaisesRegex(ValueError,'STOPPED_FIRST_FAILURE'):self.run_chain()
        self.assertEqual(len(self.adapter.calls),2)
        self.assertTrue((self.controller.store.phase/'execution/stdout.raw').exists())

    def test_forged_owned_bool_cannot_open_third_connection(self):
        self.forged_root=True
        with self.assertRaisesRegex(ValueError,'STOPPED_FIRST_FAILURE'):self.run_chain()
        self.assertEqual(len(self.adapter.calls),2)
        self.assertFalse((self.controller.store.phase/'readback/intent.json').exists())

    def test_changed_capture_with_matching_new_review_still_rejected(self):
        self.changed_capture=True
        with self.assertRaisesRegex(ValueError,'STOPPED_FIRST_FAILURE'):self.run_chain()
        self.assertEqual(len(self.adapter.calls),1)
        self.assertFalse((self.controller.store.phase/'execution/intent.json').exists())


if __name__=='__main__':unittest.main()
