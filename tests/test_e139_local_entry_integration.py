"""Actual private entry/material/packet wiring, SYNTHETIC authority only.

No actual grant file, controller phase, host query or transport is created.
The start test replaces pinned construction and role execution, using an actual
scoped controller object. It proves the clock join/method stays intact, not real
pinned construction or capture execution.
"""
import copy
from pathlib import Path
import types
import unittest
from unittest import mock

from scripts import e139_entry_candidate as entry_source
from scripts import e139_local_source_session as session_source
from scripts import e139_local_materials as materials

REPO = Path(__file__).resolve().parents[1]


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.materials = materials.prepare()
        if cls.materials.public_summary()['status'] != materials.READY:
            raise AssertionError('fixed local inputs unavailable; no substitutions')
        cls.entry_bytes = entry_source.build((REPO/'scripts/run_physical_f_clean_replay_e138.py').read_bytes()).private_sources()[entry_source.KEY]
        native_pins, script_pins = session_source.effective_maps()
        adapter_pin = materials.sha((REPO/session_source.SELF).read_bytes())
        cls.freeze = dict(origin_sha256=session_source.origin_manifest(adapter_pin),
            effective_native_sha256=native_pins, effective_script_sha256=script_pins,
            adapter_sha256=adapter_pin, binding_sha256=session_source.binding_digest())
        cls.worker = (REPO/'scripts/worker_e138_batch.py').read_bytes()
        cls.proposal = (REPO/'contracts/physical_f_clean_replay_proposal_e139_v1.json').read_bytes()

    def entry(self, session):
        c = session.native_modules['physical_e138_contract']
        authority = c.canonical(dict(schema='e139-explicit-whole-package-authorization-v1',
            approved_package='E139', approval_source='explicit_user_reply',
            user_reply='SYNTHETIC INTEGRATION ONLY 中文“不是实际批准”', user_authorization_received=True,
            proposal_sha256=c.sha(self.proposal), approved_scope=copy.deepcopy(c.POLICY), execution_ready=False))
        def read(path, cap, pin=None):
            expected = {'physical_f_clean_replay_authorization_e139.json':authority,
                        'physical_f_clean_replay_proposal_e139_v1.json':self.proposal}
            raw = expected[path.name]
            self.assertEqual(c.sha(raw),pin); self.assertLessEqual(len(raw),cap)
            return raw
        facade = types.SimpleNamespace(prepare=lambda:self.materials, _read=mock.Mock(side_effect=read))
        module = types.ModuleType('_TEST_ONLY_E139_entry')
        module.E139_MATERIALS = facade
        exec(compile(self.entry_bytes,'<test-e139-real-private-entry>','exec'),module.__dict__)
        module._repo=lambda:REPO
        module._staging=lambda:REPO.parent/'runtime_training_staging_20260928'
        source_map = {'scripts.worker_e138_batch':self.worker,
            **{'scripts.'+key:session._scripts[key] for key in
               ('e138_source_session','e138_reviewed_envelope','e138_packet')}}
        def source_bytes(key):
            session._check()
            return source_map[key]
        def manifest():
            return dict(session.local_source_closure(), **{entry_source.KEY:entry_source.EFFECTIVE_SHA256,
                        'scripts.worker_e138_batch':c.sha(self.worker)})
        module.SOURCE_BYTES=source_bytes; module.SOURCE_MANIFEST=manifest
        return module,authority,facade

    def test_default_authority_denies_in_actual_private_graph_before_io(self):
        with mock.patch.object(session_source,'FROZEN',self.freeze), session_source.local_session() as session:
            entry,_,facade=self.entry(session)
            with mock.patch('subprocess.Popen') as spawn, mock.patch('time.monotonic') as now:
                with self.assertRaisesRegex(ValueError,'ENTRY_AUTHORITY_PINS_REQUIRED'):entry.prepare_capture()
            facade._read.assert_not_called(); spawn.assert_not_called(); now.assert_not_called()

    def test_actual_capture_preparation_uses_effective_roles_and_new_identity(self):
        with mock.patch.object(session_source,'FROZEN',self.freeze), session_source.local_session() as session:
            entry,authority,facade=self.entry(session)
            entry.AUTH_SHA256=materials.sha(authority)
            with mock.patch('subprocess.Popen') as spawn, mock.patch('time.monotonic') as now:
                prepared=entry.prepare_capture()
            spawn.assert_not_called(); now.assert_not_called()
            request=prepared.public_review_request(); bundle=self.materials.private_bytes()['roles']['capture']
            self.assertEqual(request['schema'],'e139-independent-exact-packet-review-request-v1')
            self.assertEqual(request['root'],session_source.native.pair.ROOT_NEW)
            self.assertEqual(request['phase'],session_source.native.pair.PHASE_NEW)
            self.assertEqual(request['projection']['source_sha256'],bundle['source_sha256'])
            self.assertEqual(len(bundle['source_order']),35)
            self.assertEqual(request['projection']['compiler_sha256'],session_source.packet_candidate.EFFECTIVE_SHA256)
            self.assertFalse(request['execution_ready'])
            self.assertEqual(facade._read.call_count,2)

    def test_start_clock_join_preserves_actual_scoped_method_with_factory_double(self):
        with mock.patch.object(session_source,'FROZEN',self.freeze), session_source.local_session() as session:
            entry,authority,_=self.entry(session); entry.AUTH_SHA256=materials.sha(authority)
            prepared=entry.prepare_capture(); c=entry.contract
            record=c.canonical(dict(schema='e139-independent-exact-packet-review-v1',role='capture',
                request_sha256=c.sha(c.canonical(prepared.public_review_request())),
                review_scope='EXACT_PAYLOAD_COMMAND_SOURCE_POLICY'))
            entry.REVIEW_PINS={'capture':c.sha(record)}  # Synthetic test review, never production evidence.
            controller_type=session.modules['e138_controller'].Controller
            instance=controller_type.__new__(controller_type)
            instance.store=types.SimpleNamespace(remaining=mock.Mock(return_value=3599))
            instance.terminal=False
            with mock.patch.object(controller_type,'create_pinned',return_value=instance) as factory, \
                 mock.patch.object(entry.ReviewedRun,'execute') as execute, \
                 mock.patch('subprocess.Popen') as spawn:
                run=entry.start(prepared,record)
            factory.assert_called_once(); spawn.assert_not_called()
            execute.assert_called_once_with(prepared,record)
            self.assertIs(run._controller,instance)
            self.assertNotIn('run_role',vars(instance))
            instance.store.remaining.assert_called_once_with()
        with self.assertRaisesRegex(ValueError,'E139_SESSION_CLOSED'):
            instance.run_role({},b'')


if __name__=='__main__':unittest.main()
