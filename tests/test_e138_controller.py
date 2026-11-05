"""Local failure-boundary tests; no transport or authority is authenticated."""
import copy
import tempfile
from pathlib import Path
import unittest
from unittest import mock

from scripts import e138_controller as m


class Adapter:
    scope = 'LOCAL_SIMULATION_ONLY'

    def __init__(self):
        self.calls = []
        self.effect = None

    def send(self, **kwargs):
        self.calls.append(kwargs)
        return self.effect(**kwargs)


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.adapter = Adapter()
        self.proposal = m.canonical(dict(schema='e138-fixed-f-replay-proposal-v1', package='E138',
            status='PENDING_EXPLICIT_WHOLE_PACKAGE_AUTHORIZATION',
            scope_if_granted=copy.deepcopy(m.contract.POLICY)))
        self.authority = m.canonical(dict(schema='e138-explicit-whole-package-authorization-v1',
            approved_package='E138', approval_source='explicit_user_reply', user_reply='synthetic-only',
            user_authorization_received=True, proposal_sha256=m.sha(self.proposal),
            approved_scope=copy.deepcopy(m.contract.POLICY), execution_ready=False))
        self.auth, self.prop = m.sha(self.authority), m.sha(self.proposal)
        repo = Path(m.__file__).resolve().parents[1]
        inputs = dict(authority=self.authority, proposal=self.proposal)
        sources = {'example': b'x=1\n'}
        loader = b'x=1\n'
        worker = b'def safe_dispatch(*args):return b"{}"\n'
        env = Path(m.envelope.__file__).read_bytes()
        template = dict(role='capture', loader_sha256=m.sha(loader),
            source_sha256={k:m.sha(v) for k,v in sources.items()}, source_order=tuple(sources),
            input_sha256={k:m.sha(v) for k,v in inputs.items()}, authorization_sha256=self.auth,
            proposal_sha256=self.prop, assembly=None)
        self.material = dict(template=template, inputs=inputs, sources=sources,
                             worker_raw=worker, loader_raw=loader, envelope_raw=env)
        pins = dict(compiler_sha256=m.sha(Path(m.packet.__file__).read_bytes()),
            worker_sha256=m.sha(worker), loader_sha256=m.sha(loader), envelope_sha256=m.sha(env),
            template_sha256=m.sha(m.canonical(template)), source_sha256=template['source_sha256'],
            source_order=template['source_order'], input_sha256=template['input_sha256'])
        plan = m._private_function(m.packet.prepare, EXPECTED=pins)(**self.material)
        self.review = m.canonical(dict(projection=plan['projection'],
            projection_sha256=plan['projection_sha256'], payload_sha256=m.sha(plan['payload']),
            remote_command=plan['remote_command'], host='bupt-vncs2', scope='LOCAL_SIMULATION_ONLY'))
        self.release = dict(authorization_sha256=self.auth, proposal_sha256=self.prop,
            adapter_source_sha256=m.sha(Path(__file__).read_bytes()), host='bupt-vncs2',
            native_source_sha256={mod.__name__:m.sha(Path(mod.__file__).read_bytes()) for mod in
                (m.packet,m.envelope,m.clock,m.storage,m.contract,m.joiner,m.exporter)},
            roles={role:dict(packet=pins,review_sha256=m.sha(self.review)) for role in m.ROLES})

    def controller(self):
        for name, value in [('AUTHORIZATION_SHA256',self.auth),('PROPOSAL_SHA256',self.prop),
                            ('RELEASE',self.release)]:
            patch = mock.patch.object(m,name,value)
            patch.start();self.addCleanup(patch.stop)
        return m.Controller(self.tmp.name,self.authority,self.proposal,self.adapter)

    def test_default_denies_before_io_clock_callback(self):
        with mock.patch.object(m,'RELEASE',None), mock.patch.object(Path,'read_bytes') as read, \
                mock.patch.object(m.storage.time,'monotonic') as now:
            with self.assertRaisesRegex(ValueError,'NO_RELEASE'):
                m.Controller(self.tmp.name,b'',b'',self.adapter)
        read.assert_not_called();now.assert_not_called()
        self.assertFalse(self.adapter.calls)

    def test_wrong_review_denies_without_connection_and_is_terminal(self):
        c=self.controller()
        with self.assertRaisesRegex(ValueError,'STOPPED_FIRST_FAILURE'):c.run_role(self.material,b'{}')
        self.assertFalse(self.adapter.calls)
        with self.assertRaisesRegex(ValueError,'TERMINAL'):c.run_role(self.material,self.review)

    def test_wrong_material_denies_without_connection(self):
        c=self.controller();self.material['worker_raw'] += b'# drift'
        with self.assertRaises(ValueError):c.run_role(self.material,self.review)
        self.assertFalse(self.adapter.calls)

    def test_intent_before_send_exception_is_terminal_and_raw_saved(self):
        c=self.controller()
        def fail(**kwargs):
            self.assertTrue((c.store.phase/'capture/intent.json').exists())
            self.assertLessEqual(kwargs['timeout'],60)
            raise OSError('ambiguous private failure')
        self.adapter.effect=fail
        with self.assertRaisesRegex(ValueError,'STOPPED_FIRST_FAILURE'):c.run_role(self.material,self.review)
        self.assertEqual(len(self.adapter.calls),1)
        self.assertTrue((c.store.phase/'capture/transport.json').exists())
        self.assertEqual((c.store.phase/'capture/stdout.raw').read_bytes(),b'')
        self.assertTrue(c.terminal)

    def test_raw_before_native_validation(self):
        c=self.controller()
        self.adapter.effect=lambda **kw: dict(stdout=b'{}',stderr=b'',exit_code=0,
            timeout=False,overflow=False,write_failed=False,threads_incomplete=False)
        def validate(*args):
            self.assertEqual((c.store.phase/'capture/stdout.raw').read_bytes(),b'{}')
            self.assertTrue((c.store.phase/'capture/transport.json').exists())
            raise ValueError('invalid capture')
        with mock.patch.object(m.clock,'build',side_effect=validate):
            with self.assertRaisesRegex(ValueError,'STOPPED_FIRST_FAILURE'):c.run_role(self.material,self.review)
        self.assertTrue(c.terminal)

    def test_original_clock_expiry_no_callback_or_reopen(self):
        c=self.controller()
        with mock.patch.object(m.storage.time,'monotonic',return_value=c.store._start+3601):
            with self.assertRaisesRegex(ValueError,'STOPPED_FIRST_FAILURE'):c.run_role(self.material,self.review)
        self.assertFalse(self.adapter.calls)
        with self.assertRaises(FileExistsError):
            m.storage.PhaseStore(self.tmp.name,self.auth,self.prop).create()

    def test_expiry_during_intent_fsync_consumes_without_send(self):
        c=self.controller();reserve=c.store.reserve
        def delayed(*args):
            result=reserve(*args)
            c.store._start -= 3601
            return result
        with mock.patch.object(c.store,'reserve',side_effect=delayed):
            with self.assertRaisesRegex(ValueError,'STOPPED_FIRST_FAILURE'):
                c.run_role(self.material,self.review)
        self.assertTrue((c.store.phase/'capture/intent.json').exists())
        self.assertFalse(self.adapter.calls)

    def test_staged_review_installed_once_without_clock_restart(self):
        descriptor=self.release['roles']['capture']
        self.release['roles']['capture']=None
        c=self.controller();started=c.store._start
        c.install_review('capture',descriptor)
        self.assertEqual(c.store._start,started)
        with self.assertRaisesRegex(ValueError,'INSTALL_ORDER'):
            c.install_review('capture',descriptor)

    def test_double_failure_hides_private_context_and_is_terminal(self):
        c=self.controller()
        with mock.patch.object(c,'_prepare',side_effect=ValueError('PRIVATE_ORIGIN')), \
                mock.patch.object(c.store,'close',side_effect=OSError('PRIVATE_CLOSE')):
            with self.assertRaisesRegex(ValueError,'STOPPED_FIRST_FAILURE') as caught:
                c.run_role(self.material,self.review)
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(c.terminal)
        with self.assertRaisesRegex(ValueError,'TERMINAL'):c.run_role(self.material,self.review)


if __name__ == '__main__':
    unittest.main()
