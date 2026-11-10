"""Actual E140 private factory/local phase only; no send or remote action."""
import copy
from contextlib import ExitStack, contextmanager
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from scripts import e140_local_source_session as source

REPO=Path(__file__).resolve().parents[1]


class Tests(unittest.TestCase):
    @contextmanager
    def session(self):
        pin=source.hashlib.sha256(Path(source.__file__).read_bytes()).hexdigest()
        native,scripts=source.effective_maps()
        freeze=dict(origin_sha256=source.origin_manifest(pin),effective_native_sha256=native,
            effective_script_sha256=scripts,adapter_sha256=pin,binding_sha256=source.binding_digest())
        with mock.patch.object(source,'FROZEN',freeze),source.local_session() as session:
            yield session

    def grant(self,s):
        c=s.native_modules['physical_e138_contract']
        p=(REPO/'contracts/physical_f_clean_replay_proposal_e140_v1.json').read_bytes()
        a=c.canonical(dict(schema='e140-explicit-whole-package-authorization-v1',approved_package='E140',
            approval_source='explicit_user_reply',user_reply='SYNTHETIC FACTORY ONLY NOT CONSENT',
            user_authorization_received=True,proposal_sha256=c.sha(p),approved_scope=copy.deepcopy(c.POLICY),
            execution_ready=False))
        return a,p

    @contextmanager
    def configure(self,s,a,p):
        c=s.modules['e138_controller'];t=s.modules['e138_pinned_transport']
        release=dict(authorization_sha256=c.sha(a),proposal_sha256=c.sha(p),
            adapter_source_sha256=s.local_source_closure()['scripts.e138_pinned_transport'],
            host=t.HOST,host_key=t.HOST_KEY,helper_sha256=t.HELPER_SHA256,scope=t.PinnedTransport.scope,
            local_source_sha256=s.local_source_closure(),roles={role:None for role in c.ROLES})
        with ExitStack() as stack:
            for module in (c,t):
                stack.enter_context(mock.patch.object(module,'AUTHORIZATION_SHA256',c.sha(a)))
                stack.enter_context(mock.patch.object(module,'PROPOSAL_SHA256',c.sha(p)))
            stack.enter_context(mock.patch.object(c,'PINNED_RELEASE',release))
            stack.enter_context(mock.patch.object(t,'FROZEN',dict(authorization_sha256=c.sha(a),proposal_sha256=c.sha(p))))
            stack.enter_context(mock.patch.object(c.storage.platform,'node',return_value='SYNTHETIC_LOCAL_NODE'))
            yield c,t,release

    def test_actual_constructor_new_phase_original_clock_and_close_lifetime(self):
        with tempfile.TemporaryDirectory() as staging,self.session() as s, \
             mock.patch('subprocess.Popen') as child,mock.patch('subprocess.run') as query, \
             mock.patch('platform.node',return_value='SYNTHETIC_LOCAL_NODE'):
            a,p=self.grant(s)
            with self.configure(s,a,p) as (c,t,_):
                instance=c.Controller.create_pinned(staging,a,p)
            self.assertEqual(instance.store.phase.name,source.native.PHASE)
            self.assertIs(type(instance.adapter),t.PinnedTransport)
            start=c.contract.decode((instance.store.phase/'start.json').read_bytes())
            self.assertEqual(start['end']-start['start'],3600)
            self.assertIsNone(c.PINNED_RELEASE);self.assertIsNone(t.FROZEN)
            self.assertIsNone(c.AUTHORIZATION_SHA256)
            self.assertLessEqual(instance.store.remaining(),3600)
            child.assert_not_called();query.assert_not_called()
        self.assertTrue(instance.terminal)
        with self.assertRaisesRegex(ValueError,'SESSION_CLOSED'):instance.run_role({},b'')

    def test_default_release_denies_before_phase_or_source_read(self):
        with self.session() as s,mock.patch.object(Path,'read_bytes') as read, \
             mock.patch.object(Path,'mkdir') as mkdir:
            with self.assertRaisesRegex(ValueError,'NO_PINNED_RELEASE'):
                s.modules['e138_controller'].Controller.create_pinned('unused',b'',b'')
            read.assert_not_called();mkdir.assert_not_called()

    def test_wrong_frozen_closure_rejected_before_phase(self):
        with tempfile.TemporaryDirectory() as staging,self.session() as s:
            a,p=self.grant(s)
            with self.configure(s,a,p) as (c,t,release):
                release['local_source_sha256']['src.data.physical_runtime_bootstrap_e138']='0'*64
                with self.assertRaisesRegex(ValueError,'SOURCE_CLOSURE'):
                    c.Controller.create_pinned(staging,a,p)
            self.assertFalse((Path(staging)/source.native.PHASE).exists())


if __name__=='__main__':unittest.main()
