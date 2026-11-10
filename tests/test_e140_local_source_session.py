"""Actual local E140 private loading, no grant/phase/remote execution."""
import ast
import copy
import io
from pathlib import Path
import sys
import unittest
from unittest import mock

from scripts import e140_local_source_session as m
from scripts import e138_controller as historical


class Tests(unittest.TestCase):
    def frozen(self):
        adapter=m.origin._sha(Path(m.__file__).read_bytes())
        native,scripts=m.effective_maps()
        return dict(adapter_sha256=adapter,binding_sha256=m.binding_digest(),origin_sha256=m.origin_manifest(adapter),
                    effective_native_sha256=native,effective_script_sha256=scripts)

    def snapshot(self):
        return {k:v for k,v in sys.modules.items() if k in ('src','scripts') or k.startswith(('src.','scripts.'))}

    def test_default_no_io_compile_or_registry_change(self):
        before=self.snapshot()
        with mock.patch.object(m,'FROZEN',None),mock.patch.object(Path,'open') as opened, \
             mock.patch('builtins.compile') as compiled:
            with self.assertRaisesRegex(ValueError,'E140_SESSION_NO_SOURCE_FREEZE'):
                with m.local_session():self.fail('entered')
        opened.assert_not_called();compiled.assert_not_called();self.assertEqual(self.snapshot(),before)

    def test_finite_session_source_counts_effective_pin_reverse_and_python36(self):
        path=m.REPO/'scripts/e139_local_source_session.py';raw=path.read_bytes()
        result=m.build(raw);effective=result.private_sources()[m.KEY]
        self.assertEqual(m.origin._sha(effective),m.EFFECTIVE_SHA256)
        self.assertEqual(len(m.REPLACEMENTS),9)
        reverse=effective
        for old,new,count in m.REPLACEMENTS:
            self.assertEqual(raw.count(old.encode()),count)
            reverse=reverse.replace(new.encode(),old.encode())
        self.assertEqual(reverse,raw);self.assertEqual(path.read_bytes(),raw)
        ast.parse(effective,feature_version=(3,6))
        with mock.patch('builtins.open') as opened,mock.patch('builtins.compile') as compiled:m.build(raw)
        opened.assert_not_called();compiled.assert_not_called()
        with self.assertRaises(ValueError):m.build(raw+b' ')

    def test_actual56_native7_scripts_e140_aliases_builtins_and_all_pins(self):
        before=self.snapshot();oldphase=historical.storage.PHASE;oldclosure=historical.local_source_closure
        frozen=self.frozen()
        with mock.patch.object(m,'FROZEN',frozen),m.local_session() as session:
            self.assertEqual(len(session.native_modules),56);self.assertEqual(len(session.modules),7)
            c=session.native_modules[m.native.CONTRACT];ctl=session.modules['e138_controller']
            self.assertEqual(c.ROOT,m.native.ROOT);self.assertEqual(c.PHASE,m.native.PHASE)
            self.assertEqual(ctl.storage.PHASE,m.native.PHASE)
            self.assertIs(ctl.contract,c);self.assertIs(ctl.require,c.require)
            self.assertIs(ctl.clock.contract,c);self.assertIs(ctl.clock.capture.contract,c)
            self.assertIs(ctl.clock.runtime.contract,c)
            cap=ctl.clock.capture
            self.assertEqual(cap.DEPENDENCY_SHA256[m.native.CONTRACT],m.native.CONTRACT_EFFECTIVE_SHA256)
            cap._source_bindings()
            self.assertIn(b'__builtins__=dict((name,getattr(builtins,name))',session._native[m.native.BOOTSTRAP])
            closure=ctl.local_source_closure()
            self.assertEqual(closure['effective.scripts.e140_local_source_session'],m.EFFECTIVE_SHA256)
            self.assertEqual(closure['bindings.e140_local_source_session'],m.binding_digest())
            self.assertEqual(closure['scripts.e140_local_source_session'],frozen['adapter_sha256'])
            for name,node in session.native_modules.items():
                self.assertEqual(node.__source_sha256__,frozen['effective_native_sha256'][name])
            for name,node in session.modules.items():
                self.assertEqual(node.__source_sha256__,frozen['effective_script_sha256'][name])
            delayed=__import__('scripts',fromlist=['e138_pinned_transport']).e138_pinned_transport
            self.assertIs(delayed,session.modules['e138_pinned_transport']);self.assertIs(delayed.contract,c)
            self.assertEqual(sys.modules['scripts'].__path__,[])
            self.assertEqual(ctl.packet.SOURCE_BYTES('scripts.e138_packet'),session._scripts['e138_packet'])
            self.assertEqual(session.binding_manifest,m.bindings())
            self.assertIsNone(c.FROZEN);self.assertIsNone(ctl.PINNED_RELEASE);self.assertIsNone(delayed.FROZEN)
        self.assertEqual(self.snapshot(),before);self.assertEqual(historical.storage.PHASE,oldphase)
        self.assertIs(historical.local_source_closure,oldclosure)

    def test_constructor_defaults_and_stale_lifetime_guards_zero_io(self):
        with mock.patch.object(m,'FROZEN',self.frozen()),m.local_session() as session:
            cls=session.modules['e138_controller'].Controller
            with mock.patch.object(Path,'open') as opened,mock.patch.object(Path,'mkdir') as mkdir:
                with self.assertRaisesRegex(ValueError,'E138_CONTROLLER_NO_PINNED_RELEASE'):
                    cls.create_pinned('UNUSED',b'',b'')
                with self.assertRaisesRegex(ValueError,'E139_SESSION_SIMULATION_UNSUPPORTED'):
                    cls('UNUSED',b'',b'',None)
            opened.assert_not_called();mkdir.assert_not_called()
            # Bare instance tests ONLY the stale method guard, not construction.
            instance=cls.__new__(cls)
        with mock.patch.object(Path,'open') as opened,mock.patch('subprocess.Popen') as spawn:
            for call in (lambda:cls.create_pinned(),lambda:instance.run_role({},b''),session.local_source_closure):
                with self.assertRaisesRegex(ValueError,'E139_SESSION_CLOSED'):call()
        opened.assert_not_called();spawn.assert_not_called()

    def test_source_config_effective_drift_and_exact_roster(self):
        original_open=Path.open
        def drift(path,*args,**kwargs):
            if path==m.REPO/'scripts/bootstrap_builtins_repair_candidate.py':return io.BytesIO(b'tampered read only')
            return original_open(path,*args,**kwargs)
        with mock.patch.object(m,'FROZEN',self.frozen()),m.local_session() as session:
            with mock.patch.object(Path,'open',drift),self.assertRaisesRegex(ValueError,'ORIGIN_DRIFT'):
                session.local_source_closure()
            with mock.patch.object(session.modules['e138_phase_store'],'PHASE','WRONG'), \
                 self.assertRaisesRegex(ValueError,'BINDING_DRIFT'):session.local_source_closure()
            session._scripts['e138_packet']=b'tamper'
            with self.assertRaisesRegex(ValueError,'EFFECTIVE_DRIFT'):session.local_source_closure()
        bad=copy.deepcopy(self.frozen());bad['origin_sha256']['unknown.py']='0'*64
        with mock.patch.object(m,'FROZEN',bad),mock.patch.object(Path,'open') as opened:
            with self.assertRaisesRegex(ValueError,'E140_SESSION_ORIGIN_MANIFEST'):
                with m.local_session():self.fail('entered')
        opened.assert_not_called()

    def test_native_exit_failure_after_real_restore_cannot_skip_outer_cleanup(self):
        before=self.snapshot();real_exec=exec;calls=[]
        def intercepted(code,namespace,*args):
            result=real_exec(code,namespace,*args)
            if namespace.get('__name__')=='_e139_local_native_loader':
                factory=namespace['source_session']
                def source_session(rows):
                    real=factory(rows)
                    class FailingExit:
                        def __enter__(self):return real.__enter__()
                        def __exit__(self,*exc):
                            real.__exit__(*exc)
                            calls.append('native actually restored')
                            raise RuntimeError('after native restore')
                    return FailingExit()
                namespace['source_session']=source_session
            return result
        with mock.patch.object(m,'FROZEN',self.frozen()),mock.patch('builtins.exec',intercepted):
            with self.assertRaisesRegex(RuntimeError,'after native restore'):
                with m.local_session():pass
        self.assertEqual(calls,['native actually restored'])
        self.assertEqual(self.snapshot(),before);self.assertFalse(m._LOCK.locked())

    def test_body_exception_nonreentrant_and_restoration(self):
        before=self.snapshot()
        with mock.patch.object(m,'FROZEN',self.frozen()):
            with self.assertRaisesRegex(RuntimeError,'body failure'):
                with m.local_session():
                    with self.assertRaisesRegex(ValueError,'E140_SESSION_SINGLE_ACTIVE'):
                        with m.local_session():self.fail('nested')
                    raise RuntimeError('body failure')
        self.assertEqual(self.snapshot(),before);self.assertFalse(m._LOCK.locked())

    def test_inherited_cleanup_close_exception_still_restores_every_registry(self):
        before=self.snapshot();real_exec=exec
        def intercepted(code,namespace,*args):
            result=real_exec(code,namespace,*args)
            if namespace.get('__name__')=='_e140_exact_private_source_session':
                real_close=namespace['Session'].close
                def close(session):
                    real_close(session);raise RuntimeError('after real close')
                namespace['Session'].close=close
            return result
        with mock.patch.object(m,'FROZEN',self.frozen()),mock.patch('builtins.exec',intercepted):
            with self.assertRaisesRegex(RuntimeError,'after real close'):
                with m.local_session():pass
        self.assertEqual(self.snapshot(),before);self.assertFalse(m._LOCK.locked())


if __name__=='__main__':unittest.main()
