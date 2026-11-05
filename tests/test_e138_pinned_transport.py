"""Actual pinned helper under mocked processes: no ssh or keygen executes."""
import base64
import io
from pathlib import Path
import types
import unittest
from unittest import mock
from scripts import e138_pinned_transport as m
from tests import test_e138_controller as boundary


class Process:
    def __init__(self):
        self.stdin=io.BytesIO();self.stdout=io.BytesIO(b'prefix');self.stderr=io.BytesIO()
        self.returncode=0;self.waits=[];self.killed=False
    def wait(self, timeout):self.waits.append(timeout);return self.returncode
    def kill(self):self.killed=True


class Tests(unittest.TestCase):
    def setUp(self):
        self.case=boundary.Tests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        for key,value in dict(AUTHORIZATION_SHA256=self.case.auth,PROPOSAL_SHA256=self.case.prop,
                FROZEN=dict(authorization_sha256=self.case.auth,proposal_sha256=self.case.prop)).items():
            p=mock.patch.object(m,key,value);p.start();self.addCleanup(p.stop)

    def adapter(self):return m.PinnedTransport(self.case.authority,self.case.proposal)

    def call(self, adapter, role='capture', **changes):
        args=dict(host=m.HOST,role=role,payload=b'x=1\n',timeout=m.LIMITS[role],
            remote_command=m.envelope.remote_command(role,m.envelope.sha(b'x=1\n')))
        args.update(changes)
        return adapter.send(**args)

    def key(self, adapter):
        # Synthetic cached ED25519 bytes, with digest substitution ONLY for that
        # key. This tests actual helper fingerprint logic, not real identity.
        sp=adapter._namespace['subprocess'];hashlib=adapter._namespace['hashlib']
        original=hashlib.sha256
        digest=base64.b64decode(m.HOST_KEY[7:]+'=')
        p=mock.patch.object(sp,'run',return_value=types.SimpleNamespace(returncode=0,
            stdout=b'vnc.buptic.top ssh-ed25519 '+base64.b64encode(b'synthetic-key')+b'\n',stderr=b''))
        run=p.start();self.addCleanup(p.stop)
        p=mock.patch.object(hashlib,'sha256',side_effect=lambda raw=b'':
            types.SimpleNamespace(digest=lambda:digest) if raw==b'synthetic-key' else original(raw))
        p.start();self.addCleanup(p.stop)
        return run

    def test_default_denial_before_io_compile_or_process(self):
        with mock.patch.object(m,'FROZEN',None),mock.patch.object(Path,'read_bytes') as read, \
                mock.patch('builtins.compile') as compile,mock.patch('subprocess.run') as run:
            with self.assertRaisesRegex(ValueError,'EXTERNAL_RELEASE'):self.adapter()
        read.assert_not_called();compile.assert_not_called();run.assert_not_called()

    def test_source_drift_before_compile(self):
        with mock.patch.object(Path,'read_bytes',return_value=b'bad'),mock.patch('builtins.compile') as compile:
            with self.assertRaisesRegex(ValueError,'SOURCE_CHANGED'):self.adapter()
        compile.assert_not_called()

    def test_actual_helper_three_roles_exact_argv_timeout_isolation_full_result(self):
        a=self.adapter();key=self.key(a);processes=[]
        def spawn(*args,**kwargs):
            self.assertEqual(a._index,len(processes)+1)
            p=Process();processes.append(p);return p
        with mock.patch('subprocess.Popen',side_effect=spawn) as popen:
            for role in m.ROLES:
                result=self.call(a,role)
                self.assertEqual(set(result),m.RESULT_KEYS)
                self.assertIs(result['remote_termination_verified'],False)
                self.assertEqual(result['stdout'],b'prefix')
                argv=popen.call_args.args[0]
                self.assertEqual(argv[-2],m.ENDPOINT)
                self.assertEqual(argv[-1],m.envelope.remote_command(role,m.envelope.sha(b'x=1\n')))
                self.assertLessEqual(processes[-1].waits[0],m.LIMITS[role]-10)
        self.assertEqual(a._namespace['TIMEOUT'],60)
        self.assertEqual(key.call_count,3)
        self.assertEqual(key.call_args.args[0],['ssh-keygen','-F',m.ENDPOINT])
        with self.assertRaisesRegex(ValueError,'TERMINAL'):self.call(a)

    def test_bad_candidates_before_any_subprocess(self):
        for change in (dict(host='B'),dict(remote_command='ssh B'),dict(role='execution'),
                dict(timeout=True),dict(timeout=float('nan')),dict(timeout=61),dict(payload=b'')):
            a=self.adapter()
            with mock.patch('subprocess.run') as run,mock.patch('subprocess.Popen') as popen:
                with self.assertRaises(ValueError):self.call(a,**change)
            run.assert_not_called();popen.assert_not_called()

    def test_key_failure_consumes_and_prevents_ssh_or_retry(self):
        a=self.adapter()
        with mock.patch('subprocess.run',return_value=types.SimpleNamespace(returncode=1,stdout=b'',stderr=b'')), \
                mock.patch('subprocess.Popen') as popen:
            with self.assertRaises(ValueError):self.call(a)
        popen.assert_not_called();self.assertEqual(a._index,1)
        with self.assertRaisesRegex(ValueError,'TERMINAL'):self.call(a)

    def test_insufficient_total_budget_does_not_query_key(self):
        a=self.adapter()
        with mock.patch('subprocess.run') as run,mock.patch('subprocess.Popen') as popen:
            with self.assertRaises(ValueError):self.call(a,timeout=20)
        run.assert_not_called();popen.assert_not_called()
        self.assertEqual(a._index,1)

    def test_key_query_consumes_original_window_before_transport(self):
        a=self.adapter();key=self.key(a);now=[1000.]
        result=key.return_value
        def delayed(*args,**kwargs):now[0]+=51;return result
        key.side_effect=delayed
        with mock.patch.object(m.time,'monotonic',side_effect=lambda:now[0]), \
                mock.patch('subprocess.Popen') as popen:
            with self.assertRaisesRegex(ValueError,'STOPPED_FIRST_FAILURE'):self.call(a)
        popen.assert_not_called();self.assertEqual(a._index,1)

    def test_ambiguous_popen_failure_is_private_and_terminal(self):
        a=self.adapter();self.key(a)
        with mock.patch('subprocess.Popen',side_effect=OSError('PRIVATE_SENTINEL')):
            with self.assertRaisesRegex(ValueError,'STOPPED_FIRST_FAILURE') as caught:self.call(a)
        self.assertIsNone(caught.exception.__context__)
        with self.assertRaisesRegex(ValueError,'TERMINAL'):self.call(a)

    def test_slow_popen_reduces_active_budget_without_reopening(self):
        a=self.adapter();self.key(a);now=[1000.];process=Process()
        def spawn(*args,**kwargs):now[0]+=30;return process
        with mock.patch.object(m.time,'monotonic',side_effect=lambda:now[0]), \
                mock.patch('subprocess.Popen',side_effect=spawn):
            result=self.call(a)
        self.assertEqual(result['stdout'],b'prefix')
        self.assertEqual(process.waits,[20.])

    def test_popen_exhaustion_kills_waits_and_closes_spawned_process(self):
        a=self.adapter();self.key(a);now=[1000.];process=Process()
        streams=[process.stdin,process.stdout,process.stderr]
        def spawn(*args,**kwargs):now[0]+=61;return process
        with mock.patch.object(m.time,'monotonic',side_effect=lambda:now[0]), \
                mock.patch('subprocess.Popen',side_effect=spawn):
            result=self.call(a)
        self.assertTrue(process.killed);self.assertEqual(process.waits[0],5)
        self.assertTrue(all(s.closed for s in streams));self.assertTrue(result['timeout'])
        with self.assertRaisesRegex(ValueError,'TERMINAL'):self.call(a)

    def test_zero_exit_late_result_retains_raw_but_is_timeout(self):
        a=self.adapter();self.key(a);now=[1000.];process=Process()
        def wait(timeout):now[0]+=61;return 0
        process.wait=wait
        with mock.patch.object(m.time,'monotonic',side_effect=lambda:now[0]), \
                mock.patch('subprocess.Popen',return_value=process):
            result=self.call(a)
        self.assertEqual(result['exit_code'],0);self.assertEqual(result['stdout'],b'prefix')
        self.assertTrue(result['timeout'])
        with self.assertRaisesRegex(ValueError,'TERMINAL'):self.call(a)

    def test_startup_cleanup_independently_attempts_kill_wait_all_closes(self):
        for failing in ('kill','wait'):
            a=self.adapter();self.key(a);now=[1000.];process=Process()
            process.returncode=None
            events=[]
            def kill():
                events.append('kill')
                if failing=='kill':raise OSError('PRIVATE_KILL')
            def wait(timeout):
                events.append('wait')
                if failing=='wait':raise OSError('PRIVATE_WAIT')
            process.kill=kill;process.wait=wait
            for name in ('stdin','stdout','stderr'):
                def close(name=name):
                    events.append(name)
                    raise OSError('PRIVATE_CLOSE')
                setattr(process,name,types.SimpleNamespace(close=close))
            def spawn(*args,**kwargs):now[0]+=61;return process
            with mock.patch.object(m.time,'monotonic',side_effect=lambda:now[0]), \
                    mock.patch('subprocess.Popen',side_effect=spawn), \
                    mock.patch('threading.Thread') as thread:
                result=self.call(a)
            self.assertEqual(events,['kill','wait','stdin','stdout','stderr'])
            thread.assert_not_called()
            self.assertEqual(set(result),m.RESULT_KEYS)
            self.assertIsNone(result['exit_code'])
            self.assertTrue(result['timeout']);self.assertTrue(result['threads_incomplete'])
            self.assertEqual(result['stdout'],b'');self.assertEqual(result['stderr'],b'')
            self.assertNotIn('PRIVATE',repr(result))
            with self.assertRaisesRegex(ValueError,'TERMINAL'):self.call(a)

    def test_pipe_read_errors_and_short_writes_fail_without_thread_traceback(self):
        for which in ('stdout','stderr','stdin'):
            a=self.adapter();self.key(a);process=Process()
            if which=='stdin':process.stdin=types.SimpleNamespace(write=lambda raw:1,close=lambda:None)
            else:
                reader=mock.Mock(side_effect=[b'retained',OSError('PRIVATE_READ')])
                setattr(process,which,types.SimpleNamespace(read=reader))
            with mock.patch('subprocess.Popen',return_value=process),mock.patch('threading.excepthook') as hook:
                result=self.call(a)
            self.assertTrue(result['threads_incomplete']);hook.assert_not_called()
            if which!='stdin':self.assertEqual(result[which],b'retained')
            with self.assertRaisesRegex(ValueError,'TERMINAL'):self.call(a)


if __name__=='__main__':unittest.main()
