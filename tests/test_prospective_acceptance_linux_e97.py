"""Physical cleanup fixture: only inside the explicitly activated E97 LSF gate."""
import os
import selectors
import subprocess
import sys
import time
import unittest

from src.data import prospective_acceptance_process_v1 as process

ENABLED = (sys.platform.startswith('linux') and
           bool(os.environ.get('LSB_JOBID')) and
           os.environ.get('E97_SYNTHETIC_JOB_GATE') == os.environ.get('LSB_JOBID'))


@unittest.skipUnless(ENABLED, 'Explicit E97 Linux job synthetic gate required')
class PhysicalCleanupTests(unittest.TestCase):
    def test_fork_setsid_descendant_and_leader_are_reaped(self):
        authority = dict(job_id=int(os.environ['LSB_JOBID']),
                         memory_cap_bytes=536870912)
        domain = process._Domain(authority)
        child = None
        identity = None
        deadline = time.monotonic() + 8
        # One harmless fixed Python process, one child, no files or tool data.
        code = ('import os,sys,time\n'
                'pid=os.fork()\n'
                'if pid == 0:\n'
                ' os.setsid(); time.sleep(30); os._exit(0)\n'
                'sys.stdout.write("E97_READY\\n"); sys.stdout.flush()\n'
                'sys.stdin.buffer.read(1)\n')
        cleaned = False
        try:
            child = subprocess.Popen(['/usr/bin/python3', '-I', '-S', '-B', '-c', code],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True, env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(2), 'dummy child readiness timeout')
                self.assertEqual(os.read(child.stdout.fileno(), 64), b'E97_READY\n')
            identity = process._identity(child.pid, domain.membership)
            child.stdin.write(b'x')
            child.stdin.flush()
            child.stdin.close()
            cleaned = domain.cleanup(child, identity, deadline)
            self.assertTrue(cleaned)
            self.assertEqual(domain.own_children(), set())
            self.assertEqual(domain.pids(), {os.getpid()})
            self.assertIsNotNone(child.returncode)
        finally:
            try:
                if not cleaned:
                    # One cleanup path, never respawn the fixture after failure.
                    domain.cleanup(child, identity, deadline)
            finally:
                if child is not None:
                    for pipe in (child.stdin, child.stdout, child.stderr):
                        if pipe is not None:
                            pipe.close()
                domain.close()


if __name__ == '__main__':
    unittest.main()
