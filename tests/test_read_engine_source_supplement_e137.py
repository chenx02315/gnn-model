import ast
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
from scripts import read_engine_source_supplement_e137 as m
from scripts import acceptance_transport_e98 as control


class Tests(unittest.TestCase):
    def test_actual_grant_prepare_ast_and_inert_bundle(self):
        repo = Path(__file__).resolve().parents[1]
        auth,proposal = (repo/m.AUTH).read_bytes(),(repo/m.PROPOSAL).read_bytes()
        m.core.check_authority(auth,proposal)
        self.assertEqual(m.core.decode(auth)['user_reply'],'\u5141\u8bb8\u8865\u5145\u8bfb\u53d6')
        with self.assertRaises(ValueError):m.core.check_authority(auth+b' ',proposal)
        plan = m.prepare()
        ast.parse(plan['payload'].decode('ascii'),feature_version=(3,6))
        for path in (Path(m.__file__),Path(m.core.__file__),Path(__file__),repo/'tests/test_engine_source_discovery_e137.py'):
            ast.parse(path.read_text(encoding='utf-8'),feature_version=(3,6))
        saved = {k:v for k,v in sys.modules.items() if k == 'src' or k.startswith('src.')}
        try:
            with mock.patch('builtins.open') as opened:
                exec(compile(plan['payload'].decode('ascii').split('result=sys.modules')[0],'<inert-supplement>','exec'),{})
            opened.assert_not_called()
        finally:
            for key in list(sys.modules):
                if key == 'src' or key.startswith('src.'):del sys.modules[key]
            sys.modules.update(saved)

    def test_bad_review_no_transport_or_attempt(self):
        plan = m.prepare()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'review.json';control.write_new(path,b'{}')
            with mock.patch.object(control,'load_transport') as load:
                with self.assertRaisesRegex(ValueError,'EXACT_SUPPLEMENT_REVIEW'):m.execute(path,plan['payload_sha256'])
            load.assert_not_called()

    def test_mocked_closed_loop_disk_rehash_single_attempt(self):
        import base64,stat
        bodies = [b'synthetic one',b'synthetic two']
        rows = [dict(path=p,bytes=len(b),sha256=m.core.sha(b),whole_file_hashed=True,
            identity=dict(st_dev=1,st_ino=i+1,st_mode=stat.S_IFREG|0o600,st_nlink=1,st_uid=0,st_size=len(b),st_mtime_ns=1,st_ctime_ns=1),
            body_base64=base64.b64encode(b).decode('ascii')) for i,(p,b) in enumerate(zip(m.core.PATHS,bodies))]
        raw = m.core.canonical(dict(schema=m.core.SCHEMA,files=rows,simulation_budget_changed=False))
        helper = mock.Mock();helper.verify_cached_host.return_value = 'cached-A'
        helper.transport.return_value = dict(stdout=raw,stderr=b'',exit_code=0,timeout=False,overflow=False,write_failed=False,threads_incomplete=False)
        plan = m.prepare()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp);review=root/'review.json'
            control.write_new(review,control.encode(dict(status='PASS',reviewed={k:plan[k] for k in m.REVIEW_KEYS})))
            def observed(*args):
                self.assertTrue((root/m.PHASE/'start.json').exists())
                return helper.transport.return_value
            helper.transport.side_effect=observed
            with mock.patch.object(control,'STAGING',root),mock.patch.object(control,'load_transport',return_value=helper):
                result = m.execute(review,plan['payload_sha256'])
                self.assertFalse(result['simulation_budget_changed'])
                for body in bodies:self.assertEqual((root/m.PHASE/'files'/m.core.sha(body)).read_bytes(),body)
                with self.assertRaises(FileExistsError):m.execute(review,plan['payload_sha256'])
            self.assertEqual(helper.transport.call_count,1)
