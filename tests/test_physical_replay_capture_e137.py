"""Deterministic virtual sources only; no runtime/network/process evidence."""
import ast
import copy
from pathlib import Path
import unittest
from unittest import mock

from src.data import physical_replay_capture_e137 as m
from tests.test_physical_replay_source_inventory_e135 import install


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.fs = install(self)
        self.tick,self.clock = mock.Mock(),mock.Mock(return_value=1000.)
        initial = m.inventory.inventory(mock.Mock())
        pin = dict(path=initial['path'],sha256=initial['sha256'],bytes=initial['bytes'],
            files=sum(r['kind'] == 'file' for r in initial['rows']),
            directories=sum(r['kind'] == 'directory' for r in initial['rows']))
        pattern = dict(m.PATTERN,bytes=len(self.fs.body[m.PATTERN['path']]),sha256=m.sha(self.fs.body[m.PATTERN['path']]))
        original_inventory = m.inventory.inventory
        def synthetic_baseline(guard):
            result = original_inventory(guard)
            # Tiny fixture's pinned original tree, not a claim about actual A.
            result['original_tree_sha256'] = pin['sha256']
            result['original_tree_matches'] = result['sha256'] == pin['sha256']
            return result
        for patch in (mock.patch.object(m,'PATTERN',pattern),mock.patch.object(m,'INPUT_PINS',tuple(dict(p) for p in m.inventory.INPUTS)),
                mock.patch.object(m,'TREE_PIN',pin),mock.patch.object(m.inventory,'inventory',side_effect=synthetic_baseline)):
            patch.start()
            self.addCleanup(patch.stop)
        self.fs.opened.clear()

    def capture(self):
        with mock.patch.object(m,'check_authority'):
            return m.capture(b'synthetic',b'synthetic',1060.,self.tick,self.clock)

    def test_default_denied_before_io_tick_or_clock(self):
        with mock.patch.object(m.source,'read_file') as read,mock.patch.object(m.inventory,'read_input') as inputs:
            with self.assertRaisesRegex(ValueError,'NO_FROZEN_E137_AUTHORITY'):
                m.capture(b'',b'',1060.,self.tick,self.clock)
        read.assert_not_called()
        inputs.assert_not_called()
        self.tick.assert_not_called()
        self.clock.assert_not_called()
        self.assertEqual(self.fs.opened,[])

    def test_exact_three_files_one_tree_hash_only_no_pdf_stat(self):
        observed = []
        original_stat = self.fs.stat
        def record(name,dir_fd=None,follow_symlinks=False):
            if dir_fd is not None:
                observed.append(self.fs.handles[dir_fd][0]+'/'+name)
            else:
                observed.append(name)
            return original_stat(name,dir_fd,follow_symlinks)
        with mock.patch.object(m.inventory.os,'stat',side_effect=record):
            value = self.capture()
        self.assertEqual(m.validate_receipt(m.canonical(value)),value)
        self.assertTrue(value['complete'])
        self.assertFalse(value['historical_vector_identity_proven'])
        self.assertFalse(value['stil_dependency_completeness_verified'])
        self.assertFalse(value['resource_enforcement_claimed'])
        self.assertNotIn('body_base64',m.canonical(value).decode('ascii'))
        pdf = m.source.FILES[1]['path']
        self.assertNotIn(pdf,observed)
        self.assertNotIn(pdf,self.fs.opened)
        self.assertEqual(self.fs.opened[:3],[m.PATTERN['path']]+[p['path'] for p in m.INPUT_PINS])
        self.assertTrue(all(p.startswith(m.inventory.BASE+'/') for p in observed if not p.startswith('/proc/self/fd/')))
        self.assertIsNone(m.source.AUTH_SHA)
        self.assertGreater(self.tick.call_count,5)

    def test_pattern_sha_or_size_drift_stops_before_other_inputs(self):
        path = m.PATTERN['path']
        self.fs.body[path] = b'x'*len(self.fs.body[path])
        with self.assertRaisesRegex(ValueError,'E137_PATTERN_DRIFT'):
            self.capture()
        self.assertEqual(self.fs.opened,[path])
        self.fs.body[path] = b'x'
        self.fs.info[path].st_size = 1
        with self.assertRaisesRegex(ValueError,'E137_PATTERN_DRIFT'):
            self.capture()

    def test_file_identity_type_uid_links_short_read_parent_mutation(self):
        import stat
        path = m.PATTERN['path']
        for key,bad in [('st_mode',stat.S_IFLNK),('st_mode',stat.S_IFIFO),('st_uid',0),('st_nlink',2)]:
            old = getattr(self.fs.info[path],key)
            setattr(self.fs.info[path],key,bad)
            with self.assertRaisesRegex(ValueError,'PREOPEN_REGULAR_SINGLE_LINK_OWNER'):
                self.capture()
            setattr(self.fs.info[path],key,old)
        self.assertEqual(self.fs.opened,[])
        self.fs.body[path] = b''
        with self.assertRaisesRegex(ValueError,'SHORT_OR_INVALID_READ'):
            self.capture()
        self.fs.body[path] = b'x'*self.fs.info[path].st_size
        self.fs.read_hook = lambda p:setattr(self.fs.info[p],'st_ctime_ns',101)
        with self.assertRaisesRegex(ValueError,'SOURCE_IDENTITY_CHANGED'):
            self.capture()
        self.fs.info[path].st_ctime_ns = 100
        parent = path.rsplit('/',1)[0]
        self.fs.read_hook = lambda p:setattr(self.fs.info[parent],'st_ino',999)
        with self.assertRaisesRegex(ValueError,'HELD_PARENT_CHANGED'):
            self.capture()

    def test_input_hash_and_tree_drift_rejected_not_new_baseline(self):
        path = m.INPUT_PINS[0]['path']
        original = self.fs.body[path]
        self.fs.body[path] = b'x'*len(original)
        with self.assertRaisesRegex(ValueError,'FIXED_INPUT_SHA'):
            self.capture()
        self.fs.body[path] = original
        self.fs.add(m.inventory.TREE+'/extra',raw=b'extra')
        with self.assertRaisesRegex(ValueError,'E137_EXACT_ORIGINAL_TREE'):
            self.capture()

    def test_bad_helper_path_scope_rejected_before_file_io(self):
        with mock.patch.object(m,'PATTERN',dict(m.PATTERN,path='/unlisted')):
            with self.assertRaisesRegex(ValueError,'E137_FIXED_HELPER_SCOPE'):
                self.capture()
        self.assertEqual(self.fs.opened,[])

    def test_supplied_deadline_never_reset_and_tick_stop(self):
        with mock.patch.object(m,'check_authority'):
            with self.assertRaisesRegex(ValueError,'E137_FIXED_READ_DEADLINE'):
                m.capture(b'',b'',1061.,self.tick,self.clock)
            with self.assertRaisesRegex(ValueError,'E137_READ_DEADLINE'):
                m.capture(b'',b'',1060.,self.tick,mock.Mock(side_effect=[1000.,1000.,1060.]))
            with self.assertRaisesRegex(ValueError,'E137_READ_DEADLINE'):
                m.capture(b'',b'',1060.,self.tick,mock.Mock(side_effect=[1000.,999.]))
            with self.assertRaisesRegex(ValueError,'RESOURCE_GUARD_STOP'):
                m.capture(b'',b'',1060.,mock.Mock(side_effect=ValueError('RESOURCE_GUARD_STOP')),self.clock)
        self.assertEqual(self.fs.opened,[])

    def test_receipt_rejects_body_export_path_hash_count_and_claim_changes(self):
        value = self.capture()
        changes = [lambda v:v['pattern'].update(body_base64='YQ=='),lambda v:v['pattern'].update(path='/other'),
            lambda v:v['pattern'].update(sha256='0'*64),lambda v:v['inputs'][1]['identity'].update(st_uid=0),
            lambda v:v['tree'].update(bytes=1),lambda v:v['tree'].update(sha256='0'*64),
            lambda v:v.update(stil_dependency_completeness_verified=True),lambda v:v.update(execution_ready=True),
            lambda v:v['tree']['rows'][2].update(relative='../x')]
        for change in changes:
            changed = copy.deepcopy(value)
            change(changed)
            with self.assertRaises(ValueError):
                m.validate_receipt(m.canonical(changed))
        with mock.patch.dict(m.BOUNDS,response_bytes=10):
            with self.assertRaisesRegex(ValueError,'E137_METADATA_CAP'):
                m.validate_receipt(m.canonical(value))


class PinTests(unittest.TestCase):
    def test_exact_pending_proposal_and_future_auth_dialect_only_synthetic(self):
        repo = Path(__file__).resolve().parents[1]
        proposal = (repo/'contracts/physical_f_clean_replay_proposal_e137_v1.json').read_bytes()
        self.assertEqual(m.sha(proposal),m.PROPOSAL_SHA)
        auth = dict(schema='physical-f-clean-replay-authorization-e137-v1',approval_source='explicit_user_reply',
            user_reply='\u90a3\u5c31\u6279\u51c6',approved_package='E137',user_authorization_received=True,
            proposal_sha256=m.PROPOSAL_SHA,approved_scope=m.decode(proposal)['scope_if_granted'])
        raw = m.canonical(auth)
        self.assertIsNone(m.AUTH_SHA)
        with mock.patch.object(m,'AUTH_SHA',m.sha(raw)):
            m.check_authority(raw,proposal)
            with self.assertRaises(ValueError):
                m.check_authority(raw+b' ',proposal)
            with self.assertRaises(ValueError):
                m.check_authority(raw,proposal+b' ')
        for key,bad in [('user_reply','\u6279\u51c6 E137 \u6574\u5305'),('approved_package','E135'),('schema','old'),('approved_scope',{}),('user_authorization_received',False)]:
            raw = m.canonical(dict(auth,**{key:bad}))
            with mock.patch.object(m,'AUTH_SHA',m.sha(raw)):
                with self.assertRaises(ValueError):
                    m.check_authority(raw,proposal)
        actual = (repo/'contracts/physical_f_clean_replay_authorization_e137.json').read_bytes()
        self.assertEqual(m.sha(actual),'49f000fe45de6cfc029ad8a9c1ead5e09edd24321de6062039d638436cce4969')
        self.assertEqual(m.decode(actual)['user_reply'],'\u90a3\u5c31\u6279\u51c6')
        self.assertNotIn('\ufffd',m.decode(actual)['user_reply'])
        with mock.patch.object(m,'AUTH_SHA',m.sha(actual)):
            m.check_authority(actual,proposal)

    def test_inert_ast36_dependency_pins_and_inherited_bounds(self):
        repo = Path(__file__).resolve().parents[1]
        raw = Path(m.__file__).read_bytes()
        ast.parse(raw.decode('utf-8'),feature_version=(3,6))
        ast.parse(Path(__file__).read_text(encoding='utf-8'),feature_version=(3,6))
        with mock.patch('builtins.open') as opened:
            namespace = dict(__package__='src.data')
            exec(compile(raw,'<inert-e137-core>','exec'),namespace)
        opened.assert_not_called()
        self.assertIsNone(namespace['AUTH_SHA'])
        self.assertNotIn('execute',namespace)
        for name,pin in m.DEPENDENCY_SHA256.items():
            self.assertEqual(m.sha((repo/'src/data'/(name+'.py')).read_bytes()),pin)
        self.assertEqual(m.BOUNDS['inherited_tree_metadata_bytes'],m.inventory.MAX_METADATA)
        self.assertLess(m.inventory.MAX_METADATA,m.BOUNDS['response_bytes'])
        self.assertEqual(m.PATTERN['bytes'],443378)
        self.assertEqual(m.TREE_PIN['files'],19)
        self.assertEqual(m.TREE_PIN['directories'],9)


if __name__ == '__main__':
    unittest.main()
