"""E138 synthetic grant + virtual sources only; no actual phase or process."""
import ast
import copy
from pathlib import Path
import unittest
from unittest import mock

from src.data import physical_replay_capture_e138 as m
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
        proposal = dict(schema='e138-fixed-f-replay-proposal-v1',package='E138',
            status='PENDING_EXPLICIT_WHOLE_PACKAGE_AUTHORIZATION',scope_if_granted=copy.deepcopy(m.contract.POLICY))
        self.proposal = m.canonical(proposal)
        self.authority = m.canonical(dict(schema='e138-explicit-whole-package-authorization-v1',
            approved_package='E138',approval_source='explicit_user_reply',user_reply='synthetic-test-only',
            user_authorization_received=True,proposal_sha256=m.sha(self.proposal),
            approved_scope=copy.deepcopy(m.contract.POLICY),execution_ready=False))
        modules = dict(physical_e138_contract=m.contract,prospective_acceptance_materializer_v1=m.anchored,
            physical_replay_source_reader_e135=m.source,physical_replay_source_inventory_e135=m.inventory)
        for patch in [mock.patch.object(m,'AUTH_SHA',m.sha(self.authority)),
                mock.patch.object(m,'PROPOSAL_SHA',m.sha(self.proposal))]+[
                mock.patch.object(module,'__source_sha256__',m.DEPENDENCY_SHA256[name],create=True)
                for name,module in modules.items()]:
            patch.start()
            self.addCleanup(patch.stop)
        self.fs.opened.clear()

    def capture(self):
        return m.capture(self.authority,self.proposal,1060.,self.tick,self.clock)

    def test_default_denied_before_io_tick_or_clock(self):
        with mock.patch.object(m,'AUTH_SHA',None),mock.patch.object(m,'PROPOSAL_SHA',None),\
                mock.patch.object(m.source,'read_file') as read,mock.patch.object(m.inventory,'read_input') as inputs:
            with self.assertRaisesRegex(ValueError,'E138_AUTHORITY_PINS_NOT_CONFIGURED'):
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
        self.assertFalse(value['remote_authorization_proven'])
        self.assertFalse(value['source_provenance_authenticated'])
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
        with self.assertRaisesRegex(ValueError,'E138_PATTERN_DRIFT'):
            self.capture()
        self.assertEqual(self.fs.opened,[path])
        self.fs.body[path] = b'x'
        self.fs.info[path].st_size = 1
        with self.assertRaisesRegex(ValueError,'E138_PATTERN_DRIFT'):
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
        with self.assertRaisesRegex(ValueError,'E138_EXACT_ORIGINAL_TREE'):
            self.capture()

    def test_bad_helper_path_scope_rejected_before_file_io(self):
        with mock.patch.object(m,'PATTERN',dict(m.PATTERN,path='/unlisted')):
            with self.assertRaisesRegex(ValueError,'E138_FIXED_HELPER_SCOPE'):
                self.capture()
        self.assertEqual(self.fs.opened,[])

    def test_supplied_deadline_never_reset_and_tick_stop(self):
        with mock.patch.object(m.contract,'check_authority',wraps=m.contract.check_authority):
            with self.assertRaisesRegex(ValueError,'E138_FIXED_READ_DEADLINE'):
                m.capture(self.authority,self.proposal,1061.,self.tick,self.clock)
            with self.assertRaisesRegex(ValueError,'E138_READ_DEADLINE'):
                m.capture(self.authority,self.proposal,1060.,self.tick,mock.Mock(side_effect=[1000.,1000.,1060.]))
            with self.assertRaisesRegex(ValueError,'E138_READ_DEADLINE'):
                m.capture(self.authority,self.proposal,1060.,self.tick,mock.Mock(side_effect=[1000.,999.]))
            with self.assertRaisesRegex(ValueError,'RESOURCE_GUARD_STOP'):
                m.capture(self.authority,self.proposal,1060.,mock.Mock(side_effect=ValueError('RESOURCE_GUARD_STOP')),self.clock)
        self.assertEqual(self.fs.opened,[])

    def test_receipt_rejects_body_export_path_hash_count_and_claim_changes(self):
        value = self.capture()
        changes = [lambda v:v['pattern'].update(body_base64='YQ=='),lambda v:v['pattern'].update(path='/other'),
            lambda v:v['pattern'].update(sha256='0'*64),lambda v:v['inputs'][1]['identity'].update(st_uid=0),
            lambda v:v['tree'].update(bytes=1),lambda v:v['tree'].update(sha256='0'*64),
            lambda v:v.update(stil_dependency_completeness_verified=True),lambda v:v.update(execution_ready=True),lambda v:v.update(remote_authorization_proven=True),
            lambda v:v.update(source_provenance_authenticated=True),lambda v:v['bounds'].update(seconds=True),
            lambda v:v['pattern']['identity'].update(st_nlink=True),lambda v:v['tree'].update(entries=True),
            lambda v:v['tree']['rows'][2].update(relative='../x')]
        for change in changes:
            changed = copy.deepcopy(value)
            change(changed)
            with self.assertRaises(ValueError):
                m.validate_receipt(m.canonical(changed))
        with mock.patch.dict(m.BOUNDS,response_bytes=10):
            with self.assertRaisesRegex(ValueError,'E138_METADATA_CAP'):
                m.validate_receipt(m.canonical(value))


    def test_source_binding_drift_missing_or_unconfigured_contract_stops_before_time(self):
        for module in (m.source,m.inventory,m.anchored,m.contract):
            with mock.patch.object(module,'__source_sha256__','0'*64,create=True):
                with self.assertRaisesRegex(ValueError,'E138_FROZEN_DEPENDENCY_SOURCE_BINDINGS'):
                    self.capture()
        with mock.patch.dict(m.DEPENDENCY_SHA256,physical_e138_contract=None):
            with self.assertRaisesRegex(ValueError,'E138_FROZEN_DEPENDENCY_SOURCE_BINDINGS'):
                self.capture()
        self.assertEqual(self.fs.opened,[])
        self.tick.assert_not_called()
        self.clock.assert_not_called()

    def test_old_grant_and_changed_policy_do_not_get_to_io(self):
        with mock.patch.object(m,'AUTH_SHA',m.contract.OLD_AUTH_SHA256):
            with self.assertRaisesRegex(ValueError,'E138_AUTHORITY_PINS_NOT_CONFIGURED'):
                self.capture()
        old = m.decode(self.authority)
        old.update(schema='physical-f-clean-replay-authorization-e137-v1',approved_package='E137')
        raw = m.canonical(old)
        with mock.patch.object(m,'AUTH_SHA',m.sha(raw)):
            with self.assertRaisesRegex(ValueError,'E138_NEW_EXPLICIT_GRANT_REQUIRED'):
                m.capture(raw,self.proposal,1060.,self.tick,self.clock)
        changed = m.decode(self.authority)
        changed['approved_scope']['automatic_retries'] = True
        raw = m.canonical(changed)
        with mock.patch.object(m,'AUTH_SHA',m.sha(raw)):
            with self.assertRaisesRegex(ValueError,'E138_EXACT_FROZEN_POLICY'):
                m.capture(raw,self.proposal,1060.,self.tick,self.clock)
        self.assertEqual(self.fs.opened,[])
        self.tick.assert_not_called()
        self.clock.assert_not_called()

    def test_alias_caps_streaming_and_protected_names_inherited_unchanged(self):
        with mock.patch.object(m.inventory.os,'readlink',return_value='/unlisted'):
            with self.assertRaisesRegex(ValueError,'TREE_FD_ALIAS_CHANGED'):
                self.capture()
        for key,bad,code in [('MAX_ENTRIES',2,'TREE_ENTRY_CAP'),('MAX_DEPTH',1,'TREE_DEPTH_CAP'),
                ('MAX_BYTES',1,'INVENTORY_BYTE_CAP'),('MAX_METADATA',10,'TREE_METADATA_CAP')]:
            with mock.patch.object(m.inventory,key,bad):
                with self.assertRaises(ValueError):
                    self.capture()
        path = m.inventory.TREE+'/.ssh'
        self.fs.add(path,directory=True)
        with self.assertRaisesRegex(ValueError,'TREE_ENTRY_NAME'):
            self.capture()
        self.assertNotIn(path,self.fs.opened)
        del self.fs.info[path]
        del self.fs.body[path]
        original = self.fs.read
        with mock.patch.object(m.source.os,'read',side_effect=lambda fd,n:original(fd,min(n,7))) as read:
            self.capture()
        self.assertTrue(all(0 < call[0][1] <= 65536 for call in read.call_args_list))

    def test_receipt_duplicate_unknown_nan_overflow_and_old_schema_rejected(self):
        value = self.capture()
        raw = m.canonical(value)
        for bad in (b'{"schema":"x",'+raw[1:],raw.replace(b'false',b'NaN',1),
                raw.replace(b'false',b'1e999',1),m.canonical(dict(value,unknown=True)),
                m.canonical(dict(value,schema='physical-f-clean-replay-source-capture-e137-v1'))):
            with self.assertRaises(ValueError):
                m.validate_receipt(bad)
        with mock.patch.object(m,'AUTH_SHA',None):
            with self.assertRaisesRegex(ValueError,'E138_RECEIPT_PINS_NOT_CONFIGURED'):
                m.validate_receipt(raw)

    def test_identity_nanoseconds_remain_exact_in_metadata_and_local_validation(self):
        nanos = 1793069176022511787
        for path in (m.PATTERN['path'],m.INPUT_PINS[0]['path'],m.inventory.TREE+'/d/a'):
            self.fs.info[path].st_mtime_ns = nanos
            self.fs.info[path].st_ctime_ns = nanos+1
        value = self.capture()
        decoded = m.validate_receipt(m.canonical(value))
        for row in (decoded['pattern'],decoded['inputs'][0],
                next(r for r in decoded['tree']['rows'] if r['relative'] == 'd/a')):
            self.assertIs(type(row['identity']['st_mtime_ns']),int)
            self.assertEqual(row['identity']['st_mtime_ns'],nanos)
            self.assertEqual(row['identity']['st_ctime_ns'],nanos+1)


class PinTests(unittest.TestCase):
    def test_inert_ast36_dependencies_original_sources_and_globals_unchanged(self):
        from src.data import physical_replay_capture_e137 as old
        repo = Path(__file__).resolve().parents[1]
        raw = Path(m.__file__).read_bytes()
        ast.parse(raw.decode('utf-8'),feature_version=(3,6))
        ast.parse(Path(__file__).read_text(encoding='utf-8'),feature_version=(3,6))
        with mock.patch('builtins.open') as opened:
            namespace = dict(__package__='src.data')
            exec(compile(raw,'<inert-e138-core>','exec'),namespace)
        opened.assert_not_called()
        self.assertIsNone(namespace['AUTH_SHA'])
        self.assertIsNone(namespace['PROPOSAL_SHA'])
        self.assertNotIn('execute',namespace)
        self.assertIsNone(m.source.AUTH_SHA)
        self.assertIsNone(old.AUTH_SHA)
        self.assertEqual(old.SCHEMA,'physical-f-clean-replay-source-capture-e137-v1')
        for name,pin in m.DEPENDENCY_SHA256.items():
            self.assertEqual(m.sha((repo/'src/data'/(name+'.py')).read_bytes()),pin)
        self.assertEqual(m.sha(Path(old.__file__).read_bytes()),
            '5d911a9df834b1e155f1bd200261ffb078be98bd0420b31b39d71140ef500e76')
        self.assertEqual(m.BOUNDS['inherited_tree_metadata_bytes'],m.inventory.MAX_METADATA)
        self.assertEqual(m.BOUNDS['sampled_memory_bytes'],536870912)
        self.assertEqual(m.PATTERN,old.PATTERN)
        self.assertEqual(m.INPUT_PINS,old.INPUT_PINS)
        self.assertEqual(m.TREE_PIN,old.TREE_PIN)
        self.assertEqual((m.PATTERN['bytes'],m.TREE_PIN['files'],m.TREE_PIN['directories']),(443378,19,9))
        self.assertNotIn(m.contract.ROOT,m.PATTERN['path'])

    def test_pure_synthetic_authority_checks_no_provenance_or_permission_claim(self):
        proposal = m.canonical(dict(schema='e138-fixed-f-replay-proposal-v1',package='E138',
            status='PENDING_EXPLICIT_WHOLE_PACKAGE_AUTHORIZATION',scope_if_granted=m.contract.POLICY))
        auth = m.canonical(dict(schema='e138-explicit-whole-package-authorization-v1',
            approved_package='E138',approval_source='explicit_user_reply',user_reply='synthetic-test-only',
            user_authorization_received=True,proposal_sha256=m.sha(proposal),
            approved_scope=m.contract.POLICY,execution_ready=False))
        result = m.contract.check_authority(auth,proposal,m.sha(auth),m.sha(proposal))
        self.assertFalse(result['remote_authorization_proven'])
        self.assertFalse(result['execution_ready'])
        for a,p in ((auth+b' ',proposal),(auth,proposal+b' ')):
            with self.assertRaisesRegex(ValueError,'E138_AUTHORITY_EXACT_BYTES'):
                m.contract.check_authority(a,p,m.sha(auth),m.sha(proposal))


if __name__ == '__main__':
    unittest.main()
