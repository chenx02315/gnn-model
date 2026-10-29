"""Synthetic virtual files only; no real STIL, process, network or A access."""
import ast
import copy
from pathlib import Path
import stat
import unittest
from unittest import mock

from src.data import physical_stil_dependencies_e137 as m
from tests.test_hf_credit_artifact_reader_e134 import Files

SIMPLE = b'STIL 1.0; Signals { "a" In; } Pattern p { V { "a" = 0; } }'
SOURCE = 'c'*64  # Synthetic bootstrap assertion, NOT an actual authority.


class DependenciesTests(unittest.TestCase):
    def setUp(self):
        self.paths = [r['path'] for r in m.FIXED]+[m.ROOT+'/tsdb/part%d.stil'%i for i in range(19)]
        self.bodies = {p:(SIMPLE if i == 0 else b'fixed binary data') for i,p in enumerate(self.paths)}
        self.fs = Files([],[])
        for path in self.paths:
            self.fs.add(path.rsplit('/',1)[0],directory=True)
            self.fs.add(path,raw=self.bodies[path])
        self.tick = mock.Mock()
        patches = [mock.patch.object(m.anchored,'_directory',side_effect=self.fs.directory),
            mock.patch.object(m.os,'stat',side_effect=self.fs.stat),
            mock.patch.object(m.os,'fstat',side_effect=self.fs.fstat),
            mock.patch.object(m.os,'open',side_effect=self.fs.open),
            mock.patch.object(m.os,'read',side_effect=self.fs.read),
            mock.patch.object(m.os,'close',side_effect=self.fs.close),
            mock.patch.object(m.os,'O_NOFOLLOW',131072,create=True),
            mock.patch.object(m.os,'O_NONBLOCK',262144,create=True),
            mock.patch.object(m.verify,'__source_sha256__',SOURCE,create=True)]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.addCleanup(lambda:self.assertEqual(self.fs.handles,{}))

    def body(self,path,raw):
        self.bodies[path] = raw
        self.fs.body[path] = raw
        self.fs.info[path].st_size = len(raw)

    def run_verify(self,allowed=None):
        rows = sorted([dict(path=p,bytes=len(self.bodies[p]),sha256=m.sha(self.bodies[p]))
            for p in self.paths],key=lambda r:r['path'])
        # Synthetic sizes/digests replace only frozen content pins, never paths
        # or count/grammar/safety checks. No production authority is created.
        fixed = tuple(next(r for r in rows if r['path'] == p) for p in self.paths[:3])
        with mock.patch.object(m,'FIXED',fixed),mock.patch.object(m,'TREE_BYTES',
                sum(len(self.bodies[p]) for p in self.paths[3:])):
            return m.verify(m.PATTERN,rows if allowed is None else allowed,self.tick)

    def test_simple_full_hash_receipt_inert_scope_and_no_mutation(self):
        with mock.patch('subprocess.Popen') as spawn,mock.patch.object(m.os,'scandir') as scan:
            result = self.run_verify()
        spawn.assert_not_called(); scan.assert_not_called()
        self.assertEqual(result['status'],'PASS')
        self.assertEqual(result['files_verified'],22)
        self.assertEqual(result['parsed_files'],[m.PATTERN])
        self.assertEqual(result['validator_source_sha256'],SOURCE)
        self.assertEqual(result['pattern_sha256'],m.sha(SIMPLE))
        for key in ('full_STIL_semantics_verified','tool_import_verified','execution_ready',
                    'training_release','runtime_authority_verified','resource_enforcement_claimed'):
            self.assertIs(result[key],False)
        self.assertEqual(len(self.fs.opened),23)
        self.assertTrue(self.tick.called)

    def test_missing_source_binding_or_bad_scope_denies_before_io_or_tick(self):
        with mock.patch.object(m.verify,'__source_sha256__',None):
            with self.assertRaisesRegex(ValueError,'FROZEN_VALIDATOR'):
                self.run_verify()
        with self.assertRaisesRegex(ValueError,'EXACT_CLONED_ALLOWLIST'):
            self.run_verify([])
        self.assertEqual(self.fs.opened,[])
        self.tick.assert_not_called()

    def test_absolute_include_recursion_repeat_edges_and_exact_allowlist_hash(self):
        a,b = self.paths[3:5]
        self.body(m.PATTERN,('STIL 1.0; Include "%s"; Include "%s"; Pattern p {}'%(a,a)).encode('ascii'))
        self.body(a,('STIL 1.0; Include "%s"; Signals {}'%b).encode('ascii'))
        self.body(b,SIMPLE)
        original = copy.deepcopy(self.bodies)
        result = self.run_verify()
        self.assertEqual(result['parsed_files'],sorted((m.PATTERN,a,b)))
        self.assertEqual(len(result['include_edges']),3)
        self.assertEqual(self.bodies,original)
        rows = sorted([dict(path=p,bytes=len(raw),sha256=m.sha(raw)) for p,raw in self.bodies.items()],key=lambda r:r['path'])
        self.assertEqual(result['exact_allowlist_sha256'],m.sha(m.canonical(rows)))

    def test_comments_strings_expressions_annotations_do_not_create_dependencies(self):
        self.body(m.PATTERN,b'''// Include "/outside";
STIL 1.0; /* Include "/outside2"; */
Ann {* Include "/outside3"; { /* "anything *}
Signals { "Include" In; "\\opaque" Out; }
Timing t { WaveformTable w { Period 'Include'; } }
Pattern p { V { "Include" = 0; } }
''')
        self.assertEqual(self.run_verify()['include_edges'],[])

    def test_outside_relative_dotdot_or_unlisted_includes_never_open_target(self):
        for target in ('/outside/file.stil','relative.stil',m.ROOT+'/tsdb/../inputs/tester.stil',
                       m.ROOT+'/tsdb/not-listed.stil',m.ROOT+'/tsdb/$ENV.stil'):
            self.body(m.PATTERN,('STIL 1.0; Include "%s";'%target).encode('ascii'))
            self.fs.opened = []
            with self.assertRaises(ValueError):
                self.run_verify()
            self.assertNotIn(target,self.fs.opened)
            self.assertTrue(set(self.fs.opened).issubset(self.paths))

    def test_ifneed_extensions_unquoted_case_variant_and_ambiguous_escapes_rejected(self):
        a = self.paths[3]
        samples = [
            'STIL 1.0; Include "%s" IfNeed Pattern;'%a,
            'STIL 1.0; Include %s;'%a,
            'STIL 1.0; include "%s";'%a,
            'STIL 1.0 { Design 2005; }',
            'STIL 1.0; UserKeywords FileReference;',
            'STIL 1.0; Pattern p { FileReference "outside"; }',
            'STIL 1.0; Signals { "escaped\\\\name" In; }',
            'STIL 1.0; Pattern p { \\q }',
        ]
        for text in samples:
            self.body(m.PATTERN,text.encode('ascii'))
            with self.assertRaises(ValueError,msg=text):
                self.run_verify()

    def test_cycle_depth_and_edge_bounds(self):
        a = self.paths[3]
        self.body(m.PATTERN,('STIL 1.0; Include "%s";'%a).encode('ascii'))
        self.body(a,('STIL 1.0; Include "%s";'%m.PATTERN).encode('ascii'))
        with self.assertRaisesRegex(ValueError,'INCLUDE_CYCLE'):
            self.run_verify()
        self.body(a,SIMPLE)
        with mock.patch.object(m,'MAX_DEPTH',0):
            with self.assertRaisesRegex(ValueError,'INCLUDE_DEPTH_CAP'):
                self.run_verify()
        with mock.patch.object(m,'MAX_EDGES',0):
            with self.assertRaisesRegex(ValueError,'INCLUDE_EDGE_CAP'):
                self.run_verify()

    def test_non_stil_target_or_incomplete_lexical_constructs_reject(self):
        for raw in (b'STIL 1.0; /* open',b'STIL 1.0; Ann {* open',
                    b'STIL 1.0; Signals { "open',b'STIL 1.0; Pattern p {',
                    b'STIL 1.0; UnknownBlock {}',b'STIL 1.0; \x00',
                    b'STIL 1.0; /* nested /* x */ */'):
            self.body(m.PATTERN,raw)
            with self.assertRaises(ValueError):
                self.run_verify()
        a = self.paths[3]
        self.body(m.PATTERN,('STIL 1.0; Include "%s";'%a).encode('ascii'))
        with self.assertRaisesRegex(ValueError,'SELF_CONTAINED_STIL'):
            self.run_verify()

    def test_preopen_special_owner_link_or_size_never_open_bad_leaf(self):
        path = self.paths[0]
        for key,bad in (('st_mode',stat.S_IFLNK),('st_mode',stat.S_IFIFO),
                        ('st_uid',999),('st_nlink',2),('st_size',999)):
            old = getattr(self.fs.info[path],key)
            setattr(self.fs.info[path],key,bad)
            self.fs.opened = []
            with self.assertRaises(ValueError):
                self.run_verify()
            self.assertNotIn(path,self.fs.opened)
            setattr(self.fs.info[path],key,old)

    def test_hash_mismatch_short_read_and_identity_change_keep_no_receipt(self):
        path = self.paths[0]
        self.fs.body[path] = b'x'*len(self.bodies[path])
        with self.assertRaisesRegex(ValueError,'SHA_MISMATCH'):
            self.run_verify()
        self.fs.body[path] = b''
        with self.assertRaisesRegex(ValueError,'SHORT_READ'):
            self.run_verify()
        self.fs.body[path] = self.bodies[path]
        def changed(readpath):
            if readpath == path:
                self.fs.info[path].st_ctime_ns += 1
        self.fs.read_hook = changed
        with self.assertRaisesRegex(ValueError,'FILE_CHANGED'):
            self.run_verify()

    def test_parent_replacement_and_cohort_mutation_after_hash_rejected(self):
        parent = m.PATTERN.rsplit('/',1)[0]
        original = self.fs.directory
        calls = [0]
        def swapped(path):
            if path == parent:
                calls[0] += 1
                if calls[0] == 2:
                    self.fs.info[parent].st_ino += 1
            return original(path)
        with mock.patch.object(m.anchored,'_directory',side_effect=swapped):
            with self.assertRaisesRegex(ValueError,'PARENT_REPLACED'):
                self.run_verify()
        self.fs.read_hook = None
        target = self.paths[1]
        reads = [0]
        def cohort(path):
            if path == m.PATTERN:
                reads[0] += 1
                if reads[0] == 3:
                    self.fs.info[target].st_ino += 1
        self.fs.read_hook = cohort
        with self.assertRaisesRegex(ValueError,'FINAL_COHORT_CHANGED'):
            self.run_verify()

    def test_stream_chunks_deadline_parse_bound_and_python36(self):
        self.body(m.PATTERN,b'STIL 1.0; //'+b'x'*140000+b'\nPattern p {}')
        real = self.fs.read
        sizes = []
        def read(fd,count):
            sizes.append(count)
            return real(fd,count)
        with mock.patch.object(m.os,'read',side_effect=read):
            self.run_verify()
        self.assertLessEqual(max(sizes),65536)
        self.tick.side_effect = ValueError('SYNTHETIC_DEADLINE')
        with self.assertRaisesRegex(ValueError,'SYNTHETIC_DEADLINE'):
            self.run_verify()
        self.tick.side_effect = None
        with mock.patch.object(m,'MAX_PARSE_BYTES',1):
            with self.assertRaisesRegex(ValueError,'PARSE_BYTE_CAP'):
                self.run_verify()
        for path in (Path(m.__file__),Path(__file__)):
            ast.parse(path.read_text(encoding='utf-8'),feature_version=(3,6))


if __name__ == '__main__':
    unittest.main()
