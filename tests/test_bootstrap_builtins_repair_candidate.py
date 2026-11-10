"""Fixed actual-authority path with controlled builtins semantics, NO child.

Empty/minimal builtins emulate the relevant old-runtime namespace behavior;
these are NOT actual Python3.6 runs or proof of the remote exception. Host,
boot/worker identity, clock, process-domain sampling and supervision are explicit
substitutes. Actual pinned E127 code/profile and source-loader tags are retained.
The mock supervisor returns one finite failure, not an environment or tool PASS.
"""
import ast
import base64
import builtins
from contextlib import contextmanager, ExitStack
import hashlib
from pathlib import Path
import types
import unittest
from unittest import mock

from scripts import bootstrap_builtins_repair_candidate as repair
from scripts import e138_deployment_materials as materials
from scripts import e138_source_session as loader
from scripts import e139_native_graph_candidate as graph

REPO = Path(__file__).resolve().parents[1]
AUTH_SHA = '9e8b899d529983e29493ea253b32c58e543afca307b7e6bff6be8e599fd37e54'
sha = lambda raw: hashlib.sha256(raw).hexdigest()


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.authority = (REPO/'contracts/physical_f_clean_replay_authorization_e139.json').read_bytes()
        if len(cls.authority) != 1801 or sha(cls.authority) != AUTH_SHA:
            raise AssertionError('actual immutable authority pin mismatch')
        cls.proposal = (REPO/'contracts/physical_f_clean_replay_proposal_e139_v1.json').read_bytes()
        cls.material = materials.prepare().private_bytes()
        cls.origins = {n: raw for bundle in cls.material['roles'].values() for n, raw in bundle['sources'].items()}
        cls.sources = graph.build(cls.origins).private_sources()
        cls.original = cls.sources[repair.KEY]
        cls.effective = repair.build(cls.original).private_sources()[repair.KEY]

    @contextmanager
    def session(self, repaired):
        sources = dict(self.sources)
        if repaired:
            sources[repair.KEY] = self.effective
        pins = {n: sha(raw) for n, raw in sources.items()}
        rows = [dict(name=n, sha256=pins[n], body_base64=base64.b64encode(sources[n]).decode('ascii'))
                for n in graph.SOURCE_ORDER]
        with mock.patch.object(loader, 'FROZEN_SOURCE_SHA256', pins), \
             mock.patch.object(loader, 'FROZEN_SOURCE_ORDER', graph.SOURCE_ORDER):
            with loader.source_session(rows) as loaded:
                yield loaded

    def run_candidate(self, repaired, semantics):
        with self.session(repaired) as loaded:
            b = loaded[repair.KEY]
            contract = loaded['physical_e138_contract']
            contract.check_authority(self.authority, self.proposal, AUTH_SHA, sha(self.proposal))
            inputs = self.material['execution_inputs']
            self.assertEqual(sha(inputs['parent_worker_source']), b.WORKER_SHA256)
            self.assertEqual(sha(inputs['profile_source']), b.PROFILE_SHA256)
            for module in (b.direct,b.direct.base,b.process,b.profile,b.adapter,b.pins):
                self.assertEqual(module.__source_sha256__, b.SOURCE_PINS[module.__name__.rsplit('.',1)[1]])
            context = contract.canonical(dict(role='execution', authorization_sha256=AUTH_SHA,
                boot_id='3ebeb9bb-410c-476c-a000-5c625f590473',package_start=1000.,package_end=4600.,
                connection_start=2000.,utc_end=9000.,root=b.ROOT,phase=b.PHASE))
            package = dict(authority=self.authority,proposal=self.proposal,context=context,e112=inputs['e112'],
                worker_source=inputs['parent_worker_source'],profile_source=inputs['profile_source'])
            frozen = dict(authorization_sha256=AUTH_SHA,proposal_sha256=sha(self.proposal),context_sha256=sha(context),
                expected_boot_id='3ebeb9bb-410c-476c-a000-5c625f590473',root=b.ROOT,phase=b.PHASE)
            # Exact class, but skip Linux /proc/subreaper initialization explicitly.
            domain = object.__new__(b.direct.Descendants); domain.peak = 123
            domain.sample = mock.Mock(return_value={})
            tick = mock.Mock(); evidence = {}; missing = []
            original_function_type = b.FunctionType
            def function_type(code, namespace, name):
                if semantics != 'modern_implicit' and '__builtins__' not in namespace:
                    namespace['__builtins__'] = {} if semantics == 'empty' else {'repr': repr}
                fn = original_function_type(code, namespace, name)
                if repaired:
                    self.assertEqual(set(namespace['__builtins__']),set(repair.BUILTIN_NAMES))
                    self.assertFalse({'open','exec','__import__'} & set(namespace['__builtins__']))
                def invoke(*args):
                    try:
                        return fn(*args)
                    except NameError as exc:
                        missing.append(exc.name)
                        raise
                return invoke
            with ExitStack() as stack:
                for attr,key in (('AUTH_SHA256','authorization_sha256'),('PROPOSAL_SHA256','proposal_sha256'),
                    ('CONTEXT_SHA256','context_sha256'),('EXPECTED_BOOT_ID','expected_boot_id')):
                    stack.enter_context(mock.patch.object(b,attr,frozen[key]))
                stack.enter_context(mock.patch.object(b,'FunctionType',function_type))
                stack.enter_context(mock.patch.object(b.platform,'node',return_value='bupt-vncs2'))
                stack.enter_context(mock.patch.object(b.os,'getuid',return_value=1047,create=True))
                stack.enter_context(mock.patch.object(b.os.sys,'platform','linux'))
                stack.enter_context(mock.patch.object(b.process,'_boot_id',return_value=frozen['expected_boot_id']))
                stack.enter_context(mock.patch.object(b.process,'_check_worker'))
                stack.enter_context(mock.patch.object(b.time,'monotonic',return_value=2001.))
                stack.enter_context(mock.patch.object(b.time,'time',return_value=5000.))
                supervise=stack.enter_context(mock.patch.object(b.direct.base,'supervise',return_value=dict(
                    output=b'',cleaned=True,returncode=124,launch_attempted=True,failure='CASE_TIMEOUT')))
                spawn=stack.enter_context(mock.patch('subprocess.Popen',side_effect=AssertionError('NO CHILD')))
                query=stack.enter_context(mock.patch('subprocess.run',side_effect=AssertionError('NO HOST QUERY')))
                mkdir=stack.enter_context(mock.patch.object(Path,'mkdir'))
                expected='CHILD_CODE_BUILD' if not repaired and semantics != 'modern_implicit' else 'OBSERVATION_CHECK'
                with self.assertRaisesRegex(ValueError,'^E138_BOOTSTRAP_'+expected+'_FAILED$'):
                    b.bootstrap(package,domain,tick,frozen,evidence)
                if expected=='OBSERVATION_CHECK':
                    self.assertEqual(supervise.call_count,1)
                    args,kwargs=supervise.call_args
                    self.assertEqual(args[0][:2],['/bin/bash','-lc'])
                    self.assertTrue(args[0][2].startswith('module load mentor/tessent2021 >/dev/null && /usr/bin/python3 -I -S -B -c '))
                    self.assertEqual(args[1],'/'); self.assertEqual(args[2],2031.)
                    self.assertIs(args[3],domain); self.assertEqual(args[4],[65536])
                    self.assertEqual(evidence['bootstrap_children'],1)  # MOCK supervision call only.
                else:
                    supervise.assert_not_called(); self.assertEqual(evidence['bootstrap_children'],0)
                spawn.assert_not_called(); query.assert_not_called(); mkdir.assert_not_called()
            self.assertLessEqual(domain.peak,536870912)
            self.assertFalse(evidence['execution_ready'])
            self.assertEqual(evidence['stage_attempted'],expected)
            return missing

    def test_exact_finite_patch_pins_syntax_no_io_and_history_unchanged(self):
        self.assertEqual(sha(self.original),repair.ORIGIN_SHA256)
        self.assertEqual(sha(self.effective),repair.EFFECTIVE_SHA256)
        reversed_source=self.effective
        for old,new,count in repair.REPLACEMENTS:
            self.assertEqual(self.original.count(old.encode()),count)
            reversed_source=reversed_source.replace(new.encode(),old.encode())
        self.assertEqual(reversed_source,self.original)
        ast.parse(self.effective,feature_version=(3,6))
        with mock.patch('builtins.open') as opened,mock.patch('builtins.compile') as compiled:
            repair.build(self.original)
        opened.assert_not_called();compiled.assert_not_called()
        with self.assertRaises(ValueError):repair.build(self.original+b' ')
        for name,raw in self.origins.items():
            self.assertEqual((REPO/'src/data'/(name+'.py')).read_bytes(),raw)

    def test_unrepaired_semantic_emulation_exposes_repr_then_min(self):
        self.assertEqual(self.run_candidate(False,'empty'),['repr'])
        self.assertEqual(self.run_candidate(False,'repr_only'),['min'])

    def test_exact_nine_builtins_cover_frozen_capture_runtime_ast(self):
        raw=self.material['execution_inputs']['parent_worker_source']
        function=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name=='capture_runtime')
        required={n.id for n in ast.walk(function) if isinstance(n,ast.Name) and
                  isinstance(n.ctx,ast.Load) and n.id in vars(builtins)}
        self.assertEqual(required,set(repair.BUILTIN_NAMES))
        self.assertEqual(len(repair.BUILTIN_NAMES),9)

    def test_explicit_builtins_reaches_checked_mock_supervision_under_both_emulations(self):
        self.assertEqual(self.run_candidate(True,'empty'),[])
        self.assertEqual(self.run_candidate(True,'repr_only'),[])

    def test_modern_implicit_builtins_masks_unrepaired_namespace_gap(self):
        self.assertEqual(self.run_candidate(False,'modern_implicit'),[])


if __name__=='__main__':
    unittest.main()
