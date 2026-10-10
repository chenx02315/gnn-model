"""Synthetic parent contracts only: zero real packages, workers, ML or remote I/O.

Packet tests use generated temp evidence/pins. Run tests explicitly mock the
fence/guard/collector while using real core-byte binding, approvals and contexts.
A separate isolated subprocess exercises the actual sealed fence + four real
supplemental byte aliases; it never calls a trainer or reads a real package.
"""
from contextlib import contextmanager, nullcontext
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests import test_ranking_v5_single_fit_worker as worker_tests
from tests import test_ranking_v5_serial_matrix as matrix_tests
from src.models import ranking_v5_independent_fit_context as binding
from src.models import ranking_v5_serial_matrix as matrix
from src.models import ranking_v5_train_artifact_readback as reader
from src.models import ranking_v5_bound_input_reader as inputs
from src.models import ranking_v4_memory_guard as guard


REPO = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location('_unit_v5_serial_parent', REPO/'scripts/run_v5_train_serial_parent.py')
parent = importlib.util.module_from_spec(spec); spec.loader.exec_module(parent)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


class SerialParentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)/'gnn_model_ranking_v5_train_20261010_r1'; self.root.mkdir()
        cli_raw = (REPO/parent.CLI).read_bytes()
        self.cli = parent.external('_synthetic_cli', cli_raw)
        required = self.cli.CORE_FILES | {parent.CLI, parent.PROGRAM, parent.CPU_PROGRAM,
                                        *self.cli.HELPERS, *parent.EXTRA}
        self.source = {name: (REPO/name).read_bytes() for name in required}
        self.core_raw = encode(dict(schema='v5-caller-source-bytes-v1', formal_training_release=False,
            sources={name: parent.sha(self.source[name]) for name in self.cli.CORE_FILES}))
        args, kwargs, loaded = worker_tests.fixture()
        self.base_request = loaded['request']
        expected = {name: parent.sha(self.source[name]) for name in self.cli.RELEASE_SOURCE_FILES}
        release = deepcopy(args[3]); release['source_binding'] = expected
        physical_raw = encode(dict(synthetic_physical_gate_not_proof=True))
        physical_pin = parent.sha(physical_raw)
        review = json.loads(args[6]); review.update(release_sha256=binding.approval.review_subject(release),
            source_binding_sha256=binding.digest(expected), physical_gate_sha256=physical_pin)
        review_raw = encode(review); release['independent_review_receipt_sha256'] = parent.sha(review_raw)
        self.evidence = {'authorization.json': args[5], 'release.json': encode(release),
            'review.json': review_raw, 'physical_gate.json': physical_raw,
            'synthetic_linux_gate.json': encode(dict(synthetic_linux_not_proof=True))}
        receipt = matrix_tests.parent_receipt()
        child = dict(synthetic_cpu_receipt_not_proof=True)
        self.evidence.update({'cpu_gate.child.json': encode(child),
            'cpu_gate.memory.json': encode(receipt),
            'cpu_gate.launch.json': encode(dict(parent_guard_receipt=receipt,
                child_receipt_sha256=parent.sha(encode(child)), child_receipt=child))})
        overrides = dict(CORE_MANIFEST_SHA256=parent.sha(self.core_raw),
            AUTHORIZATION_SHA256=parent.sha(args[5]),
            SYNTHETIC_LINUX_GATE_SHA256=parent.sha(self.evidence['synthetic_linux_gate.json']))
        cli_raw += b'\n'+b'\n'.join((key+' = '+repr(value)).encode() for key, value in overrides.items())+b'\n'
        self.source[parent.CLI] = cli_raw
        self.cli = parent.external('_synthetic_cli', cli_raw)
        cpu_pins = {name: parent.sha(self.source[name]) for name in parent.CPU_PINS}
        cpu_evidence = {name: parent.sha(self.evidence[name]) for name in parent.CPU_EVIDENCE}
        self.enterContext(patch.object(parent, 'CPU_PINS', cpu_pins))
        self.enterContext(patch.object(parent, 'CPU_EVIDENCE', cpu_evidence))
        self.enterContext(patch.object(parent, 'ROOT_PATTERN', re.escape(self.root.as_posix())))
        self.envelopes = {}
        source_pins = {name: parent.sha(raw) for name, raw in self.source.items()}
        for family in sorted(self.cli.FAMILIES):
            for seed in self.cli.SEEDS:
                name = f'prelaunch_{family}_{seed}.json'
                envelope = dict(schema='v5-train-prelaunch-envelope-v1', source_root=self.root.as_posix(),
                    output=self.root.as_posix()+f'_{family}_{seed}', package_root=self.cli.PACKAGE_ROOT,
                    family=family, seed=seed, roles=['TRAIN'], parent_resource_guard_required=True,
                    core_manifest_sha256=self.cli.CORE_MANIFEST_SHA256,
                    helper_sha256={p: source_pins[p] for p in self.cli.HELPERS},
                    authorization_id=self.cli.AUTHORIZATION_ID,
                    **{field: parent.sha(self.evidence[p]) for p, field in self.cli.EVIDENCE.items()})
                self.envelopes[name] = encode(envelope)
        self.packet = dict(schema='v5-train-serial-launch-packet-v1', source_root=self.root.as_posix(),
            package_root=self.cli.PACKAGE_ROOT, core_manifest_sha256=self.cli.CORE_MANIFEST_SHA256,
            source_sha256=source_pins,
            evidence_sha256={name: parent.sha(raw) for name, raw in self.evidence.items()},
            prelaunch_sha256={name: parent.sha(raw) for name, raw in self.envelopes.items()})
        for name, raw in {**self.source, **self.evidence, **self.envelopes,
                          self.cli.MANIFEST_NAME: self.core_raw}.items():
            path = self.root/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
        self.refresh_packet()

    def refresh_packet(self):
        raw = encode(self.packet); (self.root/parent.MANIFEST).write_bytes(raw)
        self.packet_sha = parent.sha(raw)

    def test_load_packet_exact_actual_source_bytes_and_generated_evidence(self):
        cli, packet, sources, evidence, core = parent.load_packet(self.root.as_posix(), self.packet_sha)
        self.assertEqual(sources, self.source); self.assertEqual(evidence, self.evidence)
        self.assertEqual(core, self.core_raw); self.assertEqual(packet, self.packet)
        self.assertEqual(len(packet['prelaunch_sha256']), 18)
        self.assertEqual(cli.CORE_FILES, self.cli.CORE_FILES)

    def test_load_packet_missing_extra_source_evidence_and_prelaunch_reject(self):
        original = deepcopy(self.packet)
        for field in ('source_sha256', 'evidence_sha256', 'prelaunch_sha256'):
            for mode in ('missing', 'extra'):
                self.packet = deepcopy(original)
                if mode == 'missing': del self.packet[field][next(iter(self.packet[field]))]
                else: self.packet[field]['unexpected.py'] = 'a'*64
                self.refresh_packet()
                with self.subTest(field=field, mode=mode), self.assertRaises(ValueError):
                    parent.load_packet(self.root.as_posix(), self.packet_sha)

    def test_rawpin_and_source_evidence_prelaunch_drift_rejected(self):
        with self.assertRaisesRegex(ValueError, 'PACKET_SHA'):
            parent.load_packet(self.root.as_posix(), '0'*64)
        for name in (parent.CLI, parent.EXTRA[0], 'review.json', next(iter(self.envelopes)), self.cli.MANIFEST_NAME):
            path = self.root/name; original = path.read_bytes(); path.write_bytes(original+b' ')
            with self.subTest(name=name), self.assertRaises(ValueError):
                parent.load_packet(self.root.as_posix(), self.packet_sha)
            path.write_bytes(original)

    def test_bootstrap_only_fixed_program_paths_and_isolation(self):
        code = parent.bootstrap(self.root.as_posix(), parent.CLI, self.packet['source_sha256'][parent.CLI])
        self.assertIn('sys.flags.no_site==1 and sys.flags.isolated==1', code)
        self.assertIn(repr(list(parent.SEARCH_PATHS)), code)
        self.assertIn('os.chdir("/ssd/cjc")', code)
        self.assertNotIn(str(REPO), code)
        for name in ('other.py', '../scripts/run_v5_train_single_fit.py'):
            with self.assertRaises(ValueError): parent.bootstrap(self.root.as_posix(), name, 'a'*64)
        with self.assertRaises(ValueError): parent.bootstrap(self.root.as_posix(), parent.CLI, None)

    def run_synthetic(self, fail_index=None, context_fail_index=None, lock_conflict=False):
        events, contexts, executions = [], [], []
        self.synthetic_events = events
        self.synthetic_package_calls = []
        original_external = parent.external
        def external(name, raw):
            if name == '_v5_serial_fence': return SimpleNamespace(sealed_imports=lambda *args: nullcontext())
            if name == '_v5_serial_cpu_evidence':
                return SimpleNamespace(validate_child=lambda *args: None, typed_equal=lambda a, b: a == b)
            return original_external(name, raw)
        def load(root, family, seed):
            self.synthetic_package_calls.append((root, family, seed))
            request = deepcopy(self.base_request); request.update(family=family, seed=seed)
            request['fit_cycles'] = {r['action_uid']: (100 if r['action_uid'].endswith(':00')
                else 200+int(r['action_uid'].rsplit(':', 1)[1])) for r in request['rows'] if r['family'] != family}
            return dict(status=inputs.STATUS, request=request, input_identity=dict(family=family, seed=seed,
                source_sha256=binding.boundary.SOURCE_SHA256, package_receipt_sha256=binding.boundary.PACKAGE_SHA256,
                fold_manifest_sha256='c'*64))
        original_build = binding.build_independent_fit_context
        def build(*args, **kwargs):
            if len(contexts) == context_fail_index:
                raise ValueError('SYNTHETIC_CONTEXT_REJECTED')
            result = original_build(*args, **kwargs); contexts.append(result)
            events.append(('context', result.family, result.seed)); return result
        def bounded(argv, log, env):
            self.assertEqual(len(contexts), 18)
            self.assertEqual(argv[:5], [parent.INTERPRETER, '-I', '-S', '-B', '-c'])
            self.assertEqual(env['CUDA_VISIBLE_DEVICES'], '')
            family = argv[argv.index('--family')+1]; seed = int(argv[argv.index('--seed')+1])
            events.append(('execute', family, seed)); index = len(executions); executions.append((family, seed))
            if index == fail_index: raise RuntimeError('SYNTHETIC_WORKER_FAILURE')
            receipt = matrix_tests.parent_receipt()
            Path(log).write_bytes(b'SYNTHETIC_MOCK_NOT_WORKER_OUTPUT\n')
            Path(log+'.memory.json').write_bytes(encode(receipt))
            return receipt
        def collect(source_root, output, log, *, context, **kwargs):
            events.append(('review', context.family, context.seed))
            task = matrix.TrainTask(context.family, context.seed, output)
            return dict(artifact_check=matrix_tests.reviewed(task).artifact_check)
        @contextmanager
        def aliases(source, cli_module):
            self.assertEqual(set(source), set(parent.EXTRA))
            with patch.object(matrix, 'ROOT_PATTERN', re.escape(self.root.as_posix())):
                yield reader, binding, matrix, SimpleNamespace(collect_parent_artifact_candidate=collect)
        @contextmanager
        def conflict():
            raise BlockingIOError('SYNTHETIC_GLOBAL_LOCK_CONFLICT')
            yield  # contextmanager entry raises; body must never execute.
        with patch.object(parent, 'runtime'), \
             patch.object(parent, 'global_worker_lock', side_effect=conflict if lock_conflict else lambda: nullcontext()), \
             patch.object(parent, 'load_packet', return_value=(self.cli, self.packet, self.source, self.evidence, self.core_raw)), \
             patch.object(parent, 'external', side_effect=external), patch.object(parent, 'supplemental_aliases', aliases), \
             patch.object(inputs, 'load_bound_fold_request', side_effect=load), \
             patch.object(binding, 'build_independent_fit_context', side_effect=build), \
             patch.object(guard, 'run_bounded', side_effect=bounded):
            return parent.run(self.root.as_posix(), self.packet_sha)

    def test_run_eighteen_contexts_before_first_guard_alternating_review(self):
        result = self.run_synthetic()
        self.assertEqual(result['completed_count'], 18)
        expected = [('context', family, seed) for family in matrix.FAMILIES for seed in matrix.SEEDS]
        expected += [(kind, family, seed) for family in matrix.FAMILIES for seed in matrix.SEEDS
                     for kind in ('execute', 'review')]
        self.assertEqual(self.synthetic_events, expected)
        self.assertIs(result['numerical_model_predictions_verified'], False)
        self.assertIs(result['numerical_held_metrics_verified'], False)

    def test_first_worker_failure_stops_without_retry_and_started_marker_blocks_second_run(self):
        result = self.run_synthetic(fail_index=0)
        self.assertEqual(result['status'], 'STOPPED_NO_RETRY')
        self.assertEqual(result['completed_count'], 0); self.assertEqual(result['failed_index'], 0)
        self.assertEqual([e[0] for e in self.synthetic_events].count('execute'), 1)
        self.assertEqual([e[0] for e in self.synthetic_events].count('review'), 0)
        self.assertEqual([e[0] for e in self.synthetic_events].count('context'), 18)
        with self.assertRaises(ValueError): self.run_synthetic()
        self.assertFalse(any(e[0] == 'execute' for e in self.synthetic_events))

    def test_existing_output_rejects_before_context_or_guard_and_creates_no_started_marker(self):
        Path(self.root.as_posix()+'_'+matrix.FAMILIES[0]+'_'+str(matrix.SEEDS[0])).mkdir()
        with self.assertRaisesRegex(ValueError, 'OUTPUT_EXISTS'): self.run_synthetic()
        self.assertEqual(self.synthetic_events, [])
        self.assertFalse((self.root/'matrix.started.json').exists())

    def test_context_preflight_failure_sealed_without_any_guard_launch(self):
        with self.assertRaisesRegex(ValueError, 'SYNTHETIC_CONTEXT_REJECTED'):
            self.run_synthetic(context_fail_index=2)
        result = json.loads((self.root/'matrix.final.json').read_bytes())
        self.assertEqual(result['status'], 'STOPPED_PREFLIGHT_NO_RETRY')
        self.assertEqual(result['preflight_context_count'], 2)
        self.assertEqual(result['completed_count'], 0)
        self.assertFalse(any(event[0] == 'execute' for event in self.synthetic_events))
        self.assertIs(result['actual_parent_guard_used'], False)
        self.assertEqual(result['actual_fits_started'], 0)
        with self.assertRaises(ValueError): self.run_synthetic()

    def test_authorization_rejects_before_any_package_or_guard_touch(self):
        with patch.object(binding.approval, 'validate_approval_integrity',
                          side_effect=ValueError('SYNTHETIC_AUTHORIZATION_REJECTED')) as approval, \
             self.assertRaisesRegex(ValueError, 'SYNTHETIC_AUTHORIZATION_REJECTED'):
            self.run_synthetic()
        approval.assert_called_once()
        self.assertEqual(self.synthetic_package_calls, [])
        self.assertEqual(self.synthetic_events, [])
        self.assertFalse((self.root/'matrix.started.json').exists())
        self.assertFalse((self.root/'matrix.final.json').exists())

    def test_global_lock_conflict_zero_fit_no_package_or_marker(self):
        with self.assertRaisesRegex(BlockingIOError, 'SYNTHETIC_GLOBAL_LOCK_CONFLICT'):
            self.run_synthetic(lock_conflict=True)
        self.assertEqual(self.synthetic_package_calls, [])
        self.assertEqual(self.synthetic_events, [])
        self.assertFalse((self.root/'matrix.started.json').exists())
        self.assertFalse((self.root/'matrix.final.json').exists())


class RealSupplementalAliasTests(unittest.TestCase):
    def test_real_pinned_four_aliases_inside_unchanged_core_fence_and_cleanup(self):
        code = r'''
import hashlib, importlib, importlib.util, sys
from pathlib import Path
repo=Path(sys.argv[1])
spec=importlib.util.spec_from_file_location('_isolated_parent',repo/'scripts/run_v5_train_serial_parent.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
cli=p.external('_isolated_cli',(repo/p.CLI).read_bytes())
fence=p.external('_isolated_fence',(repo/p.FENCE).read_bytes())
sources={n:(repo/n).read_bytes() for n in cli.CORE_FILES if n.endswith('.py')}
pins={n:hashlib.sha256(v).hexdigest() for n,v in sources.items()}
extras={n:(repo/n).read_bytes() for n in p.EXTRA}
assert set(sources)==fence.FILES and len(fence.FILES)==25
names=[n[:-3].replace('/','.') for n in p.EXTRA]+['scripts.run_v5_train_single_fit']
with fence.sealed_imports(sources,pins):
    try:
        with p.supplemental_aliases(extras,cli) as modules:
            assert len(modules)==4
            assert all(n in sys.modules for n in names)
            assert modules[3].cli is cli
            try: importlib.import_module('src.models.unexpected_local_module')
            except ModuleNotFoundError as e: assert 'V5_FENCE_UNKNOWN_LOCAL' in str(e)
            else: raise AssertionError('unknown local accepted')
            assert not any(n.split('.')[0] in fence.HEAVY_ROOTS for n in sys.modules)
            raise RuntimeError('synthetic body failure')
    except RuntimeError as e: assert str(e)=='synthetic body failure'
    assert all(n not in sys.modules for n in names)
    package=importlib.import_module('src.models')
    assert not any(hasattr(package,n.rsplit('.',1)[-1]) for n in names[:-1])
    broken=dict(extras);broken[p.EXTRA[1]]=b'raise RuntimeError("synthetic compile body")\n'
    try:
        with p.supplemental_aliases(broken,cli): pass
    except RuntimeError: pass
    else: raise AssertionError('body failure not propagated')
    assert all(n not in sys.modules for n in names)
assert not any(n=='src' or n.startswith('src.') or n=='scripts' or n.startswith('scripts.') for n in sys.modules)
print('REAL_PINNED_ALIASES_SYNTHETIC_ONLY_OK')
'''
        result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', code, str(REPO)],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'REAL_PINNED_ALIASES_SYNTHETIC_ONLY_OK')


if __name__ == '__main__':
    unittest.main()
