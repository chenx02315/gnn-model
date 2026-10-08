import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock
from contextlib import contextmanager
from types import SimpleNamespace

from scripts import run_v5_controlled_runtime_gate as gate
from scripts import v5_runtime_gate_packet as packet


class RuntimeGateTests(unittest.TestCase):
    def pins(self): return {name: 'a'*64 for name in (gate.OBS, gate.CONTEXT, gate.PROGRAM)}

    def worker(self):
        site = '/ssd/cjc/gnn_model_runtime_v2_98efbd4f_20261002T235119/venv/lib/python3.11/site-packages/'
        return dict(status='PASS_CONTROLLED_CPU_IMPORT_TENSOR_ONLY', supplemental_sha256=self.pins(),
            core_manifest_sha256=gate.CORE_SHA, torch_version='2.5.1+cu124', numpy_version='2.1.3',
            torch_origin=site+'torch/__init__.py', numpy_origin=site+'numpy/__init__.py',
            threads=1, interop_threads=1, cuda_available=False,
            child_prerequisites=dict(status='PASS_CHILD_PREREQUISITES_ONLY',
                address_space_limits=[8*1024**3]*2, core_limits=[0, 0], threads=1,
                parent_sampled_rss_enforcement_proven=False, authentic_user_consent_proven=False),
            actual_torch_fits=0, production_package_reads=0, formal_training_release=False, automatic_retries=0)

    def test_worker_pass(self): gate.validate_child(self.worker(), self.pins())

    def test_prerequisite_bool_int_masquerade_refuses(self):
        for key, value in [('core_limits', [False, False]), ('address_space_limits', [float(8*1024**3)]*2),
                           ('parent_sampled_rss_enforcement_proven', 0), ('authentic_user_consent_proven', 0),
                           ('threads', True), ('extra', False)]:
            with self.subTest(key=key):
                payload = self.worker(); payload['child_prerequisites'][key] = value
                with self.assertRaises(ValueError): gate.validate_child(payload, self.pins())

    @contextmanager
    def synthetic_context(self, *args, **kwargs): yield {'synthetic': True}

    def test_parent_guard_receipt_and_child_reread_order(self):
        from src.models import ranking_v4_memory_guard as guard
        memory = dict(status='PASS_BOUNDED_WORKER', memory_policy=guard.policy(),
            initial_available_bytes=60*1024**3, effective_total_bytes=64*1024**3,
            reserve_bytes=6871947674, sample_count=1, peak_group_rss_bytes=123,
            peak_combined_rss_bytes=456, exit_code=0, process_group=9, elapsed_seconds=.5)
        root = '/ssd/cjc/gnn_model_ranking_v5_runtime_gate_20261008_r1'
        events = []
        def bounded(*args):
            events.append('guard')
            self.assertEqual(args[0][:5], [gate.INTERPRETER, '-I', '-S', '-B', '-c'])
            self.assertIn('--child', args[0]); return memory
        def read(path, cap):
            events.append(Path(path).name)
            return json.dumps(memory if str(path).endswith('.memory.json') else self.worker()).encode()
        loaded = (SimpleNamespace(sealed_imports=self.synthetic_context), {}, {}, {}, {})
        with mock.patch.object(gate, 'load', return_value=loaded), mock.patch.object(Path, 'is_symlink', return_value=False), \
                mock.patch.object(Path, 'exists', return_value=False), mock.patch.object(guard, 'run_bounded', side_effect=bounded), \
                mock.patch.object(gate, 'read', side_effect=read), mock.patch.object(gate, 'write', side_effect=lambda *a: events.append('write')):
            result = gate.parent(root, self.pins())
        self.assertEqual(events, ['guard', gate.LOG+'.memory.json', gate.CHILD, 'write'])
        self.assertFalse(result['formal_training_release'])
        self.assertEqual(result['actual_torch_fits'], 0)

    def test_parent_guard_failure_never_reads_or_writes_success(self):
        from src.models import ranking_v4_memory_guard as guard
        loaded = (SimpleNamespace(sealed_imports=self.synthetic_context), {}, {}, {}, {})
        with mock.patch.object(gate, 'load', return_value=loaded), mock.patch.object(Path, 'is_symlink', return_value=False), \
                mock.patch.object(Path, 'exists', return_value=False), mock.patch.object(guard, 'run_bounded', side_effect=RuntimeError('fail')), \
                mock.patch.object(gate, 'read') as read, mock.patch.object(gate, 'write') as write:
            with self.assertRaises(RuntimeError): gate.parent('/ssd/cjc/gnn_model_ranking_v5_runtime_gate_20261008_r1', self.pins())
        read.assert_not_called(); write.assert_not_called()

    def test_child_resource_failure_before_ml_import(self):
        from src.models import ranking_v5_worker_resource_context as resource
        import builtins
        original = builtins.__import__
        ml_imports = []
        def watched(name, *args, **kwargs):
            if name in ('torch', 'numpy'): ml_imports.append(name)
            return original(name, *args, **kwargs)
        loaded = (object(), {gate.OBS: b'pass', gate.CONTEXT: b'pass'}, {'requirements/runtime_v2.lock.txt': b'lock'}, {}, {})
        context = SimpleNamespace(controlled_imports=self.synthetic_context)
        with mock.patch.object(gate, 'load', return_value=loaded), mock.patch.object(gate, 'external', side_effect=[object(), context]), \
                mock.patch.object(resource, 'check_current_process', side_effect=ValueError('resource')), \
                mock.patch.object(gate, 'write') as write, mock.patch.object(builtins, '__import__', side_effect=watched):
            with self.assertRaises(ValueError): gate.child('/ssd/cjc/gnn_model_ranking_v5_runtime_gate_20261008_r1', self.pins())
        self.assertEqual(ml_imports, []); write.assert_not_called()

    def test_worker_rejects_bad_binding_origin_fit_threads(self):
        for key, value in [('torch_origin', '/ssd/cjc/multimode_ate_gnn_v1/x'),
                           ('actual_torch_fits', 1), ('threads', True),
                           ('cuda_available', True), ('core_manifest_sha256', 'b'*64),
                           ('formal_training_release', True), ('numpy_version', '0')]:
            with self.subTest(key=key):
                payload = self.worker(); payload[key] = value
                with self.assertRaises(ValueError): gate.validate_child(payload, self.pins())

    def test_runtime_refuses_before_path_io(self):
        with mock.patch.object(gate.sys, 'platform', 'win32'), mock.patch.object(gate, 'read') as reader:
            with self.assertRaises(ValueError): gate.load('/ssd/cjc/x', self.pins())
            reader.assert_not_called()

    def test_bootstrap_fixed_paths_and_no_site(self):
        code = gate.bootstrap('/ssd/cjc/gnn_model_ranking_v5_runtime_gate_20261008_r2', 'a'*64)
        compile(code, '<test>', 'exec')
        self.assertIn('sys.flags.no_site==1', code)
        self.assertIn('sys.flags.isolated==1', code)
        self.assertIn(repr(list(gate.SEARCH_PATHS)), code)
        self.assertNotIn('/etc/', code)
        self.assertNotIn('sys.path.append', code)
        for root in ('/ssd/cjc/multimode_ate_gnn_v1', '/ssd/cjc/gnn_model_ranking_v5_runtime_gate_20261008_r2/../x'):
            with self.assertRaises(ValueError): gate.bootstrap(root, 'a'*64)

    def test_bootstrap_prerequisites_reject_before_source_io(self):
        root = '/ssd/cjc/gnn_model_ranking_v5_runtime_gate_20261008_r2'
        for kind in ('site_enabled', 'cached_hook', 'wrong_path'):
            with self.subTest(kind=kind), mock.patch.object(gate.sys, 'platform', 'linux'), \
                    mock.patch.object(gate.sys, 'executable', gate.INTERPRETER), \
                    mock.patch.object(gate.sys, 'version_info', (3, 11, 2)), \
                    mock.patch.object(gate.sys, 'flags', SimpleNamespace(no_site=0 if kind=='site_enabled' else 1, isolated=1)), \
                    mock.patch.object(gate.sys, 'path', ['/tmp'] if kind=='wrong_path' else list(gate.SEARCH_PATHS)), \
                    mock.patch.object(gate.os, 'getcwd', return_value='/ssd/cjc'), \
                    mock.patch.dict(gate.sys.modules, {'sitecustomize': object()} if kind=='cached_hook' else {}), \
                    mock.patch.object(gate, 'read') as read:
                with self.assertRaisesRegex(ValueError, 'SITE_BOOTSTRAP'): gate.load(root, self.pins())
                read.assert_not_called()

    def test_root_refuses_before_io(self):
        with mock.patch.object(gate.sys, 'platform', 'linux'), mock.patch.object(gate.sys, 'executable', gate.INTERPRETER), \
                mock.patch.object(gate.sys, 'version_info', (3, 11, 2)), mock.patch.object(gate.os, 'getcwd', return_value='/ssd/cjc'), \
                mock.patch.object(gate, 'read') as reader:
            with self.assertRaises(ValueError): gate.load('/ssd/cjc/multimode_ate_gnn_v1', self.pins())
            reader.assert_not_called()

    def test_json_duplicate_nonfinite_bound(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b' '*20001):
            with self.assertRaises(ValueError): gate.decode(raw)

    def test_write_create_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'receipt.json'
            gate.write(path, {'training': False})
            self.assertEqual(json.loads(gate.read(path)), {'training': False})
            with self.assertRaises(FileExistsError): gate.write(path, {'training': True})


class RuntimePacketTests(unittest.TestCase):
    def archive(self, alteration=None):
        files = {name: b'pass\n' for name in packet.NAMES}
        manifest = dict(schema='v5-runtime-gate-packet-v1', files={name:packet.digest(raw) for name,raw in files.items()},
                        formal_training_release=False)
        files[packet.MANIFEST] = json.dumps(manifest).encode()
        entries = list(files.items())
        if alteration: entries = alteration(entries)
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name, raw in entries:
                entry = tarfile.TarInfo(name); entry.size = len(raw)
                archive.addfile(entry, io.BytesIO(raw))
        return gzip.compress(buffer.getvalue(), mtime=0)

    def test_exact_four_pass(self):
        raw = self.archive()
        payloads, manifest, size = packet.validate(raw, packet.digest(raw))
        self.assertEqual(len(payloads), 4)
        self.assertLessEqual(size, packet.TAR_CAP)
        self.assertFalse(manifest['formal_training_release'])

    def test_missing_extra_duplicate_traversal_reject(self):
        for mutate in (lambda entries: entries[:-1], lambda entries: entries+[('extra', b'x')],
                       lambda entries: entries+[entries[0]],
                       lambda entries: [('../x', entries[0][1])]+entries[1:]):
            raw = self.archive(mutate)
            with self.assertRaises(ValueError): packet.validate(raw, packet.digest(raw))

    def test_sha_and_compressed_bounds(self):
        with self.assertRaises(ValueError): packet.validate(self.archive(), 'a'*64)
        raw = b'x'*(packet.ARCHIVE_CAP+1)
        with self.assertRaises(ValueError): packet.validate(raw, packet.digest(raw))

    def test_root_reject_before_io(self):
        raw = self.archive()
        with mock.patch.object(packet, 'Path') as path:
            with self.assertRaises(ValueError): packet.receive(raw, packet.digest(raw), '/ssd/cjc/multimode_ate_gnn_v1')
            path.assert_not_called()

    def test_corrupt_before_mkdir(self):
        raw = self.archive()
        with mock.patch.object(packet, 'Path') as path:
            with self.assertRaises(ValueError): packet.receive(raw, 'a'*64, '/ssd/cjc/gnn_model_ranking_v5_runtime_gate_20261008_r1')
            path.assert_not_called()

    def test_build_roundtrip_create_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/'packet.tar.gz'
            result = packet.build(output)
            self.assertEqual(result['entries'], 4)
            self.assertEqual(packet.digest(output.read_bytes()), result['archive_sha256'])
            with self.assertRaises(FileExistsError): packet.build(output)


if __name__ == '__main__': unittest.main()
