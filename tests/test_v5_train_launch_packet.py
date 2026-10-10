"""Synthetic temp sources/evidence only; no remote deployment or formal data."""
from copy import deepcopy
import gzip
import io
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import unittest
from unittest.mock import patch

from scripts import v5_train_launch_packet as transport
from tests import test_run_v5_train_serial_parent as base

encode = base.encode


class LaunchPacketTests(unittest.TestCase):
    def setUp(self):
        # Existing base-source fixture creates only small synthetic temp evidence.
        fixture = base.SerialParentTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.temp_root = fixture.root.parent
        self.root = '/ssd/cjc/gnn_model_ranking_v5_train_20261010_r199'
        self.sources = dict(fixture.source)
        parent_raw = self.sources[transport.PARENT]
        parent_raw += b'\nCPU_EVIDENCE = '+repr({p: transport.sha(raw)
            for p, raw in fixture.evidence.items() if p.startswith('cpu_gate.')}).encode()+b'\n'
        self.sources[transport.PARENT] = parent_raw
        self.source_pins = {p: transport.sha(raw) for p, raw in self.sources.items()}
        self.evidence_pins = {p: transport.sha(raw) for p, raw in fixture.evidence.items()}
        self.payloads = {**self.sources, **fixture.evidence, transport.CORE_MANIFEST: fixture.core_raw}
        envelope_pins = {}
        for name, raw in fixture.envelopes.items():
            item = fixture.cli._json(raw)
            item['source_root'] = self.root
            item['output'] = self.root+f"_{item['family']}_{item['seed']}"
            self.payloads[name] = encode(item)
            envelope_pins[name] = transport.sha(self.payloads[name])
        manifest = deepcopy(fixture.packet)
        manifest.update(source_root=self.root, source_sha256=self.source_pins,
                        prelaunch_sha256=envelope_pins)
        self.payloads[transport.MANIFEST] = encode(manifest)
        self.enterContext(patch.object(transport, 'CORE_SHA', fixture.cli.CORE_MANIFEST_SHA256))
        self.approval = self.enterContext(patch.object(transport, 'approval_integrity'))
        self.packet_pin = transport.sha(self.payloads[transport.MANIFEST])
        self.packet = transport.archive(self.payloads)

    def check(self, packet=None, packet_pin=None, source=None, evidence=None, root=None):
        raw = self.packet if packet is None else packet
        return transport.validate(raw, transport.sha(raw), packet_pin or self.packet_pin,
            root or self.root, trusted_source_sha256=source or self.source_pins,
            trusted_evidence_sha256=evidence or self.evidence_pins)

    def test_exact_64_entries_36_sources_8_evidence_18_envelopes(self):
        payloads, manifest, tar_bytes = self.check()
        self.assertEqual(payloads, self.payloads)
        self.assertEqual((len(manifest['source_sha256']), len(manifest['evidence_sha256']),
                          len(manifest['prelaunch_sha256']), len(payloads)), (36, 8, 18, 64))
        self.assertLessEqual(tar_bytes, transport.TAR_CAP)
        self.approval.assert_called_once()

    def test_external_review_and_source_pin_drift_rejected_before_approval(self):
        for kind in ('source', 'evidence'):
            pins = dict(self.source_pins if kind == 'source' else self.evidence_pins)
            pins[next(iter(pins))] = 'f'*64
            with self.assertRaises(ValueError):
                self.check(**{kind: pins})
        self.approval.assert_not_called()

    def test_byte_drift_missing_unknown_entries_rejected(self):
        for mutation in ('drift', 'missing', 'unknown'):
            payloads = dict(self.payloads)
            name = next(iter(self.sources))
            if mutation == 'drift': payloads[name] += b'\n'
            elif mutation == 'missing': del payloads[name]
            else: payloads['unknown.json'] = b'{}'
            with self.assertRaises(ValueError):
                self.check(transport.archive(payloads))

    def test_envelope_output_drift_even_with_updated_manifest_pin(self):
        payloads = dict(self.payloads)
        name = next(p for p in payloads if p.startswith('prelaunch_'))
        item = transport.decode(payloads[name]); item['output'] += '_other'
        payloads[name] = encode(item)
        manifest = transport.decode(payloads[transport.MANIFEST])
        manifest['prelaunch_sha256'][name] = transport.sha(payloads[name])
        payloads[transport.MANIFEST] = encode(manifest)
        with self.assertRaises(ValueError):
            self.check(transport.archive(payloads), transport.sha(payloads[transport.MANIFEST]))

    def test_pax_symlink_directory_duplicate_and_trailer_rejected(self):
        for kind in ('pax', 'symlink', 'directory', 'duplicate'):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode='w', format=tarfile.PAX_FORMAT if kind == 'pax'
                              else tarfile.USTAR_FORMAT) as stream:
                for index, (name, raw) in enumerate(sorted(self.payloads.items())):
                    entry = tarfile.TarInfo(name); entry.size = len(raw)
                    if index == 0:
                        if kind == 'pax': entry.pax_headers = {'comment': 'forbidden'}
                        elif kind == 'symlink': entry.type = tarfile.SYMTYPE; entry.linkname = 'elsewhere'; entry.size = 0
                        elif kind == 'directory': entry.type = tarfile.DIRTYPE; entry.size = 0
                    stream.addfile(entry, io.BytesIO(raw))
                    if kind == 'duplicate' and index == 0: stream.addfile(entry, io.BytesIO(raw))
            with self.assertRaises(ValueError):
                self.check(gzip.compress(buffer.getvalue()))
        raw = gzip.decompress(self.packet)+b'x'*512
        with self.assertRaises(ValueError): self.check(gzip.compress(raw))

    def test_gzip_bomb_and_archive_hash_rejected(self):
        with self.assertRaises(ValueError): self.check(gzip.compress(b'0'*(transport.TAR_CAP+1)))
        with self.assertRaises(ValueError):
            transport.unpack(self.packet, 'f'*64)

    def test_receive_rejects_root_or_invalid_approval_before_filesystem(self):
        with patch.object(transport.Path, 'mkdir') as mkdir, patch.object(transport.Path, 'lstat') as lstat:
            for root in ('/ssd/cjc/multimode_ate_gnn_v1', self.root+'/../other'):
                with self.assertRaises(ValueError):
                    transport.receive(self.packet, transport.sha(self.packet), self.packet_pin, root,
                        trusted_source_sha256=self.source_pins, trusted_evidence_sha256=self.evidence_pins)
            self.approval.side_effect = ValueError('external review missing')
            with self.assertRaises(ValueError):
                transport.receive(self.packet, transport.sha(self.packet), self.packet_pin, self.root,
                    trusted_source_sha256=self.source_pins, trusted_evidence_sha256=self.evidence_pins)
            mkdir.assert_not_called(); lstat.assert_not_called()

    def test_duplicate_and_nonfinite_json_are_rejected(self):
        with self.assertRaises(ValueError): transport.decode(b'{"a":1,"a":2}')
        with self.assertRaises(ValueError): transport.decode(b'{"a":NaN}')

    def test_build_authenticates_bootstrap_before_exec(self):
        for name in (transport.CLI, transport.PARENT):
            pins = dict(self.source_pins); pins[name] = 'f'*64
            with patch.object(transport, 'read', side_effect=lambda p, cap: self.sources[
                    Path(p).relative_to(Path(transport.__file__).resolve().parents[1]).as_posix()]), \
                    patch.object(transport, 'external') as external:
                with self.assertRaisesRegex(ValueError, 'BOOTSTRAP_SHA'):
                    transport.build(self.temp_root/'negative.tar.gz', self.root, self.temp_root,
                        trusted_source_sha256=pins, trusted_evidence_sha256=self.evidence_pins)
                external.assert_not_called()

    def test_real_authenticated_approval_in_clean_isolated_process_no_ml(self):
        archive_path = self.temp_root/'synthetic.tar.gz'
        archive_path.write_bytes(self.packet)
        trust_path = self.temp_root/'external-test-trust.json'
        trust_path.write_bytes(encode(dict(source_sha256=self.source_pins, evidence_sha256=self.evidence_pins)))
        script_path = Path(transport.__file__).resolve()
        code = (
            'from pathlib import Path; import json,sys; '
            f'p=Path({str(script_path)!r}); '
            'ns={"__name__":"isolated_transport_test","__file__":str(p)}; '
            'exec(compile(p.read_bytes(),str(p),"exec"),ns); '
            f'ns["CORE_SHA"]={transport.CORE_SHA!r}; '
            f'trust=json.loads(Path({str(trust_path)!r}).read_bytes()); '
            f'raw=Path({str(archive_path)!r}).read_bytes(); '
            f'ns["validate"](raw,ns["sha"](raw),{self.packet_pin!r},{self.root!r},'
            'trusted_source_sha256=trust["source_sha256"],trusted_evidence_sha256=trust["evidence_sha256"]); '
            'assert "torch" not in sys.modules and "numpy" not in sys.modules; print("PASS_REAL_APPROVAL_NO_ML")')
        result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', code],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('PASS_REAL_APPROVAL_NO_ML', result.stdout)

    def test_build_fixed_bounded_reads_and_create_once_archive(self):
        output = self.temp_root/'local-test.tar.gz'
        repo = Path(transport.__file__).resolve().parents[1]
        evidence_root = self.temp_root/'evidence-fixture'
        actual_read = transport.read
        reads = []
        def synthetic_read(path, cap):
            path = Path(path); reads.append((path, cap))
            if path == output:
                return actual_read(path, cap)
            if path.is_relative_to(repo):
                return self.payloads[path.relative_to(repo).as_posix()]
            return self.payloads[path.relative_to(evidence_root).as_posix()]
        with patch.object(transport, 'read', side_effect=synthetic_read):
            result = transport.build(output, self.root, evidence_root,
                trusted_source_sha256=self.source_pins, trusted_evidence_sha256=self.evidence_pins)
            with self.assertRaises(FileExistsError):
                transport.build(output, self.root, evidence_root,
                    trusted_source_sha256=self.source_pins, trusted_evidence_sha256=self.evidence_pins)
        self.assertEqual((result['entries'], result['actual_fits']), (64, 0))
        self.assertEqual(transport.sha(output.read_bytes()), result['archive_sha256'])
        self.assertEqual({p.relative_to(evidence_root).as_posix() for p, cap in reads
                          if p.is_relative_to(evidence_root)}, set(self.evidence_pins))
        self.assertTrue(all(cap <= transport.SOURCE_CAP or p == output for p, cap in reads))

    def test_receive_new_temp_root_readback_then_existing_root_rejected(self):
        root = (self.temp_root/'receive-fixture').as_posix()
        payloads = dict(self.payloads)
        manifest = transport.decode(payloads[transport.MANIFEST]); manifest['source_root'] = root
        for name in manifest['prelaunch_sha256']:
            item = transport.decode(payloads[name]); item['source_root'] = root
            item['output'] = root+f"_{item['family']}_{item['seed']}"
            payloads[name] = encode(item)
            manifest['prelaunch_sha256'][name] = transport.sha(payloads[name])
        payloads[transport.MANIFEST] = encode(manifest)
        packet = transport.archive(payloads)
        with patch.object(transport, 'ROOT_PATTERN', re.escape(root)):
            kwargs = dict(trusted_source_sha256=self.source_pins, trusted_evidence_sha256=self.evidence_pins)
            args = (packet, transport.sha(packet), transport.sha(payloads[transport.MANIFEST]), root)
            result = transport.receive(*args, **kwargs)
            with self.assertRaises(FileExistsError): transport.receive(*args, **kwargs)
        self.assertEqual((result['entries'], result['actual_fits']), (64, 0))
        for name, raw in payloads.items():
            self.assertEqual((Path(root)/name).read_bytes(), raw)


if __name__ == '__main__':
    unittest.main()
