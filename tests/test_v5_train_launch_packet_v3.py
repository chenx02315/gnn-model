"""Synthetic bounded in-memory transport; no real approval or ML execution."""
from copy import deepcopy
import gzip
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts import v5_train_launch_packet_v3 as packet
from scripts import run_v5_train_serial_parent_v3 as parent

REPO = Path(__file__).resolve().parents[1]


class PacketV3Tests(unittest.TestCase):
    def setUp(self):
        cli_raw = (REPO/packet.CLI).read_bytes()
        cli = packet.external(cli_raw, '_synthetic_cli_initial')
        required = cli.CORE_FILES | {packet.CLI, packet.PARENT, *cli.GATE_SOURCES,
                                    *cli.HELPERS, *parent.EXTRA}
        self.payloads = {p: (REPO/p).read_bytes() for p in required}
        evidence = {p: packet.encode({'synthetic': p}) for p in set(cli.EVIDENCE)|set(parent.CPU_EVIDENCE)}
        evidence['run_authorization.json'] = (REPO/'contracts/ranking_v5_freeze_v2_fresh_train_authorization_20261011_r1.json').read_bytes()
        self.evidence_pins = {p: packet.sha(raw) for p, raw in evidence.items()}
        overrides = {
            'AUTHORIZATION_SHA256': self.evidence_pins['authorization.json'],
            'SCOPE_AUTHORIZATION_SHA256': self.evidence_pins['scope_authorization.json'],
            'SYNTHETIC_LINUX_GATE_SHA256': self.evidence_pins['synthetic_linux_gate.json'],
            'OPTIMIZER_EVIDENCE_PINS': {p: self.evidence_pins[p] for p in cli.OPTIMIZER_EVIDENCE_PINS}}
        cli_raw += b'\n'+b'\n'.join((key+' = '+repr(value)).encode() for key,value in overrides.items())+b'\n'
        self.payloads[packet.CLI] = cli_raw
        self.payloads[packet.PARENT] += b'\nCPU_EVIDENCE = '+repr(
            {p:self.evidence_pins[p] for p in parent.CPU_EVIDENCE}).encode()+b'\n'
        self.cli = packet.external(cli_raw, '_synthetic_cli')
        self.source_pins = {p: packet.sha(raw) for p,raw in self.payloads.items()}

        source_digest = parent.mapping_digest(self.source_pins)
        evidence_digest = parent.mapping_digest({p: h for p, h in self.evidence_pins.items()
                                                 if p != 'run_binding_review.json'})
        evidence['run_binding_review.json'] = packet.encode(dict(
            schema='v5-fresh-train-run-binding-review-v1', status='PASS_V5_FRESH_RUN_BINDING_REVIEW',
            scope='V5_FREEZE_V2_TRAIN_ONLY_18_FITS', source_root=packet.ROOT,
            run_authorization_sha256=self.evidence_pins['run_authorization.json'],
            core_manifest_sha256=packet.CORE_SHA, source_binding_sha256=source_digest,
            legacy_evidence_binding_sha256=evidence_digest))
        self.evidence_pins['run_binding_review.json'] = packet.sha(evidence['run_binding_review.json'])
        self.payloads.update(evidence)
        self.payloads[packet.CORE_MANIFEST] = (REPO/packet.CORE_MANIFEST).read_bytes()
        envelopes = {}
        for family in sorted(cli.FAMILIES):
            for seed in cli.SEEDS:
                name = f'prelaunch_{family}_{seed}.json'
                item = dict(schema='v5-train-prelaunch-envelope-v3', source_root=packet.ROOT,
                    output=packet.ROOT+f'_{family}_{seed}', package_root=cli.PACKAGE_ROOT,
                    family=family, seed=seed, jit_root=packet.ROOT+f'/jit_tmp/{family}_{seed}',
                    roles=['TRAIN'], parent_resource_guard_required=True,
                    core_manifest_sha256=packet.CORE_SHA, authorization_id=cli.AUTHORIZATION_ID,
                    helper_sha256={p:self.source_pins[p] for p in cli.HELPERS},
                    gate_source_sha256=cli.optimizer_source_pins(),
                    freeze_supplement_sha256={p:self.source_pins[p] for p in parent.FREEZE_SOURCES},
                    freeze_loader_sha256=self.source_pins[parent.FREEZE_LOADER],
                    source_binding_sha256=source_digest, legacy_evidence_binding_sha256=evidence_digest,
                    run_authorization_id=cli.RUN_AUTHORIZATION_ID,
                    **{field:self.evidence_pins[p] for p,field in cli.EVIDENCE.items()})
                self.payloads[name] = packet.encode(item)
                envelopes[name] = packet.sha(self.payloads[name])
        self.manifest = dict(schema='v5-train-serial-launch-packet-v3', source_root=packet.ROOT,
            package_root=cli.PACKAGE_ROOT, core_manifest_sha256=packet.CORE_SHA,
            source_sha256=self.source_pins, evidence_sha256=self.evidence_pins,
            prelaunch_sha256=envelopes)
        self.payloads[packet.MANIFEST] = packet.encode(self.manifest)
        self.approval = self.enterContext(patch.object(packet, 'approval_integrity'))

    def check(self, payloads=None, sources=None, evidence=None, root=None):
        payloads = self.payloads if payloads is None else payloads
        raw = packet.archive(payloads)
        return packet.validate(raw, packet.sha(raw), packet.sha(payloads[packet.MANIFEST]),
            packet.ROOT if root is None else root,
            trusted_source_sha256=self.source_pins if sources is None else sources,
            trusted_evidence_sha256=self.evidence_pins if evidence is None else evidence)

    def test_exact_derived_source_evidence_archive_sets_and_all18(self):
        payloads,manifest,tar_bytes = self.check()
        required = self.cli.CORE_FILES | {packet.CLI, packet.PARENT,*self.cli.GATE_SOURCES,
                                        *self.cli.HELPERS,*parent.EXTRA}
        self.assertEqual(set(manifest['source_sha256']), required)
        self.assertEqual(set(manifest['evidence_sha256']), set(self.cli.EVIDENCE)|set(parent.CPU_EVIDENCE))
        self.assertEqual(len(manifest['prelaunch_sha256']),18)
        self.assertEqual(set(payloads), required|set(self.evidence_pins)|set(manifest['prelaunch_sha256'])|
                         {packet.MANIFEST,packet.CORE_MANIFEST})
        self.assertEqual(len(self.cli.CORE_FILES),26)
        self.assertLessEqual(tar_bytes,1024**2)
        self.approval.assert_called_once()

    def test_external_anchor_missing_extra_drift_rejected(self):
        for kind,pins in (('sources',self.source_pins),('evidence',self.evidence_pins)):
            for mutation in ('missing','extra','drift'):
                value = dict(pins)
                if mutation == 'missing': del value[next(iter(value))]
                elif mutation == 'extra': value['unapproved.json']='a'*64
                else: value[next(iter(value))]='f'*64
                with self.assertRaises(ValueError): self.check(**{kind:value})
        self.approval.assert_not_called()

    def test_every_envelope_cross_task_temp_rejected_even_resealed(self):
        for name in self.manifest['prelaunch_sha256']:
            payloads = dict(self.payloads)
            item = packet.decode(payloads[name]); item['jit_root']=packet.ROOT+'/jit_tmp/iwls_spi_20260826'
            if item['jit_root'] == self.cli.jit_root_for(packet.ROOT,item['family'],item['seed']):
                item['jit_root']=packet.ROOT+'/jit_tmp/iwls_spi_20260825'
            payloads[name]=packet.encode(item)
            manifest=deepcopy(self.manifest); manifest['prelaunch_sha256'][name]=packet.sha(payloads[name])
            payloads[packet.MANIFEST]=packet.encode(manifest)
            with self.assertRaises(ValueError): self.check(payloads)
        self.approval.assert_not_called()

    def test_protected_or_invalid_review_receive_zero_io(self):
        raw=packet.archive(self.payloads)
        with patch.object(packet.Path,'lstat') as lstat,patch.object(packet.Path,'mkdir') as mkdir:
            for root in ('/ssd/cjc/multimode_ate_gnn_v1',packet.ROOT+'_other'):
                with self.assertRaises(ValueError):
                    packet.receive(raw,packet.sha(raw),packet.sha(self.payloads[packet.MANIFEST]),root,
                        trusted_source_sha256=self.source_pins,trusted_evidence_sha256=self.evidence_pins)
            self.approval.side_effect=ValueError('missing independent review')
            with self.assertRaises(ValueError):
                packet.receive(raw,packet.sha(raw),packet.sha(self.payloads[packet.MANIFEST]),packet.ROOT,
                    trusted_source_sha256=self.source_pins,trusted_evidence_sha256=self.evidence_pins)
            lstat.assert_not_called();mkdir.assert_not_called()
        with patch.object(packet.Path,'lstat') as lstat:
            denied = ('/ssd/cjc/multimode_ate_gnn_v1/trust.json',
                '/ssd/cjc/x/../multimode_ate_gnn_v1/a', '/ssd//cjc/multimode_ate_gnn_v1/a',
                '/SSD/CJC/MULTIMODE_ATE_GNN_V1/a', '\\ssd\\cjc\\multimode_ate_gnn_v1\\a',
                'trust.json', '../multimode_ate_gnn_v1/a', '/ssd/cjc/./multimode_ate_gnn_v1/a')
            for path in denied:
                with self.subTest(path=path),self.assertRaises(ValueError):
                    packet.read(path,packet.JSON_CAP)
            lstat.assert_not_called()

    def test_bounds_extra_missing_and_byte_drift(self):
        for mutation in ('extra','missing','drift'):
            payloads=dict(self.payloads); name=next(iter(self.source_pins))
            if mutation=='extra': payloads['unapproved.json']=b'{}'
            elif mutation=='missing': del payloads[name]
            else: payloads[name]+=b' '
            with self.assertRaises(ValueError): self.check(payloads)
        raw=gzip.compress(b'x'*(packet.TAR_CAP+1))
        with self.assertRaises(ValueError): packet.unpack(raw,packet.sha(raw),len(self.payloads))
        self.assertEqual((packet.ARCHIVE_CAP,packet.TAR_CAP,packet.SOURCE_CAP,packet.JSON_CAP),
                         (256*1024,1024*1024,65536,20000))

    def test_build_bad_output_paths_reject_before_all_io(self):
        denied = ('/ssd/cjc/multimode_ate_gnn_v1/a.tar.gz',
            '/ssd/cjc/x/../multimode_ate_gnn_v1/a.tar.gz',
            '/ssd//cjc/multimode_ate_gnn_v1/a.tar.gz',
            '/SSD/CJC/MULTIMODE_ATE_GNN_V1/a.tar.gz',
            '\\ssd\\cjc\\multimode_ate_gnn_v1\\a.tar.gz',
            'relative.tar.gz', '../escape.tar.gz', '/ordinary/wrong.zip')
        with patch.object(packet, 'read') as read, patch.object(packet.Path, 'resolve') as resolve, \
             patch.object(packet.Path, 'lstat') as lstat, patch.object(packet.Path, 'open') as opened, \
             patch.object(packet.os, 'open') as os_open:
            for output in denied:
                with self.subTest(output=output), self.assertRaises(ValueError):
                    packet.build(output, packet.ROOT, '/ordinary/evidence',
                        trusted_source_sha256=self.source_pins, trusted_evidence_sha256=self.evidence_pins)
            for callback in (read, resolve, lstat, opened, os_open):
                callback.assert_not_called()

    def test_lexical_output_accepts_canonical_absolute_without_io(self):
        with patch.object(packet.Path, 'lstat') as lstat, patch.object(packet.Path, 'resolve') as resolve:
            self.assertEqual(packet.lexical_path('/ordinary/new.tar.gz'), Path('/ordinary/new.tar.gz'))
            if packet.os.name == 'nt':
                self.assertEqual(packet.lexical_path('C:\\ordinary\\new.tar.gz'), Path('C:\\ordinary\\new.tar.gz'))
            lstat.assert_not_called(); resolve.assert_not_called()

    def test_resealed_review_cannot_approve_wrong_entire_source_or_evidence_digest(self):
        for field in ('source_binding_sha256', 'legacy_evidence_binding_sha256', 'run_authorization_sha256',
                      'source_root', 'scope', 'status'):
            payloads = dict(self.payloads)
            review = packet.decode(payloads['run_binding_review.json']); review[field] = '0'*64
            payloads['run_binding_review.json'] = packet.encode(review)
            evidence = dict(self.evidence_pins); evidence['run_binding_review.json'] = packet.sha(payloads['run_binding_review.json'])
            manifest = deepcopy(self.manifest); manifest['evidence_sha256'] = evidence
            payloads[packet.MANIFEST] = packet.encode(manifest)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(payloads=payloads, evidence=evidence)
        self.approval.assert_not_called()

    def test_freeze_map_and_loader_pin_tamper_fail_even_resealed(self):
        for field in ('freeze_loader_sha256','freeze_supplement_sha256'):
            payloads = dict(self.payloads); name = next(iter(self.manifest['prelaunch_sha256']))
            item = packet.decode(payloads[name])
            if field == 'freeze_loader_sha256': item[field] = '0'*64
            else: item[field] = dict(item[field]); item[field][next(iter(item[field]))] = '0'*64
            payloads[name] = packet.encode(item)
            manifest = deepcopy(self.manifest); manifest['prelaunch_sha256'][name] = packet.sha(payloads[name])
            payloads[packet.MANIFEST] = packet.encode(manifest)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(payloads)
        self.approval.assert_not_called()

    def test_review_is_required_and_old_authorization_cannot_replace_new_run(self):
        for name, raw in [('run_authorization.json', self.payloads['authorization.json']),
                          ('run_binding_review.json', packet.encode({'status':'PASS'}))]:
            payloads = dict(self.payloads); payloads[name] = raw
            evidence = dict(self.evidence_pins); evidence[name] = packet.sha(raw)
            manifest = deepcopy(self.manifest); manifest['evidence_sha256'] = evidence
            payloads[packet.MANIFEST] = packet.encode(manifest)
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.check(payloads, evidence=evidence)
        self.approval.assert_not_called()


if __name__=='__main__': unittest.main()
