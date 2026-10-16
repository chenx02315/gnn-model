"""Fabricated bytes only. POSIX descriptor tests skip explicitly on Windows."""
import ast
import contextlib
import csv
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1]/'scripts/audit_ranking_v6_train_metadata_e34.py'
SPEC = importlib.util.spec_from_file_location('e34_metadata_auditor_test', str(SOURCE))
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


def encode(fields, rows):
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fields, delimiter='\t', lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode('utf-8')


def fabricated():
    tables = {}
    for circuit, family in audit.FAMILIES.items():
        row = {name: '' for name in audit.MANIFEST_FIELDS}
        row.update(attempt_id=circuit+'-parent', circuit=circuit, family=family, role='TRAIN',
                   stage='fabricated', mode='F', environment_cohort='fabricated', wall_s='1.25',
                   retry_group_id='rawgroup', retry_order='1', retry_order_status='KNOWN_ORDER',
                   attempt_outcome_class='SUCCESS', timeout_status='NOT_TIMEOUT',
                   semantics_status='FOOTER_VERIFIED', semantics_contract='tessent_process_wall_seconds',
                   elapsed_semantics='tessent_process_wall_seconds', elapsed_source='gnu_time_footer',
                   source_artifact='/never/open/artifact', source_log_path='/never/open/log',
                   source_artifact_sha256='a'*64, source_log_sha256='b'*64)
        linked = dict(circuit=circuit, parent_attempt_id=row['attempt_id'], attempt_id=row['attempt_id'],
                      retry_group_id='rawgroup', retry_order='1', order_evidence='STRUCTURAL_SINGLETON',
                      session_index='1', session_count='1', attempt_outcome_class='SUCCESS', timeout_status='NOT_TIMEOUT')
        tables[(circuit, 'manifest')] = [row]
        tables[(circuit, 'lineage')] = [linked]
    return tables


class MetadataAuditTests(unittest.TestCase):
    def setUp(self):
        self.tables = fabricated()

    def payloads(self):
        specs, payloads = [], {}
        for (circuit, kind), rows in self.tables.items():
            fields = audit.MANIFEST_FIELDS if kind == 'manifest' else audit.LINEAGE_FIELDS
            raw = encode(fields, rows)
            suffix = '_attempt_manifest_v2_remediated.tsv' if kind == 'manifest' else '_lineage_v2.tsv'
            path = audit._PIN_ROOT+'/'+circuit+suffix
            specs.append(dict(path=path, sha256=hashlib.sha256(raw).hexdigest(), circuit=circuit, kind=kind))
            payloads[path] = raw
        return specs, payloads

    def run_fabricated(self):
        specs, payloads = self.payloads()
        with patch.object(audit, '_read_regular', side_effect=lambda path, sha, cap:payloads[path]) as reader:
            result = audit.audit_files(specs)
        self.assertEqual(reader.call_count, 12)
        return result

    def test_exact_schemas_pinned_roster_python36_and_no_writes_network(self):
        from src.data.runtime_schema import MANIFEST_V2_FIELDS
        self.assertEqual(audit.MANIFEST_FIELDS, MANIFEST_V2_FIELDS)
        remediation = SOURCE.parents[1]/'src/data/remediate_runtime_attempts_v2.py'
        lineage_fields = next(node.value for node in ast.parse(remediation.read_text()).body
                              if isinstance(node, ast.Assign)
                              and any(isinstance(target, ast.Name) and target.id == 'LINEAGE_FIELDS'
                                      for target in node.targets))
        self.assertEqual(audit.LINEAGE_FIELDS, ast.literal_eval(lineage_fields))
        self.assertEqual(len(audit.CONFIGURED_SPECS), 12)
        self.assertTrue(all(audit._SHA.match(spec['sha256']) for spec in audit.CONFIGURED_SPECS))
        self.assertEqual({s['circuit'] for s in audit.CONFIGURED_SPECS}, set(audit.FAMILIES))
        ast.parse(SOURCE.read_text(), feature_version=(3, 6))
        with patch('builtins.open', side_effect=AssertionError('FILE_WRITE_OR_READ')), \
                patch('socket.socket', side_effect=AssertionError('NETWORK')), \
                patch('random.Random', side_effect=AssertionError('SAMPLING')):
            result = self.run_fabricated()
        self.assertEqual(result['status'], 'PASS_PINNED_TRAIN_METADATA_ONLY_AUDIT')
        self.assertEqual(result['total_rows'], 12)
        self.assertEqual(result['circuits']['spi']['declared_session_wall_sum_s'], '1.25')
        serialized = str(result)
        self.assertNotIn('/never/open', serialized)
        self.assertNotIn('spi-parent', serialized)
        self.assertFalse(result['original_logs_read'])
        self.assertFalse(result['source_semantics_authenticated'])

    def test_mixed_role_circuit_and_unknown_quality_header_fail_closed(self):
        for name, value in (('role', 'BLIND_TEST'), ('family', 'wrong'), ('circuit', 's5378')):
            self.tables = fabricated()
            self.tables[('spi', 'manifest')][0][name] = value
            with self.assertRaises(audit.AuditError):
                self.run_fabricated()
        specs, payloads = self.payloads()
        path = specs[0]['path']
        payloads[path] = payloads[path].replace(b'attempt_id\t', b'total_cycles\t', 1)
        specs[0]['sha256'] = hashlib.sha256(payloads[path]).hexdigest()
        with patch.object(audit, '_read_regular', side_effect=lambda p,s,c:payloads[p]):
            with self.assertRaisesRegex(audit.AuditError, 'EXACT_SCHEMA_REQUIRED'):
                audit.audit_files(specs)

    def test_wrong_sha_and_bounds(self):
        specs, payloads = self.payloads()
        specs[0]['sha256'] = '0'*64
        with patch.object(audit, '_read_regular', side_effect=lambda p,s,c:payloads[p]):
            with self.assertRaisesRegex(audit.AuditError, 'SHA256_MISMATCH'):
                audit.audit_files(specs)
        for limit, value in (('MAX_FILE_BYTES', 10), ('MAX_TOTAL_BYTES', 10),
                             ('MAX_LINE_BYTES', 5), ('MAX_ROWS', 1)):
            with patch.object(audit, limit, value), self.assertRaises(audit.AuditError):
                self.run_fabricated()

    def test_lineage_join_gap_partial_not_fabricated_or_global_abort(self):
        self.tables[('spi', 'lineage')][0]['attempt_id'] = 'unjoined'
        result = self.run_fabricated()
        self.assertEqual(result['status'], 'PARTIAL_PINNED_TRAIN_METADATA_AUDIT')
        self.assertEqual(result['circuits']['spi']['issues'], ['EXACT_LINEAGE_JOIN'])
        self.assertFalse(result['circuits']['spi']['parent_session_lineage_consistent'])
        self.assertEqual(len(result['circuits']), 6)
        self.assertEqual(result['circuits']['spi']['declared_session_wall_sum_s'], '1.25')

    def test_duplicate_attempt_is_structural_failure_not_partial(self):
        self.tables[('spi', 'manifest')].append(dict(self.tables[('spi', 'manifest')][0]))
        with self.assertRaisesRegex(audit.AuditError, 'DUPLICATE_MANIFEST_ATTEMPT'):
            self.run_fabricated()

    def test_semantics_distribution_not_authentication_and_failure_charged(self):
        row = self.tables[('spi', 'manifest')][0]
        row.update(attempt_outcome_class='TIMEOUT', semantics_status='UNKNOWN', wall_s='4', elapsed_source='')
        self.tables[('spi', 'lineage')][0]['attempt_outcome_class'] = 'TIMEOUT'
        summary = self.run_fabricated()['circuits']['spi']
        self.assertEqual(summary['outcome_class_counts']['TIMEOUT'], 1)
        self.assertEqual(summary['declared_wall_sum_by_outcome_class_s']['TIMEOUT'], '4')
        self.assertEqual(summary['semantics_status_counts']['UNKNOWN'], 1)
        self.assertFalse(summary['timing_scope_authenticated'])
        self.assertEqual(summary['environment_cohort_distinct_count'], 1)
        self.assertFalse(summary['environment_cohort_equality_is_authentication'])
        self.assertEqual(summary['source_hash_statistics']['inventory_manifest_sha256']['empty_count'], 1)

    def test_invalid_wall_no_cpu_or_timeout_fallback(self):
        for value in ('', '-1', 'nan', '1e3', '1000000001'):
            self.tables[('spi', 'manifest')][0].update(wall_s=value, user_s='99', system_s='1')
            with self.assertRaises(audit.AuditError):
                self.run_fabricated()

    def test_bad_specs_zero_io_and_no_arbitrary_cli_arguments(self):
        specs, _ = self.payloads()
        for change in (dict(path='../relative'), dict(circuit='s5378'), dict(kind='original_log'),
                       dict(sha256='bad'), dict(extra='bad'), dict(path='/etc/passwd'),
                       dict(path='/ssd/cjc/multimode_ate_gnn_v1/metadata.tsv'),
                       dict(path=audit._PIN_ROOT+'/../original.tsv'),
                       dict(path=audit._PIN_ROOT+'/spi_source_log.tsv')):
            changed = [dict(spec) for spec in specs]
            changed[0].update(change)
            with patch.object(audit, '_read_regular', side_effect=AssertionError('IO')):
                with self.assertRaises(audit.AuditError):
                    audit.audit_files(changed)
        with patch.object(audit, 'CONFIGURED_SPECS', ()), patch.object(audit.sys, 'argv', ['stdin']), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(audit.main(), 2)
            self.assertIn('UNCONFIGURED', output.getvalue())
        with patch.object(audit.sys, 'argv', ['stdin', '/arbitrary']), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(audit.main(), 2)
            self.assertIn('CLI_ARGUMENTS_FORBIDDEN', output.getvalue())

    def test_memory_limit_never_raises_existing_soft_or_hard(self):
        class Resource:
            RLIMIT_AS = 9
            RLIM_INFINITY = -1
            applied = None
            def getrlimit(self, resource): return (512*1024**2, 768*1024**2)
            def setrlimit(self, resource, values): self.applied = values
        fake = Resource()
        with patch.object(audit, 'resource', fake):
            audit._limit_memory()
        self.assertEqual(fake.applied, (512*1024**2, 768*1024**2))


@unittest.skipUnless(os.name == 'posix', 'POSIX descriptor-walk not executable on Windows; no Linux evidence claimed')
class PosixDescriptorTests(unittest.TestCase):
    def test_actual_regular_sha_symlink_hardlink_and_oversize(self):
        with tempfile.TemporaryDirectory(prefix='e34_fixture_') as directory:
            path = Path(directory)/'metadata.tsv'
            path.write_bytes(b'fabricated')
            digest = hashlib.sha256(b'fabricated').hexdigest()
            self.assertEqual(audit._read_regular(str(path), digest, 100), b'fabricated')
            with self.assertRaisesRegex(audit.AuditError, 'SHA256_MISMATCH'):
                audit._read_regular(str(path), '0'*64, 100)
            with patch.object(audit, 'MAX_FILE_BYTES', 1), self.assertRaises(audit.AuditError):
                audit._read_regular(str(path), digest, 100)
            alias = Path(directory)/'link.tsv'
            alias.symlink_to(path)
            with self.assertRaises(audit.AuditError):
                audit._read_regular(str(alias), digest, 100)
            alias.unlink()
            os.link(str(path), str(alias))
            with self.assertRaisesRegex(audit.AuditError, 'REGULAR_SINGLE_LINK'):
                audit._read_regular(str(path), digest, 100)
            parent_alias = Path(directory)/'parent_link'
            parent_alias.symlink_to(directory, target_is_directory=True)
            with self.assertRaises(audit.AuditError):
                audit._read_regular(str(parent_alias/'metadata.tsv'), digest, 100)


if __name__ == '__main__':
    unittest.main()
