"""Actual fixed local caches and pure RAM rebinding; no physical execution."""
import ast
import copy
import json
import pickle
import unittest
from unittest import mock

from scripts import e138_deployment_materials as origin
from scripts import e139_local_materials as m
from scripts import e139_native_graph_candidate as graph


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        old = origin.prepare()
        cls.summary = old.public_summary()
        assert cls.summary['status'] == m.READY, 'Actual fixed caches required'
        cls.private = old.private_bytes()
        cls.prepared = m.rebind(cls.summary, cls.private)

    def test_actual_prepare_ready_with_all_release_gates_disabled(self):
        summary = m.prepare().public_summary()
        self.assertEqual(summary['status'], m.READY)
        self.assertEqual(summary['role_source_counts'], dict(capture=35, execution=53, readback=36))
        self.assertEqual(summary['unique_source_count'], 56)
        self.assertEqual(summary['package'], 'E139')
        self.assertIsNone(summary['effective_dependency_checks'])
        for key in ('execution_ready', 'authority_supplied', 'remote_execution_observed', 'source_session_released'):
            self.assertIs(summary[key], False)

    def test_every_role_effective_pin_original_order_subset_and_explicit_origin(self):
        private = self.prepared.private_bytes()
        spec = {r['name']: r for r in graph.specification()['origins']}
        rows = {(r['role'], r['path']): r for r in self.prepared.public_summary()['artifacts']}
        for role, bundle in private['roles'].items():
            self.assertIsNone(bundle['dependency_checks'])
            self.assertEqual(bundle['origin_dependency_checks'], self.private['roles'][role]['dependency_checks'])
            self.assertEqual(bundle['effective_source_pin_checks'], m.ROLE_COUNTS[role])
            self.assertEqual(bundle['source_order'], self.private['roles'][role]['source_order'])
            self.assertEqual(len(bundle['sources']), m.ROLE_COUNTS[role])
            self.assertLess(len(bundle['sources']), 56)
            for name, raw in bundle['sources'].items():
                row = rows[role, 'src/data/' + name + '.py']
                self.assertEqual(row['origin_sha256'], spec[name]['sha256'])
                self.assertEqual(row['sha256'], spec[name]['effective_sha256'])
                self.assertEqual(m.sha(raw), row['sha256'])
                self.assertEqual(bundle['source_sha256'][name], row['sha256'])

    def test_all_five_dynamic_input_crossjoins_static_bytes_unchanged_and_policy_new(self):
        private = self.prepared.private_bytes()
        inputs = private['execution_inputs']
        self.assertEqual(len(m.INPUT_SOURCES), 5)
        for key, name in m.INPUT_SOURCES.items():
            self.assertEqual(inputs[key], private['roles']['execution']['sources'][name])
        for key in set(m.STATIC_INPUT_PINS) - {'policy'}:
            self.assertEqual(inputs[key], self.private['execution_inputs'][key])
        contract_raw = private['roles']['execution']['sources']['physical_e138_contract']
        policy = origin._declarations(ast.parse(contract_raw))['POLICY']
        self.assertEqual(inputs['policy'], m.canonical(policy))
        self.assertEqual(json.loads(inputs['policy'])['package'], 'E139')
        self.assertNotIn(graph.pair.ROOT_OLD.encode(), inputs['policy'])
        self.assertNotIn(graph.pair.PHASE_OLD.encode(), inputs['policy'])
        self.assertFalse(set(inputs) & {'authority', 'proposal', 'original_clock', 'role1_response', 'role2_intent'})

    def test_pure_rebinding_zero_io_no_process_clock_or_import_of_effective_bodies(self):
        with mock.patch('builtins.open') as opened, mock.patch('pathlib.Path.open') as path_open, \
             mock.patch('subprocess.Popen') as spawn, mock.patch('time.monotonic') as clock:
            private = m.rebind(self.summary, self.private).private_bytes()
        for operation in (opened, path_open, spawn, clock):
            operation.assert_not_called()
        for name, fields in {
            'physical_e138_contract': ('FROZEN', 'LOADED_SOURCE_ORDER'),
            'physical_e138_runtime_primitives': ('FACTORY_FREEZE',),
            'physical_e138_batch_assembler': ('AUTH_SHA256', 'FROZEN_SOURCE_SHA256'),
            'physical_e138_batch_candidate': ('AUTH_SHA256',),
        }.items():
            declarations = origin._declarations(ast.parse(private['roles']['execution']['sources'][name]))
            for field in fields:
                self.assertIsNone(declarations[field])

    def test_missing_tampered_origin_manifest_input_and_role_order_failclosed(self):
        mutations = []
        bad = copy.deepcopy(self.private); del bad['roles']['capture']['dependency_checks']; mutations.append(bad)
        bad = copy.deepcopy(self.private); del bad['roles']['capture']['source_sha256']['physical_e138_contract']; mutations.append(bad)
        bad = copy.deepcopy(self.private); bad['roles']['capture']['sources']['physical_e138_contract'] += b' '; mutations.append(bad)
        bad = copy.deepcopy(self.private); bad['roles']['capture']['source_sha256']['physical_e138_contract'] = '0'*64; mutations.append(bad)
        bad = copy.deepcopy(self.private); bad['roles']['capture']['source_order'] = tuple(reversed(bad['roles']['capture']['source_order'])); mutations.append(bad)
        for key in self.private['execution_inputs']:
            bad = copy.deepcopy(self.private); bad['execution_inputs'][key] += b' '; mutations.append(bad)
        for bad in mutations:
            with self.assertRaises(ValueError):
                m.rebind(self.summary, bad)
        with self.assertRaisesRegex(ValueError, 'ORIGIN_NOT_READY'):
            m.rebind(dict(status='NOT_READY'), self.private)
        with mock.patch.object(origin, 'prepare', return_value=origin.Materials({}, {}, dict(status='NOT_READY'))):
            failed = m.prepare()
        self.assertEqual(failed.public_summary()['status'], 'MISSING_OR_INVALID_FIXED_MATERIALS')
        with self.assertRaises(ValueError):
            failed.private_bytes()

    def test_defensive_snapshots_redacted_repr_nonserialization_public_allowlist(self):
        instance = m.rebind(self.summary, self.private)
        private = instance.private_bytes(); private['roles']['capture']['sources'].clear()
        summary = instance.public_summary(); summary['artifacts'].clear()
        self.assertEqual(len(instance.private_bytes()['roles']['capture']['sources']), 35)
        self.assertTrue(instance.public_summary()['artifacts'])
        self.assertIn('PRIVATE_RAM_ONLY', repr(instance))
        with self.assertRaises(TypeError):
            pickle.dumps(instance)
        with self.assertRaises(TypeError):
            json.dumps(instance)
        for row in instance.public_summary()['artifacts']:
            self.assertLessEqual(set(row), {'role', 'path', 'bytes', 'sha256', 'origin_sha256', 'check'})
        text = json.dumps(instance.public_summary())
        self.assertNotIn('body_base64', text)
        self.assertNotIn('user_reply', text)


if __name__ == '__main__':
    unittest.main()
