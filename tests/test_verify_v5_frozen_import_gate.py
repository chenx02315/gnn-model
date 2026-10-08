import hashlib
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from scripts import verify_v5_frozen_import_gate as gate


def pins():
    root = Path(__file__).resolve().parents[1]
    return dict(manifest_sha256=hashlib.sha256((root/gate.MANIFEST).read_bytes()).hexdigest(),
                helper_sha256=hashlib.sha256((root/gate.HELPER).read_bytes()).hexdigest())


class FrozenImportGateTests(unittest.TestCase):
    def test_actual_isolated_child_imports_verified_caller_without_ml_or_training(self):
        result = gate.run(**pins())
        self.assertEqual(result['status'], 'PASS_FROZEN_SOURCE_IMPORT_GATE_ONLY')
        self.assertEqual(result['child_exit_code'], 0)
        self.assertTrue(result['isolated_python_child'])
        self.assertTrue(result['heavy_ml_imports_blocked'])
        self.assertIn('sealed://src/models/ranking_v5_single_fit_worker.py', result['origins'])
        self.assertEqual(result['actual_torch_fits'], 0)
        self.assertFalse(result['actual_linux_resource_proof'])

    def test_bad_anchor_before_any_io(self):
        with patch.object(gate, 'bounded_read', side_effect=AssertionError('no read')):
            with self.assertRaisesRegex(ValueError, 'TRUSTED_SHA'):
                gate.run(manifest_sha256='invalid',helper_sha256='a'*64)

    def test_manifest_or_helper_drift_prevents_child(self):
        for key in ('manifest_sha256','helper_sha256'):
            values = pins(); values[key] = 'a'*64
            with patch.object(gate.subprocess,'run') as child:
                with self.assertRaisesRegex(ValueError, 'SHA'): gate.run(**values)
                child.assert_not_called()

    def test_child_timeout_failure_or_invalid_receipt_is_not_retried(self):
        for response in (subprocess.TimeoutExpired('fixture',15),
                         subprocess.CompletedProcess([],1,b'',b'fixture failure'),
                         subprocess.CompletedProcess([],0,b'{}',b'')):
            with patch.object(gate.subprocess,'run', **(
                    {'side_effect':response} if isinstance(response,Exception) else {'return_value':response})) as child:
                with self.assertRaises((subprocess.TimeoutExpired,RuntimeError,ValueError)):
                    gate.run(**pins())
                self.assertEqual(child.call_count,1)

    def test_exit_zero_without_worker_origin_is_refused(self):
        receipt = dict(status='PASS_FROZEN_SOURCE_IMPORT_GATE_ONLY',loaded_python_modules=1,
                       origins=['sealed://src/models/runtime_training_v2.py'],
                       namespaces_empty=True,heavy_ml_imports_blocked=True,
                       actual_torch_fits=0,production_package_reads=0,
                       actual_linux_resource_proof=False,formal_training_release=False)
        with patch.object(gate.subprocess,'run',return_value=subprocess.CompletedProcess(
                [],0,json.dumps(receipt).encode(),b'')) as child:
            with self.assertRaisesRegex(ValueError,'CHILD_RECEIPT'): gate.run(**pins())
            self.assertEqual(child.call_count,1)


if __name__ == '__main__': unittest.main()
