import ast
import copy
import json
from pathlib import Path
import unittest
from src.data import prospective_runtime_adapter_e114 as m


class Adapter(unittest.TestCase):
    def runtime(self):
        return dict(PATH='/bin:/usr/bin', LD_LIBRARY_PATH='/vendor/lib',
                    LM_LICENSE_FILE='1717@fixture.invalid', MGLS_LICENSE_FILE='1717@fixture.invalid')

    def run_adapter(self, runtime):
        return m.prepare_runtime(runtime, m.profile.snapshot(runtime, False), m.pins.LAUNCHER_SHA256)

    def test_rootless_keeps_missing_fact_no_fabricated_values(self):
        runtime = self.runtime()
        before = copy.deepcopy(runtime)
        observed = m.profile.snapshot(runtime, False)
        self.assertFalse(observed['strict_compatible'])
        normalized, receipt = m.prepare_runtime(runtime, observed, m.pins.LAUNCHER_SHA256)
        self.assertEqual(normalized, runtime)
        self.assertEqual(runtime, before)
        self.assertEqual(receipt['compatibility_branch'], 'OBSERVED_ROOTLESS_ABSOLUTE_LAUNCHER')
        self.assertTrue(receipt['missing_mgc_root_preserved'])
        self.assertFalse(receipt['execution_ready'])
        for value in runtime.values():
            self.assertNotIn(value, json.dumps(receipt))

    def test_explicit_root_and_normalization(self):
        runtime = self.runtime()
        runtime.update(PATH=':/bin/:/usr/bin::', MGC_HOME='/vendor/root/')
        normalized, receipt = self.run_adapter(runtime)
        self.assertEqual(normalized['PATH'], '/bin:/usr/bin')
        self.assertEqual(normalized['MGC_HOME'], '/vendor/root')
        self.assertEqual(receipt['compatibility_branch'], 'EXPLICIT_VENDOR_ROOT')

    def test_changed_current_profile_refused(self):
        runtime = self.runtime()
        observed = m.profile.snapshot(runtime, False)
        runtime['PATH'] = '/other'
        with self.assertRaisesRegex(ValueError, 'DRIFT'):
            m.prepare_runtime(runtime, observed, m.pins.LAUNCHER_SHA256)

    def test_no_automatic_extension_of_rootless_case(self):
        runtime = self.runtime()
        runtime.pop('MGLS_LICENSE_FILE')
        with self.assertRaisesRegex(ValueError, 'UNQUALIFIED'):
            self.run_adapter(runtime)
        for key, value in (('PATH', '/bin:relative'), ('LD_LIBRARY_PATH', '/lib/../x'),
                           ('LM_LICENSE_FILE', '99999@fixture.invalid')):
            runtime = self.runtime()
            runtime[key] = value
            with self.assertRaises(ValueError):
                self.run_adapter(runtime)

    def test_unknown_keys_wrong_launcher_and_launch_limits(self):
        runtime = self.runtime()
        runtime['LD_PRELOAD'] = '/poison'
        with self.assertRaisesRegex(ValueError, 'ALLOWLIST'):
            self.run_adapter(runtime)
        runtime = self.runtime()
        with self.assertRaisesRegex(ValueError, 'LAUNCHER'):
            m.prepare_runtime(runtime, m.profile.snapshot(runtime, False), '0' * 64)
        runtime['PATH'] = '/' + 'x' * 4096
        with self.assertRaisesRegex(ValueError, 'RUNTIME_ENV_VALUE'):
            self.run_adapter(runtime)

    def test_python36(self):
        ast.parse(Path(m.__file__).read_text(), feature_version=(3, 6))


if __name__ == '__main__':
    unittest.main()
