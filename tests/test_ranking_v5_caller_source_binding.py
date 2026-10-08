import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from src.models import ranking_v5_caller_source_binding as binding


def fixture():
    sources = {name: b'# synthetic source fixture\n' for name in binding.FILES}
    sources['requirements/runtime_v2.lock.txt'] = b'numpy==2.1.3\ntorch==2.5.1\nscipy==1.14.1\nscikit-learn==1.5.2\nxgboost==2.1.2\n'
    manifest = dict(schema=binding.SCHEMA, formal_training_release=False,
                    sources={name: hashlib.sha256(raw).hexdigest() for name, raw in sources.items()})
    return manifest, sources


def validate(manifest, sources):
    raw = json.dumps(manifest, sort_keys=True).encode()
    return binding.validate_source_bytes(raw, sources, trusted_manifest_sha256=hashlib.sha256(raw).hexdigest())


class SourceBindingTests(unittest.TestCase):
    def test_current_local_caller_bytes_fit_caps_and_lock(self):
        root = Path(__file__).resolve().parents[1]
        sources = {name: (root / name).read_bytes() for name in binding.FILES}
        manifest = dict(schema=binding.SCHEMA, formal_training_release=False,
                        sources={name: hashlib.sha256(raw).hexdigest() for name, raw in sources.items()})
        result = validate(manifest, sources)
        self.assertEqual(len(result['locked_versions']), 31)
        self.assertLessEqual(result['total_source_bytes'], binding.MAX_TOTAL_BYTES)
        self.assertFalse(result['installed_dependencies_verified'])

    def test_supplied_bytes_not_environment_consent_or_execution(self):
        manifest, sources = fixture()
        with patch('builtins.open', side_effect=AssertionError('no IO')):
            result = validate(manifest, sources)
        self.assertEqual(result['source_count'], 26)
        for field in ('installed_dependencies_verified', 'runtime_import_origins_verified',
                      'parent_sampled_rss_enforcement_proven', 'authentic_user_consent_proven',
                      'formal_training_release'):
            self.assertIs(result[field], False)

    def test_every_additional_caller_source_is_required_and_pinned(self):
        manifest, sources = fixture()
        for name in sorted(binding.FILES):
            with self.subTest(name=name):
                absent = dict(sources); absent.pop(name)
                with self.assertRaisesRegex(ValueError, 'SOURCE_SET'): validate(manifest, absent)
                changed = dict(sources); changed[name] += b'changed'
                with self.assertRaisesRegex(ValueError, 'SOURCE_DRIFT'): validate(manifest, changed)

    def test_manifest_set_schema_and_authority_refused(self):
        for field, value in [('schema', 'other'), ('formal_training_release', True),
                             ('formal_training_release', 0), ('sources', {})]:
            manifest, sources = fixture(); manifest[field] = value
            with self.assertRaisesRegex(ValueError, 'MANIFEST_SCHEMA'): validate(manifest, sources)
        for name in ('/ssd/cjc/multimode_ate_gnn_v1/x.py', '../outside', 'src\\models\\x.py'):
            manifest, sources = fixture(); manifest['sources'][name] = 'a' * 64
            with self.assertRaisesRegex(ValueError, 'MANIFEST_SCHEMA'): validate(manifest, sources)

    def test_manifest_anchor_duplicate_deep_and_nonfinite(self):
        for raw in (b'{"schema":1,"schema":2}', b'[' * 3000 + b']' * 3000,
                    b'{"x":NaN}', b'\xff'):
            with self.assertRaises(ValueError):
                binding.validate_source_bytes(raw, {}, trusted_manifest_sha256=hashlib.sha256(raw).hexdigest())
        with self.assertRaisesRegex(ValueError, 'MANIFEST_PIN'):
            binding.validate_source_bytes(b'{}', {}, trusted_manifest_sha256='a' * 64)

    def test_source_and_aggregate_caps(self):
        for raw in (b'', bytearray(b'x'), b'x' * (binding.MAX_FILE_BYTES + 1)):
            manifest, sources = fixture(); sources[next(iter(sources))] = raw
            with self.assertRaisesRegex(ValueError, 'SOURCE_BOUND'): validate(manifest, sources)
        manifest, sources = fixture()
        with patch.object(binding, 'MAX_TOTAL_BYTES', 1):
            with self.assertRaisesRegex(ValueError, 'TOTAL_BOUND'): validate(manifest, sources)

    def test_lock_rejects_unpinned_duplicates_options_and_missing(self):
        manifest, sources = fixture(); raw = sources['requirements/runtime_v2.lock.txt']
        for extra in (b'numpy>=2\n', b'--extra-index-url x\n', b'NumPy==2.1.3\n',
                      b'scikit_learn==1.5.2\n', b'torch==2.5.1; python_version>"3"\n'):
            with self.assertRaises(ValueError): binding.parse_lock_bytes(raw + extra)
        with self.assertRaisesRegex(ValueError, 'INCOMPLETE_LOCK'):
            binding.parse_lock_bytes(b'numpy==2.1.3\n')


if __name__ == '__main__': unittest.main()
