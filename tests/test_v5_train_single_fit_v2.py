"""Portable non-ML tests: audited raw receipts plus mocked physical callbacks."""
import base64
from contextlib import contextmanager
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('_v5_cli_v2_test', ROOT/'scripts/run_v5_train_single_fit_v2.py')
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)
CHILD_RAW = base64.b64decode("eyJhY3R1YWxfZm9ybWFsX2ZpdHMiOiAwLCAiYXV0aGVudGljX3VzZXJfY29uc2VudF9wcm92ZW4iOiBmYWxzZSwgImF1dGhvcml6YXRpb25fcmF3X3NoYTI1NiI6ICJlZWIxNWYyYzU2NGMzNGZhNDZmOTkzODlmYmE0YTA5MmQzMDZmY2QxYjZkYjc4Mjg4NmVlOTAyYWQzZmYxNGEwIiwgImF1dG9tYXRpY19yZXRyaWVzIjogMCwgImNoaWxkX3ByZXJlcXVpc2l0ZXMiOiB7ImFkZHJlc3Nfc3BhY2VfbGltaXRzIjogWzg1ODk5MzQ1OTIsIDg1ODk5MzQ1OTJdLCAiYXV0aGVudGljX3VzZXJfY29uc2VudF9wcm92ZW4iOiBmYWxzZSwgImNvcmVfbGltaXRzIjogWzAsIDBdLCAicGFyZW50X3NhbXBsZWRfcnNzX2VuZm9yY2VtZW50X3Byb3ZlbiI6IGZhbHNlLCAic3RhdHVzIjogIlBBU1NfQ0hJTERfUFJFUkVRVUlTSVRFU19PTkxZIiwgInRocmVhZHMiOiAxfSwgImNvcmVfbWFuaWZlc3Rfc2hhMjU2IjogIjUzOTQ3NzlmYWFjNWM3NzgwMGEwYTlkOGVkNTJiZjlmMjRiYTJkZDcwMWY0OTlhNDk3NTRlNTFlN2RkY2VhZTciLCAiY3VkYV9hdmFpbGFibGUiOiBmYWxzZSwgImZpbmFsX2hlYWRfbG9zcyI6IDAuMDA2MTMxODk1MTYxMzk4MDk5LCAiZmluYWxfcGFpcl9yZWZlcmVuY2UiOiAwLjExODc1OTM5ODA5NDA3NzUxLCAiZml0dGluZ19sb2dfYnl0ZXMiOiAyODQ3MDYsICJmaXR0aW5nX2xvZ19yZWNvcmRzIjogMTIyLCAiZml0dGluZ19sb2dfc2hhMjU2IjogIjQ1NTEwZDljMmIxNzc3OTI3M2Y1MjZkNTdlMDUxNWM5OTc2NTU3YzFkMWQ2YTM2YWVhNzFmNDgwYzI2ZjAzMzgiLCAiZm9ybWFsX3RyYWluaW5nX3JlbGVhc2UiOiBmYWxzZSwgImZ4MnRydF9wcm9iZSI6IHsiYWN0dWFsX2xpbnV4X3Jlc291cmNlX3Byb29mIjogZmFsc2UsICJmb3JtYWxfdHJhaW5pbmdfcmVsZWFzZSI6IGZhbHNlLCAibmVnYXRpdmVfcHJvYmVfbmFtZXMiOiBbImZ4MnRydF9vc3MiLCAiaHlwb3RoZXNpcyIsICJvbWVnYWNvbmYiLCAib25ueCIsICJvbm54cnVudGltZSIsICJvbm54X3RmIiwgInBhbmRhcyIsICJ0YWJ1bGF0ZSIsICJ0ZW5zb3JmbG93IiwgInRlbnNvcnJ0IiwgInRvcmNoMnRydCIsICJ0cWRtIiwgInRyZWUiLCAidHZtIiwgInhhcnJheSJdLCAicHJvYmVfY291bnRzIjogeyJmeDJ0cnRfb3NzIjogMSwgImh5cG90aGVzaXMiOiAxLCAib21lZ2Fjb25mIjogMSwgIm9ubngiOiAxLCAib25ueF90ZiI6IDEsICJvbm54cnVudGltZSI6IDEsICJwYW5kYXMiOiAxLCAidGFidWxhdGUiOiAxLCAidGVuc29yZmxvdyI6IDEsICJ0ZW5zb3JydCI6IDEsICJ0b3JjaDJ0cnQiOiAxLCAidHFkbSI6IDEsICJ0cmVlIjogMSwgInR2bSI6IDEsICJ4YXJyYXkiOiAxfSwgInByb2JlX2ludm9jYXRpb25zIjogMTUsICJwcm9iZV9uYW1lIjogImZ4MnRydF9vc3MiLCAicHJvYmVfdmVyaWZpZWQiOiB0cnVlLCAic2VhcmNoX3BhdGhzIjogWyIvdXNyL2xpYi9weXRob24zMTEuemlwIiwgIi91c3IvbGliL3B5dGhvbjMuMTEiLCAiL3Vzci9saWIvcHl0aG9uMy4xMS9saWItZHlubG9hZCIsICIvc3NkL2NqYy9nbm5fbW9kZWxfcmFua2luZ192M190cmFpbl8wY2E3ZGJmXzIwMjYxMDA0X3IxL3ZlbnYvbGliL3B5dGhvbjMuMTEvc2l0ZS1wYWNrYWdlcyIsICIvc3NkL2NqYy9nbm5fbW9kZWxfcnVudGltZV92Ml85OGVmYmQ0Zl8yMDI2MTAwMlQyMzUxMTkvdmVudi9saWIvcHl0aG9uMy4xMS9zaXRlLXBhY2thZ2VzIl0sICJ0cmFjZV9vcmlnaW4iOiAiL3NzZC9jamMvZ25uX21vZGVsX3J1bnRpbWVfdjJfOThlZmJkNGZfMjAyNjEwMDJUMjM1MTE5L3ZlbnYvbGliL3B5dGhvbjMuMTEvc2l0ZS1wYWNrYWdlcy90b3JjaC9fZHluYW1vL3RyYWNlX3J1bGVzLnB5IiwgInRyYWNlX3NvdXJjZV9ieXRlcyI6IDE0MDk1MSwgInRyYWNlX3NvdXJjZV9zaGEyNTYiOiAiYmE0MzhhZmQyYjU3NGQ1ZDczMzUzMmU3OTk1ZWQwNGMyOTMwNmYzMmI3NWRmODc2NTc5NzgyODgzNzViY2VkNSJ9LCAiaGVsZF9sYWJlbF9yZWFkcyI6IDAsICJpbml0aWFsX2hlYWRfbG9zcyI6IDAuNzA0ODk1MDg4MjI5OTc2NiwgImluaXRpYWxfcGFpcl9yZWZlcmVuY2UiOiAwLjcxNTY0ODIzNzcwMzM1ODYsICJpbnRlcm9wX3RocmVhZHMiOiAxLCAiaml0X2FkbWlzc2lvbiI6IHsiYWN0dWFsX2xpbnV4X3Jlc291cmNlX3Byb29mIjogZmFsc2UsICJmb3JtYWxfdHJhaW5pbmdfcmVsZWFzZSI6IGZhbHNlLCAiZ2VuZXJhdGVkX3NvdXJjZV9ieXRlcyI6IDIzNTUsICJnZW5lcmF0ZWRfc291cmNlX3NoYTI1NiI6ICI4MjA1YjE2OTU2ZmIyNjQ4NDFlY2Q4NjQ0Nzg0YTBkMTU3Zjg3ZGY3OWIxN2MxNjgyNWRjMTE2MzQzM2NlNWQ4IiwgImluc3RhbGxlZF9zb3VyY2VfcGlucyI6IHsidG9yY2guZGlzdHJpYnV0ZWQubm4uaml0Lmluc3RhbnRpYXRvciI6ICI0NDBhNjE5Yzc2NGU0MTMzNTY0ZDc5NTZiYTA2MGE3MjIzZTk0NjY0ODU0Yjk0YTRhMjA3NGQwOTU3NTZkYjdlIiwgInRvcmNoLmRpc3RyaWJ1dGVkLm5uLmppdC50ZW1wbGF0ZXMucmVtb3RlX21vZHVsZV90ZW1wbGF0ZSI6ICIwZmYxODU2YmJkMDMxYjUyOThkNDZjMDZjMDUwMmFiYzIwYmQ4MDRmNDJjMTk0OWVkNDEyN2U4Yzc3MzY2MGNjIn0sICJqaXRfcm9vdCI6ICIvc3NkL2NqYy9nbm5fbW9kZWxfcmFua2luZ192NV9vcHRpbWl6ZXJfZ2F0ZV8yMDI2MTAxMV9yMS9qaXRfdG1wIiwgImppdF90ZW1wX2RpciI6ICIvc3NkL2NqYy9nbm5fbW9kZWxfcmFua2luZ192NV9vcHRpbWl6ZXJfZ2F0ZV8yMDI2MTAxMV9yMS9qaXRfdG1wL3RtcGRsNmN5ZnQzIiwgImppdF90ZW1wbGF0ZV9wcm92ZW4iOiB0cnVlfSwgIm1vZGVsX2J5dGVzIjogNzc1MiwgIm1vZGVsX3NoYTI1NiI6ICIzNzE3Y2RiZmUyZjg0OTY0MmY4ZDcyYmQ4ZDUyZjM3NDYwN2YyY2M2YTVjYWE3N2U0YjEwNjk3ZWU0MjMwMjhkIiwgIm51bXB5X29yaWdpbiI6ICIvc3NkL2NqYy9nbm5fbW9kZWxfcnVudGltZV92Ml85OGVmYmQ0Zl8yMDI2MTAwMlQyMzUxMTkvdmVudi9saWIvcHl0aG9uMy4xMS9zaXRlLXBhY2thZ2VzL251bXB5L19faW5pdF9fLnB5IiwgIm51bXB5X3ZlcnNpb24iOiAiMi4xLjMiLCAib3B0aW1pemVyX3N0ZXBzIjogMTIwLCAicHJvZHVjdGlvbl9wYWNrYWdlX3JlYWRzIjogMCwgInJlcXVlc3Rfc2hhMjU2IjogImRiMWZkZTU5MGM1ZmVhMDYxYjVjYmYzYTU1MWRiZTJlMDQ1ZWFlNjNjZGZjMzMxN2RmOTNmMTMyMWRkYjQ4MTQiLCAic3RhdHVzIjogIlBBU1NfQ09OVFJPTExFRF9DUFVfU1lOVEhFVElDX09QVElNSVpFUl9PTkxZIiwgInN1cHBsZW1lbnRhbF9zaGEyNTYiOiB7ImF1dGgvdXNlcl9hdXRob3JpemF0aW9uLnJhdy50eHQiOiAiZWViMTVmMmM1NjRjMzRmYTQ2Zjk5Mzg5ZmJhNGEwOTJkMzA2ZmNkMWI2ZGI3ODI4ODZlZTkwMmFkM2ZmMTRhMCIsICJkYXRhL2ZpeHR1cmVzL3JhbmtpbmdfdjVfcmVtb3RlX21vZHVsZV9ub25fc2NyaXB0YWJsZV8yMDI2MTAxMC50eHQiOiAiODIwNWIxNjk1NmZiMjY0ODQxZWNkODY0NDc4NGEwZDE1N2Y4N2RmNzliMTdjMTY4MjVkYzExNjM0MzNjZTVkOCIsICJzY3JpcHRzL3J1bl92NV9jb250cm9sbGVkX3J1bnRpbWVfZ2F0ZS5weSI6ICIwYTRiYjAzODljY2UyNWMyYWM1MGYzYWRjYzcyMWFjMmIyNTQ1YWNiZjJkMTVkZjNjNDFkNWFjOGJjYTVjNDYyIiwgInNjcmlwdHMvcnVuX3Y1X2Z4MnRydF9vcHRpbWl6ZXJfZ2F0ZS5weSI6ICJiZDMxMzlmODU3ZjE1MDQ1MjcyNzc3OTIzODA1OGZjMjg3MzFhNzZhNDQ5YTJjMTk3ZjAxODVkZTVhYWJiNjgxIiwgInNyYy9tb2RlbHMvcmFua2luZ192NV9meDJ0cnRfcHJvYmVfYWRtaXNzaW9uLnB5IjogImRlZjgxYzZhZjA0NTQ5MDk2ODU5NTdlZGY2ZTNhYTdjMmM0OGI2NmZiMDliNWFkMzFkZTIwZGVmNzBkNTRmNmUiLCAic3JjL21vZGVscy9yYW5raW5nX3Y1X2ppdF90ZW1wbGF0ZV9hZG1pc3Npb24ucHkiOiAiZDk2MWNjZDM4OWM0M2VmMmFlODg3ZTIwNzIxNDIyNTlhYTFiMWUxMzkxMzM0MzNhMTU4NjNjOWMxNTdkMzM5NiIsICJzcmMvbW9kZWxzL3JhbmtpbmdfdjVfbG9ja2VkX3J1bnRpbWVfaW1wb3J0cy5weSI6ICJiMWJkZGJkYTFlZjZlYTIzMjNhMWIzZmFjZTI4MmZiYjIxY2QxYTAxZGI2NGQ2OGRmZjhkZWFhMjgzMDhiMWRhIiwgInNyYy9tb2RlbHMvcmFua2luZ192NV9sb2NrZWRfcnVudGltZV9vYnNlcnZhdGlvbnMucHkiOiAiMDUyNGE3YjhjY2U3ZDAxN2MzZmU5ZmUzOGRjYzg2YjI5YTQ0MGVkN2IzNzNjMWMyMzYxZWJiYjc3Mzg0NTljOCJ9LCAic3ludGhldGljX29wdGltaXplcl9maXRzIjogMSwgInRocmVhZHMiOiAxLCAidG9yY2hfb3JpZ2luIjogIi9zc2QvY2pjL2dubl9tb2RlbF9ydW50aW1lX3YyXzk4ZWZiZDRmXzIwMjYxMDAyVDIzNTExOS92ZW52L2xpYi9weXRob24zLjExL3NpdGUtcGFja2FnZXMvdG9yY2gvX19pbml0X18ucHkiLCAidG9yY2hfdmVyc2lvbiI6ICIyLjUuMStjdTEyNCJ9")
MEMORY_RAW = base64.b64decode("eyJlZmZlY3RpdmVfdG90YWxfYnl0ZXMiOiAxMDgxNzk5NTIwMjU2LCAiZWxhcHNlZF9zZWNvbmRzIjogMy40NTgwNjA4MzgwNDkyNzc3LCAiZXhpdF9jb2RlIjogMCwgImluaXRpYWxfYXZhaWxhYmxlX2J5dGVzIjogMTAyNjI3NzE0NjYyNCwgIm1lbW9yeV9wb2xpY3kiOiB7ImNoaWxkX2FkZHJlc3Nfc3BhY2VfY2FwX2J5dGVzIjogODU4OTkzNDU5MiwgImNvbWJpbmVkX3Jzc19jYXBfYnl0ZXMiOiAxMDczNzQxODI0LCAibGltaXRhdGlvbiI6ICJSU1MgaXMgc2FtcGxlZDsgYnJpZWYgb3ZlcnNob290IGNhbiBvY2N1ci4gUkxJTUlUX0FTIGNhcHMgYWRkcmVzcyBzcGFjZSwgbm90IFJTUy4iLCAibWF4X2NvbmN1cnJlbnRfd29ya2VycyI6IDEsICJwb2xsX3NlY29uZHMiOiAwLjI1LCAicmVzZXJ2ZV9mcmFjdGlvbiI6IDAuMSwgInJlc2VydmVfbWluX2J5dGVzIjogNDI5NDk2NzI5NiwgInJldHJpZXMiOiAwLCAidGltZW91dF9zZWNvbmRzIjogMTgwMH0sICJwZWFrX2NvbWJpbmVkX3Jzc19ieXRlcyI6IDUzMzA4NjIwOCwgInBlYWtfZ3JvdXBfcnNzX2J5dGVzIjogNTExODIzODcyLCAicHJvY2Vzc19ncm91cCI6IDIyOTUzNTgsICJyZXNlcnZlX2J5dGVzIjogMTA4MTc5OTUyMDI2LCAic2FtcGxlX2NvdW50IjogMTEsICJzdGF0dXMiOiAiUEFTU19CT1VOREVEX1dPUktFUiJ9")

def encode(value):
    return json.dumps(value, sort_keys=True, allow_nan=False).encode()

def fixture():
    child, memory = json.loads(CHILD_RAW), json.loads(MEMORY_RAW)
    final = dict(status='PASS_BOUNDED_CONTROLLED_CPU_SYNTHETIC_OPTIMIZER_ONLY',
        root=cli.SMOKE_ROOT, supplemental_sha256=child['supplemental_sha256'],
        core_manifest_sha256=cli.CORE_MANIFEST_SHA256,
        child_receipt_sha256=cli._sha(CHILD_RAW), child_receipt=child,
        parent_guard_receipt=memory, actual_linux_resource_proof=True,
        formal_training_release=False, automatic_retries=0, worker_count=1)
    evidence = {
        'authorization.json': (ROOT/'contracts/ranking_v5_user_authorization_20261010_r2.json').read_bytes(),
        'scope_authorization.json': (ROOT/'contracts/ranking_v5_fixed_skiplist_smoke_authorization_20261011_r1.json').read_bytes(),
        'controlled_optimizer.child.json': CHILD_RAW,
        'controlled_optimizer.log.memory.json': MEMORY_RAW,
        'controlled_optimizer.launch.json': encode(final),
        cli.AUDIT: (ROOT/'data/manifests/ranking_v5_fixed_probe_optimizer_pass_20261011_r1.json').read_bytes(),
    }
    source = {p: (ROOT/p).read_bytes() for p in set(cli.GATE_SOURCES) | set(cli.FIXED_HELPER_PINS)}
    receipt = cli._helper((ROOT/'src/models/ranking_v5_parent_guard_receipt.py').read_bytes(), '_pure_receipt')
    return source, evidence, receipt

def trust():
    helpers = dict(cli.FIXED_HELPER_PINS, **{cli.TRAIN_JIT: 'a'*64})
    evidence = {p: 'b'*64 for p in cli.EVIDENCE}
    evidence.update(cli.OPTIMIZER_EVIDENCE_PINS)
    evidence.update({'authorization.json': cli.AUTHORIZATION_SHA256,
        'scope_authorization.json': cli.SCOPE_AUTHORIZATION_SHA256,
        'synthetic_linux_gate.json': cli.SYNTHETIC_LINUX_GATE_SHA256})
    return helpers, evidence

def envelope(helpers, pins, family='iwls_aes_core', seed=20260824):
    return dict(schema='v5-train-prelaunch-envelope-v2', source_root=cli.SOURCE_ROOT,
        output=cli.SOURCE_ROOT+'_'+family+'_'+str(seed), package_root=cli.PACKAGE_ROOT,
        family=family, seed=seed, roles=['TRAIN'], parent_resource_guard_required=True,
        core_manifest_sha256=cli.CORE_MANIFEST_SHA256, helper_sha256=helpers,
        authorization_id=cli.AUTHORIZATION_ID, gate_source_sha256=cli.optimizer_source_pins(),
        jit_root=cli.jit_root_for(cli.SOURCE_ROOT, family, seed),
        **{field: pins[path] for path, field in cli.EVIDENCE.items()})

class ActualEvidenceTests(unittest.TestCase):
    def test_exact_audited_receipts_and_sources_pass_without_ml(self):
        source, evidence, receipt = fixture()
        for path, digest in cli.OPTIMIZER_EVIDENCE_PINS.items():
            self.assertEqual(cli._sha(evidence[path]), digest)
        self.assertNotEqual(cli.AUTHORIZATION_SHA256, cli.SCOPE_AUTHORIZATION_SHA256)
        cli.validate_optimizer_evidence(source, evidence, receipt)

    def test_old_source_and_scope_authorization_rejected(self):
        for what in ('program', 'probe', 'auth'):
            source, evidence, receipt = fixture()
            if what == 'program':
                source[cli.OPTIMIZER_PROGRAM] = (ROOT/'scripts/run_v5_controlled_optimizer_gate.py').read_bytes()
            elif what == 'probe':
                source[cli.PROBE] += b'\n'
            else:
                evidence['scope_authorization.json'] = b'{}'
            with self.subTest(what=what), self.assertRaises(ValueError):
                cli.validate_optimizer_evidence(source, evidence, receipt)

    def test_raw_receipt_byte_changes_and_missing_audit_before_execution(self):
        for name in cli.OPTIMIZER_EVIDENCE_PINS:
            source, evidence, receipt = fixture()
            evidence[name] += b' '
            with self.subTest(name=name), patch.object(cli, '_helper', side_effect=AssertionError('exec')), self.assertRaisesRegex(ValueError, 'ACTUAL_EVIDENCE_BYTES'):
                cli.validate_optimizer_evidence(source, evidence, receipt)
        source, evidence, receipt = fixture()
        del evidence[cli.AUDIT]
        with patch.object(cli, '_helper', side_effect=AssertionError('exec')), self.assertRaisesRegex(ValueError, 'ACTUAL_EVIDENCE_BYTES'):
            cli.validate_optimizer_evidence(source, evidence, receipt)

    def test_actual_audit_rejects_wrong_fields_and_types(self):
        _, evidence, _ = fixture()
        audit = json.loads(evidence[cli.AUDIT])
        child, memory, final = json.loads(CHILD_RAW), json.loads(MEMORY_RAW), json.loads(evidence['controlled_optimizer.launch.json'])
        for key, bad in (('status', 'PASS_IMPLEMENTATION_ONLY'), ('root', cli.SOURCE_ROOT),
            ('optimizer_steps', True), ('optimizer_steps', 119), ('negative_probe_count', 14),
            ('jit_template_proven', 1), ('formal_fits', False), ('checkpoint_remains_on_B', False),
            ('child_raw_sha256', '0'*64), ('model_bytes', True), ('workers', True)):
            mutated = dict(audit); mutated[key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                cli.validate_actual_audit(mutated, child, memory, final)
        del audit['jit_template_proven']
        with self.assertRaises(ValueError):
            cli.validate_actual_audit(audit, child, memory, final)

    def test_old_root_final_rejected_even_with_external_raw_pin(self):
        source, evidence, receipt = fixture()
        final = json.loads(evidence['controlled_optimizer.launch.json'])
        final['root'] = cli.SMOKE_ROOT.replace('20261011_r1', '20261010_r2')
        evidence['controlled_optimizer.launch.json'] = encode(final)
        pins = dict(cli.OPTIMIZER_EVIDENCE_PINS)
        pins['controlled_optimizer.launch.json'] = cli._sha(evidence['controlled_optimizer.launch.json'])
        with patch.object(cli, 'OPTIMIZER_EVIDENCE_PINS', pins), self.assertRaises(ValueError):
            cli.validate_optimizer_evidence(source, evidence, receipt)

class TrustAndScopeTests(unittest.TestCase):
    def test_external_trust_and_exact18_envelopes(self):
        helpers, pins = trust()
        cli.validate_external_trust(helpers, pins)
        seen = set()
        for family in cli.FAMILIES:
            for seed in cli.SEEDS:
                item = envelope(helpers, pins, family, seed); raw = encode(item)
                args = (raw, cli._sha(raw), cli.SOURCE_ROOT, item['output'], cli.PACKAGE_ROOT, family, seed)
                self.assertEqual(cli._envelope(*args, trusted_supplement_sha256=helpers, trusted_evidence_sha256=pins), item)
                seen.add(item['jit_root'])
        self.assertEqual(len(seen), 18)

    def test_external_pin_mismatch_and_old_schema(self):
        helpers, pins = trust()
        for field, bad in (('helper_sha256', {}), ('schema', 'v5-train-prelaunch-envelope-v1'),
                            ('jit_root', cli.SOURCE_ROOT+'/jit_tmp/iwls_spi_20260824'),
                            ('optimizer_audit_sha256', '0'*64)):
            item = envelope(helpers, pins); item[field] = bad; raw = encode(item)
            with self.subTest(field=field), self.assertRaises(ValueError):
                cli._envelope(raw, cli._sha(raw), cli.SOURCE_ROOT, item['output'], cli.PACKAGE_ROOT,
                    item['family'], item['seed'], trusted_supplement_sha256=helpers, trusted_evidence_sha256=pins)

    def test_missing_external_maps_fail_closed(self):
        helpers, pins = trust()
        for h, p in (({}, pins), (helpers, {}), (None, pins), (helpers, {**pins, 'unknown': 'a'*64})):
            with self.assertRaises(ValueError):
                cli.validate_external_trust(h, p)

    def test_invalid_task_and_old_root_zero_io(self):
        for root, family, seed in ((cli.SOURCE_ROOT, 'wrong', 20260824),
            (cli.SOURCE_ROOT, 'iwls_spi', True), ('/ssd/cjc/gnn_model_ranking_v5_train_20261010_r1', 'iwls_spi', 20260824),
            ('/ssd/cjc/multimode_ate_gnn_v1', 'iwls_spi', 20260824)):
            with patch.object(Path, 'lstat', side_effect=AssertionError('IO')), self.assertRaises(ValueError):
                cli.jit_root_for(root, family, seed)

class SidecarTests(unittest.TestCase):
    def setUp(self):
        self.helpers, _ = trust()
        self.family, self.seed = 'iwls_spi', 20260824
        self.output = cli.SOURCE_ROOT+'_'+self.family+'_'+str(self.seed)
        child = json.loads(CHILD_RAW)
        jit = copy.deepcopy(child['jit_admission'])
        jit['jit_root'] = cli.jit_root_for(cli.SOURCE_ROOT, self.family, self.seed)
        jit['jit_temp_dir'] = jit['jit_root']+'/tmpabcd1234'
        self.value = dict(schema='v5-train-fit-boundary-admission-v2',
            status='PASS_TRAIN_FIT_BOUNDARY_ADMISSION_ONLY', source_root=cli.SOURCE_ROOT,
            output=self.output, family=self.family, seed=self.seed, helper_sha256=self.helpers,
            jit_admission=jit, fx2trt_probe=child['fx2trt_probe'], admission_at_fit_boundaries_only=True,
            inside_save_hook_verified=False, formal_training_authorized_by_this_function=False)

    def validate(self, value):
        return cli.validate_fit_admission_receipt(encode(value), source_root=cli.SOURCE_ROOT,
            output=self.output, family=self.family, seed=self.seed, trusted_supplement_sha256=self.helpers)

    def test_task_bound_sidecar_and_no_inside_save_claim(self):
        self.assertEqual(self.validate(self.value), self.value)
        self.assertEqual(cli.admission_sidecar_path(cli.SOURCE_ROOT, self.family, self.seed),
            cli.SOURCE_ROOT+'/jit_admission_iwls_spi_20260824.json')

    def test_sidecar_wrong_task_types_and_false_authority_rejected(self):
        for key, bad in (('output', self.output+'x'), ('seed', True), ('inside_save_hook_verified', True),
                         ('formal_training_authorized_by_this_function', True)):
            value = copy.deepcopy(self.value); value[key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate(value)

    def test_sidecar_jit_and_probe_drift_rejected(self):
        for kind in ('root', 'count', 'typed_count', 'probe_verified', 'jit_verified'):
            value = copy.deepcopy(self.value)
            if kind == 'root': value['jit_admission']['jit_root'] = cli.SMOKE_ROOT+'/jit_tmp'
            elif kind == 'count': value['fx2trt_probe']['probe_counts']['onnx'] = 2
            elif kind == 'typed_count': value['fx2trt_probe']['probe_counts']['onnx'] = True
            elif kind == 'probe_verified': value['fx2trt_probe']['probe_verified'] = False
            else: value['jit_admission']['jit_template_proven'] = False
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.validate(value)

class BoundaryIntegrationTests(unittest.TestCase):
    def run_mock(self, fail_exit=False):
        source, evidence, _ = fixture()
        family, seed = 'iwls_spi', 20260824
        output = cli.SOURCE_ROOT+'_'+family+'_'+str(seed)
        core = {p: b'# synthetic core only\n' for p in cli.CORE_FILES}
        manifest = encode(dict(schema='v5-caller-source-bytes-v1', formal_training_release=False,
                               sources={p: cli._sha(raw) for p, raw in core.items()}))
        helpers = {p: (ROOT/p).read_bytes() for p in cli.HELPERS}
        evidence.update({'release.json': encode({'user_authorization_id': cli.AUTHORIZATION_ID}),
            'review.json': b'{}', 'physical_gate.json': b'{}', 'synthetic_linux_gate.json': b'{}'})
        helper_pins = {p: cli._sha(raw) for p, raw in helpers.items()}
        evidence_pins = {p: cli._sha(evidence[p]) for p in cli.EVIDENCE}
        table = {**core, **helpers, **source, **evidence, cli.MANIFEST_NAME: manifest}
        events = []
        child = json.loads(CHILD_RAW)
        admission_receipt = copy.deepcopy(child['jit_admission'])
        admission_receipt['jit_root'] = cli.jit_root_for(cli.SOURCE_ROOT, family, seed)
        admission_receipt['jit_temp_dir'] = admission_receipt['jit_root']+'/tmpabcd1234'
        admission_receipt['fx2trt_probe'] = copy.deepcopy(child['fx2trt_probe'])
        @contextmanager
        def context(*args, **kwargs):
            self.assertEqual(kwargs['jit_root'], cli.jit_root_for(cli.SOURCE_ROOT, family, seed))
            events.append('enter')
            yield admission_receipt
            events.append('exit')
            if fail_exit:
                raise ValueError('synthetic exit proof failed')
        def verify(receipt):
            self.assertIs(receipt, admission_receipt)
            events.append('verify')
        admission = SimpleNamespace(controlled_imports=context, validate_current=verify)
        helper_objects = {'_v5_train_frozen_helper': object(), '_v5_train_observation_helper': object(),
            '_v5_train_runtime_helper': object(), '_v5_train_jit_helper': object(),
            '_v5_train_negative_helper': admission}
        def worker(*args, **kwargs):
            events.append('worker')
            return dict(status='PASS_SINGLE_FIT_CALLBACK_ADAPTER_ONLY',
                formal_training_authorized_by_this_function=False, new_formal_18_fit_release=False)
        imported = {
            'src.models.ranking_v5_caller_source_binding': SimpleNamespace(validate_source_bytes=lambda *a, **k: None),
            'src.models.ranking_v5_approval_binding': SimpleNamespace(validate_approval_integrity=lambda *a, **k: None),
            'src.models.ranking_v5_parent_guard_receipt': object(),
            'src.models.ranking_v5_worker_resource_context': SimpleNamespace(check_current_process=lambda: None),
            'src.models.ranking_v5_single_fit_worker': SimpleNamespace(execute_single_fit=worker),
            'torch': SimpleNamespace(cuda=SimpleNamespace(is_available=lambda: False)), 'numpy': object(),
        }
        def import_mock(name):
            if name == 'torch._dynamo':
                events.append('eager_dynamo')
                return object()
            return imported[name]
        with patch.object(cli, 'CORE_MANIFEST_SHA256', cli._sha(manifest)), \
             patch.object(cli, 'LOCK_SHA256', cli._sha(core['requirements/runtime_v2.lock.txt'])), \
             patch.object(cli, 'SYNTHETIC_LINUX_GATE_SHA256', cli._sha(b'{}')), \
             patch.object(cli, '_runtime'), patch.object(cli, '_read', side_effect=lambda r, p, c: table[p]), \
             patch.object(cli, '_helper', side_effect=lambda raw, name: helper_objects[name]), \
             patch.object(cli, '_import', side_effect=import_mock), \
             patch.object(cli, 'validate_optimizer_evidence'), patch.object(cli, 'persist_admission_sidecar') as persist:
            item = envelope(helper_pins, evidence_pins, family, seed); raw = encode(item)
            kwargs = dict(trusted_envelope_sha256=cli._sha(raw), source_root=cli.SOURCE_ROOT,
                output=output, package_root=cli.PACKAGE_ROOT, family=family, seed=seed,
                trusted_supplement_sha256=helper_pins, trusted_evidence_sha256=evidence_pins)
            if fail_exit:
                with self.assertRaisesRegex(ValueError, 'exit proof'):
                    cli.execute_prelaunch(raw, **kwargs)
                persist.assert_not_called()
            else:
                cli.execute_prelaunch(raw, **kwargs)
                persist.assert_called_once()
                self.assertFalse(json.loads(persist.call_args.args[0])['inside_save_hook_verified'])
        return events

    def test_eager_admission_and_proof_order_without_real_ml(self):
        self.assertEqual(self.run_mock(), ['enter', 'eager_dynamo', 'verify', 'worker', 'verify', 'exit'])

    def test_failed_context_exit_does_not_persist_acceptance_sidecar(self):
        self.run_mock(fail_exit=True)


if __name__ == '__main__':
    unittest.main()
