"""Portable non-ML tests: audited raw receipts plus mocked physical callbacks."""
import base64
from contextlib import contextmanager
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from types import ModuleType
from importlib.machinery import ModuleSpec
import sys
import stat
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('_v5_cli_v3_test', ROOT/'scripts/run_v5_train_single_fit_v3.py')
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
    helpers = dict(cli.FIXED_HELPER_PINS, **{cli.TRAIN_JIT: 'a'*64,
        cli.FREEZE_LOADER: cli.RUN_AUTHORIZATION_EXPECTED['freeze_runtime_sha256'][cli.FREEZE_LOADER]})
    evidence = {p: 'b'*64 for p in cli.EVIDENCE}
    evidence.update(cli.OPTIMIZER_EVIDENCE_PINS)
    evidence.update({'authorization.json': cli.AUTHORIZATION_SHA256,
        'run_authorization.json': cli.RUN_AUTHORIZATION_SHA256,
        'scope_authorization.json': cli.SCOPE_AUTHORIZATION_SHA256,
        'synthetic_linux_gate.json': cli.SYNTHETIC_LINUX_GATE_SHA256})
    return helpers, evidence

def freeze_trust():
    return {p: cli.RUN_AUTHORIZATION_EXPECTED['freeze_runtime_sha256'][p] for p in cli.FREEZE_SOURCES}


def envelope(helpers, pins, family='iwls_aes_core', seed=20260824):
    return dict(schema='v5-train-prelaunch-envelope-v3', source_root=cli.SOURCE_ROOT,
        output=cli.SOURCE_ROOT+'_'+family+'_'+str(seed), package_root=cli.PACKAGE_ROOT,
        family=family, seed=seed, roles=['TRAIN'], parent_resource_guard_required=True,
        core_manifest_sha256=cli.CORE_MANIFEST_SHA256, helper_sha256=helpers,
        authorization_id=cli.AUTHORIZATION_ID, gate_source_sha256=cli.optimizer_source_pins(),
        jit_root=cli.jit_root_for(cli.SOURCE_ROOT, family, seed),
        freeze_supplement_sha256=freeze_trust(), freeze_loader_sha256=helpers[cli.FREEZE_LOADER],
        run_authorization_id=cli.RUN_AUTHORIZATION_ID, source_binding_sha256='c'*64,
        legacy_evidence_binding_sha256='d'*64,
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
        cli.validate_external_trust(helpers, pins, trusted_freeze_supplement_sha256=freeze_trust())
        seen = set()
        for family in cli.FAMILIES:
            for seed in cli.SEEDS:
                item = envelope(helpers, pins, family, seed); raw = encode(item)
                args = (raw, cli._sha(raw), cli.SOURCE_ROOT, item['output'], cli.PACKAGE_ROOT, family, seed)
                self.assertEqual(cli._envelope(*args, trusted_supplement_sha256=helpers, trusted_evidence_sha256=pins, trusted_freeze_supplement_sha256=freeze_trust()), item)
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
                    item['family'], item['seed'], trusted_supplement_sha256=helpers, trusted_evidence_sha256=pins, trusted_freeze_supplement_sha256=freeze_trust())

    def test_missing_external_maps_fail_closed(self):
        helpers, pins = trust()
        for h, p in (({}, pins), (helpers, {}), (None, pins), (helpers, {**pins, 'unknown': 'a'*64})):
            with self.assertRaises(ValueError):
                cli.validate_external_trust(h, p, trusted_freeze_supplement_sha256=freeze_trust())

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
        self.value = dict(schema='v5-train-fit-boundary-admission-v3',
            status='PASS_TRAIN_FIT_BOUNDARY_ADMISSION_ONLY', source_root=cli.SOURCE_ROOT,
            output=self.output, family=self.family, seed=self.seed, helper_sha256=self.helpers,
            freeze_supplement_sha256=freeze_trust(), freeze_loader_sha256=self.helpers[cli.FREEZE_LOADER],
            run_authorization_sha256=cli.RUN_AUTHORIZATION_SHA256, run_authorization_id=cli.RUN_AUTHORIZATION_ID,
            source_binding_sha256='c'*64, legacy_evidence_binding_sha256='d'*64,
            run_binding_review_sha256='b'*64, freeze_worker_context_completed=True,
            freeze_loaded_names=list(cli.FREEZE_CHILD_NAMES),
            jit_admission=jit, fx2trt_probe=child['fx2trt_probe'], admission_at_fit_boundaries_only=True,
            inside_save_hook_verified=False, formal_training_authorized_by_this_function=False)

    def validate(self, value):
        return cli.validate_fit_admission_receipt(encode(value), source_root=cli.SOURCE_ROOT,
            output=self.output, family=self.family, seed=self.seed, trusted_supplement_sha256=self.helpers, trusted_freeze_supplement_sha256=freeze_trust(),
            source_binding_sha256='c'*64, legacy_evidence_binding_sha256='d'*64,
            run_binding_review_sha256='b'*64)

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


class SidecarDriftTests(SidecarTests):
    def test_sidecar_jit_and_probe_drift_rejected(self):
        for kind in ('root', 'count', 'typed_count', 'probe_verified', 'jit_verified', 'worker_context', 'loaded_names'):
            value = copy.deepcopy(self.value)
            if kind == 'root': value['jit_admission']['jit_root'] = cli.SMOKE_ROOT+'/jit_tmp'
            elif kind == 'count': value['fx2trt_probe']['probe_counts']['onnx'] = 2
            elif kind == 'typed_count': value['fx2trt_probe']['probe_counts']['onnx'] = True
            elif kind == 'probe_verified': value['fx2trt_probe']['probe_verified'] = False
            elif kind == 'worker_context': value['freeze_worker_context_completed'] = False
            elif kind == 'loaded_names': value['freeze_loaded_names'].append('scripts.run_v5_train_single_fit')
            else: value['jit_admission']['jit_template_proven'] = False
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.validate(value)


def binding_review(source_digest='c'*64, evidence_digest='d'*64):
    return dict(schema='v5-fresh-train-run-binding-review-v1',
        status='PASS_V5_FRESH_RUN_BINDING_REVIEW', scope=cli.RUN_AUTHORIZATION_EXPECTED['scope'],
        source_root=cli.SOURCE_ROOT, run_authorization_sha256=cli.RUN_AUTHORIZATION_SHA256,
        core_manifest_sha256=cli.CORE_MANIFEST_SHA256, source_binding_sha256=source_digest,
        legacy_evidence_binding_sha256=evidence_digest)


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def packet_fixture(helpers=None, evidence=None, source_overrides=None):
    default_helpers, default_evidence = trust()
    helpers = default_helpers if helpers is None else helpers
    evidence = default_evidence if evidence is None else evidence
    names = cli.CORE_FILES | set(cli.HELPERS) | set(cli.GATE_SOURCES) | set(cli.FREEZE_SOURCES) | {
        'scripts/run_v5_train_single_fit_v3.py', 'scripts/run_v5_train_serial_parent_v3.py',
        'src/models/ranking_v5_serial_matrix.py'}
    sources = {p: 'a'*64 for p in names}
    sources.update(helpers); sources.update(freeze_trust()); sources.update(cli.optimizer_source_pins())
    if source_overrides:
        sources.update(source_overrides)
    all_evidence = dict(evidence, **{p: 'b'*64 for p in
        ('cpu_gate.child.json', 'cpu_gate.memory.json', 'cpu_gate.launch.json')})
    source_digest = cli._sha(compact(sources))
    evidence_digest = cli._sha(compact({p: v for p, v in all_evidence.items()
                                     if p != 'run_binding_review.json'}))
    review = compact(binding_review(source_digest, evidence_digest))
    all_evidence['run_binding_review.json'] = cli._sha(review)
    evidence = {p: all_evidence[p] for p in cli.EVIDENCE}
    item = envelope(helpers, evidence)
    item.update(source_binding_sha256=source_digest, legacy_evidence_binding_sha256=evidence_digest)
    raw = compact(item)
    prelaunch = {f'prelaunch_{f}_{s}.json': 'a'*64 for f in cli.FAMILIES for s in cli.SEEDS}
    prelaunch[f"prelaunch_{item['family']}_{item['seed']}.json"] = cli._sha(raw)
    packet = compact(dict(schema='v5-train-serial-launch-packet-v3', source_root=cli.SOURCE_ROOT,
        package_root=cli.PACKAGE_ROOT, core_manifest_sha256=cli.CORE_MANIFEST_SHA256,
        source_sha256=sources, evidence_sha256=all_evidence, prelaunch_sha256=prelaunch))
    once = compact(dict(schema='v5-fresh-train-one-use-authorization-v1', source_root=cli.SOURCE_ROOT,
        run_authorization_sha256=cli.RUN_AUTHORIZATION_SHA256,
        run_authorization_id=cli.RUN_AUTHORIZATION_ID, source_binding_sha256=source_digest,
        packet_sha256=cli._sha(packet), planned_fits=18, automatic_retries=0))
    return item, evidence, packet, review, once


class NewRunGateTests(unittest.TestCase):
    def test_actual_new_authorization_and_legacy_separation(self):
        raw = (ROOT/'contracts/ranking_v5_freeze_v2_fresh_train_authorization_20261011_r1.json').read_bytes()
        actual = cli.validate_run_authorization(raw,
            trusted_run_authorization_sha256=cli.RUN_AUTHORIZATION_SHA256, source_root=cli.SOURCE_ROOT)
        self.assertEqual(actual, cli.RUN_AUTHORIZATION_EXPECTED)
        self.assertNotEqual(cli.RUN_AUTHORIZATION_SHA256, cli.AUTHORIZATION_SHA256)
        old = (ROOT/'contracts/ranking_v5_user_authorization_20261010_r2.json').read_bytes()
        with self.assertRaises(ValueError):
            cli.validate_run_authorization(old, trusted_run_authorization_sha256=cli.AUTHORIZATION_SHA256,
                                           source_root=cli.SOURCE_ROOT)

    def test_run_authorization_exact_types_and_unknown_fields(self):
        for key, bad in [('planned_fits', True), ('workers', 2), ('roles', ['TRAIN', 'BLIND']),
                         ('source_root', cli.SOURCE_ROOT.replace('_r2', '_r1')),
                         ('legacy_release_is_integrity_only_for_this_run', False), ('unknown', 0)]:
            value = copy.deepcopy(cli.RUN_AUTHORIZATION_EXPECTED); value[key] = bad; raw = compact(value)
            with self.subTest(key=key), patch.object(cli, 'RUN_AUTHORIZATION_SHA256', cli._sha(raw)):
                with self.assertRaises(ValueError):
                    cli.validate_run_authorization(raw, trusted_run_authorization_sha256=cli._sha(raw),
                                                   source_root=cli.SOURCE_ROOT)

    def test_review_and_once_exact_binding_and_types(self):
        review = compact(binding_review())
        cli.validate_run_binding_review(review, trusted_review_sha256=cli._sha(review),
            source_root=cli.SOURCE_ROOT, source_binding_sha256='c'*64,
            legacy_evidence_binding_sha256='d'*64)
        item, pins, packet, _, once = packet_fixture()
        cli.validate_fresh_once(once, source_root=cli.SOURCE_ROOT,
            source_binding_sha256=item['source_binding_sha256'], packet_sha256=cli._sha(packet))
        for key, bad in [('planned_fits', True), ('automatic_retries', False),
                         ('run_authorization_sha256', cli.AUTHORIZATION_SHA256), ('packet_sha256', 'f'*64),
                         ('source_root', cli.SOURCE_ROOT.replace('_r2', '_r1')), ('unknown', 0)]:
            value = json.loads(once); value[key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                cli.validate_fresh_once(compact(value), source_root=cli.SOURCE_ROOT,
                    source_binding_sha256=item['source_binding_sha256'], packet_sha256=cli._sha(packet))
        for key, bad in [('schema', 'v5-independent-release-binding-review-v1'),
                         ('status', 'PASS_IMPLEMENTATION_ONLY'), ('source_binding_sha256', 'e'*64),
                         ('unknown', 1)]:
            value = binding_review(); value[key] = bad; raw = compact(value)
            with self.subTest(review_key=key), self.assertRaises(ValueError):
                cli.validate_run_binding_review(raw, trusted_review_sha256=cli._sha(raw),
                    source_root=cli.SOURCE_ROOT, source_binding_sha256='c'*64,
                    legacy_evidence_binding_sha256='d'*64)

    def test_current_packet_maps_and_legacy_root_cannot_self_authorize(self):
        helpers, _ = trust(); item, pins, packet, _, _ = packet_fixture(helpers)
        kwargs = dict(envelope=item, trusted_supplement_sha256=helpers,
                      trusted_evidence_sha256=pins, trusted_freeze_supplement_sha256=freeze_trust())
        self.assertEqual(cli.validate_current_launch_packet(packet, **kwargs), cli._sha(packet))
        for target in ('source', 'evidence', 'root', 'missing', 'old_schema'):
            value = json.loads(packet)
            if target == 'source': value['source_sha256'][cli.FREEZE_WORKER] = 'e'*64
            elif target == 'evidence': value['evidence_sha256']['authorization.json'] = 'e'*64
            elif target == 'root': value['source_root'] = cli.SOURCE_ROOT.replace('_r2', '_r1')
            elif target == 'old_schema': value['schema'] = 'v5-train-serial-launch-packet-v2'
            else: del value['prelaunch_sha256'][next(iter(value['prelaunch_sha256']))]
            with self.subTest(target=target), self.assertRaises(ValueError):
                cli.validate_current_launch_packet(compact(value), **kwargs)

    def test_missing_freeze_trust_and_wrong_loader_fail_before_compile(self):
        helpers, pins = trust()
        for changed in ({}, dict(freeze_trust(), arbitrary='a'*64),
                        dict(freeze_trust(), **{cli.FREEZE_WORKER: 'f'*64})):
            with patch('builtins.compile') as compiler, self.assertRaises(ValueError):
                cli.validate_external_trust(helpers, pins, trusted_freeze_supplement_sha256=changed)
            compiler.assert_not_called()
        helpers[cli.FREEZE_LOADER] = 'f'*64
        with self.assertRaises(ValueError):
            cli.validate_external_trust(helpers, pins, trusted_freeze_supplement_sha256=freeze_trust())


class ChildContextTests(unittest.TestCase):
    """Stdlib synthetic source-selection/cache tests, not runtime authority proof."""
    def fixture(self):
        loader = cli._helper((ROOT/cli.FREEZE_LOADER).read_bytes(), '_unit_sealed_loader')
        sources = {p: b"raise AssertionError('parent-only source executed')\n" for p in cli.FREEZE_SOURCES}
        sources[cli.FREEZE_SOURCES[0]] = b'value = 1\n'
        sources[cli.FREEZE_SOURCES[1]] = b'from src.models import ranking_v5_freeze_codec_v2 as codec\nvalue = codec.value + 1\n'
        sources[cli.FREEZE_WORKER] = b'from src.models import ranking_v5_real_artifact_store_v2 as store\nvalue = store.value + 1\n'
        pins = {p: cli._sha(raw) for p, raw in sources.items()}
        package = ModuleType('src.models'); package.__path__ = []
        package.__spec__ = ModuleSpec('src.models', None, origin='sealed://namespace/src.models', is_package=True)
        return loader, sources, pins, package

    @contextmanager
    def namespace(self, package):
        with patch.dict(sys.modules, {'src.models': package}), patch.object(cli, 'validate_freeze_trust'):
            for name in cli.FREEZE_CHILD_NAMES:
                sys.modules.pop(name, None)
            yield

    def test_all_six_authenticated_before_compile(self):
        loader, sources, pins, package = self.fixture()
        for path in cli.FREEZE_SOURCES:
            changed = dict(sources); changed[path] += b'\n'
            with self.namespace(package), patch('builtins.compile') as compiler:
                with self.assertRaises(ValueError):
                    with cli.authenticated_child_worker(loader, changed, pins): self.fail('entered')
                compiler.assert_not_called()

    def test_only_three_load_identity_cleanup_success_and_failure(self):
        loader, sources, pins, package = self.fixture()
        old = object(); package.ranking_v5_single_fit_worker = old
        for fail in (False, True):
            with self.namespace(package):
                try:
                    with cli.authenticated_child_worker(loader, sources, pins) as worker:
                        self.assertEqual(worker.value, 3)
                        self.assertTrue(all(name in sys.modules for name in cli.FREEZE_CHILD_NAMES))
                        self.assertIs(package.ranking_v5_single_fit_worker, old)
                        if fail: raise RuntimeError('unit callback failure')
                except RuntimeError:
                    self.assertTrue(fail)
                self.assertTrue(all(name not in sys.modules for name in cli.FREEZE_CHILD_NAMES))
                self.assertTrue(all(name.rsplit('.', 1)[1] not in package.__dict__ for name in cli.FREEZE_CHILD_NAMES))
                self.assertIs(package.ranking_v5_single_fit_worker, old)

    def test_preload_rejected_and_replacement_preserved_on_cache_failure(self):
        loader, sources, pins, package = self.fixture()
        sentinel = ModuleType(cli.FREEZE_CHILD_NAMES[0])
        with self.namespace(package):
            sys.modules[cli.FREEZE_CHILD_NAMES[0]] = sentinel
            with self.assertRaisesRegex(ValueError, 'FREEZE_PRELOADED'):
                with cli.authenticated_child_worker(loader, sources, pins): self.fail('entered')
            self.assertIs(sys.modules[cli.FREEZE_CHILD_NAMES[0]], sentinel)
        with self.namespace(package):
            with self.assertRaisesRegex(ValueError, 'FREEZE_CACHE_DRIFT'):
                with cli.authenticated_child_worker(loader, sources, pins):
                    sys.modules[cli.FREEZE_CHILD_NAMES[0]] = sentinel
            self.assertIs(sys.modules[cli.FREEZE_CHILD_NAMES[0]], sentinel)
            self.assertTrue(all(name not in sys.modules for name in cli.FREEZE_CHILD_NAMES[1:]))


class BoundaryIntegrationTests(unittest.TestCase):
    """Mock physical callback only; fresh authority/packet/once gates stay real."""
    def run_mock(self, failed_context=None, missing_once=False):
        source, evidence, _ = fixture()
        core = {p: (ROOT/p).read_bytes() for p in cli.CORE_FILES}
        helpers = {p: (ROOT/p).read_bytes() for p in cli.HELPERS}
        freeze = {p: (ROOT/p).read_bytes() for p in cli.FREEZE_SOURCES}
        evidence.update({'release.json': compact({'user_authorization_id': cli.AUTHORIZATION_ID}),
            'review.json': b'{}', 'physical_gate.json': b'{}', 'synthetic_linux_gate.json': b'{}',
            'run_authorization.json': (ROOT/'contracts/ranking_v5_freeze_v2_fresh_train_authorization_20261011_r1.json').read_bytes(),
            'run_binding_review.json': b'{}'})
        helper_pins = {p: cli._sha(raw) for p, raw in helpers.items()}
        evidence_pins = {p: cli._sha(evidence[p]) for p in cli.EVIDENCE}
        with patch.object(cli, 'SYNTHETIC_LINUX_GATE_SHA256', cli._sha(b'{}')):
            item, evidence_pins, packet, review, once = packet_fixture(helper_pins, evidence_pins,
                source_overrides={p: cli._sha(raw) for p, raw in core.items()})
        evidence['run_binding_review.json'] = review
        table = {**core, **helpers, **source, **evidence, **freeze,
                 cli.MANIFEST_NAME: (ROOT/cli.MANIFEST_NAME).read_bytes(), 'launch_packet.json': packet}
        events = []
        child = json.loads(CHILD_RAW)
        receipt = copy.deepcopy(child['jit_admission'])
        receipt['jit_root'] = item['jit_root']; receipt['jit_temp_dir'] = receipt['jit_root']+'/tmpabcd1234'
        receipt['fx2trt_probe'] = copy.deepcopy(child['fx2trt_probe'])
        @contextmanager
        def admission_context(*args, **kwargs):
            events.append('admission_enter'); yield receipt
            events.append('admission_exit')
            if failed_context == 'admission': raise ValueError('unit admission exit failure')
        def verify(value):
            self.assertIs(value, receipt); events.append('verify')
        def callback(*args, **kwargs):
            events.append('new_worker')
            return dict(status='PASS_SINGLE_FIT_CALLBACK_ADAPTER_ONLY',
                        formal_training_authorized_by_this_function=False, new_formal_18_fit_release=False)
        @contextmanager
        def child_context(loader, raws, pins):
            self.assertEqual(set(raws), set(cli.FREEZE_SOURCES))
            loader.validate_sources(raws, pins)
            events.append('child_enter'); yield SimpleNamespace(execute_single_fit=callback)
            events.append('child_exit')
            if failed_context == 'child': raise ValueError('unit child exit failure')
        admission = SimpleNamespace(controlled_imports=admission_context, validate_current=verify)
        real_loader = cli._helper(helpers[cli.FREEZE_LOADER], '_unit_loader_for_boundary')
        helper_objects = {'_v5_train_frozen_helper': object(), '_v5_train_observation_helper': object(),
            '_v5_train_runtime_helper': object(), '_v5_train_jit_helper': object(),
            '_v5_train_negative_helper': admission, '_v5_train_freeze_loader': real_loader}
        imported = {
            'src.models.ranking_v5_caller_source_binding': SimpleNamespace(validate_source_bytes=lambda *a, **k: None),
            'src.models.ranking_v5_approval_binding': SimpleNamespace(validate_approval_integrity=lambda *a, **k: None),
            'src.models.ranking_v5_parent_guard_receipt': object(),
            'src.models.ranking_v5_worker_resource_context': SimpleNamespace(check_current_process=lambda: None),
            'torch': SimpleNamespace(cuda=SimpleNamespace(is_available=lambda: False)), 'numpy': object(),
        }
        def import_mock(name):
            if name == 'torch._dynamo': events.append('eager_dynamo'); return object()
            self.assertNotEqual(name, 'src.models.ranking_v5_single_fit_worker')
            return imported[name]
        with patch.object(cli, 'SYNTHETIC_LINUX_GATE_SHA256', cli._sha(b'{}')), \
             patch.object(cli, '_runtime'), patch.object(cli, '_read', side_effect=lambda r,p,c: table[p]), \
             patch.object(cli, '_read_global_once', side_effect=FileNotFoundError('unit missing once')
                          if missing_once else None, return_value=once), \
             patch.object(cli, '_helper', side_effect=lambda raw,name: helper_objects[name]) as compiler, \
             patch.object(cli, '_import', side_effect=import_mock), \
             patch.object(cli, 'authenticated_child_worker', side_effect=child_context), \
             patch.object(cli, 'validate_optimizer_evidence'), \
             patch.object(cli, 'persist_admission_sidecar') as persist:
            raw = compact(item)
            kwargs = dict(trusted_envelope_sha256=cli._sha(raw), source_root=cli.SOURCE_ROOT,
                output=item['output'], package_root=cli.PACKAGE_ROOT, family=item['family'], seed=item['seed'],
                trusted_supplement_sha256=helper_pins, trusted_evidence_sha256=evidence_pins,
                trusted_freeze_supplement_sha256=freeze_trust())
            if failed_context or missing_once:
                with self.assertRaises((ValueError, FileNotFoundError)):
                    cli.execute_prelaunch(raw, **kwargs)
                persist.assert_not_called()
                if missing_once: compiler.assert_not_called(); self.assertEqual(events, [])
            else:
                cli.execute_prelaunch(raw, **kwargs); persist.assert_called_once()
                value = json.loads(persist.call_args.args[0])
                self.assertEqual(value['freeze_loaded_names'], list(cli.FREEZE_CHILD_NAMES))
                self.assertFalse(value['inside_save_hook_verified'])
        return events

    def test_new_worker_only_after_eager_admission_and_fresh_authority(self):
        self.assertEqual(self.run_mock(), ['admission_enter', 'child_enter', 'eager_dynamo',
            'verify', 'new_worker', 'verify', 'child_exit', 'admission_exit'])

    def test_either_failed_context_blocks_sidecar(self):
        self.run_mock(failed_context='child'); self.run_mock(failed_context='admission')

    def test_missing_fresh_once_blocks_every_compile_and_callback(self):
        self.run_mock(missing_once=True)


class OnceIOTests(unittest.TestCase):
    """Portable bounded-read predicates; no real SSD or formal marker writes."""
    def metadata(self, raw, **changed):
        fields = dict(st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_uid=77,
                      st_size=len(raw), st_dev=1, st_ino=2, st_mtime_ns=3)
        fields.update(changed)
        return SimpleNamespace(**fields)

    def test_private_owner_hardlink_and_cap_reject_before_open(self):
        raw = b'{}'; good = self.metadata(raw)
        for changed in (dict(st_mode=stat.S_IFREG|0o644), dict(st_uid=78),
                        dict(st_nlink=2), dict(st_size=cli.JSON_CAP+1)):
            before = self.metadata(raw, **changed)
            path = SimpleNamespace(parents=(), lstat=lambda: before)
            with patch.object(cli, 'Path', return_value=path), \
                 patch.object(cli.os, 'getuid', return_value=77, create=True), \
                 patch.object(cli.os, 'open') as opened:
                with self.assertRaisesRegex(ValueError, 'ONCE_PRIVATE'):
                    cli._read_global_once()
                opened.assert_not_called()

    def test_bounded_snapshot_read_and_identity_change_refused(self):
        raw = b'{}'; good = self.metadata(raw)
        path = SimpleNamespace(parents=(), lstat=lambda: good)
        @contextmanager
        def descriptor(*args):
            yield SimpleNamespace(fileno=lambda: 99, read=lambda cap: raw)
        with patch.object(cli, 'Path', return_value=path), \
             patch.object(cli.os, 'getuid', return_value=77, create=True), \
             patch.object(cli.os, 'open', return_value=99) as opened, \
             patch.object(cli.os, 'fdopen', side_effect=descriptor), \
             patch.object(cli.os, 'fstat', return_value=good):
            self.assertEqual(cli._read_global_once(), raw)
            self.assertEqual(opened.call_args.args[0], path)
        with patch.object(cli, 'Path', return_value=path), \
             patch.object(cli.os, 'getuid', return_value=77, create=True), \
             patch.object(cli.os, 'open', return_value=99), \
             patch.object(cli.os, 'fdopen', side_effect=descriptor), \
             patch.object(cli.os, 'fstat', return_value=self.metadata(raw, st_ino=3)):
            with self.assertRaisesRegex(ValueError, 'ONCE_CHANGED'):
                cli._read_global_once()


if __name__ == '__main__':
    unittest.main()
