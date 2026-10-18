"""E53 synthetic-only feasibility tests. No actual session files are opened."""
import hashlib
import json
from pathlib import Path
import subprocess
import unittest

MODULE = Path(__file__).resolve().parents[1] / "scripts/recover_ranking_v6_e53_receipt_history.cjs"
SCHEMA = "formal-candidate-space-v2-receipt"


def fixture():
    return {
        "schema_version": SCHEMA,
        "status": "SYNTHETIC_RECEIPT_STATUS",
        "required_circuits": ["SYNTHETIC_PRIVATE_CIRCUIT", "escaped_é"],
        "counts": {
            "input_measurement_count": 987654321,
            "eligible_source_invocation_count": 0,
            "action_count": 0,
            "duplicate_action_count": 0,
            "outcome_conflict_action_count": 0,
            "phase4_reproduced_source_invocation_count": 0,
            "phase4_reproduced_action_count": 0,
        },
        "sha256": {
            "normalized_measurements": "1" * 64,
            "candidate_space": "2" * 64,
            "candidate_space_audit": "3" * 64,
            "source_provenance": "4" * 64,
        },
        "gates": {
            "phase4_source_reproduction_exact": True,
            "phase4_action_reproduction_exact": True,
            "circuit_roster_exact": True,
            "source_candidate_uid_unique": True,
            "action_uid_unique": True,
            "outcome_conflict_count_zero": True,
        },
        "boundaries": {
            "training_allowed": False,
            "blind_rows_read": False,
            "lsf_or_tessent_submitted": False,
            "repeat_aggregation_allowed": False,
        },
    }


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("ascii")


def wrapper(text, kind="custom_tool_call_output", array=True, **extra):
    output = [{"type": "text", "text": text}] if array else text
    payload = {"type": kind, "call_id": "synthetic-call", "output": output}
    payload.update(extra)
    return json.dumps({"timestamp": "2026-10-02T10:53:00Z", "type": "response_item", "payload": payload}) + "\n"


def node(body):
    prefix = "const m=require(" + json.dumps(str(MODULE)) + ");const crypto=require('node:crypto');\n"
    result = subprocess.run(["node", "-e", prefix + body], capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise AssertionError(result.stderr)
    return json.loads(result.stdout)


def recover(lines, expected=None, poison=False, limits=None):
    options = {"allowedCallIds": ["synthetic-call"]}
    if expected:
        options["expectedSha"] = expected
    if limits:
        options["limits"] = limits
    code = "const s=m.createRecovery(" + json.dumps(options) + ");const lines=" + json.dumps(lines) + ";\n"
    if poison:
        code += """
const oldParse=JSON.parse,oldString=Buffer.prototype.toString;let parses=0,utf8=0;
JSON.parse=()=>{parses++;throw Error('POISON_JSON_PARSE');};
Buffer.prototype.toString=function(encoding,...args){if(!encoding||encoding==='utf8'||encoding==='utf-8'){utf8++;throw Error('POISON_UTF8');}return oldString.call(this,encoding,...args);};
let result;try{for(const line of lines){const b=Buffer.from(line);for(let i=0;i<b.length;i+=13)s.feed(b.subarray(i,i+13));}result=s.finish();}
finally{JSON.parse=oldParse;Buffer.prototype.toString=oldString;}
console.log(JSON.stringify({result,parses,utf8}));
"""
    else:
        code += "for(const line of lines)s.feed(Buffer.from(line));console.log(JSON.stringify(s.finish()));"
    return node(code)


class ReceiptHistoryTests(unittest.TestCase):
    def test_python_builder_canonical_reconstruction_and_hash_gated_projection(self):
        value = fixture()
        compact = json.dumps(value, sort_keys=True)
        expected = hashlib.sha256(canonical(value)).hexdigest()
        data = recover([wrapper(compact)], expected, poison=True)
        self.assertEqual(data["parses"], 0)
        self.assertEqual(data["utf8"], 0)
        result = data["result"]
        self.assertEqual(result["counts"]["authenticated"], 1)
        self.assertEqual(result["projection"], {
            "schema_version": SCHEMA,
            "sha256": {
                "source_provenance": "4" * 64,
                "candidate_space": "2" * 64,
                "normalized_measurements": "1" * 64,
            },
        })
        self.assertNotIn("SYNTHETIC_PRIVATE_CIRCUIT", json.dumps(result))
        self.assertNotIn("SYNTHETIC_RECEIPT_STATUS", json.dumps(result))
        self.assertNotIn("987654321", json.dumps(result))
        self.assertFalse(result["provenance_recovered"])
        self.assertFalse(result["execution_authorized"])

    def test_raw_quoted_tool_output_supported_without_full_output_parse(self):
        value = fixture()
        result = recover([wrapper(json.dumps(value, sort_keys=True), kind="function_call_output", array=False)],
                         hashlib.sha256(canonical(value)).hexdigest(), poison=True)
        self.assertEqual(result["result"]["counts"]["authenticated"], 1)
        self.assertEqual(result["parses"], 0)
        self.assertEqual(result["utf8"], 0)

    def test_wrong_real_hash_exports_no_candidate_fields(self):
        result = recover([wrapper(json.dumps(fixture(), sort_keys=True))], poison=True)["result"]
        self.assertEqual(result["counts"]["hash_mismatch"], 1)
        self.assertIsNone(result["projection"])
        self.assertNotIn("44444444", json.dumps(result))
        self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(result))

    def test_commands_users_and_ordinary_results_never_decoded(self):
        text = json.dumps(fixture(), sort_keys=True)
        lines = [
            wrapper(text, kind="custom_tool_call"),
            wrapper(text, kind="message"),
            json.dumps({"timestamp": "2026-10-02T00:00:00Z", "type": "user", "payload": {"type": "custom_tool_call_output", "output": text}}) + "\n",
            wrapper("ORDINARY_QUALITY_TABLE_PRIVATE", metadata={"marker": SCHEMA}),
            wrapper("ORDINARY_MODEL_RESULT_PRIVATE", name="web.run", metadata={"marker": SCHEMA}),
        ]
        result = recover(lines, poison=True)
        self.assertEqual(result["parses"], 0)
        self.assertEqual(result["utf8"], 0)
        self.assertEqual(result["result"]["counts"]["authenticated"], 0)
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_nonreceipt_schema_extra_quality_fields_and_trailing_text_rejected(self):
        value = fixture()
        value["schema_version"] = SCHEMA + "-wrong"
        extra = fixture()
        extra["quality_rows"] = [{"PRIVATE": 987654321}]
        lines = [
            wrapper(json.dumps(value, sort_keys=True)),
            wrapper(json.dumps(extra, sort_keys=True)),
            wrapper(json.dumps(fixture(), sort_keys=True) + "\nORDINARY_TRAILING_QUALITY"),
        ]
        result = recover(lines, poison=True)["result"]
        self.assertIsNone(result["projection"])
        self.assertEqual(result["counts"]["candidate_schema"], 2)
        self.assertEqual(result["counts"]["text_rejected"], 1)
        self.assertNotIn("987654321", json.dumps(result))

    def test_duplicate_keys_and_malformed_json_rejected(self):
        text = json.dumps(fixture(), sort_keys=True)
        duplicate = text.replace('"action_count": 0', '"action_count": 0, "action_count": 0', 1)
        malformed = text.replace('"action_count": 0', '"action_count": 01', 1)
        result = recover([wrapper(duplicate), wrapper(malformed)], poison=True)["result"]
        self.assertEqual(result["counts"]["candidate_grammar"], 2)
        self.assertIsNone(result["projection"])

    def test_unsupported_wrapper_and_no_call_id_do_not_broaden(self):
        text = json.dumps(fixture(), sort_keys=True)
        lines = [
            wrapper(text, output={"type": "text", "text": text}),
            wrapper(text, output=[{"type": "image", "text": text}]),
            wrapper(text, output=[{"type": "text", "text": text, "unexpected": "PRIVATE"}]),
            wrapper(text, call_id=None),
        ]
        result = recover(lines, poison=True)["result"]
        self.assertEqual(result["counts"]["unsupported_wrappers"], 2)
        self.assertEqual(result["counts"]["envelope_skipped"], 2)
        self.assertIsNone(result["projection"])

    def test_utf8_nonascii_body_fail_closed(self):
        raw = wrapper('{"schema_version":"' + SCHEMA + '","bad":"é"}', array=False)
        # raw outer Unicode escape unescapes to non-ASCII: unsupported, not decoded.
        result = recover([raw], poison=True)["result"]
        self.assertEqual(result["counts"]["text_rejected"], 1)
        self.assertIsNone(result["projection"])

    def test_selected_line_input_and_output_bounds(self):
        text = json.dumps(fixture(), sort_keys=True)
        line = wrapper(text)
        selected = recover([line], limits={"selectedBytes": 32})
        self.assertEqual(selected["counts"]["text_rejected"], 1)
        oversized = recover(["x" * 200 + "\n"], limits={"lineBytes": 100})
        self.assertEqual(oversized["counts"]["oversized_lines"], 1)
        bounded = recover([line], limits={"inputBytes": 100})
        self.assertTrue(bounded["input_bound_reached"])
        self.assertIsNone(bounded["projection"])
        packet = node("""
let rejected=false;try{const s=m.createRecovery({allowedCallIds:[],limits:{outputBytes:8}});s.finish();}catch{rejected=true;}
console.log(JSON.stringify({rejected}));
""")
        self.assertTrue(packet["rejected"])

    def test_pretty_byte_cap_and_matched_hash_shapes(self):
        value = fixture()
        text = json.dumps(value, sort_keys=True)
        cap = len(text.encode("ascii")) + 10
        result = recover([wrapper(text)], limits={"selectedBytes": cap})
        self.assertEqual(result["counts"]["canonical_bound"], 1)
        bad = fixture()
        bad["sha256"]["source_provenance"] = "not-a-hash"
        result = recover([wrapper(json.dumps(bad, sort_keys=True))],
                         hashlib.sha256(canonical(bad)).hexdigest())
        self.assertEqual(result["counts"]["matched_hash_field_shape"], 1)
        self.assertIsNone(result["projection"])

    def test_cli_is_disabled_without_history_access(self):
        result = subprocess.run(["node", str(MODULE)], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        data = json.loads(result.stdout)
        self.assertFalse(data["execution_authorized"])
        self.assertEqual(data["status"], "DISABLED_PENDING_SCOPE_AND_INDEPENDENT_REVIEW")

    def test_duplicate_schema_parts_reject_before_unescape(self):
        text = json.dumps(fixture(), sort_keys=True)
        lines = [
            wrapper(text + "\\n" + text, array=False),
            wrapper(text, output=[{"type": "text", "text": text}, {"type": "text", "text": text}]),
        ]
        result = recover(lines, poison=True, limits={"selectedBytes": 1})
        self.assertEqual(result["parses"], 0)
        self.assertEqual(result["utf8"], 0)
        self.assertEqual(result["result"]["counts"]["unsupported_wrappers"], 2)
        self.assertEqual(result["result"]["counts"]["selected_texts"], 0)
        self.assertEqual(result["result"]["counts"]["text_rejected"], 0)
        self.assertIsNone(result["result"]["projection"])

    def test_matching_duplicate_outputs_are_ambiguous_not_released(self):
        value = fixture()
        line = wrapper(json.dumps(value, sort_keys=True))
        result = recover([line, line], hashlib.sha256(canonical(value)).hexdigest())
        self.assertEqual(result["counts"]["authenticated"], 2)
        self.assertEqual(result["status"], "AMBIGUOUS_MATCHING_COPIES_NO_RELEASE")
        self.assertIsNone(result["projection"])

    def test_receipt_plus_ordinary_quality_text_rejected_before_unescape(self):
        value = fixture()
        text = json.dumps(value, sort_keys=True)
        line = wrapper(text, output=[{"type": "text", "text": text},
                                     {"type": "text", "text": "ORDINARY_QUALITY_PRIVATE"}])
        result = recover([line], hashlib.sha256(canonical(value)).hexdigest(),
                         poison=True, limits={"selectedBytes": 1})
        self.assertEqual(result["parses"], 0)
        self.assertEqual(result["utf8"], 0)
        self.assertEqual(result["result"]["counts"]["unsupported_wrappers"], 1)
        self.assertEqual(result["result"]["counts"]["selected_texts"], 0)
        self.assertEqual(result["result"]["counts"]["text_rejected"], 0)
        self.assertIsNone(result["result"]["projection"])
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_input_bound_after_valid_candidate_suppresses_projection(self):
        value = fixture()
        line = wrapper(json.dumps(value, sort_keys=True))
        result = recover([line, "x" * 100], hashlib.sha256(canonical(value)).hexdigest(),
                         limits={"inputBytes": len(line.encode("ascii")) + 10})
        self.assertEqual(result["counts"]["authenticated"], 1)
        self.assertTrue(result["input_bound_reached"])
        self.assertEqual(result["status"], "INCOMPLETE_INPUT_NO_RELEASE")
        self.assertIsNone(result["projection"])

    def test_oversized_line_after_valid_candidate_suppresses_projection(self):
        value = fixture()
        line = wrapper(json.dumps(value, sort_keys=True))
        cap = len(line.encode("ascii")) + 10
        result = recover([line, "x" * (cap + 1) + "\n"],
                         hashlib.sha256(canonical(value)).hexdigest(), limits={"lineBytes": cap})
        self.assertEqual(result["counts"]["authenticated"], 1)
        self.assertEqual(result["counts"]["oversized_lines"], 1)
        self.assertFalse(result["input_bound_reached"])
        self.assertEqual(result["status"], "INCOMPLETE_INPUT_NO_RELEASE")
        self.assertIsNone(result["projection"])

    def test_explicit_positive_call_binding_is_required_before_decode(self):
        line = wrapper(json.dumps(fixture(), sort_keys=True))
        code = "const raw=Buffer.from(" + json.dumps(line) + ");"
        code += """
let missingRejected=false;try{m.createRecovery();}catch{missingRejected=true;}
const s=m.createRecovery({allowedCallIds:['different-positive-call']});
const oldParse=JSON.parse,oldString=Buffer.prototype.toString;let parses=0,decodes=0;
JSON.parse=()=>{parses++;throw Error('POISON_PARSE');};
Buffer.prototype.toString=function(encoding,...args){if(!encoding||encoding==='utf8'||encoding==='utf-8'){decodes++;throw Error('POISON_UTF8');}return oldString.call(this,encoding,...args);};
let result;try{s.feed(raw);result=s.finish();}finally{JSON.parse=oldParse;Buffer.prototype.toString=oldString;}
console.log(JSON.stringify({missingRejected,parses,decodes,result}));
"""
        result = node(code)
        self.assertTrue(result["missingRejected"])
        self.assertEqual(result["parses"], 0)
        self.assertEqual(result["decodes"], 0)
        self.assertEqual(result["result"]["counts"]["selected_texts"], 0)
        self.assertIsNone(result["result"]["projection"])


if __name__ == "__main__":
    unittest.main()
