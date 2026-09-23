import csv, hashlib, importlib.util, json, os, pathlib, tempfile, unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("v11",ROOT/"src"/"data"/"run_blind_unseal_v11_final.py"); v11=importlib.util.module_from_spec(spec); spec.loader.exec_module(v11)

class v11Tests(unittest.TestCase):
 def setUp(self): self.tmp=tempfile.TemporaryDirectory(); self.root=pathlib.Path(self.tmp.name)
 def tearDown(self):
  v11._ACTIVE_SOURCE_CAPABILITY=None
  self.tmp.cleanup()
 def source_guard(self):
  marker=self.root/"guard_CONSUMED"
  if not marker.exists(): v11.exclusive(str(marker),v11.json_bytes({"schema_version":"blind-runtime-unseal-consumed-v11","status":"CONSUMED","contract_sha256":"c","tool_set_sha256":"t"}))
  token=object(); v11._ACTIVE_SOURCE_CAPABILITY=token
  return (str(marker),"c","t",token)
 def test_layout_semantics(self):
  self.assertEqual(v11.source_rows("hf",{"h_result":"h","f_result":"f"}),[("H","h"),("F","f")])
  self.assertEqual(v11.source_rows("hmf",{"h_result":"h","m_result":"m","f_result":"f"}),[("H","h"),("M","m"),("F","f")])
  self.assertTrue(v11.is_not_run({"status":"TARGET_BEFORE_F","f_result":"stale"},"F","stale")); self.assertFalse(v11.is_not_run({"status":"TARGET_BEFORE_F"},"H",""))
  self.assertEqual(v11.source_rows("repeatability",{"scheme":"H64-M16-F4"}),[("H",""),("M",""),("F","")])
 def test_failed_timeout_attempt_retained(self):
  log=self.root/"F_case.driver.log"; log.write_text("MAPPED_COMMON_ATPG_RUN_ID=F_case\nMAPPED_COMMON_ATPG_MODE=F\nTIMEOUT\nElapsed (wall clock) time (h:mm:ss or m:ss): 0:04.00\nExit status: 124\n",encoding="utf-8")
  rows=v11._attempt_rows(str(self.root),{"phase":"p","cohort":"c","environment_cohort":"e"},self.source_guard())
  self.assertEqual(len(rows),1); self.assertEqual(rows[0]["parse_status"],"TIMEOUT"); self.assertTrue(rows[0]["attempt_id"]); self.assertTrue(rows[0]["source_log_sha256"])
 def test_missing_elapsed_not_dropped(self):
  (self.root/"H_case.driver.log").write_text("MAPPED_COMMON_ATPG_MODE=H\nExit status: 1\n",encoding="utf-8")
  rows=v11._attempt_rows(str(self.root),{"phase":"p","cohort":"c","environment_cohort":"e"},self.source_guard())
  self.assertEqual(rows[0]["parse_status"],"MISSING_ELAPSED")
 def test_direct_source_read_without_consumed_guard_refuses_before_walk(self):
  with mock.patch.object(v11.os,"walk") as walk:
   with self.assertRaises(v11.Refusal): v11._attempt_rows(str(self.root),{"phase":"p","cohort":"c","environment_cohort":"e"},None)
   walk.assert_not_called()
 def test_forged_consumed_marker_and_tuple_is_not_a_source_capability(self):
  marker=self.root/"forged_CONSUMED"
  v11.exclusive(str(marker),v11.json_bytes({"schema_version":"blind-runtime-unseal-consumed-v11","status":"CONSUMED","contract_sha256":"c","tool_set_sha256":"t"}))
  with self.assertRaisesRegex(v11.Refusal,"^SOURCE_ACCESS_BEFORE_CONSUMED$"):
   v11._attempt_rows(str(self.root),{"phase":"p","cohort":"c","environment_cohort":"e"},(str(marker),"c","t",object()))
 def test_every_source_reader_refuses_before_consumed_without_probe(self):
  entry={"measurements_root":str(self.root),"log_root":str(self.root),"measurement_file_set_sha256":"x","driver_log_file_set_sha256":"x","expected_driver_log_count":0}
  readers={
   "table_paths":lambda: list(v11.table_paths(str(self.root),None)),
   "source_sha":lambda: v11._source_sha_file(str(self.root/"source.tsv"),None),
   "scan_log":lambda: v11._scan_log(str(self.root/"source.driver.log"),None),
   "attempt_rows":lambda: v11._attempt_rows(str(self.root),{"phase":"p","cohort":"c","environment_cohort":"e"},None),
   "inventory":lambda: v11._inventory(str(self.root),["source.tsv"],"",None),
   "log_inventory":lambda: v11._log_inventory(str(self.root),None),
   "audit_circuit":lambda: v11._audit_circuit(entry,[],None),
  }
  for name,reader in readers.items():
   with self.subTest(reader=name), mock.patch.object(v11,"_require_source_guard",side_effect=v11.Refusal("SOURCE_ACCESS_BEFORE_CONSUMED")), mock.patch("builtins.open") as opened, mock.patch.object(v11.os,"walk") as walked, mock.patch.object(v11.os.path,"isfile") as isfile:
    with self.assertRaisesRegex(v11.Refusal,"^SOURCE_ACCESS_BEFORE_CONSUMED$"): reader()
    opened.assert_not_called(); walked.assert_not_called(); isfile.assert_not_called()
 def test_retired_generic_readers_refuse_blind_like_paths_before_read_or_hash(self):
  for suffix,reader in (("measurements.tsv",lambda p: v11.read_json(p)),("F_case.driver.log",lambda p: v11.sha_file(p))):
   path=str(self.root/"Phase3"/"blind_x"/suffix)
   with self.subTest(path=path), mock.patch("builtins.open") as opened, mock.patch.object(v11.os.path,"isfile") as isfile, mock.patch.object(v11.os.path,"islink") as islink, mock.patch.object(v11.hashlib,"sha256") as sha:
    with self.assertRaisesRegex(v11.Refusal,"^CONTROL_READER_REQUIRED$"): reader(path)
    opened.assert_not_called(); isfile.assert_not_called(); islink.assert_not_called(); sha.assert_not_called()
 def test_control_reader_rejects_measurement_driver_absolute_escape_and_symlink_before_open(self):
  bad=("01_single_boundaries/measurements.tsv","logs/H_case.driver.log","../Phase3/blind.tsv",str(self.root/"source.driver.log"))
  for relative in bad:
   with self.subTest(relative=relative), mock.patch("builtins.open") as opened, mock.patch.object(v11.os.path,"isfile") as isfile, mock.patch.object(v11.os.path,"islink") as islink, mock.patch.object(v11.hashlib,"sha256") as sha:
     with self.assertRaises(v11.Refusal): v11.control_sha_file(str(self.root),relative)
     opened.assert_not_called(); isfile.assert_not_called(); islink.assert_not_called(); sha.assert_not_called()
 def test_control_reader_rejects_symlinked_whitelisted_control_before_open_or_hash(self):
  relative="contracts/blind_runtime_unseal_v11.json"
  def link(path): return str(path).replace("\\","/").endswith("/contracts")
  with mock.patch("builtins.open") as opened, mock.patch.object(v11.os.path,"isfile") as isfile, mock.patch.object(v11.os.path,"islink",side_effect=link), mock.patch.object(v11.hashlib,"sha256") as sha:
   with self.assertRaisesRegex(v11.Refusal,"^CONTROL_PATH_SYMLINK$"): v11.control_sha_file(str(self.root),relative)
   opened.assert_not_called(); isfile.assert_not_called(); sha.assert_not_called()
 def test_pending_runner_refuses(self): self.assertEqual(v11.main(["--bundle-root",str(self.root)]),2)
 def test_runtime_external_manifest_is_re_read_and_control_drift_refuses(self):
  for relative in sorted(v11.CONTROL_MANIFEST_PATHS):
   path=self.root/relative; path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes((relative+"\n").encode("utf-8"))
  reviewed="a"*40
  manifest={"schema_version":"blind-runtime-unseal-control-manifest-v11","bundle_root":str(self.root),"freeze_commit":reviewed,
            "files":[{"path":relative,"sha256":hashlib.sha256((self.root/relative).read_bytes()).hexdigest()} for relative in sorted(v11.CONTROL_MANIFEST_PATHS)]}
  raw=json.dumps(manifest,sort_keys=True,indent=2).encode("utf-8")+b"\n"
  external=self.root.parent/(self.root.name+"-external-manifest.json"); external.write_bytes(raw)
  try:
   with mock.patch.object(v11,"EXPECTED_EXTERNAL_CONTROL_MANIFEST",str(external)):
    self.assertTrue(v11.verify_external_control_manifest(str(self.root),reviewed,str(external),hashlib.sha256(raw).hexdigest()))
    target=self.root/sorted(v11.CONTROL_MANIFEST_PATHS)[0]; target.write_bytes(b"drift\n")
    with self.assertRaisesRegex(v11.Refusal,"^EXTERNAL_MANIFEST_CONTROL_DIGEST$"):
     v11.verify_external_control_manifest(str(self.root),reviewed,str(external),hashlib.sha256(raw).hexdigest())
    with self.assertRaisesRegex(v11.Refusal,"^EXTERNAL_MANIFEST_DIGEST$"):
     v11.verify_external_control_manifest(str(self.root),reviewed,str(external),"0"*64)
  finally:
   if external.exists(): external.unlink()
 def test_release_pass_equations_and_scheduler_pending_marker(self):
  out=self.root/"out"; out.mkdir(); c={"scope":{"blind_circuits":["x"],"formal_runtime_membership_sha256":"membership","method_registry_sha256":"registry"}}
  v11.exclusive(str(out/"CONSUMED"),v11.json_bytes({"schema_version":"blind-runtime-unseal-consumed-v11","status":"CONSUMED","contract_sha256":"c","tool_set_sha256":"t"}))
  receipt={"schema_version":"blind-runtime-unseal-receipt-v11","status":"PASS","formal_runtime_membership_sha256":"membership","method_registry_sha256":"registry","tool_set_sha256":"t","contract_sha256":"c","failure_code":None,"circuits":[{"circuit":"x","executed_stage_reference_count":2,"unique_runtime_join_count":2,"missing_runtime_join_count":0,"ambiguous_runtime_join_count":0,"coverage_rate":1.0,"distinct_runtime_attempt_count":1,"cross_stage_reference_count":1,"frozen_runtime_eligible_action_space_sha256":"a"*64,"source_artifact_set_sha256":"b"*64,"action_coverage_summary":{"eligible_action_count":1,"all_unique_action_count":1}}]}
  raw=v11.json_bytes(receipt); v11.atomic(str(out/"receipt.json"),raw); dig=hashlib.sha256(raw).hexdigest(); v11.atomic(str(out/"receipt.json.sha256"),(dig+"  receipt.json\n").encode()); v11.exclusive(str(out/"RELEASED"),v11.json_bytes({"schema_version":"blind-runtime-unseal-release-v11","status":"RELEASED_RUNNER_VERIFIED_SCHEDULER_AUDIT_PENDING","contract_sha256":"c","receipt_sha256":dig}))
  self.assertTrue(v11.verify_release(c,"c","t",str(out)))
 def test_release_rejects_empty_action_coverage(self):
  out=self.root/"out"; out.mkdir(); c={"scope":{"blind_circuits":["x"],"formal_runtime_membership_sha256":"membership","method_registry_sha256":"registry"}}; v11.exclusive(str(out/"CONSUMED"),v11.json_bytes({"schema_version":"blind-runtime-unseal-consumed-v11","status":"CONSUMED","contract_sha256":"c","tool_set_sha256":"t"}))
  r={"schema_version":"blind-runtime-unseal-receipt-v11","status":"PASS","formal_runtime_membership_sha256":"membership","method_registry_sha256":"registry","tool_set_sha256":"t","contract_sha256":"c","failure_code":None,"circuits":[{"circuit":"x","executed_stage_reference_count":1,"unique_runtime_join_count":1,"missing_runtime_join_count":0,"ambiguous_runtime_join_count":0,"coverage_rate":1.0,"distinct_runtime_attempt_count":1,"cross_stage_reference_count":0,"frozen_runtime_eligible_action_space_sha256":"a"*64,"source_artifact_set_sha256":"b"*64,"action_coverage_summary":{"eligible_action_count":0,"all_unique_action_count":0}}]}; raw=v11.json_bytes(r); v11.atomic(str(out/"receipt.json"),raw); d=hashlib.sha256(raw).hexdigest(); v11.atomic(str(out/"receipt.json.sha256"),(d+"  receipt.json\n").encode()); v11.exclusive(str(out/"RELEASED"),v11.json_bytes({"schema_version":"blind-runtime-unseal-release-v11","status":"RELEASED_RUNNER_VERIFIED_SCHEDULER_AUDIT_PENDING","contract_sha256":"c","receipt_sha256":d})); self.assertFalse(v11.verify_release(c,"c","t",str(out)))
 def test_release_rejects_count_mismatch(self):
  # A malformed PASS receipt can never verify even when the four files exist.
  out=self.root/"out"; out.mkdir(); c={"scope":{"blind_circuits":["x"],"formal_runtime_membership_sha256":"membership","method_registry_sha256":"registry"}}; v11.exclusive(str(out/"CONSUMED"),v11.json_bytes({"schema_version":"blind-runtime-unseal-consumed-v11","status":"CONSUMED","contract_sha256":"c","tool_set_sha256":"t"}))
  r={"schema_version":"blind-runtime-unseal-receipt-v11","status":"PASS","formal_runtime_membership_sha256":"membership","method_registry_sha256":"registry","tool_set_sha256":"t","contract_sha256":"c","failure_code":None,"circuits":[{"circuit":"x","executed_stage_reference_count":2,"unique_runtime_join_count":1,"missing_runtime_join_count":0,"ambiguous_runtime_join_count":0,"coverage_rate":1.0,"distinct_runtime_attempt_count":1,"cross_stage_reference_count":0,"frozen_runtime_eligible_action_space_sha256":"a"*64,"source_artifact_set_sha256":"b"*64,"action_coverage_summary":{"eligible_action_count":1,"all_unique_action_count":1}}]}; raw=v11.json_bytes(r); v11.atomic(str(out/"receipt.json"),raw); d=hashlib.sha256(raw).hexdigest(); v11.atomic(str(out/"receipt.json.sha256"),(d+"  receipt.json\n").encode()); v11.exclusive(str(out/"RELEASED"),v11.json_bytes({"schema_version":"blind-runtime-unseal-release-v11","status":"RELEASED_RUNNER_VERIFIED_SCHEDULER_AUDIT_PENDING","contract_sha256":"c","receipt_sha256":d})); self.assertFalse(v11.verify_release(c,"c","t",str(out)))
 def test_synthetic_main_success_and_failure_after_consumption(self):
  job={"output_root":str(self.root/"out"),"measurement_files":[],"circuits":[{}]}; contract={"scope":{"blind_circuits":["x"],"formal_runtime_membership_sha256":"membership","method_registry_sha256":"registry"}}; artifacts={"src/data/run_blind_unseal_v11_final.py":"a"*64}
  good={"circuit":"x","executed_stage_reference_count":1,"unique_runtime_join_count":1,"missing_runtime_join_count":0,"ambiguous_runtime_join_count":0,"coverage_rate":1.0,"distinct_runtime_attempt_count":1,"cross_stage_reference_count":0,"frozen_runtime_eligible_action_space_sha256":"a"*64,"source_artifact_set_sha256":"b"*64,"action_coverage_summary":{"eligible_action_count":1,"all_unique_action_count":1}}
  with mock.patch.object(v11,"validate_bundle",return_value=(contract,"c",job,artifacts)), mock.patch.object(v11,"_audit_circuit",return_value=good): self.assertEqual(v11.run(self.tmp.name),0)
  self.assertTrue((self.root/"out"/"CONSUMED").exists())
  self.tmp.cleanup(); self.tmp=tempfile.TemporaryDirectory(); self.root=pathlib.Path(self.tmp.name); job["output_root"]=str(self.root/"out")
  with mock.patch.object(v11,"validate_bundle",return_value=(contract,"c",job,artifacts)), mock.patch.object(v11,"_audit_circuit",side_effect=ValueError("bad")): self.assertEqual(v11.run(self.tmp.name),1)
  self.assertTrue((self.root/"out"/"CONSUMED").exists()); self.assertTrue((self.root/"out"/"RELEASED").exists())
 def test_audit_exception_selects_one_fail_release_without_pass_rewrite(self):
  job={"output_root":str(self.root/"out"),"measurement_files":[],"circuits":[{}]}; contract={"scope":{"blind_circuits":["x"],"formal_runtime_membership_sha256":"membership","method_registry_sha256":"registry"}}; artifacts={"src/data/run_blind_unseal_v11_final.py":"a"*64}; releases=[]
  with mock.patch.object(v11,"validate_bundle",return_value=(contract,"c",job,artifacts)), mock.patch.object(v11,"_audit_circuit",side_effect=RuntimeError("late audit error")), mock.patch.object(v11,"write_release",side_effect=lambda *_args: releases.append(_args[-1])):
   self.assertEqual(v11.run(self.tmp.name),1)
  self.assertEqual(len(releases),1); self.assertEqual((releases[0]["status"],releases[0]["failure_stage"],releases[0]["failure_code"],releases[0]["circuits"]),("FAIL","INTERNAL_AUDIT","INTERNAL_AUDIT_FAILURE",[]))
 def test_failure_receipt_taxonomy_is_exact_and_fail_closed(self):
  contract={"scope":{"blind_circuits":["x"],"formal_runtime_membership_sha256":"membership","method_registry_sha256":"registry"}}
  for stage,code in sorted(v11.FAILURE_TAXONOMY.items()):
   receipt={"schema_version":"blind-runtime-unseal-receipt-v11","status":"FAIL","contract_sha256":"c","tool_set_sha256":"t","failure_stage":stage,"failure_code":code,"circuits":[]}
   with self.subTest(stage=stage):
    self.assertTrue(v11.verify_receipt(contract,"c","t",receipt))
    wrong=dict(receipt); wrong["failure_code"]="WRONG"
    self.assertFalse(v11.verify_receipt(contract,"c","t",wrong))
    extra=dict(receipt); extra["detail"]="leak"
    self.assertFalse(v11.verify_receipt(contract,"c","t",extra))
 def test_preconsumption_refusal_creates_no_output(self):
  with mock.patch.object(v11,"validate_bundle",side_effect=v11.Refusal("EMPTY_CIRCUITS")):
   with self.assertRaisesRegex(v11.Refusal,"^EMPTY_CIRCUITS$"): v11.run(self.tmp.name)
  self.assertFalse((self.root/"out").exists())
 def test_timeout_or_nonzero_without_elapsed_is_missing_runtime_and_fails_r07(self):
  measurement_dir=self.root/"02_hf_coarse"; measurement_dir.mkdir(); logs=self.root/"logs"; logs.mkdir()
  (measurement_dir/"measurements.tsv").write_text("h_patterns\th_result\tf_result\n1\tH_case\tF_case\n",encoding="utf-8")
  (logs/"H_case.driver.log").write_text("MAPPED_COMMON_ATPG_RUN_ID=H_case\nMAPPED_COMMON_ATPG_MODE=H\nElapsed (wall clock) time (h:mm:ss or m:ss): 0:01.00\nExit status: 0\n",encoding="utf-8")
  (logs/"F_case.driver.log").write_text("MAPPED_COMMON_ATPG_RUN_ID=F_case\nMAPPED_COMMON_ATPG_MODE=F\nTIMEOUT\nExit status: 124\n",encoding="utf-8")
  guard=self.source_guard(); files=["02_hf_coarse/measurements.tsv"]
  entry={"circuit":"blind_x","measurements_root":str(self.root),"log_root":str(logs),"phase":"Phase2","cohort":"blind","environment_cohort":"env","measurement_file_set_sha256":v11._inventory(str(self.root),files,"",guard)}
  entry["driver_log_file_set_sha256"],entry["expected_driver_log_count"]=v11._log_inventory(str(logs),guard)
  row=v11._audit_circuit(entry,files,guard)
  self.assertEqual((row["executed_stage_reference_count"],row["unique_runtime_join_count"],row["missing_runtime_join_count"],row["coverage_rate"]),(2,1,1,0.5))
  job={"output_root":str(self.root/"out"),"measurement_files":files,"circuits":[entry]}; contract={"scope":{"blind_circuits":["blind_x"],"formal_runtime_membership_sha256":"membership","method_registry_sha256":"registry"}}; artifacts={"src/data/run_blind_unseal_v11_final.py":"a"*64}
  with mock.patch.object(v11,"validate_bundle",return_value=(contract,"c",job,artifacts)):
   self.assertEqual(v11.run(self.tmp.name),1)
  receipt=json.loads((self.root/"out"/"receipt.json").read_text(encoding="utf-8"))
  self.assertEqual((receipt["status"],receipt["failure_stage"],receipt["failure_code"]),("FAIL","COVERAGE_GATE","R06_R07_FAILED"))
if __name__=="__main__": unittest.main()


